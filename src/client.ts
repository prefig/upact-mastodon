// SPDX-License-Identifier: Apache-2.0
/**
 * `MastodonClient` — the adapter's substrate-call seam.
 *
 * Five operations cover the entire OAuth + identity-validation flow.
 * The default `FetchBackedClient` uses the global `fetch`, runs in any
 * Web-platform runtime (Node ≥18, Bun, Deno, Cloudflare Workers, Vercel
 * Edge), and has no runtime dependencies. Tests inject a mock client.
 *
 * Each method throws on failure with a `MastodonApiError` carrying the
 * HTTP status and (when present) the OAuth error code from the response
 * body. The adapter (`adapter.ts`) maps thrown errors to `AuthError`
 * codes per `CONFORMANCE.md`.
 */

import type {
	AccountClaims,
	AppRegistration,
	ClientCredentials,
	InstanceInfo,
	RevokeParams,
	TokenExchangeParams,
	TokenResponse,
} from './types.js';

export interface MastodonClient {
	/**
	 * `GET /api/v1/instance` (with v2 fallback). Verifies the origin is
	 * Mastodon-API-compatible. Throws `MastodonApiError` on non-2xx or
	 * `MastodonNetworkError` on transport failure.
	 */
	probeInstance(origin: URL): Promise<InstanceInfo>;

	/**
	 * `POST /api/v1/apps`. Registers an OAuth client at runtime; the
	 * substrate returns `client_id` + `client_secret` to be cached in
	 * the deployment's `ClientStore`.
	 */
	registerClient(
		origin: URL,
		app: AppRegistration,
	): Promise<ClientCredentials>;

	/**
	 * `POST /oauth/token` (authorization-code grant + PKCE verifier).
	 */
	exchangeCode(
		origin: URL,
		params: TokenExchangeParams,
	): Promise<TokenResponse>;

	/**
	 * `GET /api/v1/accounts/verify_credentials`. The substrate response is
	 * destructured into the closed `AccountClaims` shape at the network
	 * boundary; non-allow-listed fields are dropped before the value
	 * leaves this method.
	 */
	verifyCredentials(origin: URL, accessToken: string): Promise<AccountClaims>;

	/**
	 * `POST /oauth/revoke`. Best-effort; the adapter swallows network
	 * errors at this stage because cookie-clear is the load-bearing
	 * client-side step.
	 */
	revokeToken(origin: URL, params: RevokeParams): Promise<void>;
}

/**
 * Carries HTTP status and (when the body parses as an OAuth error) the
 * substrate's `error` and `error_description` strings. The adapter
 * inspects `status` and `error` to map to upact `AuthErrorCode`.
 */
export class MastodonApiError extends Error {
	override name = 'MastodonApiError';
	constructor(
		message: string,
		readonly status: number,
		readonly error?: string,
		readonly errorDescription?: string,
	) {
		super(message);
	}
}

/** Thrown when `fetch` itself rejects (DNS, TLS, network). */
export class MastodonNetworkError extends Error {
	override name = 'MastodonNetworkError';
	constructor(
		message: string,
		readonly cause?: unknown,
	) {
		super(message);
	}
}

interface JsonShape {
	[key: string]: unknown;
}

async function readJson(response: Response): Promise<JsonShape> {
	const text = await response.text();
	if (text === '') return {};
	try {
		return JSON.parse(text) as JsonShape;
	} catch {
		return {};
	}
}

async function throwForStatus(
	response: Response,
	context: string,
): Promise<never> {
	const body = await readJson(response);
	const errorCode =
		typeof body['error'] === 'string' ? body['error'] : undefined;
	const errorDescription =
		typeof body['error_description'] === 'string'
			? body['error_description']
			: undefined;
	throw new MastodonApiError(
		`${context}: HTTP ${response.status}${errorCode ? ` (${errorCode})` : ''}`,
		response.status,
		errorCode,
		errorDescription,
	);
}

async function fetchWrapped(
	url: URL,
	init: RequestInit,
	context: string,
): Promise<Response> {
	try {
		return await fetch(url, init);
	} catch (cause) {
		throw new MastodonNetworkError(`${context}: network failure`, cause);
	}
}

/**
 * Default `MastodonClient` backed by the global `fetch`. Stateless and
 * dependency-free; the adapter can swap it for a mock in tests.
 */
export class FetchBackedClient implements MastodonClient {
	async probeInstance(origin: URL): Promise<InstanceInfo> {
		const v1 = new URL('/api/v1/instance', origin);
		let response = await fetchWrapped(
			v1,
			{ headers: { Accept: 'application/json' } },
			'probeInstance',
		);
		if (response.status === 404) {
			const v2 = new URL('/api/v2/instance', origin);
			response = await fetchWrapped(
				v2,
				{ headers: { Accept: 'application/json' } },
				'probeInstance',
			);
		}
		if (!response.ok) {
			await throwForStatus(response, 'probeInstance');
		}
		const body = await readJson(response);
		const uri = typeof body['uri'] === 'string' ? body['uri'] : undefined;
		const domain =
			typeof body['domain'] === 'string' ? body['domain'] : undefined;
		const version =
			typeof body['version'] === 'string' ? body['version'] : undefined;
		if (!uri && !domain) {
			throw new MastodonApiError(
				'probeInstance: response did not include uri or domain',
				response.status,
			);
		}
		return { uri, domain, version };
	}

	async registerClient(
		origin: URL,
		app: AppRegistration,
	): Promise<ClientCredentials> {
		const url = new URL('/api/v1/apps', origin);
		const response = await fetchWrapped(
			url,
			{
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Accept: 'application/json',
				},
				body: JSON.stringify(app),
			},
			'registerClient',
		);
		if (!response.ok) {
			await throwForStatus(response, 'registerClient');
		}
		const body = await readJson(response);
		const clientId = body['client_id'];
		const clientSecret = body['client_secret'];
		if (typeof clientId !== 'string' || typeof clientSecret !== 'string') {
			throw new MastodonApiError(
				'registerClient: response missing client_id or client_secret',
				response.status,
			);
		}
		return { client_id: clientId, client_secret: clientSecret };
	}

	async exchangeCode(
		origin: URL,
		params: TokenExchangeParams,
	): Promise<TokenResponse> {
		const url = new URL('/oauth/token', origin);
		const form = new URLSearchParams({
			grant_type: 'authorization_code',
			code: params.code,
			code_verifier: params.code_verifier,
			client_id: params.client_id,
			client_secret: params.client_secret,
			redirect_uri: params.redirect_uri,
		});
		const response = await fetchWrapped(
			url,
			{
				method: 'POST',
				headers: {
					'Content-Type': 'application/x-www-form-urlencoded',
					Accept: 'application/json',
				},
				body: form,
			},
			'exchangeCode',
		);
		if (!response.ok) {
			await throwForStatus(response, 'exchangeCode');
		}
		const body = await readJson(response);
		const accessToken = body['access_token'];
		const scope = body['scope'];
		const tokenType = body['token_type'];
		if (
			typeof accessToken !== 'string' ||
			typeof scope !== 'string' ||
			typeof tokenType !== 'string'
		) {
			throw new MastodonApiError(
				'exchangeCode: response missing access_token, scope, or token_type',
				response.status,
			);
		}
		return {
			access_token: accessToken,
			scope,
			token_type: tokenType,
		};
	}

	async verifyCredentials(
		origin: URL,
		accessToken: string,
	): Promise<AccountClaims> {
		const url = new URL('/api/v1/accounts/verify_credentials', origin);
		const response = await fetchWrapped(
			url,
			{
				headers: {
					Authorization: `Bearer ${accessToken}`,
					Accept: 'application/json',
				},
			},
			'verifyCredentials',
		);
		if (!response.ok) {
			await throwForStatus(response, 'verifyCredentials');
		}
		const body = await readJson(response);
		const id = body['id'];
		const acct = body['acct'];
		const username = body['username'];
		const displayName = body['display_name'];
		const accountUrl = body['url'];
		if (
			typeof id !== 'string' ||
			typeof acct !== 'string' ||
			typeof username !== 'string' ||
			typeof displayName !== 'string' ||
			typeof accountUrl !== 'string'
		) {
			throw new MastodonApiError(
				'verifyCredentials: response missing required fields',
				response.status,
			);
		}
		// Allow-list destructure: any other fields the substrate returned
		// are dropped here and never reach the claims-mapper.
		return {
			id,
			acct,
			username,
			display_name: displayName,
			url: accountUrl,
		};
	}

	async revokeToken(origin: URL, params: RevokeParams): Promise<void> {
		const url = new URL('/oauth/revoke', origin);
		const form = new URLSearchParams({
			client_id: params.client_id,
			client_secret: params.client_secret,
			token: params.token,
		});
		const response = await fetchWrapped(
			url,
			{
				method: 'POST',
				headers: {
					'Content-Type': 'application/x-www-form-urlencoded',
					Accept: 'application/json',
				},
				body: form,
			},
			'revokeToken',
		);
		if (!response.ok) {
			await throwForStatus(response, 'revokeToken');
		}
	}
}
