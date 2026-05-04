// SPDX-License-Identifier: Apache-2.0
/**
 * `createMastodonAdapter`: the per-request factory that produces a
 * conforming `IdentityPort` plus the out-of-port `buildAuthRedirect`
 * extension.
 *
 * The factory is the operational form of upact SPEC.md §7.5: substrate
 * state (tokens, instance origin, actor URL) lives in closure scope,
 * never on enumerable instance properties. `(adapter as any).client`
 * returns undefined; the sixteen-vector reflection test in U11 asserts
 * this for every common reflection vector.
 *
 * U8 ships `buildAuthRedirect` (the init phase). U9 fills in
 * `authenticate`, `currentUpactor`. U10 fills in `invalidate` and
 * `issueRenewal`.
 */

import {
	createSession,
	SubstrateUnavailableError,
	type AuthError,
	type AuthErrorCode,
	type IdentityPort,
	type Session,
	type Upactor,
} from '@prefig/upact';
import { _unwrapSession } from '@prefig/upact/internal';
import { mapAccountToUpactor } from './claims-mapper.js';
import {
	FetchBackedClient,
	MastodonApiError,
	MastodonNetworkError,
	type MastodonClient,
} from './client.js';
import { InMemoryClientStore, type ClientStore } from './client-store.js';
import { resolveInstance } from './instance-resolver.js';
import { DEFAULT_SCOPES, validateScopes } from './scope-policy.js';
import {
	clearPendingState,
	clearSessionState,
	readPendingState,
	readSessionState,
	writePendingState,
	writeSessionState,
	type CookieJar,
	type PendingState,
	type SessionState,
} from './state-cookies.js';
import type {
	BuildAuthRedirectInput,
	MastodonAdapterExtensions,
	MastodonConfig,
} from './types.js';

/**
 * Module-scoped cache for `verify_credentials` results. Keyed by
 * access token; entries expire after `verifyCredentialsCacheMs`. The
 * cache survives across adapter instances within the same process,
 * which matches the per-request adapter pattern (each request builds
 * a fresh adapter; the cache spans them all).
 */
const VERIFY_CACHE = new Map<
	string,
	{ upactor: Upactor; expires_at: number }
>();

const DEFAULT_VERIFY_CACHE_MS = 60_000;

export function createMastodonAdapter(
	config: MastodonConfig,
	cookies: CookieJar,
): IdentityPort & MastodonAdapterExtensions {
	const scopes = config.scopes ?? DEFAULT_SCOPES;
	validateScopes(scopes);
	const client: MastodonClient = config.client ?? new FetchBackedClient();
	const clientStore: ClientStore = config.clientStore ?? new InMemoryClientStore();
	const scopeString = scopes.join(' ');
	const verifyCacheMs = config.verifyCredentialsCacheMs ?? DEFAULT_VERIFY_CACHE_MS;

	return {
		async buildAuthRedirect(input: BuildAuthRedirectInput): Promise<URL> {
			const origin = await resolveInstance(input.instanceInput, client);
			const originKey = origin.toString();
			let credentials = await clientStore.get(originKey);
			if (!credentials) {
				const fresh = await client.registerClient(origin, {
					client_name: config.appName,
					redirect_uris: config.redirectUri.toString(),
					scopes: scopeString,
				});
				credentials = { ...fresh, registered_at: new Date() };
				await clientStore.set(originKey, credentials);
			}

			const state = randomBase64url(32);
			const codeVerifier = randomBase64url(64);
			const codeChallenge = await sha256Base64url(codeVerifier);

			const pending: PendingState = {
				state,
				code_verifier: codeVerifier,
				instance: originKey,
				...(input.returnTo !== undefined ? { returnTo: input.returnTo } : {}),
			};
			await writePendingState(cookies, config.cookieSecret, pending, {
				redirectUri: config.redirectUri,
			});

			const authorize = new URL('/oauth/authorize', origin);
			authorize.searchParams.set('response_type', 'code');
			authorize.searchParams.set('client_id', credentials.client_id);
			authorize.searchParams.set('redirect_uri', config.redirectUri.toString());
			authorize.searchParams.set('scope', scopeString);
			authorize.searchParams.set('state', state);
			authorize.searchParams.set('code_challenge', codeChallenge);
			authorize.searchParams.set('code_challenge_method', 'S256');
			return authorize;
		},

		async authenticate(credential: unknown): Promise<Session | AuthError> {
			if (!isCallbackCredential(credential)) {
				return authError(
					'credential_invalid',
					'authenticate: expected { kind: "mastodon-callback", request }',
				);
			}

			const pending = await readPendingState(cookies, config.cookieSecret);
			clearPendingState(cookies, { redirectUri: config.redirectUri });
			if (!pending) {
				return authError(
					'credential_invalid',
					'authenticate: PendingState cookie missing or expired',
				);
			}

			let queryState: string | null;
			let code: string | null;
			try {
				const url = new URL(credential.request.url);
				queryState = url.searchParams.get('state');
				code = url.searchParams.get('code');
			} catch {
				return authError(
					'credential_invalid',
					'authenticate: request URL is not parseable',
				);
			}

			if (!queryState || queryState !== pending.state) {
				return authError(
					'credential_invalid',
					'authenticate: state mismatch (possible CSRF)',
				);
			}
			if (!code) {
				return authError(
					'credential_invalid',
					'authenticate: callback URL missing "code"',
				);
			}

			const instanceOrigin = new URL(pending.instance);
			const credentials = await clientStore.get(pending.instance);
			if (!credentials) {
				// Client credentials gone (cache evicted between init and
				// callback). Deployments can avoid this by using a persistent
				// ClientStore; for the in-memory default it is recoverable
				// only by retrying the login flow.
				return authError(
					'auth_failed',
					'authenticate: client credentials unavailable for this instance (cache miss between init and callback)',
				);
			}

			let token: string;
			try {
				const tokenResponse = await client.exchangeCode(instanceOrigin, {
					code,
					code_verifier: pending.code_verifier,
					client_id: credentials.client_id,
					client_secret: credentials.client_secret,
					redirect_uri: config.redirectUri.toString(),
				});
				token = tokenResponse.access_token;
			} catch (e) {
				return mapAuthError(e, 'authenticate.exchangeCode');
			}

			let claims;
			try {
				claims = await client.verifyCredentials(instanceOrigin, token);
			} catch (e) {
				return mapAuthError(e, 'authenticate.verifyCredentials');
			}

			const upactor = await mapAccountToUpactor(claims, instanceOrigin);
			VERIFY_CACHE.set(token, {
				upactor,
				expires_at: Date.now() + verifyCacheMs,
			});

			const sessionState: SessionState = {
				access_token: token,
				actor_url: claims.url,
				instance: pending.instance,
			};
			await writeSessionState(cookies, config.cookieSecret, sessionState);

			return createSession(sessionState);
		},

		async currentUpactor(_request: Request): Promise<Upactor | null> {
			const session = await readSessionState(cookies, config.cookieSecret);
			if (!session) return null;

			const cached = VERIFY_CACHE.get(session.access_token);
			if (cached && cached.expires_at > Date.now()) {
				return cached.upactor;
			}

			const instanceOrigin = new URL(session.instance);
			let claims;
			try {
				claims = await client.verifyCredentials(
					instanceOrigin,
					session.access_token,
				);
			} catch (e) {
				if (
					e instanceof MastodonApiError &&
					(e.status === 401 || e.status === 410)
				) {
					// Token revoked or account suspended: treat as logged-out.
					VERIFY_CACHE.delete(session.access_token);
					clearSessionState(cookies);
					return null;
				}
				if (e instanceof SubstrateUnavailableError) throw e;
				throw new SubstrateUnavailableError(
					`currentUpactor: ${formatErrorMessage(e)}`,
				);
			}

			const upactor = await mapAccountToUpactor(claims, instanceOrigin);
			VERIFY_CACHE.set(session.access_token, {
				upactor,
				expires_at: Date.now() + verifyCacheMs,
			});
			return upactor;
		},

		async invalidate(session: Session): Promise<void> {
			const state = _unwrapSession<SessionState>(session);
			clearSessionState(cookies);
			if (!state) return;
			VERIFY_CACHE.delete(state.access_token);
			const credentials = await clientStore.get(state.instance);
			if (!credentials) return;
			try {
				await client.revokeToken(new URL(state.instance), {
					client_id: credentials.client_id,
					client_secret: credentials.client_secret,
					token: state.access_token,
				});
			} catch {
				// Best-effort. The cookie clear is the load-bearing
				// client-side step; the substrate-side revoke is hygiene
				// and can fail silently.
			}
		},

		async issueRenewal(
			_identity: Upactor,
			_evidence: unknown,
		): Promise<Upactor | null> {
			return null;
		},
	};
}

function randomBase64url(byteLength: number): string {
	const bytes = new Uint8Array(byteLength);
	crypto.getRandomValues(bytes);
	let binary = '';
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sha256Base64url(input: string): Promise<string> {
	const bytes = new TextEncoder().encode(input);
	const digest = await crypto.subtle.digest('SHA-256', bytes);
	const view = new Uint8Array(digest);
	let binary = '';
	for (const byte of view) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function isCallbackCredential(
	value: unknown,
): value is { kind: 'mastodon-callback'; request: Request } {
	if (typeof value !== 'object' || value === null) return false;
	const candidate = value as { kind?: unknown; request?: unknown };
	return (
		candidate.kind === 'mastodon-callback' &&
		typeof candidate.request === 'object' &&
		candidate.request !== null &&
		'url' in candidate.request
	);
}

function authError(code: AuthErrorCode, message: string): AuthError {
	return { code, message };
}

/**
 * Maps a thrown error from `exchangeCode` or `verifyCredentials` to an
 * upact `AuthError` per CONFORMANCE.md. The OAuth error codes inside
 * `MastodonApiError` carry the substrate's intent; HTTP status alone is
 * coarser. Both are inspected.
 */
function mapAuthError(error: unknown, context: string): AuthError {
	if (error instanceof MastodonApiError) {
		// Rate limits at any endpoint surface as rate_limited.
		if (error.status === 429 || error.error === 'slow_down') {
			return authError(
				'rate_limited',
				`${context}: ${error.message}`,
			);
		}
		// 5xx and 5xx-like substrate failures: not the credential's fault.
		if (error.status >= 500) {
			return authError(
				'substrate_unavailable',
				`${context}: ${error.message}`,
			);
		}
		// 401 / 410 on verifyCredentials: token rejected or account gone.
		// 401 invalid_grant on exchangeCode: code expired or already used.
		if (
			error.status === 401 ||
			error.status === 410 ||
			error.error === 'invalid_grant' ||
			error.error === 'access_denied' ||
			error.error === 'interaction_required'
		) {
			return authError(
				'credential_rejected',
				`${context}: ${error.message}`,
			);
		}
		// invalid_request, invalid_client, unsupported_grant_type: misconfig.
		if (
			error.error === 'invalid_request' ||
			error.error === 'invalid_client' ||
			error.error === 'unauthorized_client' ||
			error.error === 'unsupported_grant_type'
		) {
			return authError(
				'auth_failed',
				`${context}: ${error.message}`,
			);
		}
		return authError('auth_failed', `${context}: ${error.message}`);
	}
	if (error instanceof MastodonNetworkError) {
		return authError(
			'substrate_unavailable',
			`${context}: ${error.message}`,
		);
	}
	return authError('auth_failed', `${context}: ${formatErrorMessage(error)}`);
}

function formatErrorMessage(error: unknown): string {
	if (error instanceof Error) return error.message;
	return String(error);
}
