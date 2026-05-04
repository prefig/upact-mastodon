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

import type { IdentityPort, Session, Upactor, AuthError } from '@prefig/upact';
import { FetchBackedClient, type MastodonClient } from './client.js';
import { InMemoryClientStore, type ClientStore } from './client-store.js';
import { resolveInstance } from './instance-resolver.js';
import { DEFAULT_SCOPES, validateScopes } from './scope-policy.js';
import {
	writePendingState,
	type CookieJar,
	type PendingState,
} from './state-cookies.js';
import type {
	BuildAuthRedirectInput,
	MastodonAdapterExtensions,
	MastodonConfig,
} from './types.js';

export function createMastodonAdapter(
	config: MastodonConfig,
	cookies: CookieJar,
): IdentityPort & MastodonAdapterExtensions {
	const scopes = config.scopes ?? DEFAULT_SCOPES;
	validateScopes(scopes);
	const client: MastodonClient = config.client ?? new FetchBackedClient();
	const clientStore: ClientStore = config.clientStore ?? new InMemoryClientStore();
	const scopeString = scopes.join(' ');

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

		async authenticate(_credential: unknown): Promise<Session | AuthError> {
			throw new Error('authenticate: not implemented yet (U9)');
		},

		async currentUpactor(_request: Request): Promise<Upactor | null> {
			throw new Error('currentUpactor: not implemented yet (U9)');
		},

		async invalidate(_session: Session): Promise<void> {
			throw new Error('invalidate: not implemented yet (U10)');
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
