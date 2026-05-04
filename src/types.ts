// SPDX-License-Identifier: Apache-2.0
/**
 * Public types for `@prefig/upact-mastodon`.
 *
 * `AccountClaims` is intentionally a closed shape: only the fields the
 * adapter is allowed to read from `verify_credentials`. The substrate's
 * actual response carries many more (avatar, header, fields, bot, source,
 * follower counts, …) — they are stripped at the type boundary so the
 * claims-mapper cannot accidentally surface them. See upact SPEC.md §7.
 */

import type { ClientStore } from './client-store.js';
import type { MastodonClient } from './client.js';
import type { CookieJar } from './state-cookies.js';

/**
 * Minimum fields the adapter reads from `GET /api/v1/instance` (v1) or
 * `GET /api/v2/instance` (v2). The probe is satisfied if either `uri`
 * (v1) or `domain` (v2) is a non-empty string.
 */
export interface InstanceInfo {
	uri?: string;
	domain?: string;
	version?: string;
}

/** Body for `POST /api/v1/apps`. */
export interface AppRegistration {
	client_name: string;
	redirect_uris: string;
	scopes: string;
	website?: string;
}

/**
 * Subset of `POST /api/v1/apps` response — only the fields the adapter
 * keeps. The full response also includes `id`, `name`, `redirect_uri`, and
 * `vapid_key`; those are not retained.
 */
export interface ClientCredentials {
	client_id: string;
	client_secret: string;
}

/** Parameters for `POST /oauth/token` (authorization-code grant). */
export interface TokenExchangeParams {
	code: string;
	code_verifier: string;
	client_id: string;
	client_secret: string;
	redirect_uri: string;
}

/**
 * Subset of `POST /oauth/token` response. `created_at` is intentionally
 * not retained — Mastodon access tokens do not auto-expire (F6).
 */
export interface TokenResponse {
	access_token: string;
	scope: string;
	token_type: string;
}

/**
 * Allow-list shape for `GET /api/v1/accounts/verify_credentials`. **The
 * adapter MUST NOT widen this shape** — substrate fields outside this list
 * (avatar, header, fields, source, bot, locked, follower counts, etc.)
 * are stripped at the network boundary so the claims-mapper cannot
 * surface them through the port. See upact SPEC.md §7.
 */
export interface AccountClaims {
	id: string;
	acct: string;
	username: string;
	display_name: string;
	url: string;
}

/** Body for `POST /oauth/revoke`. */
export interface RevokeParams {
	client_id: string;
	client_secret: string;
	token: string;
}

/**
 * Configuration for `createMastodonAdapter`.
 *
 * - `appName` is the name shown when the user authorises at the instance.
 * - `redirectUri` is the URL the instance redirects to after consent.
 *   It MUST match the registered redirect_uri exactly (Mastodon enforces
 *   exact-match including trailing slashes).
 * - `cookieSecret` is the HMAC-SHA256 key used to sign state and session
 *   cookies. Keep it ≥32 bytes and rotate on suspected compromise.
 * - `scopes` defaults to `['read:accounts']`. Forbidden scopes throw at
 *   construction time per upact SPEC.md §7.
 * - `clientStore` defaults to an in-memory Map. Inject a deployment-owned
 *   store (KV, Redis, Postgres, …) for multi-process or persisted setups.
 * - `verifyCredentialsCacheMs` defaults to 60_000. Caching is per-token
 *   in adapter scope; tighter values mean lower revocation latency at the
 *   cost of more `verify_credentials` calls.
 * - `client` is the injection seam for tests and edge runtimes; defaults
 *   to a global-`fetch`-backed implementation.
 */
export interface MastodonConfig {
	appName: string;
	redirectUri: URL;
	cookieSecret: Uint8Array;
	scopes?: readonly string[];
	clientStore?: ClientStore;
	verifyCredentialsCacheMs?: number;
	client?: MastodonClient;
}

/** Input to `buildAuthRedirect`. `instanceInput` accepts a bare hostname
 *  (`mastodon.social`), a WebFinger-shaped handle (`@alice@hachyderm.io`),
 *  or a full URL (`https://social.coop`). */
export interface BuildAuthRedirectInput {
	instanceInput: string;
	returnTo?: string;
}

/**
 * Out-of-port adapter extensions. `buildAuthRedirect` is the init phase
 * of the OAuth flow; it lives outside `IdentityPort` for consistency with
 * the upact-oidc pattern (Decision: D-MAS-3).
 *
 * There is no `buildLogoutRedirect` — Mastodon has no end-session URL
 * analog. `invalidate` revokes the access token via `/oauth/revoke` and
 * clears the session cookie; deployment owns its post-logout UX.
 */
export interface MastodonAdapterExtensions {
	buildAuthRedirect(
		input: BuildAuthRedirectInput,
		cookies: CookieJar,
	): Promise<URL>;
}

/**
 * The credential shape `authenticate` accepts. The adapter only handles
 * the callback phase via the port; the init phase is `buildAuthRedirect`.
 */
export type MastodonCredential = {
	kind: 'mastodon-callback';
	request: Request;
};
