// SPDX-License-Identifier: Apache-2.0
/**
 * Public entry point for `@prefig/upact-mastodon`.
 *
 * The adapter implements `IdentityPort` (from `@prefig/upact`) against any
 * Mastodon-API-compatible server, with per-login instance discovery and
 * dynamic OAuth client registration.
 *
 * Substrate: the Mastodon REST API. Not a generic ActivityPub adapter, and
 * not an ATProto/Bluesky adapter: see the plan in the upact repo for the
 * full framing.
 */

export { createMastodonAdapter } from './adapter.js';
export {
	MastodonInstanceUnreachableError,
} from './errors.js';
export {
	DEFAULT_SCOPES,
	validateScopes,
} from './scope-policy.js';
export {
	InMemoryClientStore,
	type ClientStore,
	type ClientRecord,
	type InMemoryClientStoreOptions,
} from './client-store.js';
export type { CookieJar, CookieSetOptions } from './state-cookies.js';
export type {
	MastodonClient,
	MastodonApiError,
	MastodonNetworkError,
} from './client.js';
export type {
	MastodonConfig,
	MastodonCredential,
	MastodonAdapterExtensions,
	BuildAuthRedirectInput,
	AccountClaims,
	InstanceInfo,
} from './types.js';
