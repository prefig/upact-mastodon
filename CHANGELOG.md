# Changelog

All notable changes to this package are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This package uses [semantic versioning](https://semver.org/) from v1.0.0 onward; v0.x breaking changes are permitted between minor versions.

---

## [0.1.0]: 2026-05-04

First public release of the direct Mastodon adapter for [upact](https://github.com/prefig/upact).

### Added

- `createMastodonAdapter(config, cookies)`: factory returning `IdentityPort & MastodonAdapterExtensions`. Substrate state lives in closure scope per upact SPEC §7.5.
- `buildAuthRedirect(input)`: out-of-port adapter extension for the OAuth init phase. Per-login instance discovery (bare hostname, WebFinger handle, or full URL), dynamic OAuth client registration via `POST /api/v1/apps` with pluggable `ClientStore` cache, PKCE S256, signed state cookie scoped to the redirect_uri path.
- `authenticate({ kind: 'mastodon-callback', request })`: callback phase. Validates state, exchanges code, calls `verify_credentials`, mints opaque `Session` via `createSession`, writes signed session cookie. Maps substrate failures to upact `AuthError` per `CONFORMANCE.md`.
- `currentUpactor(request)`: re-validates the cookie-bound access token via `verify_credentials` with a configurable per-token cache (default 60s). 401 / 410 returns `null` and clears the cookie; 5xx and network failures throw `SubstrateUnavailableError`.
- `invalidate(session)`: revokes the access token via `POST /oauth/revoke` (best-effort) and clears the session cookie.
- `issueRenewal(_, _)`: returns `null` unconditionally per upact Decision 9 + cross-adapter finding F6 (Mastodon access tokens never auto-expire).
- `validateScopes`: runtime guard. Allow-list `['read:accounts', 'profile']`. Forbidden scopes throw at construction time.
- `InMemoryClientStore`: 30-day TTL, injectable now() for testing. Multi-process deployments inject their own `ClientStore` (KV, Redis, Postgres).
- `MastodonInstanceUnreachableError`: extends `SubstrateUnavailableError`. Thrown when the instance probe fails.
- `FetchBackedClient`: default `MastodonClient` implementation backed by the global `fetch`. No runtime dependencies; runs in any Web-platform runtime (Node ≥18, Bun, Deno, Cloudflare Workers, Vercel Edge).
- `CONFORMANCE.md`: filled-in conformance statement against upact v0.1.
- 16-vector reflection test (`tests/back-channel.test.ts`) verifies no sentinel substrate token leaks through the adapter instance.
- Integration test (`tests/integration/mastodon-flow.test.ts`) skipped without `MASTODON_INTEGRATION_TEST_TOKEN` env, validates substrate-call paths against a real instance.

### Substrate

The Mastodon REST API. Validated against Mastodon proper at v0.1; Pleroma, Akkoma, GoToSocial, and Iceshrimp implement the same API as a compatibility layer and MAY work, but are not validated at this version. Not a generic ActivityPub adapter (ActivityPub does not define third-party-app authentication) and not an ATProto / Bluesky adapter (different protocol, different identity shape).
