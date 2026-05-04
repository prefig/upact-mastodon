# Conformance: @prefig/upact-mastodon

**Spec version:** upact v0.1
**Package version:** 0.1.0
**Date:** 2026-05-04

## Substrate

The Mastodon REST API. Specifically, any server implementing the client-side REST API endpoints `GET /api/v1/instance` (or `/api/v2/instance`), `POST /api/v1/apps`, `POST /oauth/token`, `GET /api/v1/accounts/verify_credentials`, and `POST /oauth/revoke`. Mastodon proper is the validated substrate at v0.1; Pleroma, Akkoma, GoToSocial, and Iceshrimp implement the same API as a compatibility layer and MAY work, but are not validated at this version.

Enforcement-camp substrate: the `verify_credentials` response carries far more than the port permits (avatar, header, fields, source, bot, locked, follower/following counts, last_status_at, created_at, ...). The adapter strips all of these at the network boundary by destructuring into the closed `AccountClaims` shape; the claims-mapper sees only the five allow-listed fields and cannot widen.

## Threat model

Casual coordination and pseudonymous fediverse use. The adapter trusts the instance the user supplies (by typing it at login) and trusts the instance's `verify_credentials` response. It does not enforce an instance allow-list, validate cryptographic actor keys (HTTP Signatures), or guard against typo-squatting. Deployments needing stronger guarantees wrap the adapter with their own policy layer.

The adapter is appropriate for fediverse-shaped social applications where the user's home instance is per-user and not knowable until login. It is not appropriate for adversarial-context coordination where substrate-operator trust is not granted; for that, consider a pre-conforming substrate per upact SPEC §10.

## Capabilities self-declared

`[]` for v0.1.

ActivityPub messaging (Direct Messages) is a real substrate affordance but is not surfaced through the port at v0.1. Per upact CONTRIBUTING.md's minimum-viable principle (`F1` in cross-adapter findings), capabilities land when a concrete consumer surfaces them.

Concrete consumer for the v0.1 cap set: none required, since `[]` is the empty case.

## AuthError mapping table

| Substrate failure | `AuthErrorCode` |
|---|---|
| `exchangeCode` returns `invalid_grant` (code expired or replayed) | `credential_rejected` |
| `exchangeCode` returns `invalid_request` / `invalid_client` / `unauthorized_client` / `unsupported_grant_type` | `auth_failed` (config error) |
| `exchangeCode` 5xx or network failure | `substrate_unavailable` |
| `exchangeCode` 429 or `slow_down` | `rate_limited` |
| `verifyCredentials` 401 (token revoked) | `credential_rejected` |
| `verifyCredentials` 410 (account suspended) | `credential_rejected` |
| `verifyCredentials` 5xx or network failure | `substrate_unavailable` |
| `verifyCredentials` 429 | `rate_limited` |
| State cookie missing, expired, or tampered | `credential_invalid` |
| State query parameter absent or mismatched | `credential_invalid` |
| `code` query parameter absent | `credential_invalid` |
| Client credentials gone from `ClientStore` between init and callback | `auth_failed` |
| Unknown error | `auth_failed` |

`identity_unavailable` is not emitted by this adapter at v0.1. Mastodon does not expose a "user does not exist" signal distinct from "credential rejected".

## Session opacity

This adapter uses `createSession` from `@prefig/upact` for `Session` construction. The opacity guarantee at SPEC §7.4 is inherited from the upact runtime kernel. `_unwrapSession` is imported from `@prefig/upact/internal` only inside `invalidate`, which is the marked boundary for substrate-side calls.

## Adapter back-channel closure

This adapter passes a 16-vector reflection test at `tests/back-channel.test.ts`. After driving the adapter through a full happy-path authenticate, sentinel substrate values (access token, client secret, actor URL, cookie secret) are unreachable through:

1. `JSON.stringify(adapter)`
2. `Object.keys(adapter)`
3. `Object.getOwnPropertyNames(adapter)`
4. `Reflect.ownKeys(adapter)`
5. `Object.getOwnPropertySymbols(adapter)`
6. `for-in` iteration
7. `structuredClone` (or `DataCloneError`)
8. `util.inspect(adapter, { depth: null, showHidden: true })`
9. Cast access to `.client`
10. Cast access to `.mastodon`
11. Cast access to `._client`
12. Cast access to `.accessToken` / `.tokens`
13. Cast access to `.cookies` / `.cookieSecret`
14. Cast access to `.clientStore`
15. Object spread (`{ ...adapter }`)
16. `JSON.stringify` wrapped in an outer object

`(adapter as any).client === undefined` is the Decision 11 conformance signal.

## Identifier derivation

`Upactor.id` is `SHA-256(actor.url).slice(0, 32)` (the first 32 hex characters of the SHA-256 digest, computed via Web Crypto's `crypto.subtle.digest`).

The actor URL (`https://hachyderm.io/users/alice`) is the network-legible identifier the substrate uses; the hash is the port-opaque form. The actor URL is held in closure for substrate-side calls (`verify_credentials`, `oauth/revoke`); it is never exposed through the port. The derivation is deterministic per actor URL and not reversible from the application layer (per upact F3 / SPEC §7.3).

## Lifecycle

`Upactor.lifecycle = { expires_at: undefined, renewable: 'reauth' }` for every Upactor this adapter produces.

Mastodon access tokens do not auto-expire (per `docs.joinmastodon.org/api/oauth-tokens`: *"tokens will not expire automatically and will become invalid only when deleted by a user or revoked by the app"*). `expires_at: undefined` is the explicit representation of "no intrinsic TTL" per SPEC §8 and cross-adapter finding F6.

`renewable: 'reauth'` because the only path to a new token is a fresh OAuth flow (Mastodon does not issue refresh tokens). `issueRenewal` returns `null` unconditionally per Decision 9.

## Provenance

`Upactor.provenance = { substrate: 'mastodon', instance: <origin URL> }` for every Upactor.

`provenance.substrate` is always the literal `'mastodon'`; this adapter does not differentiate between Mastodon proper and the API-compatible forks at the port level. Applications that need to discriminate can check `provenance.instance` against a known-fork origin list.

## Scope policy

Default scope: `['read:accounts']` (works on Mastodon ≥3.x).
Allowed scope set: `['read:accounts', 'profile']`. `'profile'` is the narrower scope on Mastodon ≥4.3.
Forbidden scope set (enforced at construction time, throws): anything outside the allowed set, including `'read'`, `'read:statuses'`, `'read:notifications'`, `'write'`, `'write:*'`, `'follow'`, `'push'`. The error message cites SPEC §7.

The runtime guard means a misconfigured deployment fails fast, before any user sees an authorize URL.

## PKCE

PKCE S256 is unconditional. Plain method is never used. The verifier is 64 random bytes, base64url-encoded; the challenge is `SHA-256(verifier)` base64url-encoded.

## Closure-captured state

- Access token: in closure (held in the `SessionState` written to a signed cookie; recovered via `_unwrapSession` only inside `invalidate`)
- Actor URL: in closure (held in `SessionState`)
- Instance origin: in closure (held in `SessionState` and in `MastodonConfig`)
- Client credentials (client_id, client_secret): in the `ClientStore` and looked up on demand by instance origin
- Cookie secret: in closure (passed to `MastodonConfig`)
- `MastodonClient` instance (default `FetchBackedClient`): in closure
- `ClientStore` instance: in closure

None of these are reachable via reflection on the adapter instance.

## Deviations from SHOULD clauses

None.

## Out-of-port helpers

`buildAuthRedirect` is exposed as an adapter extension method (out of `IdentityPort`) for the OAuth init phase. It returns the `/oauth/authorize` URL and writes the signed `PendingState` cookie. There is no `buildLogoutRedirect`: Mastodon has no end-session URL analog. `invalidate` calls `POST /oauth/revoke` and clears the session cookie; deployment owns post-logout UX.
