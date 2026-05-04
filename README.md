# @prefig/upact-mastodon

upact adapter for the Mastodon REST API. The adapter implements [`IdentityPort`](https://github.com/prefig/upact/blob/main/SPEC.md) against any Mastodon-API-compatible fediverse server, with per-login instance discovery and dynamic OAuth client registration.

> Implementation in progress. Usage docs land with v0.1.0; see `CONFORMANCE.md` for the conformance statement once shipped.

## Substrate

The adapter targets servers implementing Mastodon's client-side REST API (`/api/v1/apps`, `/oauth/authorize`, `/oauth/token`, `/api/v1/accounts/verify_credentials`, `/oauth/revoke`). Validated against Mastodon proper at v0.1; Pleroma, Akkoma, GoToSocial, and Iceshrimp MAY work via API compatibility but are not guaranteed.

This is not a generic ActivityPub adapter (ActivityPub does not define third-party-app authentication) and not an ATProto / Bluesky adapter (different protocol, different identity shape). See `docs/plans/2026-05-04-001-feat-upact-mastodon-adapter-plan.md` in the upact repo for the full substrate framing.

## Status

v0.1.0 in progress.

## License

Apache-2.0. See `LICENSE`.
