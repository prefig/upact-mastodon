# @prefig/upact-mastodon

[upact](https://github.com/prefig/upact) adapter for the Mastodon REST API. Per-login instance discovery, dynamic OAuth client registration, and the privacy-strip discipline upact requires. The user signs in with any Mastodon-API-compatible fediverse server they choose.

## What this adapter is, and is not

This is a **Mastodon REST API OAuth client** that exposes an `IdentityPort` to your application. The adapter targets servers implementing Mastodon's client-side REST API: Mastodon proper, and (transitively, MAY-work-not-guaranteed at v0.1) Pleroma, Akkoma, GoToSocial, and Iceshrimp.

It is **not a generic ActivityPub adapter**. ActivityPub does not define an end-user authentication mechanism for third-party apps. It is **not an ATProto / Bluesky adapter** either; ATProto uses different identity (DIDs), different discovery (PLC directory), and OAuth + DPoP. Pick the right adapter for your substrate.

## Why a direct adapter (vs configuring `@prefig/upact-oidc` with Authentik)

Path B (the OIDC adapter brokered through Authentik or Keycloak) requires preregistering each instance as a federation source at the IDP. For an application whose value proposition is "sign in with any fediverse handle," that preregistration loop is incompatible with the user experience. The direct adapter resolves the user-supplied instance at login time and registers OAuth credentials dynamically.

If your deployment authenticates against ONE fixed instance (your-org.social), prefer `@prefig/upact-oidc` plus Authentik. If users pick their own home instance, use this package.

## Install

```bash
npm install @prefig/upact @prefig/upact-mastodon
```

The adapter has no runtime dependencies beyond the global `fetch`. Runs in Node ≥18, Bun, Deno, Cloudflare Workers, and Vercel Edge.

## Usage (SvelteKit)

```ts
// src/hooks.server.ts
import type { Handle } from '@sveltejs/kit';
import { createMastodonAdapter } from '@prefig/upact-mastodon';
import { MASTODON_COOKIE_SECRET } from '$env/static/private';

export const handle: Handle = async ({ event, resolve }) => {
	event.locals.identityPort = createMastodonAdapter(
		{
			appName: 'My App',
			redirectUri: new URL('https://app.example.com/auth/callback'),
			cookieSecret: new TextEncoder().encode(MASTODON_COOKIE_SECRET),
		},
		event.cookies,
	);
	event.locals.upactor = await event.locals.identityPort.currentUpactor(event.request);
	return resolve(event);
};
```

```ts
// src/routes/auth/login/+page.server.ts
import type { Actions } from './$types';
import { redirect } from '@sveltejs/kit';

export const actions: Actions = {
	default: async ({ request, locals }) => {
		const data = await request.formData();
		const instance = String(data.get('instance') ?? '').trim();
		const url = await locals.identityPort.buildAuthRedirect({
			instanceInput: instance,
			returnTo: '/',
		});
		throw redirect(303, url.toString());
	},
};
```

```ts
// src/routes/auth/callback/+page.server.ts
import type { PageServerLoad } from './$types';
import { redirect } from '@sveltejs/kit';

export const load: PageServerLoad = async ({ request, locals }) => {
	const result = await locals.identityPort.authenticate({
		kind: 'mastodon-callback',
		request,
	});
	if ('code' in result) {
		// AuthError: render an error page or redirect to login with a flash message
		throw redirect(303, `/auth/login?error=${result.code}`);
	}
	throw redirect(303, '/');
};
```

```ts
// src/routes/+layout.server.ts
import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = async ({ locals }) => {
	return { upactor: locals.upactor };
};
```

The login UI is whatever you want. The minimum it needs is a text input where the user types their home instance (or the WebFinger handle form, `@alice@hachyderm.io`).

## Configuration

```ts
interface MastodonConfig {
	appName: string;
	redirectUri: URL;
	cookieSecret: Uint8Array;
	scopes?: readonly string[];
	clientStore?: ClientStore;
	verifyCredentialsCacheMs?: number;
	client?: MastodonClient;
}
```

| Field | Required | Default | Notes |
|---|---|---|---|
| `appName` | yes | | The name shown to the user when they authorise at their instance. |
| `redirectUri` | yes | | The URL the instance redirects to after consent. MUST match exactly (including trailing slash). |
| `cookieSecret` | yes | | HMAC-SHA256 key for state and session cookies. ≥32 bytes recommended; rotate on suspected compromise. |
| `scopes` | no | `['read:accounts']` | Forbidden scopes throw at construction. Allow-list: `['read:accounts', 'profile']`. See SPEC §7. |
| `clientStore` | no | `InMemoryClientStore` | Pluggable cache for per-instance OAuth client credentials. Inject your own (KV, Redis, Postgres) for multi-process deployments. |
| `verifyCredentialsCacheMs` | no | `60_000` | Per-token cache window for `verify_credentials`. Tighter values mean lower revocation latency. |
| `client` | no | `FetchBackedClient` | Injection seam for tests and custom transports. |

## Capabilities

`Upactor.capabilities` is always `[]` for this adapter at v0.1. ActivityPub messaging is a real substrate affordance, but it is not declared here pre-emptively per the [project's audit discipline](https://github.com/prefig/upact/blob/main/CONTRIBUTING.md). New capabilities land when a concrete consumer surfaces.

## Security posture

- The adapter follows upact SPEC.md §7 (privacy minima) and §7.5 (back-channel closure). The `Upactor` carries only `id`, `display_hint`, `capabilities`, `lifecycle`, `provenance`. Substrate fields outside the closed `AccountClaims` allow-list are stripped at the network boundary.
- Substrate state (access token, client credentials, cookie secret, instance origin, actor URL) lives in closure scope. `(adapter as any).client` returns `undefined`. The 16-vector reflection test at `tests/back-channel.test.ts` is the operational form of §7.5 conformance.
- PKCE S256 is unconditional, even though Mastodon does not strictly require it for confidential clients (defense in depth).
- The state cookie carries `state`, `code_verifier`, `instance`, and `returnTo`, signed with HMAC-SHA256 and scoped to the redirect_uri path. 10-minute TTL.
- Mastodon access tokens do NOT auto-expire (per `docs.joinmastodon.org/api/oauth-tokens`). `Upactor.lifecycle.expires_at` is `undefined`; `renewable` is `'reauth'`. `issueRenewal` returns `null` unconditionally.

## Threat model and instance trust

The adapter trusts the instance the user supplies. It does NOT enforce an instance allow-list, validate cryptographic actor keys, or guard against typo-squatting (`mastod0n.social`). Deployments that need any of these wrap the adapter:

```ts
const ALLOWED = new Set(['mastodon.social', 'hachyderm.io', 'social.coop']);

async function buildRestrictedRedirect(input: string) {
	const host = parseHost(input);
	if (!ALLOWED.has(host)) throw new Error('instance not allowed');
	return identityPort.buildAuthRedirect({ instanceInput: input });
}
```

See `CONFORMANCE.md` for the full conformance statement and the `AuthError` mapping table.

## Status

v0.1.0. First public release. Breaking changes between v0.x revisions are permitted; v1.0 marks the first stable version.

## License

Apache-2.0. See `LICENSE`.
