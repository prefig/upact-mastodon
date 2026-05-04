// SPDX-License-Identifier: Apache-2.0
/**
 * Tests for `createMastodonAdapter` and the `buildAuthRedirect` init phase.
 *
 * Tests for `authenticate`, `currentUpactor`, `invalidate` land in U9/U10.
 */

import { describe, it, expect, vi } from 'vitest';
import { SubstrateUnavailableError, type Session, type Upactor } from '@prefig/upact';
import { _unwrapSession } from '@prefig/upact/internal';
import { createMastodonAdapter } from '../src/adapter.js';
import { MastodonInstanceUnreachableError } from '../src/errors.js';
import {
	MastodonApiError,
	MastodonNetworkError,
	type MastodonClient,
} from '../src/client.js';
import type { ClientStore, ClientRecord } from '../src/client-store.js';
import type { CookieJar, CookieSetOptions } from '../src/state-cookies.js';
import {
	PENDING_COOKIE_NAME,
	SESSION_COOKIE_NAME,
} from '../src/state-cookies.js';
import type { MastodonConfig, AccountClaims } from '../src/types.js';

const SECRET = new Uint8Array(
	Array.from('test-secret-32-bytes-long-aaaaaa').map((c) => c.charCodeAt(0)),
);

function jar(): CookieJar & {
	store: Map<string, string>;
	options: Map<string, CookieSetOptions | undefined>;
} {
	const store = new Map<string, string>();
	const options = new Map<string, CookieSetOptions | undefined>();
	return {
		store,
		options,
		get: (name) => store.get(name),
		set: (name, value, opts) => {
			store.set(name, value);
			options.set(name, opts);
		},
		delete: (name) => store.delete(name),
	};
}

function makeClient(overrides: Partial<MastodonClient> = {}): MastodonClient {
	return {
		probeInstance: vi.fn(async () => ({
			uri: 'hachyderm.io',
			version: '4.3.0',
		})),
		registerClient: vi.fn(async () => ({
			client_id: 'cid-fresh',
			client_secret: 'csec-fresh',
		})),
		exchangeCode: vi.fn(),
		verifyCredentials: vi.fn(),
		revokeToken: vi.fn(),
		...overrides,
	} as MastodonClient;
}

function makeStore(seed: Map<string, ClientRecord> = new Map()): ClientStore {
	return {
		get: vi.fn(async (origin: string) => seed.get(origin) ?? null),
		set: vi.fn(async (origin: string, record: ClientRecord) => {
			seed.set(origin, record);
		}),
	};
}

function config(overrides: Partial<MastodonConfig> = {}): MastodonConfig {
	return {
		appName: 'Test App',
		redirectUri: new URL('https://app.example/auth/callback'),
		cookieSecret: SECRET,
		...overrides,
	};
}

describe('createMastodonAdapter: construction', () => {
	it('throws synchronously on forbidden scope', () => {
		expect(() =>
			createMastodonAdapter(
				config({ scopes: ['read:statuses'] }),
				jar(),
			),
		).toThrow(/forbidden scope/);
	});

	it('throws on empty scope list', () => {
		expect(() => createMastodonAdapter(config({ scopes: [] }), jar())).toThrow(
			/at least one scope/,
		);
	});

	it('does not throw with default scopes', () => {
		expect(() => createMastodonAdapter(config(), jar())).not.toThrow();
	});

	it('does not throw with explicit ["profile"]', () => {
		expect(() =>
			createMastodonAdapter(config({ scopes: ['profile'] }), jar()),
		).not.toThrow();
	});
});

describe('buildAuthRedirect: happy path', () => {
	it('returns an /oauth/authorize URL with all OAuth + PKCE params', async () => {
		const client = makeClient();
		const adapter = createMastodonAdapter(config({ client }), jar());
		const url = await adapter.buildAuthRedirect({
			instanceInput: 'hachyderm.io',
		});
		expect(url.protocol).toBe('https:');
		expect(url.host).toBe('hachyderm.io');
		expect(url.pathname).toBe('/oauth/authorize');
		expect(url.searchParams.get('response_type')).toBe('code');
		expect(url.searchParams.get('client_id')).toBe('cid-fresh');
		expect(url.searchParams.get('redirect_uri')).toBe(
			'https://app.example/auth/callback',
		);
		expect(url.searchParams.get('scope')).toBe('read:accounts');
		expect(url.searchParams.get('state')).toMatch(/^[A-Za-z0-9_-]+$/);
		expect(url.searchParams.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect(url.searchParams.get('code_challenge_method')).toBe('S256');
	});

	it('writes the PendingState cookie', async () => {
		const cookies = jar();
		const adapter = createMastodonAdapter(config({ client: makeClient() }), cookies);
		await adapter.buildAuthRedirect({ instanceInput: 'hachyderm.io' });
		expect(cookies.store.has(PENDING_COOKIE_NAME)).toBe(true);
	});

	it('resolves WebFinger handle form', async () => {
		const client = makeClient();
		const adapter = createMastodonAdapter(config({ client }), jar());
		const url = await adapter.buildAuthRedirect({
			instanceInput: '@alice@hachyderm.io',
		});
		expect(url.host).toBe('hachyderm.io');
	});

	it('passes the configured redirectUri to registerClient', async () => {
		const client = makeClient();
		// Fresh store: ensure registerClient is invoked rather than served
		// from the module-scoped default cache.
		const adapter = createMastodonAdapter(
			config({ client, clientStore: makeStore() }),
			jar(),
		);
		await adapter.buildAuthRedirect({ instanceInput: 'hachyderm.io' });
		expect(client.registerClient).toHaveBeenCalledWith(
			expect.any(URL),
			expect.objectContaining({
				redirect_uris: 'https://app.example/auth/callback',
				scopes: 'read:accounts',
				client_name: 'Test App',
			}),
		);
	});

	it('does NOT call registerClient when credentials are cached', async () => {
		const client = makeClient();
		const seeded = new Map<string, ClientRecord>([
			[
				'https://hachyderm.io/',
				{
					client_id: 'cid-cached',
					client_secret: 'csec-cached',
					registered_at: new Date(),
				},
			],
		]);
		const store = makeStore(seeded);
		const adapter = createMastodonAdapter(
			config({ client, clientStore: store }),
			jar(),
		);
		const url = await adapter.buildAuthRedirect({
			instanceInput: 'hachyderm.io',
		});
		expect(client.registerClient).not.toHaveBeenCalled();
		expect(url.searchParams.get('client_id')).toBe('cid-cached');
	});
});

describe('buildAuthRedirect: error paths', () => {
	it('surfaces MastodonInstanceUnreachableError when probe fails', async () => {
		const client = makeClient({
			probeInstance: vi.fn(async () => {
				throw new Error('not Mastodon');
			}),
		});
		const adapter = createMastodonAdapter(config({ client }), jar());
		await expect(
			adapter.buildAuthRedirect({ instanceInput: 'broken.example' }),
		).rejects.toBeInstanceOf(MastodonInstanceUnreachableError);
	});

	it('propagates registerClient failures (config errors)', async () => {
		const client = makeClient({
			registerClient: vi.fn(async () => {
				throw new Error('oops');
			}),
		});
		// Fresh store so registerClient is actually called.
		const adapter = createMastodonAdapter(
			config({ client, clientStore: makeStore() }),
			jar(),
		);
		await expect(
			adapter.buildAuthRedirect({ instanceInput: 'hachyderm.io' }),
		).rejects.toThrow(/oops/);
	});
});

describe('buildAuthRedirect: PKCE shape', () => {
	it('generates a unique state per call', async () => {
		const adapter = createMastodonAdapter(config({ client: makeClient() }), jar());
		const a = await adapter.buildAuthRedirect({ instanceInput: 'hachyderm.io' });
		const b = await adapter.buildAuthRedirect({ instanceInput: 'hachyderm.io' });
		expect(a.searchParams.get('state')).not.toBe(b.searchParams.get('state'));
	});

	it('always uses S256 (never plain)', async () => {
		const adapter = createMastodonAdapter(config({ client: makeClient() }), jar());
		const url = await adapter.buildAuthRedirect({ instanceInput: 'hachyderm.io' });
		expect(url.searchParams.get('code_challenge_method')).toBe('S256');
	});

	it('code_challenge is 43-char base64url (SHA-256 of verifier)', async () => {
		const adapter = createMastodonAdapter(config({ client: makeClient() }), jar());
		const url = await adapter.buildAuthRedirect({ instanceInput: 'hachyderm.io' });
		const challenge = url.searchParams.get('code_challenge');
		expect(challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
	});
});

describe('buildAuthRedirect: returnTo round-trip', () => {
	it('preserves returnTo through the PendingState cookie', async () => {
		const cookies = jar();
		const adapter = createMastodonAdapter(config({ client: makeClient() }), cookies);
		await adapter.buildAuthRedirect({
			instanceInput: 'hachyderm.io',
			returnTo: '/dashboard',
		});
		// Read the cookie back via the same module's helper to verify the
		// payload survives the round-trip including the returnTo field.
		const { readPendingState } = await import('../src/state-cookies.js');
		const pending = await readPendingState(cookies, SECRET);
		expect(pending?.returnTo).toBe('/dashboard');
	});

	it('omits returnTo when not provided', async () => {
		const cookies = jar();
		const adapter = createMastodonAdapter(config({ client: makeClient() }), cookies);
		await adapter.buildAuthRedirect({ instanceInput: 'hachyderm.io' });
		const { readPendingState } = await import('../src/state-cookies.js');
		const pending = await readPendingState(cookies, SECRET);
		expect(pending?.returnTo).toBeUndefined();
	});
});

// ---- U9 helpers ----

const ALICE_CLAIMS: AccountClaims = {
	id: '12345',
	acct: 'alice',
	username: 'alice',
	display_name: 'Alice',
	url: 'https://hachyderm.io/users/alice',
};

function seededStore(): ClientStore {
	const seed = new Map<string, ClientRecord>([
		[
			'https://hachyderm.io/',
			{
				client_id: 'cid-cached',
				client_secret: 'csec-cached',
				registered_at: new Date(),
			},
		],
	]);
	return {
		get: async (origin) => seed.get(origin) ?? null,
		set: async (origin, record) => {
			seed.set(origin, record);
		},
	};
}

async function performInit(client: MastodonClient, cookies: CookieJar): Promise<URL> {
	const adapter = createMastodonAdapter(
		config({ client, clientStore: seededStore() }),
		cookies,
	);
	return adapter.buildAuthRedirect({ instanceInput: 'hachyderm.io' });
}

async function callbackUrl(authUrl: URL, code = 'authcode-xyz'): Promise<Request> {
	const callback = new URL('https://app.example/auth/callback');
	const state = authUrl.searchParams.get('state');
	if (!state) throw new Error('test setup: no state in authUrl');
	callback.searchParams.set('code', code);
	callback.searchParams.set('state', state);
	return new Request(callback.toString());
}

describe('authenticate (callback): happy path', () => {
	it('exchanges code, verifies credentials, returns Session, sets SessionState cookie', async () => {
		const client: MastodonClient = {
			probeInstance: vi.fn(async () => ({ uri: 'hachyderm.io', version: '4.3' })),
			registerClient: vi.fn(async () => ({
				client_id: 'cid',
				client_secret: 'cs',
			})),
			exchangeCode: vi.fn(async () => ({
				access_token: 'tok-abc',
				scope: 'read:accounts',
				token_type: 'Bearer',
			})),
			verifyCredentials: vi.fn(async () => ALICE_CLAIMS),
			revokeToken: vi.fn(),
		};
		const cookies = jar();
		const adapter = createMastodonAdapter(
			config({ client, clientStore: seededStore() }),
			cookies,
		);
		const authUrl = await adapter.buildAuthRedirect({
			instanceInput: 'hachyderm.io',
		});
		const request = await callbackUrl(authUrl);

		const result = await adapter.authenticate({
			kind: 'mastodon-callback',
			request,
		});

		expect('code' in result).toBe(false);
		const session = result as ReturnType<typeof Object>;
		expect(typeof session).toBe('object');
		expect(cookies.store.has(SESSION_COOKIE_NAME)).toBe(true);
		expect(cookies.store.has(PENDING_COOKIE_NAME)).toBe(false); // cleared
		const unwrapped = _unwrapSession<{
			access_token: string;
			actor_url: string;
			instance: string;
		}>(session as never);
		expect(unwrapped?.access_token).toBe('tok-abc');
		expect(unwrapped?.actor_url).toBe('https://hachyderm.io/users/alice');
		expect(unwrapped?.instance).toBe('https://hachyderm.io/');
	});
});

describe('authenticate (callback): credential_invalid paths', () => {
	it('returns credential_invalid when called with non-callback credential', async () => {
		const adapter = createMastodonAdapter(config({ client: makeClient() }), jar());
		const result = await adapter.authenticate({
			kind: 'mastodon-init' as never,
		} as never);
		expect(result).toEqual(
			expect.objectContaining({ code: 'credential_invalid' }),
		);
	});

	it('returns credential_invalid when PendingState cookie is missing', async () => {
		const cookies = jar();
		const adapter = createMastodonAdapter(
			config({ client: makeClient(), clientStore: seededStore() }),
			cookies,
		);
		const result = await adapter.authenticate({
			kind: 'mastodon-callback',
			request: new Request('https://app.example/auth/callback?code=x&state=y'),
		});
		expect(result).toEqual(
			expect.objectContaining({ code: 'credential_invalid' }),
		);
	});

	it('returns credential_invalid on state mismatch', async () => {
		const cookies = jar();
		const client = makeClient();
		const adapter = createMastodonAdapter(
			config({ client, clientStore: seededStore() }),
			cookies,
		);
		await adapter.buildAuthRedirect({ instanceInput: 'hachyderm.io' });
		const result = await adapter.authenticate({
			kind: 'mastodon-callback',
			request: new Request(
				'https://app.example/auth/callback?code=x&state=WRONG',
			),
		});
		expect(result).toEqual(
			expect.objectContaining({ code: 'credential_invalid' }),
		);
	});

	it('clears the PendingState cookie even on state mismatch', async () => {
		const cookies = jar();
		const adapter = createMastodonAdapter(
			config({ client: makeClient(), clientStore: seededStore() }),
			cookies,
		);
		await adapter.buildAuthRedirect({ instanceInput: 'hachyderm.io' });
		await adapter.authenticate({
			kind: 'mastodon-callback',
			request: new Request(
				'https://app.example/auth/callback?code=x&state=WRONG',
			),
		});
		expect(cookies.store.has(PENDING_COOKIE_NAME)).toBe(false);
	});
});

describe('authenticate (callback): error mapping', () => {
	async function setupAndCallback(
		clientOverride: Partial<MastodonClient>,
	): Promise<{
		result: Awaited<ReturnType<ReturnType<typeof createMastodonAdapter>['authenticate']>>;
	}> {
		const client = makeClient(clientOverride);
		const cookies = jar();
		const adapter = createMastodonAdapter(
			config({ client, clientStore: seededStore() }),
			cookies,
		);
		const authUrl = await adapter.buildAuthRedirect({
			instanceInput: 'hachyderm.io',
		});
		const request = await callbackUrl(authUrl);
		const result = await adapter.authenticate({
			kind: 'mastodon-callback',
			request,
		});
		return { result };
	}

	it('exchangeCode invalid_grant -> credential_rejected', async () => {
		const { result } = await setupAndCallback({
			exchangeCode: vi.fn(async () => {
				throw new MastodonApiError('bad', 401, 'invalid_grant');
			}),
		});
		expect(result).toEqual(
			expect.objectContaining({ code: 'credential_rejected' }),
		);
	});

	it('exchangeCode invalid_client -> auth_failed', async () => {
		const { result } = await setupAndCallback({
			exchangeCode: vi.fn(async () => {
				throw new MastodonApiError('bad', 400, 'invalid_client');
			}),
		});
		expect(result).toEqual(expect.objectContaining({ code: 'auth_failed' }));
	});

	it('exchangeCode network failure -> substrate_unavailable', async () => {
		const { result } = await setupAndCallback({
			exchangeCode: vi.fn(async () => {
				throw new MastodonNetworkError('boom');
			}),
		});
		expect(result).toEqual(
			expect.objectContaining({ code: 'substrate_unavailable' }),
		);
	});

	it('exchangeCode 5xx -> substrate_unavailable', async () => {
		const { result } = await setupAndCallback({
			exchangeCode: vi.fn(async () => {
				throw new MastodonApiError('boom', 500);
			}),
		});
		expect(result).toEqual(
			expect.objectContaining({ code: 'substrate_unavailable' }),
		);
	});

	it('exchangeCode 429 -> rate_limited', async () => {
		const { result } = await setupAndCallback({
			exchangeCode: vi.fn(async () => {
				throw new MastodonApiError('bad', 429);
			}),
		});
		expect(result).toEqual(
			expect.objectContaining({ code: 'rate_limited' }),
		);
	});

	it('verifyCredentials 401 (after successful exchange) -> credential_rejected', async () => {
		const { result } = await setupAndCallback({
			exchangeCode: vi.fn(async () => ({
				access_token: 'tok',
				scope: 'read:accounts',
				token_type: 'Bearer',
			})),
			verifyCredentials: vi.fn(async () => {
				throw new MastodonApiError('unauth', 401);
			}),
		});
		expect(result).toEqual(
			expect.objectContaining({ code: 'credential_rejected' }),
		);
	});

	it('verifyCredentials 410 -> credential_rejected', async () => {
		const { result } = await setupAndCallback({
			exchangeCode: vi.fn(async () => ({
				access_token: 'tok',
				scope: 'read:accounts',
				token_type: 'Bearer',
			})),
			verifyCredentials: vi.fn(async () => {
				throw new MastodonApiError('gone', 410);
			}),
		});
		expect(result).toEqual(
			expect.objectContaining({ code: 'credential_rejected' }),
		);
	});

	it('verifyCredentials 5xx -> substrate_unavailable', async () => {
		const { result } = await setupAndCallback({
			exchangeCode: vi.fn(async () => ({
				access_token: 'tok',
				scope: 'read:accounts',
				token_type: 'Bearer',
			})),
			verifyCredentials: vi.fn(async () => {
				throw new MastodonApiError('boom', 503);
			}),
		});
		expect(result).toEqual(
			expect.objectContaining({ code: 'substrate_unavailable' }),
		);
	});
});

describe('currentUpactor: happy path and caching', () => {
	async function authenticated(client: MastodonClient): Promise<{
		adapter: ReturnType<typeof createMastodonAdapter>;
		cookies: ReturnType<typeof jar>;
	}> {
		const cookies = jar();
		const adapter = createMastodonAdapter(
			config({ client, clientStore: seededStore() }),
			cookies,
		);
		const authUrl = await adapter.buildAuthRedirect({
			instanceInput: 'hachyderm.io',
		});
		const request = await callbackUrl(authUrl);
		await adapter.authenticate({ kind: 'mastodon-callback', request });
		return { adapter, cookies };
	}

	it('returns the Upactor minted at authenticate', async () => {
		const verifyMock = vi.fn(async () => ALICE_CLAIMS);
		const client = makeClient({
			exchangeCode: vi.fn(async () => ({
				access_token: 'tok-current',
				scope: 'read:accounts',
				token_type: 'Bearer',
			})),
			verifyCredentials: verifyMock,
		});
		const { adapter } = await authenticated(client);
		const upactor = await adapter.currentUpactor(
			new Request('https://app.example/'),
		);
		expect(upactor?.id).toMatch(/^[0-9a-f]{32}$/);
		expect(upactor?.provenance?.substrate).toBe('mastodon');
	});

	it('uses the verify cache within the cache window', async () => {
		const verifyMock = vi.fn(async () => ALICE_CLAIMS);
		const client = makeClient({
			exchangeCode: vi.fn(async () => ({
				access_token: 'tok-cached',
				scope: 'read:accounts',
				token_type: 'Bearer',
			})),
			verifyCredentials: verifyMock,
		});
		const { adapter } = await authenticated(client);
		const callsAfterAuth = verifyMock.mock.calls.length;
		await adapter.currentUpactor(new Request('https://app.example/'));
		expect(verifyMock.mock.calls.length).toBe(callsAfterAuth);
	});

	it('returns null when no SessionState cookie', async () => {
		const adapter = createMastodonAdapter(
			config({ client: makeClient() }),
			jar(),
		);
		expect(
			await adapter.currentUpactor(new Request('https://app.example/')),
		).toBeNull();
	});
});

describe('currentUpactor: error paths', () => {
	async function authenticatedThenSwap(
		afterAuthClient: MastodonClient,
	): Promise<{
		adapter: ReturnType<typeof createMastodonAdapter>;
		cookies: ReturnType<typeof jar>;
	}> {
		const happy = makeClient({
			exchangeCode: vi.fn(async () => ({
				access_token: `tok-${Math.random()}`,
				scope: 'read:accounts',
				token_type: 'Bearer',
			})),
			verifyCredentials: vi.fn(async () => ALICE_CLAIMS),
		});
		const cookies = jar();
		// Use no-cache so the post-auth currentUpactor actually calls the
		// (replaced) verify endpoint.
		const adapter1 = createMastodonAdapter(
			config({ client: happy, clientStore: seededStore(), verifyCredentialsCacheMs: 0 }),
			cookies,
		);
		const authUrl = await adapter1.buildAuthRedirect({
			instanceInput: 'hachyderm.io',
		});
		const request = await callbackUrl(authUrl);
		await adapter1.authenticate({ kind: 'mastodon-callback', request });
		// New adapter instance on the same cookies, with the failure-mode client.
		const adapter2 = createMastodonAdapter(
			config({ client: afterAuthClient, clientStore: seededStore(), verifyCredentialsCacheMs: 0 }),
			cookies,
		);
		return { adapter: adapter2, cookies };
	}

	it('401 (token revoked) returns null and clears the cookie', async () => {
		const { adapter, cookies } = await authenticatedThenSwap(
			makeClient({
				verifyCredentials: vi.fn(async () => {
					throw new MastodonApiError('unauth', 401);
				}),
			}),
		);
		const got = await adapter.currentUpactor(new Request('https://app.example/'));
		expect(got).toBeNull();
		expect(cookies.store.has(SESSION_COOKIE_NAME)).toBe(false);
	});

	it('410 (account suspended) returns null and clears the cookie', async () => {
		const { adapter, cookies } = await authenticatedThenSwap(
			makeClient({
				verifyCredentials: vi.fn(async () => {
					throw new MastodonApiError('gone', 410);
				}),
			}),
		);
		const got = await adapter.currentUpactor(new Request('https://app.example/'));
		expect(got).toBeNull();
		expect(cookies.store.has(SESSION_COOKIE_NAME)).toBe(false);
	});

	it('5xx throws SubstrateUnavailableError', async () => {
		const { adapter } = await authenticatedThenSwap(
			makeClient({
				verifyCredentials: vi.fn(async () => {
					throw new MastodonApiError('boom', 503);
				}),
			}),
		);
		await expect(
			adapter.currentUpactor(new Request('https://app.example/')),
		).rejects.toBeInstanceOf(SubstrateUnavailableError);
	});

	it('network failure throws SubstrateUnavailableError', async () => {
		const { adapter } = await authenticatedThenSwap(
			makeClient({
				verifyCredentials: vi.fn(async () => {
					throw new MastodonNetworkError('boom');
				}),
			}),
		);
		await expect(
			adapter.currentUpactor(new Request('https://app.example/')),
		).rejects.toBeInstanceOf(SubstrateUnavailableError);
	});
});

describe('invalidate', () => {
	async function authenticate(client: MastodonClient, cookies: ReturnType<typeof jar>) {
		const adapter = createMastodonAdapter(
			config({ client, clientStore: seededStore() }),
			cookies,
		);
		const authUrl = await adapter.buildAuthRedirect({
			instanceInput: 'hachyderm.io',
		});
		const request = await callbackUrl(authUrl);
		const result = await adapter.authenticate({
			kind: 'mastodon-callback',
			request,
		});
		return { adapter, session: result as Session };
	}

	it('clears the SessionState cookie', async () => {
		const cookies = jar();
		const client = makeClient({
			exchangeCode: vi.fn(async () => ({
				access_token: 'tok-inv',
				scope: 'read:accounts',
				token_type: 'Bearer',
			})),
			verifyCredentials: vi.fn(async () => ALICE_CLAIMS),
		});
		const { adapter, session } = await authenticate(client, cookies);
		expect(cookies.store.has(SESSION_COOKIE_NAME)).toBe(true);
		await adapter.invalidate(session);
		expect(cookies.store.has(SESSION_COOKIE_NAME)).toBe(false);
	});

	it('calls revokeToken with cached client credentials', async () => {
		const cookies = jar();
		const revoke = vi.fn(async () => {});
		const client = makeClient({
			exchangeCode: vi.fn(async () => ({
				access_token: 'tok-inv',
				scope: 'read:accounts',
				token_type: 'Bearer',
			})),
			verifyCredentials: vi.fn(async () => ALICE_CLAIMS),
			revokeToken: revoke,
		});
		const { adapter, session } = await authenticate(client, cookies);
		await adapter.invalidate(session);
		expect(revoke).toHaveBeenCalledWith(
			expect.any(URL),
			expect.objectContaining({
				client_id: 'cid-cached',
				client_secret: 'csec-cached',
				token: 'tok-inv',
			}),
		);
	});

	it('does not throw when revokeToken fails (best-effort)', async () => {
		const cookies = jar();
		const client = makeClient({
			exchangeCode: vi.fn(async () => ({
				access_token: 'tok-inv',
				scope: 'read:accounts',
				token_type: 'Bearer',
			})),
			verifyCredentials: vi.fn(async () => ALICE_CLAIMS),
			revokeToken: vi.fn(async () => {
				throw new MastodonNetworkError('boom');
			}),
		});
		const { adapter, session } = await authenticate(client, cookies);
		await expect(adapter.invalidate(session)).resolves.toBeUndefined();
		expect(cookies.store.has(SESSION_COOKIE_NAME)).toBe(false);
	});

	it('is a no-op when given a foreign Session (not produced by this adapter)', async () => {
		const adapter = createMastodonAdapter(
			config({ client: makeClient() }),
			jar(),
		);
		// A Session-shaped value not minted by this adapter.
		const fakeSession = { _opaque: Symbol() } as never;
		await expect(adapter.invalidate(fakeSession)).resolves.toBeUndefined();
	});

	it('subsequent currentUpactor returns null', async () => {
		const cookies = jar();
		const client = makeClient({
			exchangeCode: vi.fn(async () => ({
				access_token: 'tok-inv',
				scope: 'read:accounts',
				token_type: 'Bearer',
			})),
			verifyCredentials: vi.fn(async () => ALICE_CLAIMS),
		});
		const { adapter, session } = await authenticate(client, cookies);
		await adapter.invalidate(session);
		expect(
			await adapter.currentUpactor(new Request('https://app.example/')),
		).toBeNull();
	});
});

describe('issueRenewal', () => {
	it('returns null unconditionally (Decision 9 + F6)', async () => {
		const adapter = createMastodonAdapter(config({ client: makeClient() }), jar());
		const fakeUpactor: Upactor = {
			id: 'abc',
			capabilities: new Set(),
		};
		expect(await adapter.issueRenewal(fakeUpactor, undefined)).toBeNull();
		expect(await adapter.issueRenewal(fakeUpactor, { anything: 1 })).toBeNull();
	});
});

describe('createMastodonAdapter: default ClientStore is module-scoped', () => {
	// Regression test for the bug where two adapter instances using the
	// default (no-config) ClientStore would not share OAuth client
	// credentials. The SvelteKit hook pattern constructs a fresh adapter
	// per request, so init (request A) and callback (request B) need to
	// see the same store.
	it('shares registered credentials across two adapters with no clientStore configured', async () => {
		const registerMock = vi.fn(async () => ({
			client_id: `cid-shared-${Math.random()}`,
			client_secret: 'shared-secret',
		}));
		const client1 = makeClient({ registerClient: registerMock });
		const adapter1 = createMastodonAdapter(
			config({ client: client1 }),
			jar(),
		);
		await adapter1.buildAuthRedirect({ instanceInput: 'shared-test.example' });
		expect(registerMock).toHaveBeenCalledTimes(1);

		// Second adapter, no clientStore configured: should hit the cache.
		const client2 = makeClient({ registerClient: registerMock });
		const adapter2 = createMastodonAdapter(
			config({ client: client2 }),
			jar(),
		);
		await adapter2.buildAuthRedirect({ instanceInput: 'shared-test.example' });
		expect(registerMock).toHaveBeenCalledTimes(1); // still 1, cache hit
	});
});

describe('createMastodonAdapter: closure conformance (Decision 11)', () => {
	it('does not expose substrate state on the adapter instance', () => {
		const adapter = createMastodonAdapter(config({ client: makeClient() }), jar());
		const reflected = adapter as unknown as Record<string, unknown>;
		expect(reflected['client']).toBeUndefined();
		expect(reflected['cookieSecret']).toBeUndefined();
		expect(reflected['cookies']).toBeUndefined();
		expect(reflected['clientStore']).toBeUndefined();
	});

	it('Object.keys returns only the IdentityPort + extension method names', () => {
		const adapter = createMastodonAdapter(config({ client: makeClient() }), jar());
		const keys = Object.keys(adapter).sort();
		expect(keys).toEqual(
			[
				'authenticate',
				'buildAuthRedirect',
				'currentUpactor',
				'invalidate',
				'issueRenewal',
			].sort(),
		);
	});
});
