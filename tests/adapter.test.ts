// SPDX-License-Identifier: Apache-2.0
/**
 * Tests for `createMastodonAdapter` and the `buildAuthRedirect` init phase.
 *
 * Tests for `authenticate`, `currentUpactor`, `invalidate` land in U9/U10.
 */

import { describe, it, expect, vi } from 'vitest';
import { createMastodonAdapter } from '../src/adapter.js';
import { MastodonInstanceUnreachableError } from '../src/errors.js';
import type { MastodonClient } from '../src/client.js';
import type { ClientStore, ClientRecord } from '../src/client-store.js';
import type { CookieJar, CookieSetOptions } from '../src/state-cookies.js';
import { PENDING_COOKIE_NAME } from '../src/state-cookies.js';
import type { MastodonConfig } from '../src/types.js';

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
		const adapter = createMastodonAdapter(config({ client }), jar());
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
		const adapter = createMastodonAdapter(config({ client }), jar());
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
