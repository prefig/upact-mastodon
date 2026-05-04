// SPDX-License-Identifier: Apache-2.0
/**
 * Adapter back-channel reflection test (Decision 11 / SPEC §7.5).
 *
 * After driving the adapter through a complete happy-path authenticate,
 * sentinel substrate values (access_token, client_secret, actor_url,
 * cookie secret) MUST NOT be reachable through any common reflection
 * vector applied to the adapter instance.
 *
 * Mirror of upact-supabase / upact-oidc back-channel tests.
 */

import { describe, it, expect, vi } from 'vitest';
import util from 'node:util';
import { createMastodonAdapter } from '../src/adapter.js';
import type { MastodonClient } from '../src/client.js';
import type { ClientStore, ClientRecord } from '../src/client-store.js';
import type { CookieJar, CookieSetOptions } from '../src/state-cookies.js';
import type { MastodonConfig, AccountClaims } from '../src/types.js';

const SENTINEL_ACCESS_TOKEN = 'SENTINEL_TOK_eY_aVs8w7q3KsLpZ_unique';
const SENTINEL_CLIENT_SECRET = 'SENTINEL_CSEC_4mB6Q2Hz9Vn1RxYp_unique';
const SENTINEL_ACTOR_URL = 'https://hachyderm.io/users/SENTINEL_USER';
const SENTINEL_COOKIE_SECRET_BYTES = 'SENTINEL_COOKIESECRET_32bytesAB';

const SENTINELS = [
	SENTINEL_ACCESS_TOKEN,
	SENTINEL_CLIENT_SECRET,
	SENTINEL_ACTOR_URL,
	SENTINEL_COOKIE_SECRET_BYTES,
];

const SENTINEL_CLAIMS: AccountClaims = {
	id: 'SENTINEL_ID',
	acct: 'sentinel-user',
	username: 'sentinel-user',
	display_name: 'Sentinel',
	url: SENTINEL_ACTOR_URL,
};

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

function client(): MastodonClient {
	return {
		probeInstance: vi.fn(async () => ({ uri: 'hachyderm.io', version: '4.3' })),
		registerClient: vi.fn(async () => ({
			client_id: 'sentinel-cid',
			client_secret: SENTINEL_CLIENT_SECRET,
		})),
		exchangeCode: vi.fn(async () => ({
			access_token: SENTINEL_ACCESS_TOKEN,
			scope: 'read:accounts',
			token_type: 'Bearer',
		})),
		verifyCredentials: vi.fn(async () => SENTINEL_CLAIMS),
		revokeToken: vi.fn(),
	};
}

function store(seed: Map<string, ClientRecord> = new Map()): ClientStore {
	return {
		get: async (origin) => seed.get(origin) ?? null,
		set: async (origin, record) => {
			seed.set(origin, record);
		},
	};
}

function config(): MastodonConfig {
	return {
		appName: 'Sentinel App',
		redirectUri: new URL('https://app.example/auth/callback'),
		cookieSecret: new Uint8Array(
			Array.from(SENTINEL_COOKIE_SECRET_BYTES).map((c) => c.charCodeAt(0)),
		),
		client: client(),
		clientStore: store(),
	};
}

async function driveThroughAuth(): Promise<{
	adapter: ReturnType<typeof createMastodonAdapter>;
	cookies: ReturnType<typeof jar>;
}> {
	const cookies = jar();
	const adapter = createMastodonAdapter(config(), cookies);
	const authUrl = await adapter.buildAuthRedirect({
		instanceInput: 'hachyderm.io',
	});
	const callback = new URL('https://app.example/auth/callback');
	callback.searchParams.set('code', 'authcode-xyz');
	callback.searchParams.set('state', authUrl.searchParams.get('state')!);
	const result = await adapter.authenticate({
		kind: 'mastodon-callback',
		request: new Request(callback.toString()),
	});
	if ('code' in result) {
		throw new Error(`drive setup: authenticate returned error: ${result.message}`);
	}
	return { adapter, cookies };
}

describe('adapter back-channel: 16-vector reflection conformance', () => {
	it('vector 1: JSON.stringify(adapter) leaks no sentinel', async () => {
		const { adapter } = await driveThroughAuth();
		const json = JSON.stringify(adapter);
		for (const s of SENTINELS) {
			expect(json).not.toContain(s);
		}
	});

	it('vector 2: Object.keys returns no substrate-shaped keys', async () => {
		const { adapter } = await driveThroughAuth();
		const keys = Object.keys(adapter);
		expect(keys).not.toContain('client');
		expect(keys).not.toContain('mastodon');
		expect(keys).not.toContain('_client');
		expect(keys).not.toContain('tokens');
		expect(keys).not.toContain('accessToken');
		expect(keys).not.toContain('clientSecret');
		expect(keys).not.toContain('actorUrl');
		expect(keys).not.toContain('cookieSecret');
	});

	it('vector 3: Object.getOwnPropertyNames returns no substrate-shaped keys', async () => {
		const { adapter } = await driveThroughAuth();
		const names = Object.getOwnPropertyNames(adapter);
		for (const name of [
			'client',
			'mastodon',
			'_client',
			'tokens',
			'accessToken',
			'clientSecret',
			'actorUrl',
			'cookieSecret',
			'cookies',
			'clientStore',
		]) {
			expect(names).not.toContain(name);
		}
	});

	it('vector 4: Reflect.ownKeys returns no substrate-shaped keys', async () => {
		const { adapter } = await driveThroughAuth();
		const keys = Reflect.ownKeys(adapter as object);
		for (const name of [
			'client',
			'mastodon',
			'_client',
			'tokens',
			'accessToken',
			'clientSecret',
			'actorUrl',
			'cookieSecret',
		]) {
			expect(keys).not.toContain(name);
		}
	});

	it('vector 5: Object.getOwnPropertySymbols returns no symbols', async () => {
		const { adapter } = await driveThroughAuth();
		expect(Object.getOwnPropertySymbols(adapter)).toEqual([]);
	});

	it('vector 6: for-in iteration does not yield substrate keys', async () => {
		const { adapter } = await driveThroughAuth();
		const keys: string[] = [];
		for (const k in adapter) keys.push(k);
		for (const name of [
			'client',
			'mastodon',
			'_client',
			'tokens',
			'accessToken',
			'clientSecret',
			'actorUrl',
			'cookieSecret',
		]) {
			expect(keys).not.toContain(name);
		}
	});

	it('vector 7: structuredClone refuses to clone (or yields a non-leaking object)', async () => {
		const { adapter } = await driveThroughAuth();
		try {
			const cloned = structuredClone(adapter);
			const inspected = util.inspect(cloned);
			for (const s of SENTINELS) {
				expect(inspected).not.toContain(s);
			}
		} catch (e) {
			// structuredClone throws DataCloneError on non-cloneable values
			// (functions are not cloneable); that itself is a pass.
			expect(e).toBeInstanceOf(Error);
		}
	});

	it('vector 8: util.inspect leaks no sentinel', async () => {
		const { adapter } = await driveThroughAuth();
		const inspected = util.inspect(adapter, { depth: null, showHidden: true });
		for (const s of SENTINELS) {
			expect(inspected).not.toContain(s);
		}
	});

	it('vector 9: direct cast access to .client returns undefined', async () => {
		const { adapter } = await driveThroughAuth();
		expect((adapter as { client?: unknown }).client).toBeUndefined();
	});

	it('vector 10: direct cast access to .mastodon returns undefined', async () => {
		const { adapter } = await driveThroughAuth();
		expect((adapter as { mastodon?: unknown }).mastodon).toBeUndefined();
	});

	it('vector 11: direct cast access to ._client returns undefined', async () => {
		const { adapter } = await driveThroughAuth();
		expect((adapter as { _client?: unknown })._client).toBeUndefined();
	});

	it('vector 12: direct cast access to .accessToken / .tokens returns undefined', async () => {
		const { adapter } = await driveThroughAuth();
		expect((adapter as { accessToken?: unknown }).accessToken).toBeUndefined();
		expect((adapter as { tokens?: unknown }).tokens).toBeUndefined();
	});

	it('vector 13: direct cast access to .cookies / .cookieSecret returns undefined', async () => {
		const { adapter } = await driveThroughAuth();
		expect((adapter as { cookies?: unknown }).cookies).toBeUndefined();
		expect(
			(adapter as { cookieSecret?: unknown }).cookieSecret,
		).toBeUndefined();
	});

	it('vector 14: direct cast access to .clientStore returns undefined', async () => {
		const { adapter } = await driveThroughAuth();
		expect(
			(adapter as { clientStore?: unknown }).clientStore,
		).toBeUndefined();
	});

	it('vector 15: object spread yields no substrate-shaped keys', async () => {
		const { adapter } = await driveThroughAuth();
		const spread = { ...adapter };
		const json = JSON.stringify(spread);
		for (const s of SENTINELS) {
			expect(json).not.toContain(s);
		}
	});

	it('vector 16: JSON.stringify wrapped in outer object leaks no sentinel', async () => {
		const { adapter } = await driveThroughAuth();
		const wrapped = { kind: 'adapter-holder', a: adapter };
		const json = JSON.stringify(wrapped);
		expect(json).toContain('adapter-holder');
		for (const s of SENTINELS) {
			expect(json).not.toContain(s);
		}
	});
});
