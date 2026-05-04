// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import {
	signValue,
	unsignValue,
	writePendingState,
	readPendingState,
	clearPendingState,
	writeSessionState,
	readSessionState,
	clearSessionState,
	PENDING_COOKIE_NAME,
	SESSION_COOKIE_NAME,
	type CookieJar,
	type CookieSetOptions,
	type PendingState,
	type SessionState,
} from '../src/state-cookies.js';

const SECRET = new Uint8Array(
	Array.from('test-secret-32-bytes-long-aaaaaa').map((c) => c.charCodeAt(0)),
);

const ALT_SECRET = new Uint8Array(
	Array.from('different-secret-32bytes-bbbbbb').map((c) => c.charCodeAt(0)),
);

function jar(): CookieJar & {
	store: Map<string, string>;
	options: Map<string, CookieSetOptions | undefined>;
	deleted: Set<string>;
} {
	const store = new Map<string, string>();
	const options = new Map<string, CookieSetOptions | undefined>();
	const deleted = new Set<string>();
	return {
		store,
		options,
		deleted,
		get(name) {
			return store.get(name);
		},
		set(name, value, opts) {
			store.set(name, value);
			options.set(name, opts);
		},
		delete(name) {
			store.delete(name);
			deleted.add(name);
		},
	};
}

const PENDING_FIXTURE: PendingState = {
	state: 'state-abc',
	code_verifier: 'verifier-xyz',
	instance: 'https://hachyderm.io/',
	returnTo: '/dashboard',
};

const SESSION_FIXTURE: SessionState = {
	access_token: 'tok-abc',
	actor_url: 'https://hachyderm.io/users/alice',
	instance: 'https://hachyderm.io/',
};

describe('signValue / unsignValue: round-trip', () => {
	it('round-trips an object payload', async () => {
		const value = await signValue({ a: 1, b: 'two' }, SECRET);
		const got = await unsignValue<{ a: number; b: string }>(value, SECRET, {
			maxAgeMs: 60_000,
		});
		expect(got).toEqual({ a: 1, b: 'two' });
	});

	it('round-trips unicode payloads', async () => {
		const value = await signValue({ name: '山田太郎', emoji: '😀' }, SECRET);
		const got = await unsignValue<{ name: string; emoji: string }>(
			value,
			SECRET,
			{ maxAgeMs: 60_000 },
		);
		expect(got).toEqual({ name: '山田太郎', emoji: '😀' });
	});

	it('round-trips an empty payload', async () => {
		const value = await signValue({}, SECRET);
		const got = await unsignValue<{}>(value, SECRET, { maxAgeMs: 60_000 });
		expect(got).toEqual({});
	});
});

describe('unsignValue: tamper rejection', () => {
	it('returns null on tampered signature', async () => {
		const value = await signValue({ a: 1 }, SECRET);
		const dot = value.indexOf('.');
		const tampered = value.slice(0, dot + 1) + 'AAAAAAAA';
		expect(
			await unsignValue(tampered, SECRET, { maxAgeMs: 60_000 }),
		).toBeNull();
	});

	it('returns null on tampered payload', async () => {
		const value = await signValue({ a: 1 }, SECRET);
		const dot = value.indexOf('.');
		// Replace one character of the payload with another base64url char
		// to invalidate the HMAC.
		const original = value.charAt(0);
		const swap = original === 'A' ? 'B' : 'A';
		const tampered = swap + value.slice(1, dot) + value.slice(dot);
		expect(
			await unsignValue(tampered, SECRET, { maxAgeMs: 60_000 }),
		).toBeNull();
	});

	it('returns null when secret differs', async () => {
		const value = await signValue({ a: 1 }, SECRET);
		expect(
			await unsignValue(value, ALT_SECRET, { maxAgeMs: 60_000 }),
		).toBeNull();
	});

	it('returns null on a malformed token (no dot separator)', async () => {
		expect(
			await unsignValue('not-a-signed-cookie', SECRET, { maxAgeMs: 60_000 }),
		).toBeNull();
	});
});

describe('unsignValue: TTL', () => {
	it('returns null when token is older than maxAgeMs', async () => {
		const t0 = new Date('2026-05-04T12:00:00Z');
		const value = await signValue({ a: 1 }, SECRET, { now: () => t0 });
		const after2min = new Date('2026-05-04T12:02:00Z');
		expect(
			await unsignValue(value, SECRET, {
				maxAgeMs: 60_000,
				now: () => after2min,
			}),
		).toBeNull();
	});

	it('returns the payload when within maxAgeMs', async () => {
		const t0 = new Date('2026-05-04T12:00:00Z');
		const value = await signValue({ a: 1 }, SECRET, { now: () => t0 });
		const after30s = new Date('2026-05-04T12:00:30Z');
		expect(
			await unsignValue(value, SECRET, {
				maxAgeMs: 60_000,
				now: () => after30s,
			}),
		).toEqual({ a: 1 });
	});
});

describe('writePendingState / readPendingState', () => {
	it('round-trips a PendingState through the jar', async () => {
		const cookies = jar();
		await writePendingState(cookies, SECRET, PENDING_FIXTURE, {
			redirectUri: new URL('https://app.example/auth/callback'),
		});
		expect(cookies.store.has(PENDING_COOKIE_NAME)).toBe(true);
		const got = await readPendingState(cookies, SECRET);
		expect(got).toEqual(PENDING_FIXTURE);
	});

	it('sets HttpOnly, Secure, SameSite=lax, scoped path', async () => {
		const cookies = jar();
		await writePendingState(cookies, SECRET, PENDING_FIXTURE, {
			redirectUri: new URL('https://app.example/auth/callback'),
		});
		const opts = cookies.options.get(PENDING_COOKIE_NAME);
		expect(opts?.httpOnly).toBe(true);
		expect(opts?.secure).toBe(true);
		expect(opts?.sameSite).toBe('lax');
		expect(opts?.path).toBe('/auth/callback');
	});

	it('readPendingState returns null when cookie absent', async () => {
		const cookies = jar();
		expect(await readPendingState(cookies, SECRET)).toBeNull();
	});

	it('readPendingState returns null when cookie tampered', async () => {
		const cookies = jar();
		await writePendingState(cookies, SECRET, PENDING_FIXTURE, {
			redirectUri: new URL('https://app.example/auth/callback'),
		});
		// Replace cookie value with garbage.
		cookies.store.set(PENDING_COOKIE_NAME, 'garbage.signature');
		expect(await readPendingState(cookies, SECRET)).toBeNull();
	});

	it('clearPendingState calls jar.delete with the cookie path', () => {
		const cookies = jar();
		clearPendingState(cookies, {
			redirectUri: new URL('https://app.example/auth/callback'),
		});
		expect(cookies.deleted.has(PENDING_COOKIE_NAME)).toBe(true);
	});

	it('expires PendingState after 10 minutes', async () => {
		const t0 = new Date('2026-05-04T12:00:00Z');
		const after11min = new Date('2026-05-04T12:11:00Z');
		const cookies = jar();
		await writePendingState(cookies, SECRET, PENDING_FIXTURE, {
			redirectUri: new URL('https://app.example/auth/callback'),
			now: () => t0,
		});
		expect(
			await readPendingState(cookies, SECRET, { now: () => after11min }),
		).toBeNull();
	});
});

describe('writeSessionState / readSessionState', () => {
	it('round-trips a SessionState', async () => {
		const cookies = jar();
		await writeSessionState(cookies, SECRET, SESSION_FIXTURE);
		expect(await readSessionState(cookies, SECRET)).toEqual(SESSION_FIXTURE);
	});

	it('uses path=/ so it is sent on every request', async () => {
		const cookies = jar();
		await writeSessionState(cookies, SECRET, SESSION_FIXTURE);
		const opts = cookies.options.get(SESSION_COOKIE_NAME);
		expect(opts?.path).toBe('/');
	});

	it('clearSessionState calls jar.delete', () => {
		const cookies = jar();
		clearSessionState(cookies);
		expect(cookies.deleted.has(SESSION_COOKIE_NAME)).toBe(true);
	});
});
