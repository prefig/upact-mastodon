// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import {
	InMemoryClientStore,
	type ClientRecord,
} from '../src/client-store.js';

function record(): ClientRecord {
	return {
		client_id: 'cid-abc',
		client_secret: 'csec-xyz',
		registered_at: new Date('2026-05-04T12:00:00Z'),
	};
}

describe('InMemoryClientStore: get and set', () => {
	it('returns null for an unset origin', async () => {
		const store = new InMemoryClientStore();
		expect(await store.get('https://hachyderm.io')).toBeNull();
	});

	it('returns the record after set', async () => {
		const store = new InMemoryClientStore({
			now: () => new Date('2026-05-04T12:00:00Z'),
		});
		await store.set('https://hachyderm.io', record());
		const got = await store.get('https://hachyderm.io');
		expect(got?.client_id).toBe('cid-abc');
		expect(got?.client_secret).toBe('csec-xyz');
	});

	it('overwrites an existing record on a second set', async () => {
		const store = new InMemoryClientStore({
			now: () => new Date('2026-05-04T12:00:00Z'),
		});
		await store.set('https://hachyderm.io', record());
		const replacement: ClientRecord = {
			client_id: 'cid-new',
			client_secret: 'csec-new',
			registered_at: new Date('2026-05-04T12:00:00Z'),
		};
		await store.set('https://hachyderm.io', replacement);
		const got = await store.get('https://hachyderm.io');
		expect(got?.client_id).toBe('cid-new');
	});
});

describe('InMemoryClientStore: TTL-based expiry', () => {
	it('returns null when record is older than maxAgeMs', async () => {
		const registeredAt = new Date('2026-01-01T00:00:00Z');
		const after31Days = new Date('2026-02-01T00:00:00Z');
		const store = new InMemoryClientStore({
			maxAgeMs: 30 * 24 * 60 * 60 * 1000,
			now: () => after31Days,
		});
		await store.set('https://hachyderm.io', {
			...record(),
			registered_at: registeredAt,
		});
		expect(await store.get('https://hachyderm.io')).toBeNull();
	});

	it('returns the record when within maxAgeMs', async () => {
		const registeredAt = new Date('2026-05-01T00:00:00Z');
		const after2Days = new Date('2026-05-03T00:00:00Z');
		const store = new InMemoryClientStore({
			maxAgeMs: 30 * 24 * 60 * 60 * 1000,
			now: () => after2Days,
		});
		await store.set('https://hachyderm.io', {
			...record(),
			registered_at: registeredAt,
		});
		const got = await store.get('https://hachyderm.io');
		expect(got).not.toBeNull();
	});

	it('default maxAgeMs is 30 days', () => {
		const store = new InMemoryClientStore();
		expect(store.maxAgeMs).toBe(30 * 24 * 60 * 60 * 1000);
	});
});

describe('InMemoryClientStore: origin keying', () => {
	it('treats different schemes as distinct keys', async () => {
		const store = new InMemoryClientStore({
			now: () => new Date('2026-05-04T12:00:00Z'),
		});
		await store.set('https://example.org', record());
		expect(await store.get('http://example.org')).toBeNull();
	});

	it('treats different ports as distinct keys', async () => {
		const store = new InMemoryClientStore({
			now: () => new Date('2026-05-04T12:00:00Z'),
		});
		await store.set('https://example.org', record());
		expect(await store.get('https://example.org:8443')).toBeNull();
	});
});
