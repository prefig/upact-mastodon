// SPDX-License-Identifier: Apache-2.0
/**
 * Tests for `mapAccountToUpactor`. Test-first per the plan's
 * Execution note for U3 — privacy stripping is the privacy boundary.
 */

import { describe, it, expect } from 'vitest';
import { mapAccountToUpactor } from '../src/claims-mapper.js';
import type { AccountClaims } from '../src/types.js';

const HACHYDERM = new URL('https://hachyderm.io');
const MASTODON_SOCIAL = new URL('https://mastodon.social');
const LOCAL_DEV = new URL('https://localhost:3001');

function alice(): AccountClaims {
	return {
		id: '12345',
		acct: 'alice',
		username: 'alice',
		display_name: 'Alice',
		url: 'https://hachyderm.io/users/alice',
	};
}

describe('mapAccountToUpactor — happy path', () => {
	it('produces an Upactor with id, display_hint, empty capabilities, lifecycle, provenance', async () => {
		const upactor = await mapAccountToUpactor(alice(), HACHYDERM);
		expect(upactor.id).toBe('9e4536fe656c192ee8f07f7265eeab91');
		expect(upactor.display_hint).toBe('Alice');
		expect(upactor.capabilities.size).toBe(0);
		expect(upactor.lifecycle).toEqual({
			expires_at: undefined,
			renewable: 'reauth',
		});
		expect(upactor.provenance).toEqual({
			substrate: 'mastodon',
			instance: 'https://hachyderm.io/',
		});
	});

	it('falls back to username when display_name is empty', async () => {
		const upactor = await mapAccountToUpactor(
			{ ...alice(), display_name: '' },
			HACHYDERM,
		);
		expect(upactor.display_hint).toBe('alice');
	});

	it('returns display_hint undefined when both fields are empty', async () => {
		const upactor = await mapAccountToUpactor(
			{ ...alice(), display_name: '', username: '' },
			HACHYDERM,
		);
		expect(upactor.display_hint).toBeUndefined();
	});

	it('trims trailing whitespace from display_name', async () => {
		const upactor = await mapAccountToUpactor(
			{ ...alice(), display_name: 'Alice  ' },
			HACHYDERM,
		);
		expect(upactor.display_hint).toBe('Alice');
	});

	it('produces stable id for known fixtures (mastodon.social / Mastodon)', async () => {
		const upactor = await mapAccountToUpactor(
			{
				id: '1',
				acct: 'Mastodon',
				username: 'Mastodon',
				display_name: 'Mastodon',
				url: 'https://mastodon.social/users/Mastodon',
			},
			MASTODON_SOCIAL,
		);
		expect(upactor.id).toBe('62f3bea638338bb36b8c6aa530ca2eca');
	});
});

describe('mapAccountToUpactor — display_hint email-shape rejection (SPEC §4.2)', () => {
	it('falls back to username when display_name is email-shaped', async () => {
		const upactor = await mapAccountToUpactor(
			{ ...alice(), display_name: 'alice@example.com' },
			HACHYDERM,
		);
		expect(upactor.display_hint).toBe('alice');
	});

	it('returns undefined when both fields are email-shaped', async () => {
		const upactor = await mapAccountToUpactor(
			{
				...alice(),
				display_name: 'alice@example.com',
				username: 'bob@malicious.example',
			},
			HACHYDERM,
		);
		expect(upactor.display_hint).toBeUndefined();
	});

	it('preserves unicode display_name (no email shape)', async () => {
		const upactor = await mapAccountToUpactor(
			{ ...alice(), display_name: '山田太郎' },
			HACHYDERM,
		);
		expect(upactor.display_hint).toBe('山田太郎');
	});

	it('preserves emoji display_name (no email shape)', async () => {
		const upactor = await mapAccountToUpactor(
			{ ...alice(), display_name: '😀 alice' },
			HACHYDERM,
		);
		expect(upactor.display_hint).toBe('😀 alice');
	});
});

describe('mapAccountToUpactor — id derivation', () => {
	it('handles actor URLs with non-default ports deterministically', async () => {
		const upactor = await mapAccountToUpactor(
			{
				...alice(),
				url: 'https://localhost:3001/users/alice',
			},
			LOCAL_DEV,
		);
		expect(upactor.id).toBe('700aebd463a16447b19ba435f0570e20');
	});

	it('is deterministic — same input twice gives same id', async () => {
		const u1 = await mapAccountToUpactor(alice(), HACHYDERM);
		const u2 = await mapAccountToUpactor(alice(), HACHYDERM);
		expect(u1.id).toBe(u2.id);
	});

	it('is 32 hex chars regardless of input length', async () => {
		const short = await mapAccountToUpactor(
			{ ...alice(), url: 'https://h.io/u/a' },
			HACHYDERM,
		);
		const long = await mapAccountToUpactor(
			{
				...alice(),
				url: 'https://very-long-instance.example.org/users/very-long-username-that-exceeds-typical-length',
			},
			HACHYDERM,
		);
		expect(short.id).toMatch(/^[0-9a-f]{32}$/);
		expect(long.id).toMatch(/^[0-9a-f]{32}$/);
	});
});

describe('mapAccountToUpactor — privacy stripping (SPEC §7)', () => {
	it('does not surface fields the substrate would have included', async () => {
		// The substrate's verify_credentials response has many more fields
		// (avatar, header, fields, bot, source, follower counts, ...). The
		// adapter's network layer (client.ts) destructures into the closed
		// AccountClaims shape, so by the time this mapper is called, those
		// fields are already absent at the type level. This test guards the
		// JSON shape of the OUTPUT (the Upactor) against any of those names.
		const upactor = await mapAccountToUpactor(alice(), HACHYDERM);
		const json = JSON.stringify(upactor);
		const forbidden = [
			'email',
			'avatar',
			'header',
			'note',
			'fields',
			'bot',
			'locked',
			'source',
			'followers_count',
			'following_count',
			'statuses_count',
			'last_status_at',
			'created_at',
		];
		for (const f of forbidden) {
			expect(json).not.toContain(`"${f}"`);
		}
	});

	it('exposes only the five spec-permitted Upactor fields', async () => {
		const upactor = await mapAccountToUpactor(alice(), HACHYDERM);
		const allowed = new Set([
			'id',
			'display_hint',
			'capabilities',
			'lifecycle',
			'provenance',
		]);
		for (const key of Object.keys(upactor)) {
			expect(allowed.has(key)).toBe(true);
		}
	});
});

describe('mapAccountToUpactor — provenance', () => {
	it('records the instance origin string (with trailing slash)', async () => {
		const upactor = await mapAccountToUpactor(alice(), HACHYDERM);
		expect(upactor.provenance?.instance).toBe('https://hachyderm.io/');
	});

	it('substrate is always the literal "mastodon"', async () => {
		const upactor = await mapAccountToUpactor(alice(), MASTODON_SOCIAL);
		expect(upactor.provenance?.substrate).toBe('mastodon');
	});
});

describe('mapAccountToUpactor — lifecycle (F6)', () => {
	it('expires_at is undefined; renewable is "reauth"', async () => {
		const upactor = await mapAccountToUpactor(alice(), HACHYDERM);
		expect(upactor.lifecycle?.expires_at).toBeUndefined();
		expect(upactor.lifecycle?.renewable).toBe('reauth');
	});
});
