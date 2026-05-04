// SPDX-License-Identifier: Apache-2.0
/**
 * Integration test against a real Mastodon-compatible instance.
 *
 * Skipped by default. To run, create a personal access token via your
 * instance's Settings > Development > New Application page (read:accounts
 * scope is sufficient), then:
 *
 *   MASTODON_INTEGRATION_TEST_TOKEN=<your-token> \
 *   MASTODON_INTEGRATION_TEST_INSTANCE=mastodon.social \
 *     npm test -- tests/integration
 *
 * The test does NOT exercise the full OAuth round-trip (which requires
 * a real user session in a browser). It exercises the load-bearing
 * substrate-call paths: probeInstance, verifyCredentials, and the
 * privacy-stripping discipline on the resulting Upactor.
 */

import { describe, it, expect } from 'vitest';
import { FetchBackedClient } from '../../src/client.js';
import { mapAccountToUpactor } from '../../src/claims-mapper.js';

const TOKEN = process.env['MASTODON_INTEGRATION_TEST_TOKEN'];
const INSTANCE_INPUT =
	process.env['MASTODON_INTEGRATION_TEST_INSTANCE'] ?? 'mastodon.social';

const skip = !TOKEN;

describe.skipIf(skip)('integration: Mastodon flow against real instance', () => {
	const origin = new URL(`https://${INSTANCE_INPUT}`);
	const client = new FetchBackedClient();

	it('probeInstance returns a Mastodon-API response', async () => {
		const info = await client.probeInstance(origin);
		expect(info.uri || info.domain).toBeTruthy();
	});

	it('verifyCredentials returns the closed AccountClaims shape', async () => {
		const claims = await client.verifyCredentials(origin, TOKEN!);
		expect(typeof claims.id).toBe('string');
		expect(typeof claims.acct).toBe('string');
		expect(typeof claims.username).toBe('string');
		expect(typeof claims.display_name).toBe('string');
		expect(typeof claims.url).toBe('string');
		const keys = Object.keys(claims).sort();
		expect(keys).toEqual(
			['acct', 'display_name', 'id', 'url', 'username'].sort(),
		);
	});

	it('mapAccountToUpactor on real claims surfaces no substrate fields', async () => {
		const claims = await client.verifyCredentials(origin, TOKEN!);
		const upactor = await mapAccountToUpactor(claims, origin);
		const json = JSON.stringify(upactor);
		// None of these substrate-side fields should appear in the Upactor.
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
		expect(upactor.id).toMatch(/^[0-9a-f]{32}$/);
		expect(upactor.provenance?.substrate).toBe('mastodon');
		expect(upactor.lifecycle?.expires_at).toBeUndefined();
		expect(upactor.lifecycle?.renewable).toBe('reauth');
	});

	it('verifyCredentials with bogus token returns 401', async () => {
		await expect(
			client.verifyCredentials(origin, 'bogus-token-that-does-not-exist'),
		).rejects.toMatchObject({ status: 401 });
	});
});
