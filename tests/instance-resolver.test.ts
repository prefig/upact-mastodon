// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import { SubstrateUnavailableError } from '@prefig/upact';
import {
	parseInstanceInput,
	resolveInstance,
} from '../src/instance-resolver.js';
import { MastodonInstanceUnreachableError } from '../src/errors.js';
import type { MastodonClient } from '../src/client.js';

function ok(): MastodonClient {
	return {
		probeInstance: async () => ({ uri: 'mastodon.social', version: '4.3.0' }),
		registerClient: () => {
			throw new Error('not used');
		},
		exchangeCode: () => {
			throw new Error('not used');
		},
		verifyCredentials: () => {
			throw new Error('not used');
		},
		revokeToken: () => {
			throw new Error('not used');
		},
	};
}

function throwingProbe(error: Error): MastodonClient {
	const c = ok();
	c.probeInstance = async () => {
		throw error;
	};
	return c;
}

describe('parseInstanceInput: happy path', () => {
	it('accepts a bare hostname', () => {
		expect(parseInstanceInput('mastodon.social').toString()).toBe(
			'https://mastodon.social/',
		);
	});

	it('accepts an @-prefixed WebFinger handle', () => {
		expect(parseInstanceInput('@alice@hachyderm.io').toString()).toBe(
			'https://hachyderm.io/',
		);
	});

	it('accepts a non-prefixed user@host handle', () => {
		expect(parseInstanceInput('alice@hachyderm.io').toString()).toBe(
			'https://hachyderm.io/',
		);
	});

	it('accepts a full https URL', () => {
		expect(parseInstanceInput('https://social.coop').toString()).toBe(
			'https://social.coop/',
		);
	});

	it('accepts a full http URL (for local dev)', () => {
		expect(parseInstanceInput('http://localhost:3001').toString()).toBe(
			'http://localhost:3001/',
		);
	});

	it('strips path, query, fragment from full URL', () => {
		expect(
			parseInstanceInput('https://social.coop/some/path?q=1#frag').toString(),
		).toBe('https://social.coop/');
	});

	it('trims whitespace and lowercases host', () => {
		expect(parseInstanceInput('  Mastodon.Social  ').toString()).toBe(
			'https://mastodon.social/',
		);
	});

	it('preserves port on bare host:port input', () => {
		expect(parseInstanceInput('localhost:3001').toString()).toBe(
			'https://localhost:3001/',
		);
	});
});

describe('parseInstanceInput: error paths', () => {
	it('rejects empty string', () => {
		expect(() => parseInstanceInput('')).toThrow(/empty input/);
	});

	it('rejects whitespace-only string', () => {
		expect(() => parseInstanceInput('   ')).toThrow(/empty input/);
	});

	it('rejects unsupported scheme (ftp)', () => {
		expect(() => parseInstanceInput('ftp://example.com')).toThrow(
			/unsupported scheme/,
		);
	});

	it('rejects unsupported scheme (file)', () => {
		expect(() => parseInstanceInput('file:///etc/passwd')).toThrow(
			/unsupported scheme/,
		);
	});

	it('rejects host with embedded whitespace', () => {
		expect(() => parseInstanceInput('mastodon social')).toThrow();
	});

	it('rejects double-@ in handle form', () => {
		expect(() => parseInstanceInput('@@hachyderm.io')).toThrow();
	});
});

describe('resolveInstance: happy path', () => {
	it('returns origin URL after successful probe', async () => {
		const origin = await resolveInstance('mastodon.social', ok());
		expect(origin.toString()).toBe('https://mastodon.social/');
	});

	it('resolves via WebFinger handle form', async () => {
		const origin = await resolveInstance('@alice@hachyderm.io', ok());
		expect(origin.toString()).toBe('https://hachyderm.io/');
	});
});

describe('resolveInstance: error paths', () => {
	it('throws MastodonInstanceUnreachableError when probe rejects', async () => {
		await expect(
			resolveInstance('unreachable.example', throwingProbe(new Error('404'))),
		).rejects.toBeInstanceOf(MastodonInstanceUnreachableError);
	});

	it('thrown error is also a SubstrateUnavailableError (subclass)', async () => {
		await expect(
			resolveInstance('unreachable.example', throwingProbe(new Error('boom'))),
		).rejects.toBeInstanceOf(SubstrateUnavailableError);
	});

	it('preserves the parsed origin on the error', async () => {
		try {
			await resolveInstance(
				'@alice@unreachable.example',
				throwingProbe(new Error('boom')),
			);
			expect.unreachable('resolveInstance should have thrown');
		} catch (e) {
			expect(e).toBeInstanceOf(MastodonInstanceUnreachableError);
			const err = e as MastodonInstanceUnreachableError;
			expect(err.origin?.toString()).toBe('https://unreachable.example/');
			expect(err.cause).toBeInstanceOf(Error);
		}
	});
});
