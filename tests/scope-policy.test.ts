// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest';
import { DEFAULT_SCOPES, validateScopes } from '../src/scope-policy.js';

describe('validateScopes — happy path', () => {
	it('accepts ["read:accounts"]', () => {
		expect(() => validateScopes(['read:accounts'])).not.toThrow();
	});

	it('accepts ["profile"]', () => {
		expect(() => validateScopes(['profile'])).not.toThrow();
	});

	it('accepts ["read:accounts", "profile"]', () => {
		expect(() => validateScopes(['read:accounts', 'profile'])).not.toThrow();
	});

	it('DEFAULT_SCOPES is ["read:accounts"]', () => {
		expect(DEFAULT_SCOPES).toEqual(['read:accounts']);
	});

	it('DEFAULT_SCOPES passes validation', () => {
		expect(() => validateScopes(DEFAULT_SCOPES)).not.toThrow();
	});
});

describe('validateScopes — error paths (forbidden scopes)', () => {
	it('throws on empty scope list', () => {
		expect(() => validateScopes([])).toThrow(/at least one scope is required/);
	});

	it('throws on the meta-scope "read"', () => {
		expect(() => validateScopes(['read'])).toThrow(/forbidden scope "read"/);
	});

	it('throws when any forbidden scope is mixed with allowed scopes', () => {
		expect(() =>
			validateScopes(['read:accounts', 'read:statuses']),
		).toThrow(/forbidden scope "read:statuses"/);
	});

	it('throws on "write:statuses"', () => {
		expect(() => validateScopes(['write:statuses'])).toThrow(
			/forbidden scope "write:statuses"/,
		);
	});

	it('throws on "write"', () => {
		expect(() => validateScopes(['write'])).toThrow(
			/forbidden scope "write"/,
		);
	});

	it('throws on "follow"', () => {
		expect(() => validateScopes(['follow'])).toThrow(
			/forbidden scope "follow"/,
		);
	});

	it('throws on "push"', () => {
		expect(() => validateScopes(['push'])).toThrow(
			/forbidden scope "push"/,
		);
	});

	it('throws on "read:notifications"', () => {
		expect(() => validateScopes(['read:notifications'])).toThrow(
			/forbidden scope "read:notifications"/,
		);
	});

	it('error message cites SPEC §7', () => {
		expect(() => validateScopes(['read'])).toThrow(/SPEC §7/);
	});
});

describe('validateScopes — case sensitivity', () => {
	it('throws on uppercase variants (Mastodon scopes are lowercase by spec)', () => {
		expect(() => validateScopes(['Read:Accounts'])).toThrow(/forbidden/);
	});
});
