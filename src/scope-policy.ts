// SPDX-License-Identifier: Apache-2.0
/**
 * Runtime scope discipline for `@prefig/upact-mastodon`.
 *
 * Scope policy is **load-bearing for the privacy contract** — what scopes
 * the adapter requests determines what claims the substrate could return.
 * SPEC.md §7 forbids the adapter from accepting scopes that grant access
 * to email, phone, address, statuses, follows, or push. Enforcing this at
 * runtime (not just convention) means a misconfigured deployment fails
 * fast at construction time, before any user sees an authorize URL.
 *
 * Default scope set: `['read:accounts']` — the narrowest scope that
 * works on Mastodon ≥3.x for `verify_credentials`. Mastodon 4.3+
 * supports the even-narrower `profile` scope; deployments running
 * exclusively against ≥4.3 instances may pass `scopes: ['profile']`.
 */

export const DEFAULT_SCOPES: readonly string[] = ['read:accounts'];

const ALLOWED_SCOPES = new Set<string>(['read:accounts', 'profile']);

export function validateScopes(scopes: readonly string[]): void {
	if (scopes.length === 0) {
		throw new Error(
			'@prefig/upact-mastodon: at least one scope is required (default is ["read:accounts"]).',
		);
	}
	for (const scope of scopes) {
		if (!ALLOWED_SCOPES.has(scope)) {
			throw new Error(
				`@prefig/upact-mastodon: forbidden scope "${scope}". ` +
					`upact SPEC §7 forbids scopes that grant access to email, phone, address, statuses, follows, or push. ` +
					`Allowed scopes: ${Array.from(ALLOWED_SCOPES).join(', ')}.`,
			);
		}
	}
}
