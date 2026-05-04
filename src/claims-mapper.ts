// SPDX-License-Identifier: Apache-2.0
/**
 * `mapAccountToUpactor` — pure function from substrate-allow-listed
 * `AccountClaims` to a port-shaped `Upactor`.
 *
 * The privacy boundary lives here. Three rules to remember:
 *
 * 1. **`id` is opaque.** `sha256(actor.url)[:32]`. The actor URL stays
 *    inside the adapter (held in closure for substrate-side calls per
 *    F3); the application sees only the hash.
 * 2. **`display_hint` is sanitised.** Falls back from `display_name` to
 *    `username` to `undefined`; rejects email-shaped values per
 *    upact SPEC.md §4.2.
 * 3. **`lifecycle` and `provenance` are populated per F6 / Decision 6.**
 *    Mastodon access tokens never auto-expire (`expires_at: undefined`);
 *    `renewable: 'reauth'` because revocation is the only path to a new
 *    token.
 *
 * The mapper is `async` because Web Crypto's `digest` is async; nothing
 * about the substrate forces a network round-trip here.
 */

import type { Upactor } from '@prefig/upact';
import type { AccountClaims } from './types.js';

const ID_LENGTH_HEX = 32;
const EMPTY_CAPABILITIES: ReadonlySet<never> = Object.freeze(new Set());

export async function mapAccountToUpactor(
	claims: AccountClaims,
	instanceOrigin: URL,
): Promise<Upactor> {
	const id = await hashHexTruncated(claims.url, ID_LENGTH_HEX);
	const displayHint = chooseDisplayHint(claims);
	return {
		id,
		...(displayHint !== undefined ? { display_hint: displayHint } : {}),
		capabilities: EMPTY_CAPABILITIES,
		lifecycle: {
			expires_at: undefined,
			renewable: 'reauth',
		},
		provenance: {
			substrate: 'mastodon',
			instance: instanceOrigin.toString(),
		},
	};
}

async function hashHexTruncated(input: string, hexLength: number): Promise<string> {
	const bytes = new TextEncoder().encode(input);
	const digest = await crypto.subtle.digest('SHA-256', bytes);
	const hex = Array.from(new Uint8Array(digest))
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
	return hex.slice(0, hexLength);
}

function chooseDisplayHint(claims: AccountClaims): string | undefined {
	const display = sanitiseCandidate(claims.display_name);
	if (display !== undefined) return display;
	return sanitiseCandidate(claims.username);
}

function sanitiseCandidate(raw: string): string | undefined {
	const trimmed = raw.trim();
	if (trimmed === '') return undefined;
	if (looksEmailShaped(trimmed)) return undefined;
	return trimmed;
}

function looksEmailShaped(value: string): boolean {
	// SPEC.md §4.2: display_hint MUST NOT be an email address. We use a
	// narrow shape check (single `@` with non-empty parts) rather than a
	// permissive regex, so unicode display names like "山田太郎" or
	// emoji-prefixed names pass freely.
	const at = value.indexOf('@');
	if (at <= 0) return false;
	if (at !== value.lastIndexOf('@')) return false;
	const local = value.slice(0, at);
	const domain = value.slice(at + 1);
	return local.length > 0 && domain.length > 0 && domain.includes('.');
}
