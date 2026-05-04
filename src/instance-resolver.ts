// SPDX-License-Identifier: Apache-2.0
/**
 * Per-login instance resolution: the load-bearing piece that justifies
 * a direct adapter (vs Path B / OIDC + IDP brokering). The adapter
 * accepts whatever the user typed, normalises it, and probes the
 * resulting origin for Mastodon-API compatibility before any OAuth
 * redirect.
 *
 * Accepted input shapes:
 *
 * 1. Bare hostname:        `mastodon.social`              → `https://mastodon.social/`
 * 2. WebFinger handle:     `@alice@hachyderm.io`          → `https://hachyderm.io/`
 *                          (the local part is discarded; we authenticate
 *                          the whole instance, not a specific user)
 * 3. Full URL:             `https://social.coop`          → `https://social.coop/`
 * 4. URL with path:        `https://example.org/some/path` → `https://example.org/`
 *
 * Inputs are trimmed and lowercased on the host. Schemes other than
 * `http`/`https` are rejected. Hosts containing whitespace or empty
 * strings throw before any network call.
 */

import { MastodonInstanceUnreachableError } from './errors.js';
import type { MastodonClient } from './client.js';

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

export function parseInstanceInput(input: string): URL {
	const trimmed = input.trim();
	if (trimmed === '') {
		throw new Error('parseInstanceInput: empty input');
	}

	// Shape 2: WebFinger-shaped handle "@user@host" or "user@host"
	// Mastodon's @-prefixed form is the canonical fediverse handle; we
	// strip the local part and take the host as the instance.
	const handleMatch = trimmed.match(/^@?[^@\s]+@([^@\s]+)$/);
	if (handleMatch) {
		const host = handleMatch[1]!.toLowerCase();
		assertHostUsable(host);
		return new URL(`https://${host}`);
	}

	// Shape 3 & 4: full URL with scheme. We require `://` (not just `:`)
	// so bare host:port forms like `localhost:3001` fall through to the
	// bare-hostname branch instead of being parsed as a URL with scheme
	// `localhost:`.
	if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
		let parsed: URL;
		try {
			parsed = new URL(trimmed);
		} catch {
			throw new Error(`parseInstanceInput: not a valid URL: ${input}`);
		}
		if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
			throw new Error(
				`parseInstanceInput: unsupported scheme "${parsed.protocol}"; expected http or https`,
			);
		}
		assertHostUsable(parsed.host);
		// Drop path/query/fragment, keep scheme + host (and port).
		return new URL(`${parsed.protocol}//${parsed.host}`);
	}

	// Shape 1: bare hostname (or host:port). Still reject whitespace,
	// embedded slashes, or anything that isn't a valid host.
	const lower = trimmed.toLowerCase();
	assertHostUsable(lower);
	return new URL(`https://${lower}`);
}

function assertHostUsable(host: string): void {
	if (host === '' || /\s/.test(host)) {
		throw new Error(
			`parseInstanceInput: host contains whitespace or is empty: "${host}"`,
		);
	}
	if (host.includes('/')) {
		throw new Error(`parseInstanceInput: host contains "/": "${host}"`);
	}
	if (host.includes('@')) {
		throw new Error(`parseInstanceInput: host contains "@": "${host}"`);
	}
}

export async function resolveInstance(
	input: string,
	client: MastodonClient,
): Promise<URL> {
	const origin = parseInstanceInput(input);
	try {
		await client.probeInstance(origin);
	} catch (cause) {
		throw new MastodonInstanceUnreachableError(
			`resolveInstance: ${origin.toString()} did not respond as a Mastodon-API server`,
			origin,
			cause,
		);
	}
	return origin;
}
