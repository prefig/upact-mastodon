// SPDX-License-Identifier: Apache-2.0
/**
 * `MastodonInstanceUnreachableError`: thrown when the adapter cannot
 * verify that a user-supplied instance is Mastodon-API-compatible.
 * Extends `SubstrateUnavailableError` so consumers that already catch
 * `SubstrateUnavailableError` for substrate-down handling pick this up
 * uniformly.
 *
 * Surfaced from:
 * - `buildAuthRedirect` when the instance probe fails
 * - `currentUpactor` when the user's session-bound instance is unreachable
 *
 * Distinct from `MastodonApiError` (in `client.ts`), which carries the
 * substrate's HTTP status and OAuth error code from a *response* the
 * adapter received but can't proceed with.
 */

import { SubstrateUnavailableError } from '@prefig/upact';

export class MastodonInstanceUnreachableError extends SubstrateUnavailableError {
	override name = 'MastodonInstanceUnreachableError';
	readonly origin: URL | undefined;
	override readonly cause: unknown;
	constructor(message: string, origin?: URL, cause?: unknown) {
		super(message);
		this.origin = origin;
		this.cause = cause;
	}
}
