// SPDX-License-Identifier: Apache-2.0
/**
 * `CookieJar`: abstraction over framework-specific cookie APIs (SvelteKit
 * `event.cookies`, Express/Connect `req.cookies` + `res.cookie`, etc).
 *
 * Signed-cookie helpers (`signValue`/`unsignValue`) and the concrete
 * `PendingState` / `SessionState` payloads land in U7.
 */

export interface CookieSetOptions {
	httpOnly?: boolean;
	secure?: boolean;
	sameSite?: 'lax' | 'strict' | 'none';
	path?: string;
	maxAge?: number;
}

export interface CookieJar {
	get(name: string): string | undefined;
	set(name: string, value: string, options?: CookieSetOptions): void;
	delete(name: string, options?: CookieSetOptions): void;
}
