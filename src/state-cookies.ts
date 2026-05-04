// SPDX-License-Identifier: Apache-2.0
/**
 * Signed-cookie state for the OAuth round-trip.
 *
 * The adapter needs durable per-user state across two HTTP redirects:
 *
 * 1. `PendingState`: the in-flight OAuth handshake. Holds the OAuth
 *    `state` value, the PKCE `code_verifier`, the resolved instance
 *    origin, and the post-login `returnTo`. Set in `buildAuthRedirect`,
 *    read and deleted in `authenticate({kind: 'mastodon-callback'})`.
 *    10-minute TTL.
 * 2. `SessionState`: the post-auth session. Holds the access_token, the
 *    actor URL, and the instance origin. Set in `authenticate` after
 *    successful verify_credentials, read on every `currentUpactor`,
 *    cleared in `invalidate`.
 *
 * Both payloads are sealed with HMAC-SHA256 via Web Crypto. A tampered
 * or expired cookie returns null at `unsignValue` time, which the
 * adapter treats as logged-out (or as a credential_invalid auth failure
 * during callback).
 *
 * The transport-layer cookie attributes (HttpOnly, Secure, SameSite,
 * path) are set by the framework's CookieJar, not in this module.
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

export interface PendingState {
	state: string;
	code_verifier: string;
	instance: string;
	returnTo?: string;
}

export interface SessionState {
	access_token: string;
	actor_url: string;
	instance: string;
}

interface SignedEnvelope {
	p: unknown;
	iat: number;
}

const PENDING_STATE_TTL_MS = 10 * 60 * 1000;
const SESSION_COOKIE_MAX_AGE_S = 14 * 24 * 60 * 60;

export const PENDING_COOKIE_NAME = 'upact_mastodon_pending';
export const SESSION_COOKIE_NAME = 'upact_mastodon_session';

export async function signValue(
	payload: unknown,
	secret: Uint8Array,
	options: { now?: () => Date } = {},
): Promise<string> {
	const now = options.now ?? (() => new Date());
	const envelope: SignedEnvelope = { p: payload, iat: now().getTime() };
	const json = JSON.stringify(envelope);
	const payloadBytes = new TextEncoder().encode(json);
	const payloadB64 = base64url(payloadBytes);
	const key = await importHmacKey(secret);
	const signature = new Uint8Array(
		await crypto.subtle.sign('HMAC', key, payloadBytes),
	);
	const signatureB64 = base64url(signature);
	return `${payloadB64}.${signatureB64}`;
}

export async function unsignValue<T>(
	token: string,
	secret: Uint8Array,
	options: { maxAgeMs: number; now?: () => Date },
): Promise<T | null> {
	const dot = token.indexOf('.');
	if (dot < 0) return null;
	const payloadB64 = token.slice(0, dot);
	const signatureB64 = token.slice(dot + 1);
	let payloadBytes: Uint8Array;
	let signatureBytes: Uint8Array;
	try {
		payloadBytes = base64urlDecode(payloadB64);
		signatureBytes = base64urlDecode(signatureB64);
	} catch {
		return null;
	}
	const key = await importHmacKey(secret);
	const ok = await crypto.subtle.verify(
		'HMAC',
		key,
		intoFreshBuffer(signatureBytes),
		intoFreshBuffer(payloadBytes),
	);
	if (!ok) return null;
	let envelope: SignedEnvelope;
	try {
		envelope = JSON.parse(new TextDecoder().decode(payloadBytes)) as SignedEnvelope;
	} catch {
		return null;
	}
	if (typeof envelope.iat !== 'number') return null;
	const now = (options.now ?? (() => new Date()))().getTime();
	if (now - envelope.iat > options.maxAgeMs) return null;
	return envelope.p as T;
}

export async function writePendingState(
	cookies: CookieJar,
	secret: Uint8Array,
	state: PendingState,
	options: { redirectUri: URL; now?: () => Date } = {} as never,
): Promise<void> {
	const value = await signValue(state, secret, { now: options.now });
	cookies.set(PENDING_COOKIE_NAME, value, {
		httpOnly: true,
		secure: true,
		sameSite: 'lax',
		path: options.redirectUri.pathname,
		maxAge: Math.floor(PENDING_STATE_TTL_MS / 1000),
	});
}

export async function readPendingState(
	cookies: CookieJar,
	secret: Uint8Array,
	options: { now?: () => Date } = {},
): Promise<PendingState | null> {
	const raw = cookies.get(PENDING_COOKIE_NAME);
	if (!raw) return null;
	return unsignValue<PendingState>(raw, secret, {
		maxAgeMs: PENDING_STATE_TTL_MS,
		...(options.now !== undefined ? { now: options.now } : {}),
	});
}

export function clearPendingState(
	cookies: CookieJar,
	options: { redirectUri: URL },
): void {
	cookies.delete(PENDING_COOKIE_NAME, {
		path: options.redirectUri.pathname,
	});
}

export async function writeSessionState(
	cookies: CookieJar,
	secret: Uint8Array,
	state: SessionState,
	options: { now?: () => Date } = {},
): Promise<void> {
	const value = await signValue(state, secret, options);
	cookies.set(SESSION_COOKIE_NAME, value, {
		httpOnly: true,
		secure: true,
		sameSite: 'lax',
		path: '/',
		maxAge: SESSION_COOKIE_MAX_AGE_S,
	});
}

export async function readSessionState(
	cookies: CookieJar,
	secret: Uint8Array,
	options: { now?: () => Date } = {},
): Promise<SessionState | null> {
	const raw = cookies.get(SESSION_COOKIE_NAME);
	if (!raw) return null;
	return unsignValue<SessionState>(raw, secret, {
		maxAgeMs: SESSION_COOKIE_MAX_AGE_S * 1000,
		...(options.now !== undefined ? { now: options.now } : {}),
	});
}

export function clearSessionState(cookies: CookieJar): void {
	cookies.delete(SESSION_COOKIE_NAME, { path: '/' });
}

async function importHmacKey(secret: Uint8Array): Promise<CryptoKey> {
	return crypto.subtle.importKey(
		'raw',
		intoFreshBuffer(secret),
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['sign', 'verify'],
	);
}

/**
 * Web Crypto's BufferSource excludes SharedArrayBuffer-backed views.
 * `Uint8Array<ArrayBufferLike>` (the inferred type of inbound bytes)
 * cannot be passed directly. Copy into a fresh ArrayBuffer to satisfy
 * the type and avoid runtime aliasing.
 */
function intoFreshBuffer(bytes: Uint8Array): ArrayBuffer {
	const buf = new ArrayBuffer(bytes.length);
	new Uint8Array(buf).set(bytes);
	return buf;
}

function base64url(bytes: Uint8Array): string {
	let binary = '';
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(input: string): Uint8Array {
	const padded = input.replace(/-/g, '+').replace(/_/g, '/');
	const padding = padded.length % 4 === 0 ? 0 : 4 - (padded.length % 4);
	const b64 = padded + '='.repeat(padding);
	const binary = atob(b64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
	return bytes;
}
