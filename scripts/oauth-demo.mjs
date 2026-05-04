// SPDX-License-Identifier: Apache-2.0
/**
 * Tiny OAuth demo server for @prefig/upact-mastodon.
 *
 * Run: npm run build && node scripts/oauth-demo.mjs
 * Then open: http://localhost:3001/
 *
 * Routes:
 *   GET  /             : login form (input for instance)
 *   GET  /auth/login   : ?instance=... -> buildAuthRedirect -> 302 to Mastodon
 *   GET  /auth/callback: handles ?code=...&state=... from Mastodon
 *   GET  /me           : currentUpactor
 *   GET  /logout       : invalidate
 *
 * Cookies are set WITHOUT the Secure attribute so they work on plain
 * http://localhost. This is fine for local development; production
 * deployments use HTTPS and the adapter's normal Secure-on cookies.
 */

import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import {
	createMastodonAdapter,
	InMemoryClientStore,
} from '../dist/index.js';

const PORT = 3001;
const REDIRECT_URI = new URL(`http://localhost:${PORT}/auth/callback`);
const COOKIE_SECRET = new TextEncoder().encode(
	process.env.UPACT_DEMO_COOKIE_SECRET ?? randomBytes(32).toString('hex'),
);

// Construct ONE InMemoryClientStore at module load and share it across
// requests. Each request creates a fresh adapter; without an externally
// shared store the OAuth client credentials registered at /auth/login
// would not be visible at /auth/callback. Multi-process deployments
// inject their own ClientStore (KV / Redis / Postgres) here.
const CLIENT_STORE = new InMemoryClientStore();

if (!process.env.UPACT_DEMO_COOKIE_SECRET) {
	console.warn(
		'[demo] UPACT_DEMO_COOKIE_SECRET not set; using a random secret. Sessions will be invalidated when the server restarts.',
	);
}

function parseCookies(header) {
	const out = new Map();
	if (!header) return out;
	for (const part of header.split(/;\s*/)) {
		const eq = part.indexOf('=');
		if (eq < 0) continue;
		out.set(part.slice(0, eq), decodeURIComponent(part.slice(eq + 1)));
	}
	return out;
}

function makeCookieJar(req, res) {
	const incoming = parseCookies(req.headers['cookie']);
	const setCookies = [];
	return {
		jar: {
			get(name) {
				return incoming.get(name);
			},
			set(name, value, options = {}) {
				const parts = [`${name}=${encodeURIComponent(value)}`];
				if (options.httpOnly) parts.push('HttpOnly');
				// Skip Secure for localhost http demo.
				if (options.sameSite) parts.push(`SameSite=${capitalize(options.sameSite)}`);
				parts.push(`Path=${options.path ?? '/'}`);
				if (options.maxAge !== undefined) parts.push(`Max-Age=${options.maxAge}`);
				setCookies.push(parts.join('; '));
				incoming.set(name, value); // reflect within-request reads
			},
			delete(name, options = {}) {
				const path = options.path ?? '/';
				setCookies.push(`${name}=; Path=${path}; Max-Age=0`);
				incoming.delete(name);
			},
		},
		flush() {
			if (setCookies.length > 0) {
				res.setHeader('Set-Cookie', setCookies);
			}
		},
	};
}

function capitalize(s) {
	return s.charAt(0).toUpperCase() + s.slice(1);
}

function html(body) {
	return `<!doctype html><html><head><meta charset="utf-8"><title>upact-mastodon demo</title>
<style>body { font: 16px/1.5 system-ui, sans-serif; max-width: 720px; margin: 3rem auto; padding: 0 1rem; color: #222; }
pre { background: #f6f6f6; padding: 1rem; border-radius: 4px; overflow-x: auto; }
input[type=text] { font: inherit; padding: .5rem; width: 24rem; }
button, .btn { font: inherit; padding: .5rem 1rem; cursor: pointer; }
a { color: #06f; }
.err { color: #c00; font-weight: bold; }
.ok { color: #060; }
</style></head><body>${body}</body></html>`;
}

const server = createServer(async (req, res) => {
	const url = new URL(req.url, `http://localhost:${PORT}`);
	const { jar, flush } = makeCookieJar(req, res);
	const adapter = createMastodonAdapter(
		{
			appName: 'upact-mastodon demo',
			redirectUri: REDIRECT_URI,
			cookieSecret: COOKIE_SECRET,
			clientStore: CLIENT_STORE,
		},
		jar,
	);

	try {
		if (url.pathname === '/') {
			let upactor = null;
			try {
				upactor = await adapter.currentUpactor(req);
			} catch (e) {
				console.error('[demo] currentUpactor failed:', e.message ?? e);
			}
			const body = upactor
				? `<h1>upact-mastodon demo</h1>
				   <p class="ok">You are signed in as <code>${escapeHtml(upactor.display_hint ?? '(no display hint)')}</code>.</p>
				   <p>Your Upactor:</p>
				   <pre>${escapeHtml(stringify(upactor))}</pre>
				   <p><a href="/me">/me (re-validates via verify_credentials)</a></p>
				   <p><a href="/logout">Sign out</a></p>`
				: `<h1>upact-mastodon demo</h1>
				   <p>Sign in with any Mastodon-compatible instance.</p>
				   <form action="/auth/login" method="get">
					 <input type="text" name="instance" placeholder="mastodon.social or @alice@hachyderm.io" required>
					 <button type="submit">Sign in</button>
				   </form>`;
			flush();
			res.setHeader('Content-Type', 'text/html; charset=utf-8');
			res.end(html(body));
			return;
		}

		if (url.pathname === '/auth/login') {
			const instance = url.searchParams.get('instance');
			if (!instance) {
				flush();
				res.statusCode = 400;
				res.setHeader('Content-Type', 'text/html; charset=utf-8');
				res.end(html('<p class="err">Missing instance.</p>'));
				return;
			}
			console.log(`[demo] buildAuthRedirect: instance=${instance}`);
			const target = await adapter.buildAuthRedirect({
				instanceInput: instance,
				returnTo: '/',
			});
			console.log(`[demo] redirecting to: ${target.toString()}`);
			flush();
			res.statusCode = 302;
			res.setHeader('Location', target.toString());
			res.end();
			return;
		}

		if (url.pathname === '/auth/callback') {
			console.log(`[demo] callback: ${req.url}`);
			const result = await adapter.authenticate({
				kind: 'mastodon-callback',
				request: new Request(`http://localhost:${PORT}${req.url}`),
			});
			flush();
			if ('code' in result) {
				console.error('[demo] AuthError:', result);
				res.statusCode = 400;
				res.setHeader('Content-Type', 'text/html; charset=utf-8');
				res.end(
					html(
						`<p class="err">AuthError: ${escapeHtml(result.code)}</p><pre>${escapeHtml(result.message)}</pre><p><a href="/">try again</a></p>`,
					),
				);
				return;
			}
			console.log('[demo] authenticate succeeded; SessionState set');
			res.statusCode = 302;
			res.setHeader('Location', '/');
			res.end();
			return;
		}

		if (url.pathname === '/me') {
			let upactor;
			try {
				upactor = await adapter.currentUpactor(req);
			} catch (e) {
				flush();
				res.statusCode = 503;
				res.setHeader('Content-Type', 'text/html; charset=utf-8');
				res.end(
					html(
						`<p class="err">SubstrateUnavailableError: ${escapeHtml(e.message ?? String(e))}</p>`,
					),
				);
				return;
			}
			flush();
			res.setHeader('Content-Type', 'text/html; charset=utf-8');
			res.end(
				html(
					`<h1>currentUpactor</h1><pre>${escapeHtml(stringify(upactor))}</pre><p><a href="/">back</a></p>`,
				),
			);
			return;
		}

		if (url.pathname === '/logout') {
			// invalidate needs the Session, which we don't have a handle to here
			// (the demo never stored it). Clear the session cookie directly via
			// the adapter's invalidate with a foreign Session: that path is a
			// no-op for revoke but still clears the cookie.
			await adapter.invalidate({ _opaque: Symbol() });
			flush();
			res.statusCode = 302;
			res.setHeader('Location', '/');
			res.end();
			return;
		}

		flush();
		res.statusCode = 404;
		res.setHeader('Content-Type', 'text/plain');
		res.end('not found');
	} catch (e) {
		flush();
		console.error('[demo] unhandled error:', e);
		res.statusCode = 500;
		res.setHeader('Content-Type', 'text/html; charset=utf-8');
		res.end(
			html(
				`<p class="err">Server error</p><pre>${escapeHtml(e.stack ?? e.message ?? String(e))}</pre>`,
			),
		);
	}
});

function stringify(v) {
	return JSON.stringify(
		v,
		(_, val) => {
			if (val instanceof Set) return Array.from(val);
			return val;
		},
		2,
	);
}

function escapeHtml(s) {
	return String(s)
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;');
}

server.listen(PORT, () => {
	console.log(`[demo] listening on http://localhost:${PORT}/`);
});
