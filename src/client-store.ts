// SPDX-License-Identifier: Apache-2.0
/**
 * `ClientStore`: pluggable cache for per-instance OAuth client credentials.
 *
 * Mastodon's runtime client registration (`POST /api/v1/apps`) is
 * cheap but not free: registering a fresh client on every login is
 * wasteful and looks suspicious in instance admin logs. The adapter
 * caches credentials by canonical origin string. The default
 * `InMemoryClientStore` is process-lifetime and single-tenant; multi-
 * process or multi-region deployments inject their own implementation
 * (Cloudflare KV, Redis, Postgres, ...) by satisfying this interface.
 *
 * Records expire after `maxAgeMs` (default 30 days). Mastodon
 * `client_secret` does not auto-expire on the substrate side, but
 * rotating periodically reduces blast radius if the cache leaks.
 */

import type { ClientCredentials } from './types.js';

export interface ClientRecord extends ClientCredentials {
	registered_at: Date;
}

export interface ClientStore {
	get(origin: string): Promise<ClientRecord | null>;
	set(origin: string, record: ClientRecord): Promise<void>;
}

export interface InMemoryClientStoreOptions {
	maxAgeMs?: number;
	now?: () => Date;
}

const DEFAULT_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

export class InMemoryClientStore implements ClientStore {
	readonly maxAgeMs: number;
	readonly now: () => Date;
	private readonly records = new Map<string, ClientRecord>();

	constructor(options: InMemoryClientStoreOptions = {}) {
		this.maxAgeMs = options.maxAgeMs ?? DEFAULT_MAX_AGE_MS;
		this.now = options.now ?? (() => new Date());
	}

	async get(origin: string): Promise<ClientRecord | null> {
		const record = this.records.get(origin);
		if (!record) return null;
		const ageMs = this.now().getTime() - record.registered_at.getTime();
		if (ageMs > this.maxAgeMs) return null;
		return record;
	}

	async set(origin: string, record: ClientRecord): Promise<void> {
		this.records.set(origin, record);
	}
}
