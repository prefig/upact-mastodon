// SPDX-License-Identifier: Apache-2.0
/**
 * `ClientStore`: pluggable cache for per-instance OAuth client credentials.
 *
 * The default `InMemoryClientStore` is process-lifetime and single-tenant.
 * Multi-process or multi-region deployments inject their own store
 * (Cloudflare KV, Redis, Postgres, …) by implementing this interface.
 *
 * The full implementation lands in U6.
 */

import type { ClientCredentials } from './types.js';

export interface ClientRecord extends ClientCredentials {
	registered_at: Date;
}

export interface ClientStore {
	get(origin: string): Promise<ClientRecord | null>;
	set(origin: string, record: ClientRecord): Promise<void>;
}
