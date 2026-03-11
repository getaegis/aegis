/**
 * Aegis Metrics — Prometheus instrumentation via prom-client.
 *
 * Provides counters, histograms, and gauges for all Aegis request activity.
 * Metrics are exposed via a `/metrics` endpoint on the Gate server and are
 * compatible with Prometheus scraping and Grafana dashboards.
 *
 * Design:
 *   - Single shared `Registry` so Gate and MCP can share the same counters
 *   - Callers use the helper functions (`recordRequest`, `recordBlocked`, etc.)
 *     rather than touching prom-client directly
 *   - `collectCredentialGauges()` is called on each `/metrics` scrape to snapshot
 *     credential inventory from the Vault (it's a pull-model gauge, not push)
 *   - All metric names use the `aegis_` prefix per Prometheus naming conventions
 */

import { Counter, Gauge, register as globalRegister, Histogram, type Registry } from 'prom-client';
import type { Vault } from '../vault/index.js';

// ─── Types ───────────────────────────────────────────────────────

export interface MetricsOptions {
  /** Custom prom-client registry (default: global). Useful for tests. */
  registry?: Registry;
  /** Vault instance — needed for credential gauge collection. */
  vault?: Vault;
  /** Default labels applied to every metric (e.g. `{ instance: 'prod-1' }`). */
  defaultLabels?: Record<string, string>;
}

export type BlockReason =
  | 'no_credential'
  | 'credential_expired'
  | 'credential_scope'
  | 'agent_auth_missing'
  | 'agent_auth_invalid'
  | 'agent_scope'
  | 'policy_violation'
  | 'policy_rate_limit'
  | 'agent_rate_limit'
  | 'credential_rate_limit'
  | 'domain_guard'
  | 'body_inspection'
  | 'body_too_large'
  | 'agent_connection_limit';

// ─── AegisMetrics ────────────────────────────────────────────────

/**
 * Central metrics collector for Aegis.
 *
 * Usage:
 * ```ts
 * const metrics = new AegisMetrics({ vault });
 * // On every proxied request:
 * metrics.recordRequest('slack', 'GET', 200, 'my-agent');
 * // On every blocked request:
 * metrics.recordBlocked('slack', 'domain_guard', 'my-agent');
 * // Duration is measured with a timer:
 * const end = metrics.startRequestTimer('slack');
 * // ...do work...
 * end(); // records duration
 * ```
 */
export class AegisMetrics {
  readonly registry: Registry;
  private vault?: Vault;

  // ─── Counters ────────────────────────────────────────────────
  /** Total requests processed (allowed through to upstream). */
  readonly requestsTotal: Counter;
  /** Total requests blocked before reaching upstream. */
  readonly requestsBlockedTotal: Counter;

  // ─── Histogram ───────────────────────────────────────────────
  /** Request duration in seconds (only for successful proxied requests). */
  readonly requestDuration: Histogram;

  // ─── Gauges ──────────────────────────────────────────────────
  /** Credential inventory by status. */
  readonly credentialsTotal: Gauge;

  constructor(options: MetricsOptions = {}) {
    this.registry = options.registry ?? globalRegister;
    this.vault = options.vault;

    if (options.defaultLabels) {
      this.registry.setDefaultLabels(options.defaultLabels);
    }

    // ── Counters ──────────────────────────────────────────────
    this.requestsTotal = new Counter({
      name: 'aegis_requests_total',
      help: 'Total requests proxied through Aegis (allowed)',
      labelNames: ['service', 'method', 'status', 'agent'] as const,
      registers: [this.registry],
    });

    this.requestsBlockedTotal = new Counter({
      name: 'aegis_requests_blocked_total',
      help: 'Total requests blocked by Aegis',
      labelNames: ['service', 'reason', 'agent'] as const,
      registers: [this.registry],
    });

    // ── Histogram ─────────────────────────────────────────────
    this.requestDuration = new Histogram({
      name: 'aegis_request_duration_seconds',
      help: 'Duration of proxied requests in seconds',
      labelNames: ['service'] as const,
      // Bucket boundaries (seconds): 5ms → 30s, web-API-appropriate
      buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30],
      registers: [this.registry],
    });

    // ── Gauges ─────────────────────────────────────────────────
    this.credentialsTotal = new Gauge({
      name: 'aegis_credentials_total',
      help: 'Number of credentials by status',
      labelNames: ['status'] as const,
      registers: [this.registry],
      // Collect callback — called on every scrape
      ...(this.vault
        ? {
            collect: () => {
              this.collectCredentialGauges();
            },
          }
        : {}),
    });
  }

  // ─── Recording helpers ─────────────────────────────────────────

  /**
   * Record a successfully proxied request.
   */
  recordRequest(service: string, method: string, status: number, agent?: string): void {
    this.requestsTotal.inc({
      service,
      method,
      status: String(status),
      agent: agent ?? '',
    });
  }

  /**
   * Record a blocked request.
   */
  recordBlocked(service: string, reason: BlockReason, agent?: string): void {
    this.requestsBlockedTotal.inc({
      service,
      reason,
      agent: agent ?? '',
    });
  }

  /**
   * Start a request duration timer. Call the returned function when the request completes.
   *
   * @returns A stop function that records the elapsed time.
   */
  startRequestTimer(service: string): () => void {
    return this.requestDuration.startTimer({ service });
  }

  // ─── Credential gauge collection ──────────────────────────────

  /**
   * Snapshot credential inventory from the Vault and update gauge values.
   * Called automatically on each `/metrics` scrape via the gauge's collect callback.
   */
  private collectCredentialGauges(): void {
    if (!this.vault) return;

    const credentials = this.vault.list();
    const now = new Date();
    const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;

    let active = 0;
    let expired = 0;
    let expiringSoon = 0;

    for (const cred of credentials) {
      if (cred.expiresAt) {
        const expiryDate = new Date(cred.expiresAt);
        if (expiryDate <= now) {
          expired++;
        } else if (expiryDate.getTime() - now.getTime() <= sevenDaysMs) {
          expiringSoon++;
        } else {
          active++;
        }
      } else {
        // No expiry = always active
        active++;
      }
    }

    this.credentialsTotal.set({ status: 'active' }, active);
    this.credentialsTotal.set({ status: 'expired' }, expired);
    this.credentialsTotal.set({ status: 'expiring_soon' }, expiringSoon);
  }

  // ─── Scrape endpoint ──────────────────────────────────────────

  /**
   * Return the Prometheus-formatted metrics string for scraping.
   * Used by the `/_aegis/metrics` endpoint handler.
   */
  async getMetricsOutput(): Promise<string> {
    return this.registry.metrics();
  }

  /**
   * Return the content-type header for the metrics response.
   */
  getContentType(): string {
    return this.registry.contentType;
  }

  /**
   * Reset all metrics. Useful for tests.
   */
  reset(): void {
    this.registry.resetMetrics();
  }
}
