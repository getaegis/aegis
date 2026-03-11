/**
 * Aegis Webhook Alerts — fire-and-forget HTTP notifications for security events.
 *
 * Webhook endpoints are stored in SQLite and can subscribe to specific event types.
 * When an event fires, all matching webhooks receive a JSON POST with event details.
 *
 * Delivery is best-effort: retries up to 3 times with exponential backoff.
 * Failed deliveries are logged but never block the request pipeline.
 */

import * as crypto from 'node:crypto';
import * as http from 'node:http';
import * as https from 'node:https';
import type Database from 'better-sqlite3-multiple-ciphers';
import type pino from 'pino';
import { createLogger } from '../logger/index.js';
import type { Vault } from '../vault/index.js';

// ─── Types ───────────────────────────────────────────────────────

/**
 * Event types that can trigger webhook notifications.
 */
export type WebhookEventType =
  | 'blocked_request'
  | 'credential_expiry'
  | 'rate_limit_exceeded'
  | 'agent_auth_failure'
  | 'body_inspection';

export const WEBHOOK_EVENT_TYPES: readonly WebhookEventType[] = [
  'blocked_request',
  'credential_expiry',
  'rate_limit_exceeded',
  'agent_auth_failure',
  'body_inspection',
] as const;

/**
 * Stored webhook configuration.
 */
export interface Webhook {
  id: string;
  url: string;
  events: WebhookEventType[];
  /** Optional human-readable label */
  label?: string;
  /** HMAC secret for signing payloads (auto-generated) */
  secret: string;
  createdAt: string;
}

/**
 * Payload sent to webhook endpoints.
 */
export interface WebhookPayload {
  /** Unique event ID */
  id: string;
  /** Event type */
  event: WebhookEventType;
  /** ISO 8601 timestamp */
  timestamp: string;
  /** Event-specific details */
  details: Record<string, unknown>;
}

interface WebhookRow {
  id: string;
  url: string;
  events: string; // JSON array
  label: string | null;
  secret: string;
  created_at: string;
}

export interface WebhookManagerOptions {
  db: Database.Database;
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
  /** Maximum retries per delivery attempt (default: 3) */
  maxRetries?: number;
  /** Base delay in ms for exponential backoff (default: 1000) */
  baseDelayMs?: number;
  /** Request timeout in ms (default: 10000) */
  timeoutMs?: number;
  /** Testing: override transport */
  _testTransport?: (
    url: string,
    payload: string,
    headers: Record<string, string>,
  ) => Promise<number>;
}

// ─── WebhookManager ──────────────────────────────────────────────

export class WebhookManager {
  private db: Database.Database;
  private logger: pino.Logger;
  private maxRetries: number;
  private baseDelayMs: number;
  private timeoutMs: number;
  private testTransport?: (
    url: string,
    payload: string,
    headers: Record<string, string>,
  ) => Promise<number>;

  constructor(options: WebhookManagerOptions) {
    this.db = options.db;
    this.logger = createLogger({
      module: 'webhook',
      level: options.logLevel ?? 'info',
    });
    this.maxRetries = options.maxRetries ?? 3;
    this.baseDelayMs = options.baseDelayMs ?? 1000;
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.testTransport = options._testTransport;
  }

  // ─── CRUD ────────────────────────────────────────────────────

  /**
   * Register a new webhook endpoint.
   */
  add(params: { url: string; events: WebhookEventType[]; label?: string }): Webhook {
    // Validate URL
    const parsed = new URL(params.url);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new Error(`Invalid webhook URL protocol: ${parsed.protocol} (must be http or https)`);
    }

    // Validate events
    for (const event of params.events) {
      if (!WEBHOOK_EVENT_TYPES.includes(event)) {
        throw new Error(
          `Invalid event type: ${event}. Valid types: ${WEBHOOK_EVENT_TYPES.join(', ')}`,
        );
      }
    }

    if (params.events.length === 0) {
      throw new Error('At least one event type is required');
    }

    const id = crypto.randomUUID();
    const secret = crypto.randomBytes(32).toString('hex');

    this.db
      .prepare(
        `INSERT INTO webhooks (id, url, events, label, secret)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(id, params.url, JSON.stringify(params.events), params.label ?? null, secret);

    this.logger.info({ id, url: params.url, events: params.events }, 'Webhook registered');

    return {
      id,
      url: params.url,
      events: params.events,
      label: params.label,
      secret,
      createdAt: new Date().toISOString(),
    };
  }

  /**
   * List all registered webhooks.
   */
  list(): Webhook[] {
    const rows = this.db
      .prepare('SELECT * FROM webhooks ORDER BY created_at DESC')
      .all() as WebhookRow[];

    return rows.map((row) => this.rowToWebhook(row));
  }

  /**
   * Get a webhook by ID.
   */
  getById(id: string): Webhook | null {
    const row = this.db.prepare('SELECT * FROM webhooks WHERE id = ?').get(id) as
      | WebhookRow
      | undefined;

    return row ? this.rowToWebhook(row) : null;
  }

  /**
   * Remove a webhook by ID.
   */
  remove(id: string): boolean {
    const result = this.db.prepare('DELETE FROM webhooks WHERE id = ?').run(id);
    if (result.changes > 0) {
      this.logger.info({ id }, 'Webhook removed');
      return true;
    }
    return false;
  }

  // ─── Event Emission ──────────────────────────────────────────

  /**
   * Emit an event to all matching webhooks.
   * This is fire-and-forget — it never blocks the caller.
   */
  emit(event: WebhookEventType, details: Record<string, unknown>): void {
    const payload: WebhookPayload = {
      id: crypto.randomUUID(),
      event,
      timestamp: new Date().toISOString(),
      details,
    };

    // Find all webhooks subscribed to this event
    const webhooks = this.list().filter((w) => w.events.includes(event));
    if (webhooks.length === 0) return;

    this.logger.debug(
      { event, webhookCount: webhooks.length, payloadId: payload.id },
      'Emitting webhook event',
    );

    // Fire-and-forget — don't await, don't block
    for (const webhook of webhooks) {
      this.deliver(webhook, payload).catch((err: unknown) => {
        this.logger.error(
          { webhookId: webhook.id, url: webhook.url, err: String(err) },
          'Webhook delivery failed after all retries',
        );
      });
    }
  }

  // ─── Delivery ────────────────────────────────────────────────

  /**
   * Deliver a payload to a webhook endpoint with retries.
   */
  private async deliver(webhook: Webhook, payload: WebhookPayload): Promise<void> {
    const body = JSON.stringify(payload);
    const signature = this.sign(body, webhook.secret);

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Aegis-Signature': signature,
      'X-Aegis-Event': payload.event,
      'X-Aegis-Delivery': payload.id,
      'User-Agent': 'Aegis-Webhook/1.0',
    };

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      try {
        const statusCode = await this.send(webhook.url, body, headers);

        if (statusCode >= 200 && statusCode < 300) {
          this.logger.debug(
            { webhookId: webhook.id, status: statusCode, attempt },
            'Webhook delivered',
          );
          return;
        }

        // Non-2xx but not a network error — log and retry
        this.logger.warn(
          { webhookId: webhook.id, status: statusCode, attempt },
          'Webhook delivery non-2xx response',
        );
      } catch (err: unknown) {
        this.logger.warn(
          { webhookId: webhook.id, attempt, err: String(err) },
          'Webhook delivery failed',
        );
      }

      // Exponential backoff before retry (skip delay on last attempt)
      if (attempt < this.maxRetries) {
        const delay = this.baseDelayMs * 2 ** attempt;
        await this.sleep(delay);
      }
    }

    // All retries exhausted
    throw new Error(
      `Webhook delivery failed after ${this.maxRetries + 1} attempts to ${webhook.url}`,
    );
  }

  /**
   * Send an HTTP/HTTPS POST request.
   */
  private send(url: string, body: string, headers: Record<string, string>): Promise<number> {
    // Use test transport if provided
    if (this.testTransport) {
      return this.testTransport(url, body, headers);
    }

    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const transport = parsed.protocol === 'https:' ? https : http;

      const req = transport.request(
        {
          hostname: parsed.hostname,
          port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
          path: parsed.pathname + parsed.search,
          method: 'POST',
          headers: {
            ...headers,
            'Content-Length': Buffer.byteLength(body),
          },
          timeout: this.timeoutMs,
        },
        (res) => {
          // Consume response body to free socket
          res.resume();
          resolve(res.statusCode ?? 0);
        },
      );

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy(new Error('Webhook request timeout'));
      });

      req.write(body);
      req.end();
    });
  }

  /**
   * HMAC-SHA256 signature for payload verification.
   * Recipients can verify the webhook came from Aegis using:
   *   sha256=HMAC(body, secret)
   */
  private sign(body: string, secret: string): string {
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(body);
    return `sha256=${hmac.digest('hex')}`;
  }

  /**
   * Sleep for a given number of milliseconds.
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  private rowToWebhook(row: WebhookRow): Webhook {
    return {
      id: row.id,
      url: row.url,
      events: JSON.parse(row.events) as WebhookEventType[],
      label: row.label ?? undefined,
      secret: row.secret,
      createdAt: row.created_at,
    };
  }

  // ─── Credential Expiry Checking ────────────────────────────────

  /**
   * Check all credentials in the vault for approaching expiry.
   * Emits `credential_expiry` webhook events for credentials expiring within `thresholdDays`.
   * Returns the number of credentials that triggered alerts.
   */
  checkExpiringCredentials(vault: Vault, thresholdDays = 7): number {
    const credentials = vault.list();
    const now = new Date();
    const thresholdMs = thresholdDays * 24 * 60 * 60 * 1000;
    let alertCount = 0;

    for (const cred of credentials) {
      if (!cred.expiresAt) continue;

      const expiresAt = new Date(cred.expiresAt);
      const timeRemaining = expiresAt.getTime() - now.getTime();

      // Already expired
      if (timeRemaining <= 0) {
        this.emit('credential_expiry', {
          credential: cred.name,
          service: cred.service,
          expiredAt: cred.expiresAt,
          status: 'expired',
          daysRemaining: 0,
        });
        alertCount++;
        continue;
      }

      // Expiring soon (within threshold)
      if (timeRemaining <= thresholdMs) {
        const daysRemaining = Math.ceil(timeRemaining / (24 * 60 * 60 * 1000));
        this.emit('credential_expiry', {
          credential: cred.name,
          service: cred.service,
          expiresAt: cred.expiresAt,
          status: 'expiring_soon',
          daysRemaining,
        });
        alertCount++;
      }
    }

    if (alertCount > 0) {
      this.logger.info(
        { alertCount, thresholdDays },
        'Credential expiry check completed with alerts',
      );
    }

    return alertCount;
  }
}
