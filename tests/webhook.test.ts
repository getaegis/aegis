import * as crypto from 'node:crypto';
import * as http from 'node:http';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AgentRegistry } from '../src/agent/index.js';
import { migrate } from '../src/db.js';
import { Gate } from '../src/gate/index.js';
import { Ledger } from '../src/ledger/index.js';
import { deriveKey, Vault } from '../src/vault/index.js';
import {
  WEBHOOK_EVENT_TYPES,
  type WebhookEventType,
  WebhookManager,
  type WebhookPayload,
} from '../src/webhook/index.js';

// ─── Test Helpers ────────────────────────────────────────────────

function createTestDb(): Database.Database {
  const db = new Database(':memory:');
  migrate(db);
  return db;
}

/**
 * Create a test transport that records all deliveries.
 */
function createRecorder(): {
  deliveries: { url: string; payload: WebhookPayload; headers: Record<string, string> }[];
  transport: (url: string, body: string, headers: Record<string, string>) => Promise<number>;
} {
  const deliveries: { url: string; payload: WebhookPayload; headers: Record<string, string> }[] =
    [];
  const transport = async (
    url: string,
    body: string,
    headers: Record<string, string>,
  ): Promise<number> => {
    deliveries.push({ url, payload: JSON.parse(body) as WebhookPayload, headers });
    return 200;
  };
  return { deliveries, transport };
}

// ─── CRUD Tests ──────────────────────────────────────────────────

describe('WebhookManager CRUD', () => {
  let db: Database.Database;

  beforeEach(() => {
    db = createTestDb();
  });

  afterEach(() => {
    db.close();
  });

  it('adds a webhook and returns it', () => {
    const manager = new WebhookManager({ db, logLevel: 'error' });

    const webhook = manager.add({
      url: 'https://example.com/hook',
      events: ['blocked_request'],
    });

    expect(webhook.id).toBeDefined();
    expect(webhook.url).toBe('https://example.com/hook');
    expect(webhook.events).toEqual(['blocked_request']);
    expect(webhook.secret).toHaveLength(64); // 32 bytes hex
    expect(webhook.createdAt).toBeDefined();
  });

  it('adds a webhook with label', () => {
    const manager = new WebhookManager({ db, logLevel: 'error' });

    const webhook = manager.add({
      url: 'https://example.com/hook',
      events: ['blocked_request'],
      label: 'Slack alerts',
    });

    expect(webhook.label).toBe('Slack alerts');
  });

  it('adds a webhook with multiple events', () => {
    const manager = new WebhookManager({ db, logLevel: 'error' });

    const webhook = manager.add({
      url: 'https://example.com/hook',
      events: ['blocked_request', 'rate_limit_exceeded', 'body_inspection'],
    });

    expect(webhook.events).toEqual(['blocked_request', 'rate_limit_exceeded', 'body_inspection']);
  });

  it('rejects invalid URL protocol', () => {
    const manager = new WebhookManager({ db, logLevel: 'error' });

    expect(() =>
      manager.add({ url: 'ftp://example.com/hook', events: ['blocked_request'] }),
    ).toThrow(/Invalid webhook URL protocol/);
  });

  it('rejects invalid event type', () => {
    const manager = new WebhookManager({ db, logLevel: 'error' });

    expect(() =>
      manager.add({
        url: 'https://example.com/hook',
        events: ['invalid_event' as WebhookEventType],
      }),
    ).toThrow(/Invalid event type/);
  });

  it('rejects empty events array', () => {
    const manager = new WebhookManager({ db, logLevel: 'error' });

    expect(() => manager.add({ url: 'https://example.com/hook', events: [] })).toThrow(
      /At least one event type/,
    );
  });

  it('lists all webhooks', () => {
    const manager = new WebhookManager({ db, logLevel: 'error' });

    manager.add({ url: 'https://a.com/hook', events: ['blocked_request'] });
    manager.add({ url: 'https://b.com/hook', events: ['credential_expiry'] });
    manager.add({ url: 'https://c.com/hook', events: ['rate_limit_exceeded'] });

    const list = manager.list();
    expect(list).toHaveLength(3);
    // Verify all 3 are present (order may vary with same-second timestamps)
    const urls = list.map((w) => w.url).sort();
    expect(urls).toEqual(['https://a.com/hook', 'https://b.com/hook', 'https://c.com/hook']);
  });

  it('gets a webhook by ID', () => {
    const manager = new WebhookManager({ db, logLevel: 'error' });

    const webhook = manager.add({ url: 'https://example.com/hook', events: ['blocked_request'] });
    const fetched = manager.getById(webhook.id);

    expect(fetched).not.toBeNull();
    expect(fetched?.id).toBe(webhook.id);
    expect(fetched?.url).toBe(webhook.url);
    expect(fetched?.secret).toBe(webhook.secret);
  });

  it('returns null for non-existent ID', () => {
    const manager = new WebhookManager({ db, logLevel: 'error' });

    expect(manager.getById('non-existent')).toBeNull();
  });

  it('removes a webhook', () => {
    const manager = new WebhookManager({ db, logLevel: 'error' });

    const webhook = manager.add({ url: 'https://example.com/hook', events: ['blocked_request'] });
    expect(manager.remove(webhook.id)).toBe(true);
    expect(manager.getById(webhook.id)).toBeNull();
    expect(manager.list()).toHaveLength(0);
  });

  it('returns false when removing non-existent webhook', () => {
    const manager = new WebhookManager({ db, logLevel: 'error' });

    expect(manager.remove('non-existent')).toBe(false);
  });

  it('each webhook gets a unique secret', () => {
    const manager = new WebhookManager({ db, logLevel: 'error' });

    const a = manager.add({ url: 'https://a.com/hook', events: ['blocked_request'] });
    const b = manager.add({ url: 'https://b.com/hook', events: ['blocked_request'] });

    expect(a.secret).not.toBe(b.secret);
  });

  it('persists webhooks across manager instances', () => {
    const manager1 = new WebhookManager({ db, logLevel: 'error' });
    const webhook = manager1.add({ url: 'https://example.com/hook', events: ['blocked_request'] });

    const manager2 = new WebhookManager({ db, logLevel: 'error' });
    const fetched = manager2.getById(webhook.id);

    expect(fetched).not.toBeNull();
    expect(fetched?.url).toBe(webhook.url);
  });
});

// ─── Event Type Constant ─────────────────────────────────────────

describe('WEBHOOK_EVENT_TYPES', () => {
  it('contains all 5 event types', () => {
    expect(WEBHOOK_EVENT_TYPES).toHaveLength(5);
    expect(WEBHOOK_EVENT_TYPES).toContain('blocked_request');
    expect(WEBHOOK_EVENT_TYPES).toContain('credential_expiry');
    expect(WEBHOOK_EVENT_TYPES).toContain('rate_limit_exceeded');
    expect(WEBHOOK_EVENT_TYPES).toContain('agent_auth_failure');
    expect(WEBHOOK_EVENT_TYPES).toContain('body_inspection');
  });
});

// ─── Emission & Delivery Tests ───────────────────────────────────

describe('WebhookManager emit', () => {
  let db: Database.Database;

  beforeEach(() => {
    db = createTestDb();
  });

  afterEach(() => {
    db.close();
  });

  it('delivers to matching webhooks only', async () => {
    const { deliveries, transport } = createRecorder();
    const manager = new WebhookManager({ db, logLevel: 'error', _testTransport: transport });

    manager.add({ url: 'https://a.com/hook', events: ['blocked_request'] });
    manager.add({ url: 'https://b.com/hook', events: ['credential_expiry'] });

    manager.emit('blocked_request', { service: 'slack', reason: 'no_credential' });

    // Give fire-and-forget promises a tick to resolve
    await vi.waitFor(() => expect(deliveries).toHaveLength(1));

    expect(deliveries[0].url).toBe('https://a.com/hook');
    expect(deliveries[0].payload.event).toBe('blocked_request');
    expect(deliveries[0].payload.details.service).toBe('slack');
  });

  it('delivers to multiple matching webhooks', async () => {
    const { deliveries, transport } = createRecorder();
    const manager = new WebhookManager({ db, logLevel: 'error', _testTransport: transport });

    manager.add({ url: 'https://a.com/hook', events: ['blocked_request'] });
    manager.add({
      url: 'https://b.com/hook',
      events: ['blocked_request', 'credential_expiry'],
    });

    manager.emit('blocked_request', { test: true });

    await vi.waitFor(() => expect(deliveries).toHaveLength(2));
  });

  it('does not deliver when no webhooks match', async () => {
    const { deliveries, transport } = createRecorder();
    const manager = new WebhookManager({ db, logLevel: 'error', _testTransport: transport });

    manager.add({ url: 'https://a.com/hook', events: ['credential_expiry'] });

    manager.emit('blocked_request', { test: true });

    // Wait a tick and verify nothing was sent
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(deliveries).toHaveLength(0);
  });

  it('payload includes correct structure', async () => {
    const { deliveries, transport } = createRecorder();
    const manager = new WebhookManager({ db, logLevel: 'error', _testTransport: transport });

    manager.add({ url: 'https://a.com/hook', events: ['rate_limit_exceeded'] });

    manager.emit('rate_limit_exceeded', { service: 'github', limit: '100/min' });

    await vi.waitFor(() => expect(deliveries).toHaveLength(1));

    const payload = deliveries[0].payload;
    expect(payload.id).toBeDefined();
    expect(payload.event).toBe('rate_limit_exceeded');
    expect(payload.timestamp).toBeDefined();
    // Verify it's a valid ISO date
    expect(() => new Date(payload.timestamp)).not.toThrow();
    expect(payload.details.service).toBe('github');
    expect(payload.details.limit).toBe('100/min');
  });

  it('includes standard headers', async () => {
    const { deliveries, transport } = createRecorder();
    const manager = new WebhookManager({ db, logLevel: 'error', _testTransport: transport });

    manager.add({ url: 'https://a.com/hook', events: ['blocked_request'] });

    manager.emit('blocked_request', { test: true });

    await vi.waitFor(() => expect(deliveries).toHaveLength(1));

    const headers = deliveries[0].headers;
    expect(headers['Content-Type']).toBe('application/json');
    expect(headers['X-Aegis-Event']).toBe('blocked_request');
    expect(headers['X-Aegis-Delivery']).toBeDefined();
    expect(headers['X-Aegis-Signature']).toMatch(/^sha256=[0-9a-f]{64}$/);
    expect(headers['User-Agent']).toBe('Aegis-Webhook/1.0');
  });
});

// ─── Signature Verification ──────────────────────────────────────

describe('WebhookManager signature', () => {
  let db: Database.Database;

  beforeEach(() => {
    db = createTestDb();
  });

  afterEach(() => {
    db.close();
  });

  it('signature can be verified by recipient', async () => {
    const { deliveries, transport } = createRecorder();
    const manager = new WebhookManager({ db, logLevel: 'error', _testTransport: transport });

    const webhook = manager.add({ url: 'https://a.com/hook', events: ['blocked_request'] });

    manager.emit('blocked_request', { test: true });

    await vi.waitFor(() => expect(deliveries).toHaveLength(1));

    // Verify signature matches what a recipient would compute
    const body = JSON.stringify(deliveries[0].payload);
    const expectedSig = `sha256=${crypto.createHmac('sha256', webhook.secret).update(body).digest('hex')}`;
    expect(deliveries[0].headers['X-Aegis-Signature']).toBe(expectedSig);
  });

  it('different webhooks have different signatures for same payload', async () => {
    const { deliveries, transport } = createRecorder();
    const manager = new WebhookManager({ db, logLevel: 'error', _testTransport: transport });

    manager.add({ url: 'https://a.com/hook', events: ['blocked_request'] });
    manager.add({ url: 'https://b.com/hook', events: ['blocked_request'] });

    manager.emit('blocked_request', { test: true });

    await vi.waitFor(() => expect(deliveries).toHaveLength(2));

    // Signatures should differ because secrets differ
    expect(deliveries[0].headers['X-Aegis-Signature']).not.toBe(
      deliveries[1].headers['X-Aegis-Signature'],
    );
  });
});

// ─── Retry & Error Handling ──────────────────────────────────────

describe('WebhookManager delivery retries', () => {
  let db: Database.Database;

  beforeEach(() => {
    db = createTestDb();
  });

  afterEach(() => {
    db.close();
  });

  it('retries on non-2xx response then succeeds', async () => {
    let callCount = 0;
    const transport = async (): Promise<number> => {
      callCount++;
      // Fail first two times, succeed on third
      return callCount < 3 ? 500 : 200;
    };

    const manager = new WebhookManager({
      db,
      logLevel: 'error',
      _testTransport: transport,
      baseDelayMs: 1, // Fast retries for test
    });

    manager.add({ url: 'https://a.com/hook', events: ['blocked_request'] });
    manager.emit('blocked_request', { test: true });

    await vi.waitFor(() => expect(callCount).toBeGreaterThanOrEqual(3));
    expect(callCount).toBe(3);
  });

  it('retries on network error then succeeds', async () => {
    let callCount = 0;
    const transport = async (): Promise<number> => {
      callCount++;
      if (callCount < 2) throw new Error('Connection refused');
      return 200;
    };

    const manager = new WebhookManager({
      db,
      logLevel: 'error',
      _testTransport: transport,
      baseDelayMs: 1,
    });

    manager.add({ url: 'https://a.com/hook', events: ['blocked_request'] });
    manager.emit('blocked_request', { test: true });

    await vi.waitFor(() => expect(callCount).toBeGreaterThanOrEqual(2));
    expect(callCount).toBe(2);
  });

  it('stops after maxRetries exhausted', async () => {
    let callCount = 0;
    const transport = async (): Promise<number> => {
      callCount++;
      return 500;
    };

    const manager = new WebhookManager({
      db,
      logLevel: 'error',
      _testTransport: transport,
      maxRetries: 2,
      baseDelayMs: 1,
    });

    manager.add({ url: 'https://a.com/hook', events: ['blocked_request'] });
    manager.emit('blocked_request', { test: true });

    // 1 initial + 2 retries = 3 total
    await vi.waitFor(() => expect(callCount).toBeGreaterThanOrEqual(3));

    // Wait a beat to confirm no more calls
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(callCount).toBe(3);
  });

  it('emit never throws even if all retries fail', async () => {
    const transport = async (): Promise<number> => {
      throw new Error('Network error');
    };

    const manager = new WebhookManager({
      db,
      logLevel: 'error',
      _testTransport: transport,
      maxRetries: 0,
      baseDelayMs: 1,
    });

    manager.add({ url: 'https://a.com/hook', events: ['blocked_request'] });

    // emit() should not throw
    expect(() => manager.emit('blocked_request', { test: true })).not.toThrow();

    // Give promises time to settle
    await new Promise((resolve) => setTimeout(resolve, 100));
  });
});

// ─── Credential Expiry Checking ──────────────────────────────────

describe('WebhookManager checkExpiringCredentials', () => {
  let db: Database.Database;

  beforeEach(() => {
    db = createTestDb();
  });

  afterEach(() => {
    db.close();
  });

  it('detects expired credentials', async () => {
    const { deliveries, transport } = createRecorder();
    const manager = new WebhookManager({ db, logLevel: 'error', _testTransport: transport });
    const vault = new Vault(db, 'test-master-key', 'deadbeef');

    // Add a credential
    vault.add({
      name: 'expired-key',
      service: 'github',
      secret: 'ghp_test123',
      authType: 'bearer',
      domains: ['api.github.com'],
      scopes: ['*'],
      bodyInspection: 'off',
    });

    // Manually set expires_at to the past
    db.prepare("UPDATE credentials SET expires_at = datetime('now', '-1 day') WHERE name = ?").run(
      'expired-key',
    );

    // Register webhook for expiry events
    manager.add({ url: 'https://alerts.example.com/hook', events: ['credential_expiry'] });

    const alertCount = manager.checkExpiringCredentials(vault);

    expect(alertCount).toBe(1);

    await vi.waitFor(() => expect(deliveries).toHaveLength(1));
    expect(deliveries[0].payload.event).toBe('credential_expiry');
    expect(deliveries[0].payload.details.status).toBe('expired');
    expect(deliveries[0].payload.details.daysRemaining).toBe(0);
    expect(deliveries[0].payload.details.credential).toBe('expired-key');
    expect(deliveries[0].payload.details.service).toBe('github');
  });

  it('detects credentials expiring soon', async () => {
    const { deliveries, transport } = createRecorder();
    const manager = new WebhookManager({ db, logLevel: 'error', _testTransport: transport });
    const vault = new Vault(db, 'test-master-key', 'deadbeef');

    vault.add({
      name: 'expiring-key',
      service: 'slack',
      secret: 'xoxb-test',
      authType: 'bearer',
      domains: ['api.slack.com'],
      scopes: ['*'],
      bodyInspection: 'off',
    });

    // Set to expire in 3 days
    db.prepare("UPDATE credentials SET expires_at = datetime('now', '+3 days') WHERE name = ?").run(
      'expiring-key',
    );

    manager.add({ url: 'https://alerts.example.com/hook', events: ['credential_expiry'] });

    const alertCount = manager.checkExpiringCredentials(vault, 7);

    expect(alertCount).toBe(1);

    await vi.waitFor(() => expect(deliveries).toHaveLength(1));
    expect(deliveries[0].payload.details.status).toBe('expiring_soon');
    expect(deliveries[0].payload.details.daysRemaining).toBeGreaterThan(0);
    expect(deliveries[0].payload.details.daysRemaining).toBeLessThanOrEqual(3);
  });

  it('ignores credentials without expiry', async () => {
    const { deliveries, transport } = createRecorder();
    const manager = new WebhookManager({ db, logLevel: 'error', _testTransport: transport });
    const vault = new Vault(db, 'test-master-key', 'deadbeef');

    vault.add({
      name: 'no-expiry-key',
      service: 'stripe',
      secret: 'sk_test_123',
      authType: 'bearer',
      domains: ['api.stripe.com'],
      scopes: ['*'],
      bodyInspection: 'off',
    });

    manager.add({ url: 'https://alerts.example.com/hook', events: ['credential_expiry'] });

    const alertCount = manager.checkExpiringCredentials(vault);

    expect(alertCount).toBe(0);

    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(deliveries).toHaveLength(0);
  });

  it('ignores credentials expiring beyond threshold', async () => {
    const { deliveries, transport } = createRecorder();
    const manager = new WebhookManager({ db, logLevel: 'error', _testTransport: transport });
    const vault = new Vault(db, 'test-master-key', 'deadbeef');

    vault.add({
      name: 'future-key',
      service: 'openai',
      secret: 'sk-test',
      authType: 'bearer',
      domains: ['api.openai.com'],
      scopes: ['*'],
      bodyInspection: 'off',
    });

    // Set to expire in 30 days — well beyond default 7-day threshold
    db.prepare(
      "UPDATE credentials SET expires_at = datetime('now', '+30 days') WHERE name = ?",
    ).run('future-key');

    manager.add({ url: 'https://alerts.example.com/hook', events: ['credential_expiry'] });

    const alertCount = manager.checkExpiringCredentials(vault, 7);

    expect(alertCount).toBe(0);

    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(deliveries).toHaveLength(0);
  });

  it('returns correct count for mixed credentials', async () => {
    const { deliveries, transport } = createRecorder();
    const manager = new WebhookManager({ db, logLevel: 'error', _testTransport: transport });
    const vault = new Vault(db, 'test-master-key', 'deadbeef');

    // One expired
    vault.add({
      name: 'expired-key',
      service: 's1',
      secret: 'aaa',
      authType: 'bearer',
      domains: ['a.com'],
      scopes: ['*'],
      bodyInspection: 'off',
    });
    db.prepare("UPDATE credentials SET expires_at = datetime('now', '-2 days') WHERE name = ?").run(
      'expired-key',
    );

    // One expiring soon
    vault.add({
      name: 'expiring-key',
      service: 's2',
      secret: 'bbb',
      authType: 'bearer',
      domains: ['b.com'],
      scopes: ['*'],
      bodyInspection: 'off',
    });
    db.prepare("UPDATE credentials SET expires_at = datetime('now', '+2 days') WHERE name = ?").run(
      'expiring-key',
    );

    // One far out
    vault.add({
      name: 'safe-key',
      service: 's3',
      secret: 'ccc',
      authType: 'bearer',
      domains: ['c.com'],
      scopes: ['*'],
      bodyInspection: 'off',
    });
    db.prepare(
      "UPDATE credentials SET expires_at = datetime('now', '+60 days') WHERE name = ?",
    ).run('safe-key');

    // One without expiry
    vault.add({
      name: 'eternal-key',
      service: 's4',
      secret: 'ddd',
      authType: 'bearer',
      domains: ['d.com'],
      scopes: ['*'],
      bodyInspection: 'off',
    });

    manager.add({ url: 'https://alerts.example.com/hook', events: ['credential_expiry'] });

    const alertCount = manager.checkExpiringCredentials(vault, 7);
    expect(alertCount).toBe(2); // expired + expiring_soon

    await vi.waitFor(() => expect(deliveries).toHaveLength(2));
  });
});

// ─── Gate Webhook Integration ────────────────────────────────────

describe('Gate + WebhookManager integration', () => {
  let db: Database.Database;
  let upstream: http.Server;
  let upstreamPort: number;

  beforeEach(async () => {
    db = createTestDb();
    upstream = http.createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
    });
    await new Promise<void>((resolve) => {
      upstream.listen(0, () => {
        const addr = upstream.address();
        if (addr && typeof addr === 'object') upstreamPort = addr.port;
        resolve();
      });
    });
  });

  afterEach(async () => {
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
    db.close();
  });

  function gateRequest(
    port: number,
    path: string,
    options: { method?: string; headers?: Record<string, string> } = {},
  ): Promise<{ status: number; body: string }> {
    return new Promise((resolve, reject) => {
      const req = http.request(
        {
          hostname: 'localhost',
          port,
          path,
          method: options.method ?? 'GET',
          headers: options.headers,
        },
        (res) => {
          let body = '';
          res.on('data', (chunk: Buffer) => {
            body += chunk.toString();
          });
          res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
        },
      );
      req.on('error', reject);
      req.end();
    });
  }

  it('emits blocked_request webhook on missing credential', async () => {
    const { deliveries, transport } = createRecorder();
    const vault = new Vault(db, 'test-master-key', 'deadbeef');
    const ledger = new Ledger(db);
    const webhookManager = new WebhookManager({
      db,
      logLevel: 'error',
      _testTransport: transport,
    });

    webhookManager.add({ url: 'https://hooks.example.com/alert', events: ['blocked_request'] });

    const gate = new Gate({
      port: 0,
      vault,
      ledger,
      logLevel: 'error',
      webhooks: webhookManager,
    });

    await gate.start();
    const gatePort = gate.listeningPort;

    // Request a service with no credential
    await gateRequest(gatePort, '/nonexistent/api/test');

    await vi.waitFor(() => expect(deliveries).toHaveLength(1));

    expect(deliveries[0].payload.event).toBe('blocked_request');
    expect(deliveries[0].payload.details.reason).toBe('no_credential');
    expect(deliveries[0].payload.details.service).toBe('nonexistent');

    await gate.stop();
  });

  it('emits agent_auth_failure webhook when agent header missing', async () => {
    const { deliveries, transport } = createRecorder();
    const vault = new Vault(db, 'test-master-key', 'deadbeef');
    const ledger = new Ledger(db);
    const key = deriveKey('test-master-key', 'deadbeef');
    const agentRegistry = new AgentRegistry(db, key);
    const webhookManager = new WebhookManager({
      db,
      logLevel: 'error',
      _testTransport: transport,
    });

    webhookManager.add({
      url: 'https://hooks.example.com/alert',
      events: ['agent_auth_failure'],
    });

    const gate = new Gate({
      port: 0,
      vault,
      ledger,
      logLevel: 'error',
      requireAgentAuth: true,
      agentRegistry,
      webhooks: webhookManager,
    });

    await gate.start();
    const gatePort = gate.listeningPort;

    await gateRequest(gatePort, '/some-service/api/test');

    await vi.waitFor(() => expect(deliveries).toHaveLength(1));

    expect(deliveries[0].payload.event).toBe('agent_auth_failure');
    expect(deliveries[0].payload.details.reason).toBe('Missing X-Aegis-Agent header');

    await gate.stop();
  });

  it('emits body_inspection webhook on credential leak detection', async () => {
    const { deliveries, transport } = createRecorder();
    const vault = new Vault(db, 'test-master-key', 'deadbeef');
    const ledger = new Ledger(db);
    const webhookManager = new WebhookManager({
      db,
      logLevel: 'error',
      _testTransport: transport,
    });

    // Add a credential with body inspection = block
    vault.add({
      name: 'test-key',
      service: 'test-svc',
      secret: 'sk_live_1234567890abcdefghijklmnop',
      authType: 'bearer',
      domains: [`localhost:${upstreamPort}`],
      scopes: ['*'],
      bodyInspection: 'block',
    });

    webhookManager.add({ url: 'https://hooks.example.com/alert', events: ['body_inspection'] });

    const gate = new Gate({
      port: 0,
      vault,
      ledger,
      logLevel: 'error',
      webhooks: webhookManager,
    });

    await gate.start();
    const gatePort = gate.listeningPort;

    // Send request with credential-like content in body
    const body = JSON.stringify({ key: 'sk_live_1234567890abcdefghijklmnop' });
    await new Promise<void>((resolve, reject) => {
      const req = http.request(
        {
          hostname: 'localhost',
          port: gatePort,
          path: '/test-svc/api/data',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body),
            'X-Target-Host': `localhost:${upstreamPort}`,
          },
        },
        (res) => {
          res.resume();
          res.on('end', resolve);
        },
      );
      req.on('error', reject);
      req.write(body);
      req.end();
    });

    await vi.waitFor(() => expect(deliveries).toHaveLength(1), { timeout: 5000 });

    expect(deliveries[0].payload.event).toBe('body_inspection');

    await gate.stop();
  });

  it('does not emit webhooks for allowed requests', async () => {
    const { deliveries, transport } = createRecorder();
    const vault = new Vault(db, 'test-master-key', 'deadbeef');
    const ledger = new Ledger(db);
    const webhookManager = new WebhookManager({
      db,
      logLevel: 'error',
      _testTransport: transport,
    });

    vault.add({
      name: 'test-key',
      service: 'test-svc',
      secret: 'test-secret',
      authType: 'bearer',
      domains: [`localhost:${upstreamPort}`],
      scopes: ['*'],
      bodyInspection: 'off',
    });

    webhookManager.add({
      url: 'https://hooks.example.com/alert',
      events: ['blocked_request', 'credential_expiry', 'rate_limit_exceeded'],
    });

    const gate = new Gate({
      port: 0,
      vault,
      ledger,
      logLevel: 'error',
      webhooks: webhookManager,
    });

    await gate.start();
    const gatePort = gate.listeningPort;

    await gateRequest(gatePort, '/test-svc/api/data', {
      headers: { 'X-Target-Host': `localhost:${upstreamPort}` },
    });

    // Wait and confirm nothing was emitted
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(deliveries).toHaveLength(0);

    await gate.stop();
  });
});
