import * as http from 'node:http';
import Database from 'better-sqlite3';
import { Registry } from 'prom-client';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { migrate } from '../src/db.js';
import { Gate } from '../src/gate/index.js';
import { Ledger } from '../src/ledger/index.js';
import { AegisMetrics } from '../src/metrics/index.js';
import { Vault } from '../src/vault/index.js';

// ─── Test Helper: Upstream Recorder ──────────────────────────────

class UpstreamRecorder {
  server: http.Server;
  port = 0;

  constructor() {
    this.server = http.createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
    });
  }

  start(): Promise<void> {
    return new Promise((resolve) => {
      this.server.listen(0, () => {
        const addr = this.server.address();
        if (addr && typeof addr === 'object') {
          this.port = addr.port;
        }
        resolve();
      });
    });
  }

  stop(): Promise<void> {
    return new Promise((resolve) => {
      this.server.close(() => resolve());
    });
  }
}

function gateRequest(
  port: number,
  path: string,
  options: {
    method?: string;
    headers?: Record<string, string>;
  } = {},
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: 'localhost',
        port,
        path,
        method: options.method ?? 'GET',
        headers: options.headers ?? {},
      },
      (res) => {
        let body = '';
        res.on('data', (chunk: Buffer) => {
          body += chunk.toString();
        });
        res.on('end', () => {
          resolve({ status: res.statusCode ?? 0, body });
        });
      },
    );
    req.on('error', reject);
    req.end();
  });
}

// ─── Unit tests: AegisMetrics class ──────────────────────────────

describe('AegisMetrics', () => {
  let registry: Registry;
  let metrics: AegisMetrics;

  beforeEach(() => {
    registry = new Registry();
    metrics = new AegisMetrics({ registry });
  });

  // ── Counter: aegis_requests_total ────────────────────────────

  describe('aegis_requests_total', () => {
    it('starts at zero', async () => {
      const output = await metrics.getMetricsOutput();
      // Counter only appears once inc'd, or check for 0
      expect(output).toContain('aegis_requests_total');
    });

    it('increments on recordRequest', async () => {
      metrics.recordRequest('slack', 'GET', 200, 'agent-1');
      const output = await metrics.getMetricsOutput();
      expect(output).toContain(
        'aegis_requests_total{service="slack",method="GET",status="200",agent="agent-1"} 1',
      );
    });

    it('increments multiple times', async () => {
      metrics.recordRequest('slack', 'GET', 200, 'agent-1');
      metrics.recordRequest('slack', 'GET', 200, 'agent-1');
      metrics.recordRequest('slack', 'POST', 201, 'agent-1');
      const output = await metrics.getMetricsOutput();
      expect(output).toContain(
        'aegis_requests_total{service="slack",method="GET",status="200",agent="agent-1"} 2',
      );
      expect(output).toContain(
        'aegis_requests_total{service="slack",method="POST",status="201",agent="agent-1"} 1',
      );
    });

    it('tracks different services separately', async () => {
      metrics.recordRequest('slack', 'GET', 200);
      metrics.recordRequest('github', 'GET', 200);
      const output = await metrics.getMetricsOutput();
      expect(output).toContain('service="slack"');
      expect(output).toContain('service="github"');
    });

    it('uses empty string for missing agent', async () => {
      metrics.recordRequest('slack', 'GET', 200);
      const output = await metrics.getMetricsOutput();
      expect(output).toContain('agent=""');
    });
  });

  // ── Counter: aegis_requests_blocked_total ─────────────────────

  describe('aegis_requests_blocked_total', () => {
    it('increments on recordBlocked', async () => {
      metrics.recordBlocked('slack', 'domain_guard', 'agent-1');
      const output = await metrics.getMetricsOutput();
      expect(output).toContain(
        'aegis_requests_blocked_total{service="slack",reason="domain_guard",agent="agent-1"} 1',
      );
    });

    it('tracks different reasons', async () => {
      metrics.recordBlocked('slack', 'domain_guard');
      metrics.recordBlocked('slack', 'no_credential');
      metrics.recordBlocked('slack', 'agent_auth_missing');
      metrics.recordBlocked('slack', 'credential_expired');
      metrics.recordBlocked('slack', 'agent_scope');
      metrics.recordBlocked('slack', 'policy_violation');
      metrics.recordBlocked('slack', 'agent_rate_limit');
      metrics.recordBlocked('slack', 'credential_rate_limit');
      metrics.recordBlocked('slack', 'body_inspection');
      metrics.recordBlocked('slack', 'agent_auth_invalid');
      const output = await metrics.getMetricsOutput();
      expect(output).toContain('reason="domain_guard"');
      expect(output).toContain('reason="no_credential"');
      expect(output).toContain('reason="agent_auth_missing"');
      expect(output).toContain('reason="credential_expired"');
      expect(output).toContain('reason="agent_scope"');
      expect(output).toContain('reason="policy_violation"');
      expect(output).toContain('reason="agent_rate_limit"');
      expect(output).toContain('reason="credential_rate_limit"');
      expect(output).toContain('reason="body_inspection"');
      expect(output).toContain('reason="agent_auth_invalid"');
    });
  });

  // ── Histogram: aegis_request_duration_seconds ─────────────────

  describe('aegis_request_duration_seconds', () => {
    it('records duration via startRequestTimer', async () => {
      const stop = metrics.startRequestTimer('slack');
      // Simulate some work
      stop();
      const output = await metrics.getMetricsOutput();
      expect(output).toContain('aegis_request_duration_seconds');
      expect(output).toContain('service="slack"');
      // Should have bucket entries
      expect(output).toContain('aegis_request_duration_seconds_bucket');
      expect(output).toContain('aegis_request_duration_seconds_count');
      expect(output).toContain('aegis_request_duration_seconds_sum');
    });
  });

  // ── Gauge: aegis_credentials_total ────────────────────────────

  describe('aegis_credentials_total', () => {
    it('reports credential inventory from vault', async () => {
      const db = new Database(':memory:');
      migrate(db);
      const vault = new Vault(db, 'test-master-key', 'aa'.repeat(32));

      // Add an active credential
      vault.add({
        name: 'active-cred',
        service: 'slack',
        secret: 'sk-test',
        authType: 'bearer',
        domains: ['api.slack.com'],
      });

      // Add a credential and then expire it by setting expires_at in the past
      vault.add({
        name: 'expired-cred',
        service: 'old-api',
        secret: 'sk-old',
        authType: 'bearer',
        domains: ['api.old.com'],
      });
      db.prepare(
        "UPDATE credentials SET expires_at = '2020-01-01T00:00:00.000Z' WHERE name = 'expired-cred'",
      ).run();

      const vaultMetrics = new AegisMetrics({ registry: new Registry(), vault });
      const output = await vaultMetrics.getMetricsOutput();

      expect(output).toContain('aegis_credentials_total{status="active"}');
      expect(output).toContain('aegis_credentials_total{status="expired"}');
      expect(output).toContain('aegis_credentials_total{status="expiring_soon"}');
    });

    it('works without vault (no credential gauges)', async () => {
      const output = await metrics.getMetricsOutput();
      // Should not crash, just won't have credential gauge data
      expect(output).toContain('aegis_credentials_total');
    });
  });

  // ── getMetricsOutput / getContentType ─────────────────────────

  describe('output format', () => {
    it('returns Prometheus text format', async () => {
      metrics.recordRequest('test', 'GET', 200);
      const output = await metrics.getMetricsOutput();
      // Prometheus text format starts with # HELP
      expect(output).toContain('# HELP aegis_requests_total');
      expect(output).toContain('# TYPE aegis_requests_total counter');
    });

    it('returns correct content type', () => {
      const contentType = metrics.getContentType();
      expect(contentType).toContain('text/plain');
    });
  });

  // ── reset ─────────────────────────────────────────────────────

  describe('reset', () => {
    it('clears all metrics', async () => {
      metrics.recordRequest('slack', 'GET', 200);
      metrics.recordBlocked('slack', 'domain_guard');
      metrics.reset();

      const output = await metrics.getMetricsOutput();
      // After reset, the specific label combos should not appear
      expect(output).not.toContain('service="slack"');
    });
  });
});

// ─── Integration tests: /_aegis/metrics endpoint ─────────────────

describe('Gate /_aegis/metrics endpoint', () => {
  let db: Database.Database;
  let vault: Vault;
  let ledger: Ledger;
  let gate: Gate;
  let upstream: UpstreamRecorder;
  let metrics: AegisMetrics;

  beforeEach(async () => {
    db = new Database(':memory:');
    migrate(db);
    vault = new Vault(db, 'test-key', 'bb'.repeat(32));
    ledger = new Ledger(db);
    upstream = new UpstreamRecorder();
    await upstream.start();

    vault.add({
      name: 'test-cred',
      service: 'test-svc',
      secret: 'sk-test-secret',
      authType: 'bearer',
      domains: ['api.test.com'],
    });

    metrics = new AegisMetrics({ registry: new Registry(), vault });
    gate = new Gate({
      port: 0,
      vault,
      ledger,
      logLevel: 'error',
      metrics,
      _testUpstream: { protocol: 'http', hostname: 'localhost', port: upstream.port },
    });
    await gate.start();
  });

  afterEach(async () => {
    await gate.stop();
    await upstream.stop();
    db.close();
  });

  it('returns Prometheus metrics at /_aegis/metrics', async () => {
    const port = (gate as unknown as { port: number }).port;
    const res = await gateRequest(port, '/_aegis/metrics');
    expect(res.status).toBe(200);
    expect(res.body).toContain('# HELP aegis_requests_total');
    expect(res.body).toContain('# HELP aegis_requests_blocked_total');
    expect(res.body).toContain('# HELP aegis_request_duration_seconds');
    expect(res.body).toContain('# HELP aegis_credentials_total');
  });

  it('returns 404 when metrics not enabled', async () => {
    const noMetricsGate = new Gate({
      port: 0,
      vault,
      ledger,
      logLevel: 'error',
      _testUpstream: { protocol: 'http', hostname: 'localhost', port: upstream.port },
    });
    await noMetricsGate.start();
    const port = (noMetricsGate as unknown as { port: number }).port;
    const res = await gateRequest(port, '/_aegis/metrics');
    expect(res.status).toBe(404);
    await noMetricsGate.stop();
  });

  it('records successful request in metrics', async () => {
    const port = (gate as unknown as { port: number }).port;
    await gateRequest(port, '/test-svc/api/chat');
    const res = await gateRequest(port, '/_aegis/metrics');
    expect(res.body).toContain(
      'aegis_requests_total{service="test-svc",method="GET",status="200",agent=""} 1',
    );
  });

  it('records blocked request in metrics', async () => {
    const port = (gate as unknown as { port: number }).port;
    await gateRequest(port, '/no-such-service/api/chat');
    const res = await gateRequest(port, '/_aegis/metrics');
    expect(res.body).toContain(
      'aegis_requests_blocked_total{service="no-such-service",reason="no_credential",agent=""} 1',
    );
  });

  it('records request duration in metrics', async () => {
    const port = (gate as unknown as { port: number }).port;
    await gateRequest(port, '/test-svc/api/chat');
    const res = await gateRequest(port, '/_aegis/metrics');
    expect(res.body).toContain('aegis_request_duration_seconds_count{service="test-svc"} 1');
  });

  it('reports credential inventory', async () => {
    const port = (gate as unknown as { port: number }).port;
    const res = await gateRequest(port, '/_aegis/metrics');
    // Should report the test credential as active
    expect(res.body).toContain('aegis_credentials_total{status="active"} 1');
    expect(res.body).toContain('aegis_credentials_total{status="expired"} 0');
  });

  it('records domain guard block in metrics', async () => {
    const port = (gate as unknown as { port: number }).port;
    await gateRequest(port, '/test-svc/api/chat', {
      headers: { 'X-Target-Host': 'evil.com' },
    });
    const res = await gateRequest(port, '/_aegis/metrics');
    expect(res.body).toContain(
      'aegis_requests_blocked_total{service="test-svc",reason="domain_guard",agent=""} 1',
    );
  });
});
