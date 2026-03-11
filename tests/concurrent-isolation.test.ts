/**
 * Concurrent Credential Isolation Test (Phase 8.1)
 *
 * Verifies that under concurrent load, credential A never leaks into request B's
 * headers. This is Aegis's core security promise: even when many requests fly
 * through Gate simultaneously, each request gets exactly the credential that
 * belongs to its service/agent — no cross-contamination.
 *
 * Strategy:
 *   - Create N credentials with distinct secrets and auth types
 *   - Create N agents, each granted exactly one credential
 *   - Fire all N requests concurrently through Gate (with agent auth)
 *   - Assert every upstream request received exactly the correct credential
 *   - Repeat with higher concurrency to stress the isolation boundary
 */

import * as http from 'node:http';
import Database from 'better-sqlite3-multiple-ciphers';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AgentRegistry } from '../src/agent/index.js';
import { migrate } from '../src/db.js';
import { Gate } from '../src/gate/index.js';
import { Ledger } from '../src/ledger/index.js';
import { deriveKey, Vault } from '../src/vault/index.js';

// ─── Test Helper: Upstream Recorder ─────────────────────────────────────────
// Records every request that arrives at the upstream, including the
// Authorization header so we can verify credential isolation.

interface RecordedRequest {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

class UpstreamRecorder {
  server: http.Server;
  requests: RecordedRequest[] = [];
  port = 0;

  constructor() {
    this.server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (chunk: Buffer) => {
        body += chunk.toString();
      });
      req.on('end', () => {
        this.requests.push({
          method: req.method ?? 'GET',
          url: req.url ?? '/',
          headers: req.headers,
          body,
        });
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{"ok":true}');
      });
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

  /** Find all upstream requests whose URL starts with the given service path */
  forService(service: string): RecordedRequest[] {
    return this.requests.filter((r) => r.url?.startsWith(`/${service}/`));
  }
}

// ─── Test Helper: Make a request to Gate ─────────────────────────────────────

function gateRequest(
  port: number,
  path: string,
  options: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
  } = {},
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
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
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body,
          });
        });
      },
    );

    req.on('error', reject);

    if (options.body) {
      req.write(options.body);
    }
    req.end();
  });
}

// ─── Concurrent Credential Isolation Tests ───────────────────────────────────

describe('concurrent credential isolation', () => {
  const masterKey = 'test-master-key-concurrent';
  const salt = 'test-salt-concurrent';
  let db: ReturnType<typeof Database>;
  let vault: Vault;
  let ledger: Ledger;
  let agentRegistry: AgentRegistry;
  let upstream: UpstreamRecorder;
  let gate: Gate;
  let gatePort: number;

  beforeEach(async () => {
    db = new Database(':memory:');
    db.pragma('journal_mode = WAL');
    migrate(db);

    vault = new Vault(db, masterKey, salt);
    ledger = new Ledger(db);
    agentRegistry = new AgentRegistry(db, deriveKey(masterKey, salt));

    upstream = new UpstreamRecorder();
    await upstream.start();

    gate = new Gate({
      port: 0,
      vault,
      ledger,
      logLevel: 'error',
      agentRegistry,
      requireAgentAuth: true,
      _testUpstream: {
        protocol: 'http',
        hostname: 'localhost',
        port: upstream.port,
      },
    });
    await gate.start();
    gatePort = gate.listeningPort;
  });

  afterEach(async () => {
    await gate.stop();
    await upstream.stop();
    db.close();
  });

  /**
   * Helper: set up N credentials with unique secrets and N agents,
   * each granted exactly one credential. Returns the mapping needed
   * to fire concurrent requests and verify isolation.
   */
  function setupCredentialsAndAgents(count: number): Array<{
    service: string;
    secret: string;
    authType: 'bearer' | 'header';
    headerName?: string;
    agentName: string;
    agentToken: string;
  }> {
    const entries: Array<{
      service: string;
      secret: string;
      authType: 'bearer' | 'header';
      headerName?: string;
      agentName: string;
      agentToken: string;
    }> = [];

    for (let i = 0; i < count; i++) {
      const service = `svc-${i}`;
      const secret = `secret-${i}-${crypto.randomUUID()}`;
      // Alternate between bearer and header auth to test both injection paths
      const authType = i % 2 === 0 ? 'bearer' : 'header';
      const headerName = authType === 'header' ? `x-api-key-${i}` : undefined;
      const credName = `cred-${i}`;
      const agentName = `agent-${i}`;

      vault.add({
        name: credName,
        service,
        secret,
        authType,
        headerName,
        domains: [`${service}.example.com`],
      });

      const { token } = agentRegistry.add({ name: agentName });
      const credential = vault.list().find((c) => c.name === credName);
      if (credential) {
        agentRegistry.grant({ agentName, credentialId: credential.id });
      }

      entries.push({ service, secret, authType, headerName, agentName, agentToken: token });
    }

    return entries;
  }

  /**
   * Core assertion: for every entry, verify the upstream received exactly
   * the correct credential — and no other credential's secret appears
   * in any request's headers.
   */
  function assertIsolation(
    entries: Array<{
      service: string;
      secret: string;
      authType: 'bearer' | 'header';
      headerName?: string;
    }>,
  ): void {
    // Collect ALL secrets for cross-contamination check
    const allSecrets = entries.map((e) => e.secret);

    for (const entry of entries) {
      const upstreamReqs = upstream.forService(entry.service);
      expect(upstreamReqs.length).toBeGreaterThanOrEqual(1);

      for (const req of upstreamReqs) {
        if (entry.authType === 'bearer') {
          // Bearer: secret must appear in Authorization header
          expect(req.headers.authorization).toBe(`Bearer ${entry.secret}`);
        } else if (entry.authType === 'header') {
          // Header: secret must appear in the custom header
          const key = entry.headerName ?? 'x-api-key';
          expect(req.headers[key]).toBe(entry.secret);
        }

        // Cross-contamination check: no OTHER credential's secret should
        // appear anywhere in this request's headers
        const headerDump = JSON.stringify(req.headers);
        for (const otherSecret of allSecrets) {
          if (otherSecret === entry.secret) continue;
          expect(headerDump).not.toContain(otherSecret);
        }
      }
    }
  }

  // ─── Tests ──────────────────────────────────────────────────────────────

  it('isolates 5 concurrent requests with different credentials', async () => {
    const entries = setupCredentialsAndAgents(5);

    // Fire all 5 requests concurrently
    // Path format: /{service}/{service}/data — Gate strips the first segment,
    // so the upstream sees /{service}/data, which forService() can filter on.
    const results = await Promise.all(
      entries.map((e) =>
        gateRequest(gatePort, `/${e.service}/${e.service}/data`, {
          headers: { 'X-Aegis-Agent': e.agentToken },
        }),
      ),
    );

    // All should succeed
    for (const res of results) {
      expect(res.status).toBe(200);
    }

    // Verify isolation
    assertIsolation(entries);
  });

  it('isolates 20 concurrent requests with different credentials', async () => {
    const entries = setupCredentialsAndAgents(20);

    const results = await Promise.all(
      entries.map((e) =>
        gateRequest(gatePort, `/${e.service}/${e.service}/data`, {
          headers: { 'X-Aegis-Agent': e.agentToken },
        }),
      ),
    );

    for (const res of results) {
      expect(res.status).toBe(200);
    }

    assertIsolation(entries);
  });

  it('isolates 50 concurrent requests with different credentials', async () => {
    const entries = setupCredentialsAndAgents(50);

    const results = await Promise.all(
      entries.map((e) =>
        gateRequest(gatePort, `/${e.service}/${e.service}/data`, {
          headers: { 'X-Aegis-Agent': e.agentToken },
        }),
      ),
    );

    for (const res of results) {
      expect(res.status).toBe(200);
    }

    assertIsolation(entries);
  });

  it('isolates when multiple agents hit the SAME service concurrently', async () => {
    // One credential, multiple agents all granted access — concurrent
    // requests should all get the same credential, none should leak
    // a different one.
    const service = 'shared-api';
    const secret = `shared-secret-${crypto.randomUUID()}`;

    vault.add({
      name: 'shared-cred',
      service,
      secret,
      authType: 'bearer',
      domains: ['shared-api.example.com'],
    });

    const credential = vault.list().find((c) => c.name === 'shared-cred');
    const agents: Array<{ name: string; token: string }> = [];

    for (let i = 0; i < 10; i++) {
      const name = `shared-agent-${i}`;
      const { token } = agentRegistry.add({ name });
      if (credential) {
        agentRegistry.grant({ agentName: name, credentialId: credential.id });
      }
      agents.push({ name, token });
    }

    // Fire 10 concurrent requests from different agents to the same service
    const results = await Promise.all(
      agents.map((a) =>
        gateRequest(gatePort, `/${service}/${service}/data`, {
          headers: { 'X-Aegis-Agent': a.token },
        }),
      ),
    );

    for (const res of results) {
      expect(res.status).toBe(200);
    }

    // All upstream requests should have the same, correct credential
    const upstreamReqs = upstream.forService(service);
    expect(upstreamReqs).toHaveLength(10);

    for (const req of upstreamReqs) {
      expect(req.headers.authorization).toBe(`Bearer ${secret}`);
    }
  });

  it('isolates under repeated burst load (3 waves of 20 requests)', async () => {
    const entries = setupCredentialsAndAgents(20);

    // Fire 3 waves sequentially, each wave is 20 concurrent requests
    for (let wave = 0; wave < 3; wave++) {
      const results = await Promise.all(
        entries.map((e) =>
          gateRequest(gatePort, `/${e.service}/${e.service}/wave-${wave}`, {
            headers: { 'X-Aegis-Agent': e.agentToken },
          }),
        ),
      );

      for (const res of results) {
        expect(res.status).toBe(200);
      }
    }

    // Total: 60 upstream requests, each service should have 3
    expect(upstream.requests).toHaveLength(60);

    // Verify isolation across all 60 requests
    assertIsolation(entries);
  });

  it('prevents cross-contamination with mixed auth types under load', async () => {
    // Set up credentials with all 4 auth types
    const configs: Array<{
      name: string;
      service: string;
      secret: string;
      authType: 'bearer' | 'header' | 'basic' | 'query';
      headerName?: string;
    }> = [
      {
        name: 'c-bearer',
        service: 'svc-bearer',
        secret: `bearer-${crypto.randomUUID()}`,
        authType: 'bearer',
      },
      {
        name: 'c-header',
        service: 'svc-header',
        secret: `header-${crypto.randomUUID()}`,
        authType: 'header',
        headerName: 'x-custom-key',
      },
      {
        name: 'c-basic',
        service: 'svc-basic',
        secret: `basic-${crypto.randomUUID()}`,
        authType: 'basic',
      },
      {
        name: 'c-query',
        service: 'svc-query',
        secret: `query-${crypto.randomUUID()}`,
        authType: 'query',
        headerName: 'api_key',
      },
    ];

    const agentTokens: string[] = [];

    for (const cfg of configs) {
      vault.add({
        name: cfg.name,
        service: cfg.service,
        secret: cfg.secret,
        authType: cfg.authType,
        headerName: cfg.headerName,
        domains: [`${cfg.service}.example.com`],
      });

      const agentName = `agent-${cfg.authType}`;
      const { token } = agentRegistry.add({ name: agentName });
      const credential = vault.list().find((c) => c.name === cfg.name);
      if (credential) {
        agentRegistry.grant({ agentName, credentialId: credential.id });
      }
      agentTokens.push(token);
    }

    // Fire 10 waves of all 4 auth types concurrently (40 total requests)
    for (let wave = 0; wave < 10; wave++) {
      const results = await Promise.all(
        configs.map((cfg, idx) =>
          gateRequest(gatePort, `/${cfg.service}/${cfg.service}/data?wave=${wave}`, {
            headers: { 'X-Aegis-Agent': agentTokens[idx] },
          }),
        ),
      );

      for (const res of results) {
        expect(res.status).toBe(200);
      }
    }

    expect(upstream.requests).toHaveLength(40);

    // Collect all secrets for cross-contamination check
    const allSecrets = configs.map((c) => c.secret);

    // Verify each auth type got the correct injection
    for (const cfg of configs) {
      const reqs = upstream.forService(cfg.service);
      expect(reqs).toHaveLength(10);

      for (const req of reqs) {
        const headerDump = JSON.stringify(req.headers);

        switch (cfg.authType) {
          case 'bearer':
            expect(req.headers.authorization).toBe(`Bearer ${cfg.secret}`);
            break;
          case 'header':
            expect(req.headers[cfg.headerName ?? 'x-api-key']).toBe(cfg.secret);
            break;
          case 'basic':
            expect(req.headers.authorization).toBe(
              `Basic ${Buffer.from(cfg.secret).toString('base64')}`,
            );
            break;
          case 'query':
            // Query auth doesn't inject into headers — it appends to URL
            // The secret should NOT be in any header
            expect(headerDump).not.toContain(cfg.secret);
            // The URL should contain the query parameter
            expect(req.url).toContain(`api_key=${encodeURIComponent(cfg.secret)}`);
            break;
        }

        // Cross-contamination: no other secret in this request's headers or URL
        for (const otherSecret of allSecrets) {
          if (otherSecret === cfg.secret) continue;
          expect(headerDump).not.toContain(otherSecret);
          if (cfg.authType !== 'query') {
            // For non-query types, other secrets shouldn't be in the URL either
            expect(req.url ?? '').not.toContain(otherSecret);
          }
        }
      }
    }
  });

  it('maintains isolation when some concurrent requests are blocked', async () => {
    // Set up 3 credentials + 3 agents, but only grant 2 of them.
    // The 3rd agent should be blocked while the other 2 succeed —
    // the blocked request should not interfere with the others.
    const secrets = [
      `secret-a-${crypto.randomUUID()}`,
      `secret-b-${crypto.randomUUID()}`,
      `secret-c-${crypto.randomUUID()}`,
    ];

    vault.add({
      name: 'cred-a',
      service: 'svc-a',
      secret: secrets[0],
      authType: 'bearer',
      domains: ['svc-a.example.com'],
    });
    vault.add({
      name: 'cred-b',
      service: 'svc-b',
      secret: secrets[1],
      authType: 'header',
      headerName: 'x-api-key',
      domains: ['svc-b.example.com'],
    });
    vault.add({
      name: 'cred-c',
      service: 'svc-c',
      secret: secrets[2],
      authType: 'bearer',
      domains: ['svc-c.example.com'],
    });

    const credA = vault.list().find((c) => c.name === 'cred-a');
    const credB = vault.list().find((c) => c.name === 'cred-b');
    // cred-c is NOT granted to agent-c

    const { token: tokenA } = agentRegistry.add({ name: 'agent-a' });
    const { token: tokenB } = agentRegistry.add({ name: 'agent-b' });
    const { token: tokenC } = agentRegistry.add({ name: 'agent-c' });

    if (credA) agentRegistry.grant({ agentName: 'agent-a', credentialId: credA.id });
    if (credB) agentRegistry.grant({ agentName: 'agent-b', credentialId: credB.id });
    // agent-c gets NO grants

    // Fire all 3 concurrently
    const [resA, resB, resC] = await Promise.all([
      gateRequest(gatePort, '/svc-a/svc-a/data', {
        headers: { 'X-Aegis-Agent': tokenA },
      }),
      gateRequest(gatePort, '/svc-b/svc-b/data', {
        headers: { 'X-Aegis-Agent': tokenB },
      }),
      gateRequest(gatePort, '/svc-c/svc-c/data', {
        headers: { 'X-Aegis-Agent': tokenC },
      }),
    ]);

    // A and B succeed, C is blocked (no grant)
    expect(resA.status).toBe(200);
    expect(resB.status).toBe(200);
    expect(resC.status).toBe(403);

    // Only 2 requests reach upstream
    expect(upstream.requests).toHaveLength(2);

    // Verify correct credentials on the 2 that made it through
    const reqA = upstream.forService('svc-a');
    expect(reqA).toHaveLength(1);
    expect(reqA[0].headers.authorization).toBe(`Bearer ${secrets[0]}`);

    const reqB = upstream.forService('svc-b');
    expect(reqB).toHaveLength(1);
    expect(reqB[0].headers['x-api-key']).toBe(secrets[1]);

    // No upstream request for svc-c
    const reqC = upstream.forService('svc-c');
    expect(reqC).toHaveLength(0);

    // Cross-contamination check on the 2 upstream requests
    const allHeaders = upstream.requests.map((r) => JSON.stringify(r.headers));
    for (const headerDump of allHeaders) {
      // secret-c should never appear anywhere
      expect(headerDump).not.toContain(secrets[2]);
    }
  });

  it('isolates 100 concurrent requests without credential leaks', async () => {
    const entries = setupCredentialsAndAgents(100);

    const results = await Promise.all(
      entries.map((e) =>
        gateRequest(gatePort, `/${e.service}/${e.service}/data`, {
          headers: { 'X-Aegis-Agent': e.agentToken },
        }),
      ),
    );

    for (const res of results) {
      expect(res.status).toBe(200);
    }

    expect(upstream.requests).toHaveLength(100);
    assertIsolation(entries);
  });
});
