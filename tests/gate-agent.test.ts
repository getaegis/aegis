import * as http from 'node:http';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AgentRegistry } from '../src/agent/index.js';
import { migrate } from '../src/db.js';
import { Gate } from '../src/gate/index.js';
import { Ledger } from '../src/ledger/index.js';
import { deriveKey, Vault } from '../src/vault/index.js';

// ─── Test Helper: Upstream Recorder ──────────────────────────────

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
  nextStatus = 200;
  nextBody = '{"ok":true}';

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
        res.writeHead(this.nextStatus, { 'content-type': 'application/json' });
        res.end(this.nextBody);
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

  get last(): RecordedRequest | undefined {
    return this.requests[this.requests.length - 1];
  }
}

// ─── Test Helper: Make a request to Gate ──────────────────────────

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

// ─── Gate Agent Integration Tests ─────────────────────────────────

describe('gate agent authentication & scoping', () => {
  const masterKey = 'test-master-key-gate-agent';
  const salt = 'test-salt-gate-agent';
  let db: ReturnType<typeof Database>;
  let vault: Vault;
  let ledger: Ledger;
  let agentRegistry: AgentRegistry;
  let derivedKeyBuf: Buffer;
  let upstream: UpstreamRecorder;
  let gate: Gate;
  let gatePort: number;

  beforeEach(async () => {
    db = new Database(':memory:');
    db.pragma('journal_mode = WAL');
    migrate(db);

    derivedKeyBuf = deriveKey(masterKey, salt);
    vault = new Vault(db, masterKey, salt);
    ledger = new Ledger(db);
    agentRegistry = new AgentRegistry(db, derivedKeyBuf);

    upstream = new UpstreamRecorder();
    await upstream.start();
  });

  afterEach(async () => {
    await gate.stop();
    await upstream.stop();
    db.close();
  });

  async function startGateWithAuth(requireAgentAuth: boolean): Promise<void> {
    gate = new Gate({
      port: 0,
      vault,
      ledger,
      logLevel: 'error',
      agentRegistry,
      requireAgentAuth,
      _testUpstream: {
        protocol: 'http',
        hostname: 'localhost',
        port: upstream.port,
      },
    });
    await gate.start();
    gatePort = gate.listeningPort;
  }

  // ─── 1. Agent Authentication Required ──────────────────────────

  describe('require agent auth', () => {
    it('returns 401 when X-Aegis-Agent header is missing', async () => {
      await startGateWithAuth(true);

      vault.add({
        name: 'test-cred',
        service: 'testapi',
        secret: 'sk-test-123',
        authType: 'bearer',
        domains: ['api.test.com'],
      });

      const res = await gateRequest(gatePort, '/testapi/v1/data');
      expect(res.status).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.error).toContain('Agent authentication required');
      expect(body.hint).toContain('X-Aegis-Agent');
    });

    it('returns 401 for invalid agent token', async () => {
      await startGateWithAuth(true);

      vault.add({
        name: 'test-cred',
        service: 'testapi',
        secret: 'sk-test-123',
        authType: 'bearer',
        domains: ['api.test.com'],
      });

      const res = await gateRequest(gatePort, '/testapi/v1/data', {
        headers: { 'x-aegis-agent': 'aegis_fake_invalid_token' },
      });
      expect(res.status).toBe(401);
      const body = JSON.parse(res.body);
      expect(body.error).toContain('Invalid agent token');
    });

    it('allows request with valid agent token and granted credential', async () => {
      await startGateWithAuth(true);

      const cred = vault.add({
        name: 'auth-cred',
        service: 'authapi',
        secret: 'sk-auth-123',
        authType: 'bearer',
        domains: ['api.auth.com'],
      });

      const agent = agentRegistry.add({ name: 'test-bot' });
      agentRegistry.grant({ agentName: 'test-bot', credentialId: cred.id });

      const res = await gateRequest(gatePort, '/authapi/v1/data', {
        headers: { 'x-aegis-agent': agent.token },
      });
      expect(res.status).toBe(200);
      expect(upstream.last).toBeDefined();
    });

    it('health endpoint is accessible without agent token', async () => {
      await startGateWithAuth(true);

      const res = await gateRequest(gatePort, '/_aegis/health');
      expect(res.status).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.status).toBe('ok');
    });

    it('stats endpoint is accessible without agent token', async () => {
      await startGateWithAuth(true);

      const res = await gateRequest(gatePort, '/_aegis/stats');
      expect(res.status).toBe(200);
    });
  });

  // ─── 2. Agent Credential Scoping ───────────────────────────────

  describe('credential scoping', () => {
    it('returns 403 when agent is not granted access', async () => {
      await startGateWithAuth(true);

      vault.add({
        name: 'scoped-cred',
        service: 'scopedapi',
        secret: 'sk-scoped-123',
        authType: 'bearer',
        domains: ['api.scoped.com'],
      });

      const agent = agentRegistry.add({ name: 'unscoped-bot' });
      // No grant!

      const res = await gateRequest(gatePort, '/scopedapi/v1/data', {
        headers: { 'x-aegis-agent': agent.token },
      });
      expect(res.status).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toContain('not granted access');
      expect(body.agent).toBe('unscoped-bot');
      expect(body.credential).toBe('scoped-cred');
    });

    it('allows access to granted credential, blocks ungrated', async () => {
      await startGateWithAuth(true);

      const cred1 = vault.add({
        name: 'cred-a',
        service: 'api-a',
        secret: 'sk-a',
        authType: 'bearer',
        domains: ['api-a.com'],
      });

      vault.add({
        name: 'cred-b',
        service: 'api-b',
        secret: 'sk-b',
        authType: 'bearer',
        domains: ['api-b.com'],
      });

      const agent = agentRegistry.add({ name: 'scoped-bot' });
      agentRegistry.grant({ agentName: 'scoped-bot', credentialId: cred1.id });

      // Granted — should succeed
      const res1 = await gateRequest(gatePort, '/api-a/v1/data', {
        headers: { 'x-aegis-agent': agent.token },
      });
      expect(res1.status).toBe(200);

      // Not granted — should fail
      const res2 = await gateRequest(gatePort, '/api-b/v1/data', {
        headers: { 'x-aegis-agent': agent.token },
      });
      expect(res2.status).toBe(403);
    });

    it('prevents access after revocation', async () => {
      await startGateWithAuth(true);

      const cred = vault.add({
        name: 'revoke-cred',
        service: 'revokeapi',
        secret: 'sk-revoke',
        authType: 'bearer',
        domains: ['api.revoke.com'],
      });

      const agent = agentRegistry.add({ name: 'revoke-bot' });
      agentRegistry.grant({ agentName: 'revoke-bot', credentialId: cred.id });

      // Should succeed
      const res1 = await gateRequest(gatePort, '/revokeapi/v1/data', {
        headers: { 'x-aegis-agent': agent.token },
      });
      expect(res1.status).toBe(200);

      // Revoke and retry
      agentRegistry.revoke({ agentName: 'revoke-bot', credentialId: cred.id });

      const res2 = await gateRequest(gatePort, '/revokeapi/v1/data', {
        headers: { 'x-aegis-agent': agent.token },
      });
      expect(res2.status).toBe(403);
    });
  });

  // ─── 3. Per-Agent Rate Limits ──────────────────────────────────

  describe('per-agent rate limits', () => {
    it('enforces agent-level rate limit', async () => {
      await startGateWithAuth(true);

      const cred = vault.add({
        name: 'rate-cred',
        service: 'rateapi',
        secret: 'sk-rate-123',
        authType: 'bearer',
        domains: ['api.rate.com'],
      });

      const agent = agentRegistry.add({ name: 'rate-bot', rateLimit: '3/second' });
      agentRegistry.grant({ agentName: 'rate-bot', credentialId: cred.id });

      // Make 3 requests (should all succeed)
      for (let i = 0; i < 3; i++) {
        const res = await gateRequest(gatePort, '/rateapi/v1/data', {
          headers: { 'x-aegis-agent': agent.token },
        });
        expect(res.status).toBe(200);
      }

      // 4th request should be rate limited
      const res = await gateRequest(gatePort, '/rateapi/v1/data', {
        headers: { 'x-aegis-agent': agent.token },
      });
      expect(res.status).toBe(429);
      const body = JSON.parse(res.body);
      expect(body.error).toContain('rate limit exceeded');
    });
  });

  // ─── 4. Agent Header Stripping ─────────────────────────────────

  describe('header stripping', () => {
    it('strips x-aegis-agent header from outbound requests', async () => {
      await startGateWithAuth(true);

      const cred = vault.add({
        name: 'strip-cred',
        service: 'stripapi',
        secret: 'sk-strip-123',
        authType: 'bearer',
        domains: ['api.strip.com'],
      });

      const agent = agentRegistry.add({ name: 'strip-bot' });
      agentRegistry.grant({ agentName: 'strip-bot', credentialId: cred.id });

      await gateRequest(gatePort, '/stripapi/v1/data', {
        headers: { 'x-aegis-agent': agent.token },
      });

      expect(upstream.last).toBeDefined();
      expect(upstream.last?.headers['x-aegis-agent']).toBeUndefined();
    });
  });

  // ─── 5. Enhanced Audit Trail ───────────────────────────────────

  describe('audit trail with agent identity', () => {
    it('logs agent identity in allowed requests', async () => {
      await startGateWithAuth(true);

      const cred = vault.add({
        name: 'audit-cred',
        service: 'auditapi',
        secret: 'sk-audit-123',
        authType: 'bearer',
        domains: ['api.audit.com'],
      });

      const agent = agentRegistry.add({ name: 'audit-bot' });
      agentRegistry.grant({ agentName: 'audit-bot', credentialId: cred.id });

      await gateRequest(gatePort, '/auditapi/v1/data', {
        headers: { 'x-aegis-agent': agent.token },
      });

      const entries = ledger.query({ limit: 10 });
      expect(entries).toHaveLength(1);
      expect(entries[0].status).toBe('allowed');
      expect(entries[0].agentName).toBe('audit-bot');
      expect(entries[0].agentTokenPrefix).toBe(agent.tokenPrefix);
    });

    it('logs agent identity in blocked requests (scoping)', async () => {
      await startGateWithAuth(true);

      vault.add({
        name: 'block-cred',
        service: 'blockapi',
        secret: 'sk-block-123',
        authType: 'bearer',
        domains: ['api.block.com'],
      });

      const agent = agentRegistry.add({ name: 'block-bot' });
      // No grant — will be blocked by scoping

      await gateRequest(gatePort, '/blockapi/v1/data', {
        headers: { 'x-aegis-agent': agent.token },
      });

      const entries = ledger.query({ limit: 10 });
      expect(entries).toHaveLength(1);
      expect(entries[0].status).toBe('blocked');
      expect(entries[0].agentName).toBe('block-bot');
      expect(entries[0].agentTokenPrefix).toBe(agent.tokenPrefix);
    });

    it('logs blocked request without agent identity for 401s', async () => {
      await startGateWithAuth(true);

      vault.add({
        name: 'no-auth-cred',
        service: 'noauthapi',
        secret: 'sk-test',
        authType: 'bearer',
        domains: ['api.noauth.com'],
      });

      await gateRequest(gatePort, '/noauthapi/v1/data');
      // No X-Aegis-Agent header → 401

      const entries = ledger.query({ limit: 10 });
      expect(entries).toHaveLength(1);
      expect(entries[0].status).toBe('blocked');
      expect(entries[0].agentName).toBeNull();
    });

    it('query can filter audit entries by agent name', async () => {
      await startGateWithAuth(true);

      const cred = vault.add({
        name: 'filter-cred',
        service: 'filterapi',
        secret: 'sk-filter',
        authType: 'bearer',
        domains: ['api.filter.com'],
      });

      const bot1 = agentRegistry.add({ name: 'bot-one' });
      const bot2 = agentRegistry.add({ name: 'bot-two' });
      agentRegistry.grant({ agentName: 'bot-one', credentialId: cred.id });
      agentRegistry.grant({ agentName: 'bot-two', credentialId: cred.id });

      await gateRequest(gatePort, '/filterapi/v1/data', {
        headers: { 'x-aegis-agent': bot1.token },
      });
      await gateRequest(gatePort, '/filterapi/v1/data', {
        headers: { 'x-aegis-agent': bot2.token },
      });

      const allEntries = ledger.query({ limit: 10 });
      expect(allEntries).toHaveLength(2);

      const bot1Entries = ledger.query({ agentName: 'bot-one', limit: 10 });
      expect(bot1Entries).toHaveLength(1);
      expect(bot1Entries[0].agentName).toBe('bot-one');
    });
  });

  // ─── 6. Optional Agent Identification ──────────────────────────

  describe('optional agent identification (auth not required)', () => {
    it('identifies agent when token is provided but auth is not required', async () => {
      await startGateWithAuth(false);

      vault.add({
        name: 'opt-cred',
        service: 'optapi',
        secret: 'sk-opt-123',
        authType: 'bearer',
        domains: ['api.opt.com'],
      });

      const agent = agentRegistry.add({ name: 'opt-bot' });
      // No grant needed when auth is not required

      const res = await gateRequest(gatePort, '/optapi/v1/data', {
        headers: { 'x-aegis-agent': agent.token },
      });

      expect(upstream.last).toBeDefined();
      expect(res.status).toBe(200);

      const entries = ledger.query({ limit: 10 });
      expect(entries).toHaveLength(1);
      expect(entries[0].agentName).toBe('opt-bot');
    });

    it('allows request without agent token when auth is not required', async () => {
      await startGateWithAuth(false);

      vault.add({
        name: 'notoken-cred',
        service: 'notokenapi',
        secret: 'sk-notoken',
        authType: 'bearer',
        domains: ['api.notoken.com'],
      });

      const res = await gateRequest(gatePort, '/notokenapi/v1/data');
      expect(res.status).toBe(200);

      const entries = ledger.query({ limit: 10 });
      expect(entries).toHaveLength(1);
      expect(entries[0].agentName).toBeNull();
    });
  });
});
