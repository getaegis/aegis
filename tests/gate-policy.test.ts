import * as http from 'node:http';
import Database from 'better-sqlite3-multiple-ciphers';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AgentRegistry } from '../src/agent/index.js';
import { migrate } from '../src/db.js';
import { Gate } from '../src/gate/index.js';
import { Ledger } from '../src/ledger/index.js';
import type { Policy } from '../src/policy/index.js';
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

// ─── Gate + Policy Integration Tests ──────────────────────────────

describe('gate policy enforcement', () => {
  const masterKey = 'test-master-key-gate-policy';
  const salt = 'test-salt-gate-policy';
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

  function buildPolicy(agent: string, rules: Policy['rules']): Policy {
    return { agent, rules };
  }

  async function startGateWithPolicies(
    policies: Map<string, Policy>,
    mode: 'enforce' | 'dry-run' = 'enforce',
  ): Promise<void> {
    gate = new Gate({
      port: 0,
      vault,
      ledger,
      logLevel: 'error',
      agentRegistry,
      requireAgentAuth: true,
      policyMode: mode,
      _testPolicies: policies,
      _testUpstream: {
        protocol: 'http',
        hostname: 'localhost',
        port: upstream.port,
      },
    });
    await gate.start();
    gatePort = gate.listeningPort;
  }

  function addCredAndAgent(serviceName: string): { agentToken: string; credentialId: string } {
    vault.add({
      name: `${serviceName}-cred`,
      service: serviceName,
      secret: `sk-${serviceName}-test`,
      authType: 'bearer',
      domains: [`api.${serviceName}.com`],
    });

    const cred = vault.getByService(serviceName);
    if (!cred) throw new Error(`Credential setup failed for ${serviceName}`);

    const agent = agentRegistry.add({ name: `${serviceName}-agent` });
    agentRegistry.grant({ agentName: agent.name, credentialId: cred.id });

    return { agentToken: agent.token, credentialId: cred.id };
  }

  // ─── 1. Enforce Mode: Service Access ───────────────────────────

  describe('enforce mode — service access', () => {
    it('allows request when policy permits the service', async () => {
      const { agentToken } = addCredAndAgent('slack');
      const policies = new Map([
        ['slack-agent', buildPolicy('slack-agent', [{ service: 'slack' }])],
      ]);
      await startGateWithPolicies(policies);

      const res = await gateRequest(gatePort, '/slack/api/chat.postMessage', {
        headers: { 'x-aegis-agent': agentToken },
      });
      expect(res.status).toBe(200);
    });

    it('blocks request when policy does not include the service', async () => {
      const { agentToken } = addCredAndAgent('slack');
      const policies = new Map([
        ['slack-agent', buildPolicy('slack-agent', [{ service: 'github' }])],
      ]);
      await startGateWithPolicies(policies);

      const res = await gateRequest(gatePort, '/slack/api/chat.postMessage', {
        headers: { 'x-aegis-agent': agentToken },
      });
      expect(res.status).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toBe('Policy violation');
      expect(body.violation).toBe('no_matching_rule');
    });

    it('allows request when agent has no policy (policies exist for other agents)', async () => {
      const { agentToken } = addCredAndAgent('slack');
      const policies = new Map([
        ['other-agent', buildPolicy('other-agent', [{ service: 'github' }])],
      ]);
      await startGateWithPolicies(policies);

      const res = await gateRequest(gatePort, '/slack/api/chat.postMessage', {
        headers: { 'x-aegis-agent': agentToken },
      });
      // No policy for this agent, so the request is not blocked by policies
      expect(res.status).toBe(200);
    });
  });

  // ─── 2. Enforce Mode: Method Restrictions ──────────────────────

  describe('enforce mode — method restrictions', () => {
    it('allows GET when policy permits GET', async () => {
      const { agentToken } = addCredAndAgent('github');
      const policies = new Map([
        ['github-agent', buildPolicy('github-agent', [{ service: 'github', methods: ['GET'] }])],
      ]);
      await startGateWithPolicies(policies);

      const res = await gateRequest(gatePort, '/github/repos/org/repo', {
        headers: { 'x-aegis-agent': agentToken },
      });
      expect(res.status).toBe(200);
    });

    it('blocks POST when policy only permits GET', async () => {
      const { agentToken } = addCredAndAgent('github');
      const policies = new Map([
        ['github-agent', buildPolicy('github-agent', [{ service: 'github', methods: ['GET'] }])],
      ]);
      await startGateWithPolicies(policies);

      const res = await gateRequest(gatePort, '/github/repos/org/repo', {
        method: 'POST',
        headers: { 'x-aegis-agent': agentToken },
      });
      expect(res.status).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.violation).toBe('method');
    });
  });

  // ─── 3. Enforce Mode: Path Restrictions ────────────────────────

  describe('enforce mode — path restrictions', () => {
    it('allows request matching path pattern', async () => {
      const { agentToken } = addCredAndAgent('github');
      const policies = new Map([
        [
          'github-agent',
          buildPolicy('github-agent', [{ service: 'github', paths: ['^/repos/.*'] }]),
        ],
      ]);
      await startGateWithPolicies(policies);

      const res = await gateRequest(gatePort, '/github/repos/org/repo', {
        headers: { 'x-aegis-agent': agentToken },
      });
      expect(res.status).toBe(200);
    });

    it('blocks request not matching any path pattern', async () => {
      const { agentToken } = addCredAndAgent('github');
      const policies = new Map([
        [
          'github-agent',
          buildPolicy('github-agent', [{ service: 'github', paths: ['^/repos/.*'] }]),
        ],
      ]);
      await startGateWithPolicies(policies);

      const res = await gateRequest(gatePort, '/github/admin/settings', {
        headers: { 'x-aegis-agent': agentToken },
      });
      expect(res.status).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.violation).toBe('path');
    });
  });

  // ─── 4. Enforce Mode: Time Window ──────────────────────────────

  describe('enforce mode — time window', () => {
    it('policy evaluation uses real time (time window covers now)', async () => {
      // We can't easily control time in integration tests,
      // so use a window that covers all 24h (00:00 to 23:59)
      const { agentToken } = addCredAndAgent('api');
      const policies = new Map([
        [
          'api-agent',
          buildPolicy('api-agent', [
            {
              service: 'api',
              timeWindow: { start: '00:00', end: '23:59', timezone: 'UTC' },
            },
          ]),
        ],
      ]);
      await startGateWithPolicies(policies);

      const res = await gateRequest(gatePort, '/api/data', {
        headers: { 'x-aegis-agent': agentToken },
      });
      expect(res.status).toBe(200);
    });
  });

  // ─── 5. Dry-Run Mode ──────────────────────────────────────────

  describe('dry-run mode', () => {
    it('logs violation but allows request through', async () => {
      const { agentToken } = addCredAndAgent('slack');
      const policies = new Map([
        ['slack-agent', buildPolicy('slack-agent', [{ service: 'github' }])],
      ]);
      await startGateWithPolicies(policies, 'dry-run');

      const res = await gateRequest(gatePort, '/slack/api/chat.postMessage', {
        headers: { 'x-aegis-agent': agentToken },
      });
      // Dry-run: request goes through despite policy violation
      expect(res.status).toBe(200);

      // But it should be logged as a would-be block
      const entries = ledger.query({});
      const dryRunEntries = entries.filter(
        (e) => e.status === 'blocked' && e.blockedReason?.includes('POLICY_DRY_RUN'),
      );
      expect(dryRunEntries.length).toBeGreaterThan(0);
      expect(dryRunEntries[0].blockedReason).toContain('No policy rule for service');
    });

    it('does not block method violations in dry-run mode', async () => {
      const { agentToken } = addCredAndAgent('github');
      const policies = new Map([
        ['github-agent', buildPolicy('github-agent', [{ service: 'github', methods: ['GET'] }])],
      ]);
      await startGateWithPolicies(policies, 'dry-run');

      const res = await gateRequest(gatePort, '/github/repos/org/repo', {
        method: 'DELETE',
        headers: { 'x-aegis-agent': agentToken },
      });
      // Should be allowed through in dry-run mode
      expect(res.status).toBe(200);
    });
  });

  // ─── 6. Audit Trail ────────────────────────────────────────────

  describe('audit trail', () => {
    it('logs policy violations to the ledger', async () => {
      const { agentToken } = addCredAndAgent('slack');
      const policies = new Map([
        ['slack-agent', buildPolicy('slack-agent', [{ service: 'github' }])],
      ]);
      await startGateWithPolicies(policies);

      await gateRequest(gatePort, '/slack/api/test', {
        headers: { 'x-aegis-agent': agentToken },
      });

      const entries = ledger.query({ status: 'blocked' });
      const policyEntries = entries.filter((e) => e.blockedReason?.includes('Policy violation'));
      expect(policyEntries.length).toBeGreaterThan(0);
      expect(policyEntries[0].agentName).toBe('slack-agent');
    });

    it('logs allowed requests normally when policy permits', async () => {
      const { agentToken } = addCredAndAgent('slack');
      const policies = new Map([
        ['slack-agent', buildPolicy('slack-agent', [{ service: 'slack' }])],
      ]);
      await startGateWithPolicies(policies);

      await gateRequest(gatePort, '/slack/api/test', {
        headers: { 'x-aegis-agent': agentToken },
      });

      const entries = ledger.query({ service: 'slack' });
      const allowed = entries.filter((e) => e.status === 'allowed');
      expect(allowed.length).toBeGreaterThan(0);
    });
  });

  // ─── 7. Gate Configuration ─────────────────────────────────────

  describe('configuration', () => {
    it('reports hasPolicies correctly', async () => {
      const policies = new Map([['bot', buildPolicy('bot', [{ service: 'api' }])]]);

      gate = new Gate({
        port: 0,
        vault,
        ledger,
        logLevel: 'error',
        _testPolicies: policies,
        _testUpstream: {
          protocol: 'http',
          hostname: 'localhost',
          port: upstream.port,
        },
      });
      await gate.start();
      gatePort = gate.listeningPort;

      expect(gate.hasPolicies).toBe(true);
      expect(gate.currentPolicyMode).toBe('enforce');
    });

    it('reports hasPolicies as false when no policies loaded', async () => {
      gate = new Gate({
        port: 0,
        vault,
        ledger,
        logLevel: 'error',
        _testUpstream: {
          protocol: 'http',
          hostname: 'localhost',
          port: upstream.port,
        },
      });
      await gate.start();
      gatePort = gate.listeningPort;

      expect(gate.hasPolicies).toBe(false);
    });

    it('defaults to enforce mode', async () => {
      gate = new Gate({
        port: 0,
        vault,
        ledger,
        logLevel: 'error',
        _testUpstream: {
          protocol: 'http',
          hostname: 'localhost',
          port: upstream.port,
        },
      });
      await gate.start();
      gatePort = gate.listeningPort;

      expect(gate.currentPolicyMode).toBe('enforce');
    });
  });
});
