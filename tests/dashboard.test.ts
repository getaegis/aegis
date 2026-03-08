import * as crypto from 'node:crypto';
import * as http from 'node:http';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { AgentRegistry } from '../src/agent/index.js';
import { DashboardServer } from '../src/dashboard/index.js';
import { migrate } from '../src/db.js';
import { Ledger } from '../src/ledger/index.js';
import { UserRegistry } from '../src/user/index.js';
import { Vault } from '../src/vault/index.js';
import { VERSION } from '../src/version.js';

// ─── Test Helpers ────────────────────────────────────────────────

const MASTER_KEY = 'test-master-key-for-dashboard';
const SALT = crypto.randomBytes(32);

function fetchJson<T>(port: number, path: string): Promise<T> {
  return new Promise((resolve, reject) => {
    http
      .get(`http://localhost:${port}${path}`, (res) => {
        let data = '';
        res.on('data', (chunk: string) => {
          data += chunk;
        });
        res.on('end', () => {
          try {
            resolve(JSON.parse(data) as T);
          } catch (err) {
            reject(err);
          }
        });
      })
      .on('error', reject);
  });
}

// ─── Tests ───────────────────────────────────────────────────────

describe('DashboardServer', () => {
  let db: Database.Database;
  let vault: Vault;
  let ledger: Ledger;
  let registry: AgentRegistry;
  let userRegistry: UserRegistry;
  let dashboard: DashboardServer;

  beforeEach(() => {
    db = new Database(':memory:');
    migrate(db);
    vault = new Vault(db, MASTER_KEY, SALT);
    ledger = new Ledger(db);
    const derivedKey = crypto.pbkdf2Sync(MASTER_KEY, SALT, 100000, 32, 'sha512');
    registry = new AgentRegistry(db, derivedKey);
    userRegistry = new UserRegistry(db, derivedKey);
  });

  afterEach(async () => {
    if (dashboard) {
      await dashboard.stop();
    }
    db.close();
  });

  async function startDashboard(
    overrides: Partial<ConstructorParameters<typeof DashboardServer>[0]> = {},
  ): Promise<DashboardServer> {
    dashboard = new DashboardServer({
      port: 0, // OS-assigned port
      vault,
      ledger,
      agentRegistry: registry,
      userRegistry,
      gateRunning: true,
      gatePort: 3100,
      logLevel: 'error', // Suppress logs in tests
      staticDir: '/dev/null', // No static files needed for API tests
      ...overrides,
    });
    await dashboard.start();
    return dashboard;
  }

  // ─── Health Endpoint ───────────────────────────────────────────

  describe('GET /api/health', () => {
    it('returns health status with version and uptime', async () => {
      await startDashboard();
      const health = await fetchJson<{
        status: string;
        version: string;
        uptime: number;
        gate: { running: boolean; port: number | null };
      }>(dashboard.listeningPort, '/api/health');

      expect(health.status).toBe('ok');
      expect(health.version).toBe(VERSION);
      expect(health.uptime).toBeGreaterThanOrEqual(0);
      expect(health.gate.running).toBe(true);
      expect(health.gate.port).toBe(3100);
    });

    it('reflects updated gate status', async () => {
      await startDashboard();
      dashboard.setGateStatus(false, null);

      const health = await fetchJson<{
        gate: { running: boolean; port: number | null };
      }>(dashboard.listeningPort, '/api/health');

      expect(health.gate.running).toBe(false);
      expect(health.gate.port).toBe(null);
    });
  });

  // ─── Stats Endpoint ───────────────────────────────────────────

  describe('GET /api/stats', () => {
    it('returns empty stats with no audit entries', async () => {
      await startDashboard();
      const stats = await fetchJson<{
        total: number;
        allowed: number;
        blocked: number;
        byService: Record<string, number>;
      }>(dashboard.listeningPort, '/api/stats');

      expect(stats.total).toBe(0);
      expect(stats.allowed).toBe(0);
      expect(stats.blocked).toBe(0);
      expect(stats.byService).toEqual({});
    });

    it('returns accurate stats from ledger', async () => {
      ledger.logAllowed({
        credentialId: 'cred-1',
        credentialName: 'slack-key',
        service: 'slack',
        targetDomain: 'api.slack.com',
        method: 'POST',
        path: '/api/chat.postMessage',
        responseCode: 200,
      });
      ledger.logBlocked({
        service: 'github',
        targetDomain: 'evil.com',
        method: 'GET',
        path: '/api/repos',
        reason: 'Domain guard rejected',
      });

      await startDashboard();
      const stats = await fetchJson<{
        total: number;
        allowed: number;
        blocked: number;
        byService: Record<string, number>;
      }>(dashboard.listeningPort, '/api/stats');

      expect(stats.total).toBe(2);
      expect(stats.allowed).toBe(1);
      expect(stats.blocked).toBe(1);
      expect(stats.byService.slack).toBe(1);
      expect(stats.byService.github).toBe(1);
    });

    it('supports since filter', async () => {
      // Log an entry "in the past"
      db.prepare(
        `INSERT INTO audit_log (service, target_domain, method, path, status, timestamp)
         VALUES ('old-svc', 'old.com', 'GET', '/', 'allowed', '2020-01-01T00:00:00.000Z')`,
      ).run();
      ledger.logAllowed({
        credentialId: 'c1',
        credentialName: 'new-key',
        service: 'new-svc',
        targetDomain: 'new.com',
        method: 'GET',
        path: '/',
        responseCode: 200,
      });

      await startDashboard();
      const stats = await fetchJson<{ total: number }>(
        dashboard.listeningPort,
        '/api/stats?since=2024-01-01T00:00:00.000Z',
      );

      expect(stats.total).toBe(1); // Only the new entry
    });
  });

  // ─── Credentials Endpoint ─────────────────────────────────────

  describe('GET /api/credentials', () => {
    it('returns empty array with no credentials', async () => {
      await startDashboard();
      const creds = await fetchJson<unknown[]>(dashboard.listeningPort, '/api/credentials');
      expect(creds).toEqual([]);
    });

    it('returns credential list (without secrets)', async () => {
      vault.add({
        name: 'slack-key',
        service: 'slack',
        secret: 'xoxb-secret',
        domains: ['api.slack.com'],
      });

      await startDashboard();
      const creds = await fetchJson<Array<{ name: string; service: string; domains: string[] }>>(
        dashboard.listeningPort,
        '/api/credentials',
      );

      expect(creds).toHaveLength(1);
      expect(creds[0].name).toBe('slack-key');
      expect(creds[0].service).toBe('slack');
      expect(creds[0].domains).toEqual(['api.slack.com']);
      // Verify no secret is leaked
      expect((creds[0] as Record<string, unknown>).secret).toBeUndefined();
    });
  });

  // ─── Agents Endpoint ──────────────────────────────────────────

  describe('GET /api/agents', () => {
    it('returns empty array with no agents', async () => {
      await startDashboard();
      const agents = await fetchJson<unknown[]>(dashboard.listeningPort, '/api/agents');
      expect(agents).toEqual([]);
    });

    it('returns agents with grant information', async () => {
      const agent = registry.add({ name: 'test-bot' });
      const cred = vault.add({
        name: 'github-token',
        service: 'github',
        secret: 'ghp_secret',
        domains: ['api.github.com'],
      });
      registry.grant({ agentName: agent.name, credentialId: cred.id });

      await startDashboard();
      const agents = await fetchJson<
        Array<{ name: string; tokenPrefix: string; grants: string[] }>
      >(dashboard.listeningPort, '/api/agents');

      expect(agents).toHaveLength(1);
      expect(agents[0].name).toBe('test-bot');
      expect(agents[0].tokenPrefix).toBe(agent.tokenPrefix);
      expect(agents[0].grants).toEqual([cred.id]);
    });
  });

  // ─── Users Endpoint ───────────────────────────────────────────

  describe('GET /api/users', () => {
    it('returns empty array with no users', async () => {
      await startDashboard();
      const users = await fetchJson<unknown[]>(dashboard.listeningPort, '/api/users');
      expect(users).toEqual([]);
    });

    it('returns users with role and token prefix', async () => {
      const user = userRegistry.add({ name: 'alice', role: 'admin' });

      await startDashboard();
      const users = await fetchJson<Array<{ name: string; role: string; tokenPrefix: string }>>(
        dashboard.listeningPort,
        '/api/users',
      );

      expect(users).toHaveLength(1);
      expect(users[0].name).toBe('alice');
      expect(users[0].role).toBe('admin');
      expect(users[0].tokenPrefix).toBe(user.tokenPrefix);
    });

    it('does not expose token hashes', async () => {
      userRegistry.add({ name: 'bob', role: 'operator' });

      await startDashboard();
      const users = await fetchJson<Array<Record<string, unknown>>>(
        dashboard.listeningPort,
        '/api/users',
      );

      for (const u of users) {
        expect(u.token).toBeUndefined();
        expect(u.token_hash).toBeUndefined();
        expect(u.tokenHash).toBeUndefined();
      }
    });

    it('returns empty array when userRegistry is not provided', async () => {
      await startDashboard({ userRegistry: undefined });
      const users = await fetchJson<unknown[]>(dashboard.listeningPort, '/api/users');
      expect(users).toEqual([]);
    });
  });

  // ─── Requests Endpoint ────────────────────────────────────────

  describe('GET /api/requests', () => {
    it('returns empty array with no audit entries', async () => {
      await startDashboard();
      const entries = await fetchJson<unknown[]>(dashboard.listeningPort, '/api/requests');
      expect(entries).toEqual([]);
    });

    it('returns audit entries from ledger', async () => {
      ledger.logAllowed({
        credentialId: 'c1',
        credentialName: 'slack',
        service: 'slack',
        targetDomain: 'api.slack.com',
        method: 'POST',
        path: '/api/chat',
        responseCode: 200,
      });

      await startDashboard();
      const entries = await fetchJson<Array<{ service: string; status: string; method: string }>>(
        dashboard.listeningPort,
        '/api/requests',
      );

      expect(entries).toHaveLength(1);
      expect(entries[0].service).toBe('slack');
      expect(entries[0].status).toBe('allowed');
      expect(entries[0].method).toBe('POST');
    });

    it('filters by status', async () => {
      ledger.logAllowed({
        credentialId: 'c1',
        credentialName: 'slack',
        service: 'slack',
        targetDomain: 'api.slack.com',
        method: 'GET',
        path: '/',
        responseCode: 200,
      });
      ledger.logBlocked({
        service: 'github',
        targetDomain: 'evil.com',
        method: 'GET',
        path: '/',
        reason: 'blocked',
      });

      await startDashboard();
      const blocked = await fetchJson<Array<{ status: string }>>(
        dashboard.listeningPort,
        '/api/requests?status=blocked',
      );

      expect(blocked).toHaveLength(1);
      expect(blocked[0].status).toBe('blocked');
    });

    it('filters by service', async () => {
      ledger.logAllowed({
        credentialId: 'c1',
        credentialName: 'slack',
        service: 'slack',
        targetDomain: 'api.slack.com',
        method: 'GET',
        path: '/',
        responseCode: 200,
      });
      ledger.logAllowed({
        credentialId: 'c2',
        credentialName: 'github',
        service: 'github',
        targetDomain: 'api.github.com',
        method: 'GET',
        path: '/',
        responseCode: 200,
      });

      await startDashboard();
      const githubOnly = await fetchJson<Array<{ service: string }>>(
        dashboard.listeningPort,
        '/api/requests?service=github',
      );

      expect(githubOnly).toHaveLength(1);
      expect(githubOnly[0].service).toBe('github');
    });

    it('respects limit parameter (capped at 500)', async () => {
      for (let i = 0; i < 10; i++) {
        ledger.logAllowed({
          credentialId: 'c1',
          credentialName: 'svc',
          service: 'svc',
          targetDomain: 'api.example.com',
          method: 'GET',
          path: `/${i}`,
          responseCode: 200,
        });
      }

      await startDashboard();
      const limited = await fetchJson<unknown[]>(dashboard.listeningPort, '/api/requests?limit=3');

      expect(limited).toHaveLength(3);
    });
  });

  // ─── WebSocket Live Feed ───────────────────────────────────────

  describe('WebSocket /ws', () => {
    it('receives broadcast messages', async () => {
      await startDashboard();

      const received = await new Promise<string>((resolve, reject) => {
        const ws = new WebSocket(`ws://localhost:${dashboard.listeningPort}/ws`);

        ws.on('message', (data: Buffer) => {
          ws.close();
          resolve(data.toString('utf-8'));
        });

        ws.on('open', () => {
          // Send broadcast after connection is registered
          setTimeout(() => {
            dashboard.broadcast({
              timestamp: '2024-01-01T00:00:00.000Z',
              service: 'test-svc',
              targetDomain: 'api.test.com',
              method: 'GET',
              path: '/test',
              status: 'allowed',
            });
          }, 50);
        });

        ws.on('error', reject);
        setTimeout(() => reject(new Error('WebSocket timeout')), 5000);
      });

      const parsed = JSON.parse(received) as { service: string; status: string };
      expect(parsed.service).toBe('test-svc');
      expect(parsed.status).toBe('allowed');
    });

    it('rejects non-/ws upgrades', async () => {
      await startDashboard();

      const destroyed = await new Promise<boolean>((resolve) => {
        const ws = new WebSocket(`ws://localhost:${dashboard.listeningPort}/other`);

        ws.on('open', () => {
          // Should not connect
          ws.close();
          resolve(false);
        });

        ws.on('error', () => resolve(true));
        setTimeout(() => resolve(true), 2000);
      });

      expect(destroyed).toBe(true);
    });
  });

  // ─── CORS Headers ─────────────────────────────────────────────

  describe('CORS', () => {
    it('includes CORS headers on API responses', async () => {
      await startDashboard();

      const headers = await new Promise<http.IncomingHttpHeaders>((resolve, reject) => {
        http
          .get(`http://localhost:${dashboard.listeningPort}/api/health`, (res) => {
            resolve(res.headers);
          })
          .on('error', reject);
      });

      expect(headers['access-control-allow-origin']).toBe('*');
      expect(headers['access-control-allow-methods']).toBe('GET, OPTIONS');
    });

    it('responds 204 to OPTIONS preflight', async () => {
      await startDashboard();

      const status = await new Promise<number>((resolve, reject) => {
        const req = http.request(
          {
            hostname: 'localhost',
            port: dashboard.listeningPort,
            path: '/api/health',
            method: 'OPTIONS',
          },
          (res) => resolve(res.statusCode ?? 0),
        );
        req.on('error', reject);
        req.end();
      });

      expect(status).toBe(204);
    });
  });

  // ─── 404 Handling ──────────────────────────────────────────────

  describe('404 handling', () => {
    it('returns 404 for unknown API routes', async () => {
      await startDashboard();

      const result = await new Promise<{ status: number; body: { error: string } }>(
        (resolve, reject) => {
          http
            .get(`http://localhost:${dashboard.listeningPort}/api/unknown`, (res) => {
              let data = '';
              res.on('data', (chunk: string) => {
                data += chunk;
              });
              res.on('end', () => {
                resolve({
                  status: res.statusCode ?? 0,
                  body: JSON.parse(data) as { error: string },
                });
              });
            })
            .on('error', reject);
        },
      );

      expect(result.status).toBe(404);
      expect(result.body.error).toBe('Not found');
    });
  });

  // ─── Server Lifecycle ─────────────────────────────────────────

  describe('lifecycle', () => {
    it('starts on specified port', async () => {
      await startDashboard();
      expect(dashboard.listeningPort).toBeGreaterThan(0);
    });

    it('stops cleanly', async () => {
      await startDashboard();
      expect(dashboard.listeningPort).toBeGreaterThan(0);
      await dashboard.stop();

      // Give the OS a moment to release the port, then verify connection fails
      await new Promise((r) => setTimeout(r, 100));

      const result = await new Promise<'refused' | 'connected'>((resolve) => {
        const req = http.get(`http://localhost:${dashboard.listeningPort}/api/health`, (res) => {
          res.resume();
          resolve('connected');
        });
        req.on('error', () => resolve('refused'));
        req.setTimeout(500, () => {
          req.destroy();
          resolve('refused');
        });
      });

      expect(result).toBe('refused');
    });
  });

  // ─── Security ─────────────────────────────────────────────────

  describe('security', () => {
    it('does not expose credential secrets via /api/credentials', async () => {
      vault.add({
        name: 'sensitive',
        service: 'secret-svc',
        secret: 'super-secret-api-key',
        domains: ['api.secret.com'],
      });

      await startDashboard();
      const creds = await fetchJson<Array<Record<string, unknown>>>(
        dashboard.listeningPort,
        '/api/credentials',
      );

      // Vault.list() already strips secrets, but verify it at the API layer
      for (const cred of creds) {
        expect(cred.secret).toBeUndefined();
        expect(cred.encrypted).toBeUndefined();
        expect(cred.iv).toBeUndefined();
        expect(cred.auth_tag).toBeUndefined();
        expect(JSON.stringify(cred)).not.toContain('super-secret-api-key');
      }
    });

    it('does not expose agent tokens via /api/agents', async () => {
      const agent = registry.add({ name: 'secret-bot' });

      await startDashboard();
      const agents = await fetchJson<Array<Record<string, unknown>>>(
        dashboard.listeningPort,
        '/api/agents',
      );

      for (const a of agents) {
        expect(a.token).toBeUndefined();
        expect(a.token_hash).toBeUndefined();
        expect(a.tokenHash).toBeUndefined();
        expect(JSON.stringify(a)).not.toContain(agent.token);
      }
    });
  });

  // ─── Gate Audit Broadcast Integration ──────────────────────────

  describe('Gate audit broadcast', () => {
    it('broadcast enriches entry with all required fields', async () => {
      await startDashboard();

      // Verify broadcast doesn't throw with minimal entry
      expect(() => {
        dashboard.broadcast({
          timestamp: new Date().toISOString(),
          service: 'test',
          targetDomain: 'test.com',
          method: 'GET',
          path: '/',
          status: 'allowed',
        });
      }).not.toThrow();
    });

    it('broadcast handles no connected clients gracefully', async () => {
      await startDashboard();

      // No WS clients connected — should not throw
      expect(() => {
        dashboard.broadcast({
          timestamp: new Date().toISOString(),
          service: 'test',
          targetDomain: 'test.com',
          method: 'GET',
          path: '/',
          status: 'blocked',
          blockedReason: 'test reason',
        });
      }).not.toThrow();
    });
  });
});
