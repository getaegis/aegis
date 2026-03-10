import { execSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as https from 'node:https';
import * as os from 'node:os';
import * as path from 'node:path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { migrate } from '../src/db.js';
import { Gate } from '../src/gate/index.js';
import { Ledger } from '../src/ledger/index.js';
import { Vault } from '../src/vault/index.js';
import { VERSION } from '../src/version.js';

// ─── Test Helper: Upstream Recorder ─────────────────────────────────────────
// A local HTTP server that records every request it receives, so we can assert
// what Gate forwarded (headers, method, path, body).

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
  /** Status code to return for the next request */
  nextStatus = 200;
  /** Body to return for the next request */
  nextBody = '{"ok":true}';
  /** Headers to include in the response */
  nextHeaders: Record<string, string> = {};

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
        const headers: Record<string, string> = {
          'content-type': 'application/json',
          ...this.nextHeaders,
        };
        res.writeHead(this.nextStatus, headers);
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

  reset(): void {
    this.requests = [];
    this.nextStatus = 200;
    this.nextBody = '{"ok":true}';
    this.nextHeaders = {};
  }

  /** The last recorded request */
  get last(): RecordedRequest | undefined {
    return this.requests[this.requests.length - 1];
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

// ─── Shared Test Setup ───────────────────────────────────────────────────────

describe('gate integration tests', () => {
  const masterKey = 'test-master-key-gate';
  let db: ReturnType<typeof Database>;
  let vault: Vault;
  let ledger: Ledger;
  let upstream: UpstreamRecorder;
  let gate: Gate;
  let gatePort: number;

  beforeEach(async () => {
    // Set up in-memory database
    db = new Database(':memory:');
    db.pragma('journal_mode = WAL');
    migrate(db);

    vault = new Vault(db, masterKey);
    ledger = new Ledger(db);

    // Start the upstream recorder
    upstream = new UpstreamRecorder();
    await upstream.start();

    // Start Gate on a random port, forwarding to our local upstream
    gate = new Gate({
      port: 0,
      vault,
      ledger,
      logLevel: 'error', // suppress logs during tests
      _testUpstream: {
        protocol: 'http',
        hostname: 'localhost',
        port: upstream.port,
      },
    });
    await gate.start();

    // Get the actual port Gate is listening on
    gatePort = gate.listeningPort;
  });

  afterEach(async () => {
    await gate.stop();
    await upstream.stop();
    db.close();
  });

  // ─── 1. Health & Stats Endpoints ────────────────────────────────────────

  describe('/_aegis/health', () => {
    it('returns 200 with status ok', async () => {
      const res = await gateRequest(gatePort, '/_aegis/health');
      expect(res.status).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.status).toBe('ok');
      expect(body.version).toBe(VERSION);
    });
  });

  describe('/_aegis/stats', () => {
    it('returns stats with zero counts initially', async () => {
      const res = await gateRequest(gatePort, '/_aegis/stats');
      expect(res.status).toBe(200);
      const body = JSON.parse(res.body);
      expect(body.total).toBe(0);
      expect(body.allowed).toBe(0);
      expect(body.blocked).toBe(0);
    });

    it('returns updated stats after requests', async () => {
      vault.add({
        name: 'test-cred',
        service: 'testapi',
        secret: 'sk-test-123',
        authType: 'bearer',
        domains: ['api.test.com'],
      });

      // Make an allowed request
      await gateRequest(gatePort, '/testapi/v1/data');

      // Make a blocked request (no such service)
      await gateRequest(gatePort, '/nonexistent/v1/data');

      const res = await gateRequest(gatePort, '/_aegis/stats');
      const body = JSON.parse(res.body);
      expect(body.total).toBe(2);
      expect(body.allowed).toBe(1);
      expect(body.blocked).toBe(1);
    });
  });

  // ─── 2. Request Routing ─────────────────────────────────────────────────

  describe('request routing', () => {
    it('returns 400 for missing service name', async () => {
      const res = await gateRequest(gatePort, '/');
      expect(res.status).toBe(400);
      const body = JSON.parse(res.body);
      expect(body.error).toContain('Missing service name');
    });

    it('returns 404 for unknown service', async () => {
      const res = await gateRequest(gatePort, '/unknown-service/v1/data');
      expect(res.status).toBe(404);
      const body = JSON.parse(res.body);
      expect(body.error).toContain('No credential registered for service');
    });

    it('extracts service name and forwards remaining path', async () => {
      vault.add({
        name: 'test-cred',
        service: 'myapi',
        secret: 'sk-test-123',
        authType: 'bearer',
        domains: ['api.myservice.com'],
      });

      await gateRequest(gatePort, '/myapi/v1/users/42/profile');

      expect(upstream.last).toBeDefined();
      expect(upstream.last?.url).toBe('/v1/users/42/profile');
    });

    it('forwards query parameters', async () => {
      vault.add({
        name: 'test-cred',
        service: 'searchapi',
        secret: 'sk-test-123',
        authType: 'bearer',
        domains: ['api.search.com'],
      });

      await gateRequest(gatePort, '/searchapi/v1/search?q=hello&limit=10');

      expect(upstream.last).toBeDefined();
      expect(upstream.last?.url).toBe('/v1/search?q=hello&limit=10');
    });

    it('forwards request method correctly', async () => {
      vault.add({
        name: 'test-cred',
        service: 'postapi',
        secret: 'sk-test-123',
        authType: 'bearer',
        domains: ['api.post.com'],
      });

      await gateRequest(gatePort, '/postapi/v1/resources', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{"name":"test"}',
      });

      expect(upstream.last).toBeDefined();
      expect(upstream.last?.method).toBe('POST');
      expect(upstream.last?.body).toBe('{"name":"test"}');
    });

    it('forwards DELETE method', async () => {
      vault.add({
        name: 'test-cred',
        service: 'deleteapi',
        secret: 'sk-test-123',
        authType: 'bearer',
        domains: ['api.delete.com'],
      });

      await gateRequest(gatePort, '/deleteapi/v1/resources/99', {
        method: 'DELETE',
      });

      expect(upstream.last?.method).toBe('DELETE');
      expect(upstream.last?.url).toBe('/v1/resources/99');
    });

    it('forwards response status code from upstream', async () => {
      vault.add({
        name: 'test-cred',
        service: 'statusapi',
        secret: 'sk-test-123',
        authType: 'bearer',
        domains: ['api.status.com'],
      });

      upstream.nextStatus = 201;
      upstream.nextBody = '{"id":"new-resource"}';

      const res = await gateRequest(gatePort, '/statusapi/v1/resources', {
        method: 'POST',
        body: '{}',
      });

      expect(res.status).toBe(201);
      expect(JSON.parse(res.body).id).toBe('new-resource');
    });
  });

  // ─── 3. Credential Injection ────────────────────────────────────────────

  describe('credential injection', () => {
    it('injects bearer token in Authorization header', async () => {
      vault.add({
        name: 'bearer-cred',
        service: 'bearer-svc',
        secret: 'sk-live-abc123',
        authType: 'bearer',
        domains: ['api.bearer.com'],
      });

      await gateRequest(gatePort, '/bearer-svc/v1/data');

      expect(upstream.last).toBeDefined();
      expect(upstream.last?.headers.authorization).toBe('Bearer sk-live-abc123');
    });

    it('injects custom header for header auth type', async () => {
      vault.add({
        name: 'header-cred',
        service: 'header-svc',
        secret: 'key-xyz-789',
        authType: 'header',
        headerName: 'x-api-key',
        domains: ['api.header.com'],
      });

      await gateRequest(gatePort, '/header-svc/v1/data');

      expect(upstream.last).toBeDefined();
      expect(upstream.last?.headers['x-api-key']).toBe('key-xyz-789');
    });

    it('uses x-api-key as default header name when headerName is not specified', async () => {
      vault.add({
        name: 'default-header-cred',
        service: 'defheader-svc',
        secret: 'key-default-456',
        authType: 'header',
        domains: ['api.defheader.com'],
      });

      await gateRequest(gatePort, '/defheader-svc/v1/data');

      expect(upstream.last).toBeDefined();
      expect(upstream.last?.headers['x-api-key']).toBe('key-default-456');
    });

    it('injects basic auth as Base64-encoded Authorization header', async () => {
      vault.add({
        name: 'basic-cred',
        service: 'basic-svc',
        secret: 'user:password123',
        authType: 'basic',
        domains: ['api.basic.com'],
      });

      await gateRequest(gatePort, '/basic-svc/v1/data');

      expect(upstream.last).toBeDefined();
      const expected = `Basic ${Buffer.from('user:password123').toString('base64')}`;
      expect(upstream.last?.headers.authorization).toBe(expected);
    });

    it('injects query auth type as URL query parameter', async () => {
      vault.add({
        name: 'query-cred',
        service: 'query-svc',
        secret: 'api-key-query-999',
        authType: 'query',
        domains: ['api.query.com'],
      });

      await gateRequest(gatePort, '/query-svc/v1/data');

      expect(upstream.last).toBeDefined();
      // Query auth appends ?key=secret to the URL
      expect(upstream.last?.url).toBe('/v1/data?key=api-key-query-999');
      // No auth headers should be injected
      expect(upstream.last?.headers.authorization).toBeUndefined();
      expect(upstream.last?.headers['x-api-key']).toBeUndefined();
    });

    it('injects query auth with custom param name via headerName', async () => {
      vault.add({
        name: 'query-cred-custom',
        service: 'query-custom-svc',
        secret: 'my-api-key-123',
        authType: 'query',
        headerName: 'api_key',
        domains: ['api.query.com'],
      });

      await gateRequest(gatePort, '/query-custom-svc/v1/search');

      expect(upstream.last).toBeDefined();
      expect(upstream.last?.url).toBe('/v1/search?api_key=my-api-key-123');
    });

    it('appends query auth to existing query parameters', async () => {
      vault.add({
        name: 'query-cred-append',
        service: 'query-append-svc',
        secret: 'key-456',
        authType: 'query',
        domains: ['api.query.com'],
      });

      await gateRequest(gatePort, '/query-append-svc/v1/data?foo=bar');

      expect(upstream.last).toBeDefined();
      expect(upstream.last?.url).toBe('/v1/data?foo=bar&key=key-456');
    });
  });

  // ─── 4. Domain Guard ────────────────────────────────────────────────────

  describe('domain guard', () => {
    it("allows requests to the credential's primary domain", async () => {
      vault.add({
        name: 'domain-cred',
        service: 'domain-svc',
        secret: 'sk-domain-123',
        authType: 'bearer',
        domains: ['api.allowed.com'],
      });

      const res = await gateRequest(gatePort, '/domain-svc/v1/data');

      // Should be proxied successfully (not blocked)
      expect(res.status).toBe(200);
      expect(upstream.requests).toHaveLength(1);
    });

    it('blocks requests to domains not in the allowlist via X-Target-Host', async () => {
      vault.add({
        name: 'guard-cred',
        service: 'guard-svc',
        secret: 'sk-guard-123',
        authType: 'bearer',
        domains: ['api.allowed.com'],
      });

      const res = await gateRequest(gatePort, '/guard-svc/v1/data', {
        headers: { 'x-target-host': 'evil.attacker.com' },
      });

      expect(res.status).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toContain('Domain not in credential allowlist');
      expect(body.requested).toBe('evil.attacker.com');
      expect(body.allowed).toEqual(['api.allowed.com']);

      // No request should have reached upstream
      expect(upstream.requests).toHaveLength(0);
    });

    it('allows X-Target-Host when it matches the allowlist', async () => {
      vault.add({
        name: 'multi-domain-cred',
        service: 'multi-svc',
        secret: 'sk-multi-123',
        authType: 'bearer',
        domains: ['api.primary.com', 'api.secondary.com'],
      });

      const res = await gateRequest(gatePort, '/multi-svc/v1/data', {
        headers: { 'x-target-host': 'api.secondary.com' },
      });

      expect(res.status).toBe(200);
      expect(upstream.requests).toHaveLength(1);
    });

    it('supports wildcard domain matching', async () => {
      vault.add({
        name: 'wildcard-cred',
        service: 'wildcard-svc',
        secret: 'sk-wild-123',
        authType: 'bearer',
        domains: ['*.slack.com'],
      });

      // api.slack.com should match *.slack.com
      const res = await gateRequest(gatePort, '/wildcard-svc/v1/data', {
        headers: { 'x-target-host': 'api.slack.com' },
      });

      expect(res.status).toBe(200);
      expect(upstream.requests).toHaveLength(1);
    });

    it("blocks wildcard when subdomain doesn't match", async () => {
      vault.add({
        name: 'wildcard-block-cred',
        service: 'wildblock-svc',
        secret: 'sk-wild-block-123',
        authType: 'bearer',
        domains: ['*.slack.com'],
      });

      // evil.com should NOT match *.slack.com
      const res = await gateRequest(gatePort, '/wildblock-svc/v1/data', {
        headers: { 'x-target-host': 'evil.com' },
      });

      expect(res.status).toBe(403);
      expect(upstream.requests).toHaveLength(0);
    });

    it('logs blocked domain guard violations to the ledger', async () => {
      vault.add({
        name: 'ledger-guard-cred',
        service: 'ledgerguard-svc',
        secret: 'sk-ledger-123',
        authType: 'bearer',
        domains: ['api.safe.com'],
      });

      await gateRequest(gatePort, '/ledgerguard-svc/v1/data', {
        headers: { 'x-target-host': 'api.unsafe.com' },
      });

      const entries = ledger.query({ status: 'blocked' });
      expect(entries).toHaveLength(1);
      expect(entries[0].service).toBe('ledgerguard-svc');
      expect(entries[0].targetDomain).toBe('api.unsafe.com');
      expect(entries[0].blockedReason).toContain('not in allowlist');
    });
  });

  // ─── 5. Header Stripping ───────────────────────────────────────────────

  describe('header stripping', () => {
    beforeEach(() => {
      vault.add({
        name: 'strip-cred',
        service: 'strip-svc',
        secret: 'sk-strip-123',
        authType: 'bearer',
        domains: ['api.strip.com'],
      });
    });

    it('strips Authorization header from agent request', async () => {
      await gateRequest(gatePort, '/strip-svc/v1/data', {
        headers: { authorization: 'Bearer agent-tried-to-inject' },
      });

      expect(upstream.last).toBeDefined();
      // The header should be Aegis's injected credential, not the agent's
      expect(upstream.last?.headers.authorization).toBe('Bearer sk-strip-123');
    });

    it('strips X-API-Key header from agent request', async () => {
      await gateRequest(gatePort, '/strip-svc/v1/data', {
        headers: { 'x-api-key': 'agent-key-attempt' },
      });

      expect(upstream.last).toBeDefined();
      // X-API-Key should be stripped (bearer auth doesn't set it)
      expect(upstream.last?.headers['x-api-key']).toBeUndefined();
    });

    it('strips Host header and sets target domain', async () => {
      await gateRequest(gatePort, '/strip-svc/v1/data', {
        headers: { host: 'localhost:9999' },
      });

      expect(upstream.last).toBeDefined();
      expect(upstream.last?.headers.host).toBe('api.strip.com');
    });

    it('strips X-Target-Host from forwarded request', async () => {
      await gateRequest(gatePort, '/strip-svc/v1/data', {
        headers: { 'x-target-host': 'api.strip.com' },
      });

      expect(upstream.last).toBeDefined();
      expect(upstream.last?.headers['x-target-host']).toBeUndefined();
    });

    it('strips Set-Cookie from upstream response', async () => {
      upstream.nextHeaders = { 'set-cookie': 'session=hijacked; Path=/' };

      const res = await gateRequest(gatePort, '/strip-svc/v1/data');

      // Set-Cookie should be stripped from the response
      expect(res.headers['set-cookie']).toBeUndefined();
    });

    it('preserves non-sensitive headers from agent request', async () => {
      await gateRequest(gatePort, '/strip-svc/v1/data', {
        headers: {
          'content-type': 'application/json',
          accept: 'application/json',
          'x-custom-header': 'custom-value',
        },
      });

      expect(upstream.last).toBeDefined();
      expect(upstream.last?.headers['content-type']).toBe('application/json');
      expect(upstream.last?.headers.accept).toBe('application/json');
      expect(upstream.last?.headers['x-custom-header']).toBe('custom-value');
    });
  });

  // ─── 6. Audit Ledger Integration ───────────────────────────────────────

  describe('audit ledger', () => {
    it('logs allowed requests with credential details', async () => {
      vault.add({
        name: 'audit-cred',
        service: 'audit-svc',
        secret: 'sk-audit-123',
        authType: 'bearer',
        domains: ['api.audit.com'],
      });

      await gateRequest(gatePort, '/audit-svc/v1/resource');

      const entries = ledger.query({ status: 'allowed' });
      expect(entries).toHaveLength(1);
      expect(entries[0].service).toBe('audit-svc');
      expect(entries[0].credentialName).toBe('audit-cred');
      expect(entries[0].method).toBe('GET');
      expect(entries[0].path).toBe('/v1/resource');
      expect(entries[0].status).toBe('allowed');
      expect(entries[0].responseCode).toBe(200);
    });

    it('logs blocked requests for unknown services', async () => {
      await gateRequest(gatePort, '/nonexistent/v1/data');

      const entries = ledger.query({ status: 'blocked' });
      expect(entries).toHaveLength(1);
      expect(entries[0].service).toBe('nonexistent');
      expect(entries[0].blockedReason).toContain('No credential found');
    });

    it('records response status code from upstream', async () => {
      vault.add({
        name: 'status-cred',
        service: 'status-svc',
        secret: 'sk-status-123',
        authType: 'bearer',
        domains: ['api.status.com'],
      });

      upstream.nextStatus = 404;
      await gateRequest(gatePort, '/status-svc/v1/missing');

      const entries = ledger.query({ status: 'allowed' });
      expect(entries).toHaveLength(1);
      expect(entries[0].responseCode).toBe(404);
    });
  });

  // ─── 7. TTL Enforcement ────────────────────────────────────────────────

  describe('TTL enforcement', () => {
    it('allows requests with non-expired credentials', async () => {
      vault.add({
        name: 'fresh-cred',
        service: 'fresh-svc',
        secret: 'sk-fresh-123',
        authType: 'bearer',
        domains: ['api.fresh.com'],
        ttlDays: 30,
      });

      const res = await gateRequest(gatePort, '/fresh-svc/v1/data');
      expect(res.status).toBe(200);
      expect(upstream.requests).toHaveLength(1);
    });

    it('blocks requests with expired credentials (403)', async () => {
      vault.add({
        name: 'expired-cred',
        service: 'expired-svc',
        secret: 'sk-expired-123',
        authType: 'bearer',
        domains: ['api.expired.com'],
      });

      // Manually expire the credential
      db.prepare('UPDATE credentials SET expires_at = ? WHERE name = ?').run(
        '2020-01-01T00:00:00.000Z',
        'expired-cred',
      );

      const res = await gateRequest(gatePort, '/expired-svc/v1/data');
      expect(res.status).toBe(403);

      const body = JSON.parse(res.body);
      expect(body.error).toContain('expired');
      expect(body.credential).toBe('expired-cred');

      // Should NOT have reached upstream
      expect(upstream.requests).toHaveLength(0);
    });

    it('logs expired credential rejections to the ledger', async () => {
      vault.add({
        name: 'ttl-ledger-cred',
        service: 'ttl-ledger-svc',
        secret: 'sk-ttl-123',
        authType: 'bearer',
        domains: ['api.ttlledger.com'],
      });

      db.prepare('UPDATE credentials SET expires_at = ? WHERE name = ?').run(
        '2020-01-01T00:00:00.000Z',
        'ttl-ledger-cred',
      );

      await gateRequest(gatePort, '/ttl-ledger-svc/v1/data');

      const entries = ledger.query({ status: 'blocked' });
      expect(entries).toHaveLength(1);
      expect(entries[0].blockedReason).toContain('expired');
    });

    it('allows credentials with no TTL (never expire)', async () => {
      vault.add({
        name: 'forever-cred',
        service: 'forever-svc',
        secret: 'sk-forever-123',
        authType: 'bearer',
        domains: ['api.forever.com'],
      });

      const res = await gateRequest(gatePort, '/forever-svc/v1/data');
      expect(res.status).toBe(200);
    });
  });

  // ─── Credential Scope Enforcement ───────────────────────────────

  describe('credential scope enforcement', () => {
    it('allows GET request with read scope', async () => {
      vault.add({
        name: 'read-cred',
        service: 'read-svc',
        secret: 'sk-read-123',
        authType: 'bearer',
        domains: ['api.read.com'],
        scopes: ['read'],
      });

      const res = await gateRequest(gatePort, '/read-svc/v1/data');
      expect(res.status).toBe(200);
      expect(upstream.requests).toHaveLength(1);
    });

    it('allows HEAD request with read scope', async () => {
      vault.add({
        name: 'head-cred',
        service: 'head-svc',
        secret: 'sk-head-123',
        authType: 'bearer',
        domains: ['api.head.com'],
        scopes: ['read'],
      });

      const res = await gateRequest(gatePort, '/head-svc/v1/data', { method: 'HEAD' });
      expect(res.status).toBe(200);
    });

    it('allows OPTIONS request with read scope', async () => {
      vault.add({
        name: 'opts-cred',
        service: 'opts-svc',
        secret: 'sk-opts-123',
        authType: 'bearer',
        domains: ['api.opts.com'],
        scopes: ['read'],
      });

      const res = await gateRequest(gatePort, '/opts-svc/v1/data', { method: 'OPTIONS' });
      expect(res.status).toBe(200);
    });

    it('blocks POST request with read-only scope (403)', async () => {
      vault.add({
        name: 'readonly-cred',
        service: 'readonly-svc',
        secret: 'sk-readonly-123',
        authType: 'bearer',
        domains: ['api.readonly.com'],
        scopes: ['read'],
      });

      const res = await gateRequest(gatePort, '/readonly-svc/v1/data', {
        method: 'POST',
        body: '{"key":"value"}',
      });
      expect(res.status).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toContain('not permitted by credential scopes');
      expect(body.method).toBe('POST');
      expect(body.scopes).toEqual(['read']);
      expect(upstream.requests).toHaveLength(0);
    });

    it('blocks PUT request with read-only scope (403)', async () => {
      vault.add({
        name: 'readonly-put',
        service: 'readonly-put-svc',
        secret: 'sk-readonly-put',
        authType: 'bearer',
        domains: ['api.readonlyput.com'],
        scopes: ['read'],
      });

      const res = await gateRequest(gatePort, '/readonly-put-svc/v1/data', { method: 'PUT' });
      expect(res.status).toBe(403);
      expect(upstream.requests).toHaveLength(0);
    });

    it('blocks DELETE request with read-only scope (403)', async () => {
      vault.add({
        name: 'readonly-del',
        service: 'readonly-del-svc',
        secret: 'sk-readonly-del',
        authType: 'bearer',
        domains: ['api.readonlydel.com'],
        scopes: ['read'],
      });

      const res = await gateRequest(gatePort, '/readonly-del-svc/v1/data', { method: 'DELETE' });
      expect(res.status).toBe(403);
      expect(upstream.requests).toHaveLength(0);
    });

    it('allows POST request with write scope', async () => {
      vault.add({
        name: 'write-cred',
        service: 'write-svc',
        secret: 'sk-write-123',
        authType: 'bearer',
        domains: ['api.write.com'],
        scopes: ['write'],
      });

      const res = await gateRequest(gatePort, '/write-svc/v1/data', {
        method: 'POST',
        body: '{"key":"value"}',
      });
      expect(res.status).toBe(200);
      expect(upstream.requests).toHaveLength(1);
    });

    it('blocks GET request with write-only scope (403)', async () => {
      vault.add({
        name: 'writeonly-cred',
        service: 'writeonly-svc',
        secret: 'sk-writeonly-123',
        authType: 'bearer',
        domains: ['api.writeonly.com'],
        scopes: ['write'],
      });

      const res = await gateRequest(gatePort, '/writeonly-svc/v1/data');
      expect(res.status).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toContain('not permitted by credential scopes');
      expect(body.scopes).toEqual(['write']);
      expect(upstream.requests).toHaveLength(0);
    });

    it('allows all methods with wildcard scope', async () => {
      vault.add({
        name: 'wildcard-cred',
        service: 'wildcard-svc',
        secret: 'sk-wildcard-123',
        authType: 'bearer',
        domains: ['api.wildcard.com'],
        scopes: ['*'],
      });

      const get = await gateRequest(gatePort, '/wildcard-svc/v1/data');
      expect(get.status).toBe(200);

      const post = await gateRequest(gatePort, '/wildcard-svc/v1/data', {
        method: 'POST',
        body: '{}',
      });
      expect(post.status).toBe(200);

      const del = await gateRequest(gatePort, '/wildcard-svc/v1/data', { method: 'DELETE' });
      expect(del.status).toBe(200);

      expect(upstream.requests).toHaveLength(3);
    });

    it('allows all methods with combined read+write scopes', async () => {
      vault.add({
        name: 'readwrite-cred',
        service: 'readwrite-svc',
        secret: 'sk-readwrite-123',
        authType: 'bearer',
        domains: ['api.readwrite.com'],
        scopes: ['read', 'write'],
      });

      const get = await gateRequest(gatePort, '/readwrite-svc/v1/data');
      expect(get.status).toBe(200);

      const post = await gateRequest(gatePort, '/readwrite-svc/v1/data', {
        method: 'POST',
        body: '{}',
      });
      expect(post.status).toBe(200);

      expect(upstream.requests).toHaveLength(2);
    });

    it('allows all methods with default scopes (no --scopes flag)', async () => {
      vault.add({
        name: 'default-scope-cred',
        service: 'default-scope-svc',
        secret: 'sk-default-scope',
        authType: 'bearer',
        domains: ['api.defaultscope.com'],
        // No scopes specified — defaults to ['*']
      });

      const get = await gateRequest(gatePort, '/default-scope-svc/v1/data');
      expect(get.status).toBe(200);

      const post = await gateRequest(gatePort, '/default-scope-svc/v1/data', {
        method: 'POST',
        body: '{}',
      });
      expect(post.status).toBe(200);

      expect(upstream.requests).toHaveLength(2);
    });

    it('logs scope violations to the ledger', async () => {
      vault.add({
        name: 'scope-ledger-cred',
        service: 'scope-ledger-svc',
        secret: 'sk-scope-ledger',
        authType: 'bearer',
        domains: ['api.scopeledger.com'],
        scopes: ['read'],
      });

      await gateRequest(gatePort, '/scope-ledger-svc/v1/data', { method: 'DELETE' });

      const entries = ledger.query({ status: 'blocked' });
      expect(entries).toHaveLength(1);
      expect(entries[0].blockedReason).toContain('not permitted by credential scopes');
    });

    it('allows PATCH request with write scope', async () => {
      vault.add({
        name: 'patch-cred',
        service: 'patch-svc',
        secret: 'sk-patch-123',
        authType: 'bearer',
        domains: ['api.patch.com'],
        scopes: ['write'],
      });

      const res = await gateRequest(gatePort, '/patch-svc/v1/data', {
        method: 'PATCH',
        body: '{"update": true}',
      });
      expect(res.status).toBe(200);
      expect(upstream.requests).toHaveLength(1);
    });
  });

  // ─── Rate Limiting ──────────────────────────────────────────────

  describe('rate limiting', () => {
    it('allows requests within the rate limit', async () => {
      vault.add({
        name: 'rate-ok-cred',
        service: 'rate-ok-svc',
        secret: 'sk-rate-ok',
        authType: 'bearer',
        domains: ['api.rateok.com'],
        rateLimit: '10/min',
      });

      const res = await gateRequest(gatePort, '/rate-ok-svc/v1/data');
      expect(res.status).toBe(200);
    });

    it('returns 429 when rate limit is exceeded', async () => {
      vault.add({
        name: 'rate-exceed-cred',
        service: 'rate-exceed-svc',
        secret: 'sk-rate-exceed',
        authType: 'bearer',
        domains: ['api.rateexceed.com'],
        rateLimit: '2/min',
      });

      // First two requests should succeed
      const r1 = await gateRequest(gatePort, '/rate-exceed-svc/v1/data');
      expect(r1.status).toBe(200);
      const r2 = await gateRequest(gatePort, '/rate-exceed-svc/v1/data');
      expect(r2.status).toBe(200);

      // Third request should be rate limited
      const r3 = await gateRequest(gatePort, '/rate-exceed-svc/v1/data');
      expect(r3.status).toBe(429);

      const body = JSON.parse(r3.body);
      expect(body.error).toBe('Rate limit exceeded');
      expect(body.limit).toBe('2/min');
      expect(body.retryAfter).toBeGreaterThan(0);
    });

    it('includes Retry-After header in 429 response', async () => {
      vault.add({
        name: 'rate-header-cred',
        service: 'rate-header-svc',
        secret: 'sk-rate-header',
        authType: 'bearer',
        domains: ['api.rateheader.com'],
        rateLimit: '1/min',
      });

      await gateRequest(gatePort, '/rate-header-svc/v1/data');
      const res = await gateRequest(gatePort, '/rate-header-svc/v1/data');

      expect(res.status).toBe(429);
      expect(res.headers['retry-after']).toBeDefined();
      expect(parseInt(res.headers['retry-after'] as string, 10)).toBeGreaterThan(0);
    });

    it('logs rate limit violations to the ledger', async () => {
      vault.add({
        name: 'rate-ledger-cred',
        service: 'rate-ledger-svc',
        secret: 'sk-rate-ledger',
        authType: 'bearer',
        domains: ['api.rateledger.com'],
        rateLimit: '1/min',
      });

      await gateRequest(gatePort, '/rate-ledger-svc/v1/data');
      await gateRequest(gatePort, '/rate-ledger-svc/v1/data'); // This one blocked

      const entries = ledger.query({ status: 'blocked' });
      expect(entries.length).toBeGreaterThanOrEqual(1);
      const rateLimitEntry = entries.find((e) => e.blockedReason?.includes('Rate limit exceeded'));
      expect(rateLimitEntry).toBeDefined();
      expect(rateLimitEntry?.service).toBe('rate-ledger-svc');
    });

    it('does not rate limit credentials without a rate limit', async () => {
      vault.add({
        name: 'no-rate-cred',
        service: 'no-rate-svc',
        secret: 'sk-no-rate',
        authType: 'bearer',
        domains: ['api.norate.com'],
      });

      // Send several requests — all should succeed
      for (let i = 0; i < 5; i++) {
        const res = await gateRequest(gatePort, '/no-rate-svc/v1/data');
        expect(res.status).toBe(200);
      }
    });

    it('rate limits credentials independently', async () => {
      vault.add({
        name: 'rate-a-cred',
        service: 'rate-a-svc',
        secret: 'sk-rate-a',
        authType: 'bearer',
        domains: ['api.ratea.com'],
        rateLimit: '1/min',
      });

      vault.add({
        name: 'rate-b-cred',
        service: 'rate-b-svc',
        secret: 'sk-rate-b',
        authType: 'bearer',
        domains: ['api.rateb.com'],
        rateLimit: '1/min',
      });

      // Exhaust rate-a
      await gateRequest(gatePort, '/rate-a-svc/v1/data');
      const rA = await gateRequest(gatePort, '/rate-a-svc/v1/data');
      expect(rA.status).toBe(429);

      // rate-b should still work
      const rB = await gateRequest(gatePort, '/rate-b-svc/v1/data');
      expect(rB.status).toBe(200);
    });
  });

  // ─── Body Inspection ───────────────────────────────────────────

  describe('body inspection', () => {
    it('blocks requests with credential patterns in body (block mode)', async () => {
      vault.add({
        name: 'body-block-cred',
        service: 'body-block-svc',
        secret: 'sk-body-block',
        authType: 'bearer',
        domains: ['api.bodyblock.com'],
        bodyInspection: 'block',
      });

      const res = await gateRequest(gatePort, '/body-block-svc/v1/data', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          message: 'Here is my key sk-1234567890abcdefghijklmnopqrstuv',
        }),
      });

      expect(res.status).toBe(403);
      const body = JSON.parse(res.body);
      expect(body.error).toContain('credential-like patterns');
      expect(body.mode).toBe('block');
      expect(upstream.requests).toHaveLength(0);
    });

    it('allows requests with credential patterns in warn mode', async () => {
      vault.add({
        name: 'body-warn-cred',
        service: 'body-warn-svc',
        secret: 'sk-body-warn',
        authType: 'bearer',
        domains: ['api.bodywarn.com'],
        bodyInspection: 'warn',
      });

      const res = await gateRequest(gatePort, '/body-warn-svc/v1/data', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          message: 'Here is my key sk-1234567890abcdefghijklmnopqrstuv',
        }),
      });

      // Should be allowed through (warn mode doesn't block)
      expect(res.status).toBe(200);
      expect(upstream.requests).toHaveLength(1);
    });

    it('skips body inspection in off mode', async () => {
      vault.add({
        name: 'body-off-cred',
        service: 'body-off-svc',
        secret: 'sk-body-off',
        authType: 'bearer',
        domains: ['api.bodyoff.com'],
        bodyInspection: 'off',
      });

      const res = await gateRequest(gatePort, '/body-off-svc/v1/data', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          message: 'Here is my key sk-1234567890abcdefghijklmnopqrstuv',
        }),
      });

      // Should be allowed through (off mode skips inspection)
      expect(res.status).toBe(200);
      expect(upstream.requests).toHaveLength(1);
    });

    it('allows clean bodies in block mode', async () => {
      vault.add({
        name: 'body-clean-cred',
        service: 'body-clean-svc',
        secret: 'sk-body-clean',
        authType: 'bearer',
        domains: ['api.bodyclean.com'],
        bodyInspection: 'block',
      });

      const res = await gateRequest(gatePort, '/body-clean-svc/v1/data', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ message: 'hello world', count: 42 }),
      });

      expect(res.status).toBe(200);
      expect(upstream.requests).toHaveLength(1);
    });

    it('logs body inspection blocks to the ledger', async () => {
      vault.add({
        name: 'body-ledger-cred',
        service: 'body-ledger-svc',
        secret: 'sk-body-ledger',
        authType: 'bearer',
        domains: ['api.bodyledger.com'],
        bodyInspection: 'block',
      });

      await gateRequest(gatePort, '/body-ledger-svc/v1/data', {
        method: 'POST',
        body: JSON.stringify({ token: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh' }),
      });

      const entries = ledger.query({ status: 'blocked' });
      expect(entries.length).toBeGreaterThanOrEqual(1);
      const bodyEntry = entries.find((e) => e.blockedReason?.includes('Body inspection'));
      expect(bodyEntry).toBeDefined();
      expect(bodyEntry?.service).toBe('body-ledger-svc');
    });

    it('allows GET requests without body even in block mode', async () => {
      vault.add({
        name: 'body-get-cred',
        service: 'body-get-svc',
        secret: 'sk-body-get',
        authType: 'bearer',
        domains: ['api.bodyget.com'],
        bodyInspection: 'block',
      });

      const res = await gateRequest(gatePort, '/body-get-svc/v1/data');
      expect(res.status).toBe(200);
      expect(upstream.requests).toHaveLength(1);
    });

    it('defaults to block mode when bodyInspection not specified', async () => {
      vault.add({
        name: 'body-default-cred',
        service: 'body-default-svc',
        secret: 'sk-body-default',
        authType: 'bearer',
        domains: ['api.bodydefault.com'],
      });

      const res = await gateRequest(gatePort, '/body-default-svc/v1/data', {
        method: 'POST',
        body: JSON.stringify({ key: 'sk-1234567890abcdefghijklmnopqrstuv' }),
      });

      expect(res.status).toBe(403);
      expect(upstream.requests).toHaveLength(0);
    });
  });
});

// ─── TLS Tests ─────────────────────────────────────────────────────────────

describe('gate TLS', () => {
  const masterKey = 'tls-test-master-key';
  const salt = 'tls-test-salt';
  let db: ReturnType<typeof Database>;
  let vault: Vault;
  let ledger: Ledger;
  let upstream: UpstreamRecorder;
  let gate: Gate;
  let gatePort: number;
  let tmpDir: string;
  let certPath: string;
  let keyPath: string;

  beforeEach(async () => {
    db = new Database(':memory:');
    migrate(db);
    vault = new Vault(db, masterKey, salt);
    ledger = new Ledger(db);

    upstream = new UpstreamRecorder();
    await upstream.start();

    // Generate temporary self-signed cert
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-tls-test-'));
    keyPath = path.join(tmpDir, 'test.key');
    certPath = path.join(tmpDir, 'test.crt');

    execSync(`openssl genrsa -out "${keyPath}" 2048`, { stdio: 'pipe' });
    execSync(
      `openssl req -new -x509 -key "${keyPath}" -out "${certPath}" -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"`,
      { stdio: 'pipe' },
    );
  });

  afterEach(async () => {
    if (gate) await gate.stop();
    await upstream.stop();
    db.close();
    // Clean up temp certs
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function httpsRequest(
    port: number,
    urlPath: string,
    options: { method?: string; headers?: Record<string, string>; body?: string } = {},
  ): Promise<{ status: number; body: string; headers: http.IncomingHttpHeaders }> {
    return new Promise((resolve, reject) => {
      const req = https.request(
        {
          hostname: 'localhost',
          port,
          path: urlPath,
          method: options.method ?? 'GET',
          headers: options.headers,
          rejectUnauthorized: false, // Self-signed cert
        },
        (res) => {
          let body = '';
          res.on('data', (chunk: Buffer) => {
            body += chunk.toString();
          });
          res.on('end', () => {
            resolve({ status: res.statusCode ?? 0, body, headers: res.headers });
          });
        },
      );
      req.on('error', reject);
      if (options.body) req.write(options.body);
      req.end();
    });
  }

  it('starts with TLS and serves HTTPS', async () => {
    vault.add({
      name: 'tls-cred',
      service: 'tls-svc',
      secret: 'tls-secret',
      authType: 'bearer',
      domains: ['api.tls.com'],
    });

    gate = new Gate({
      port: 0,
      vault,
      ledger,
      logLevel: 'error',
      tls: { certPath, keyPath },
      _testUpstream: { protocol: 'http', hostname: 'localhost', port: upstream.port },
    });

    await gate.start();
    gatePort = gate.listeningPort;

    expect(gate.isTls).toBe(true);

    const res = await httpsRequest(gatePort, '/tls-svc/v1/test');
    expect(res.status).toBe(200);
    expect(upstream.requests).toHaveLength(1);
    expect(upstream.requests[0].headers.authorization).toBe('Bearer tls-secret');
  });

  it('serves health check over HTTPS', async () => {
    gate = new Gate({
      port: 0,
      vault,
      ledger,
      logLevel: 'error',
      tls: { certPath, keyPath },
      _testUpstream: { protocol: 'http', hostname: 'localhost', port: upstream.port },
    });

    await gate.start();
    gatePort = gate.listeningPort;

    const res = await httpsRequest(gatePort, '/_aegis/health');
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.status).toBe('ok');
  });

  it('isTls is false when no TLS config provided', () => {
    gate = new Gate({
      port: 0,
      vault,
      ledger,
      logLevel: 'error',
      _testUpstream: { protocol: 'http', hostname: 'localhost', port: upstream.port },
    });

    expect(gate.isTls).toBe(false);
  });

  it('credential injection works over TLS', async () => {
    vault.add({
      name: 'tls-header-cred',
      service: 'tls-header-svc',
      secret: 'x-custom-secret-value',
      authType: 'header',
      headerName: 'x-api-key',
      domains: ['api.tlsheader.com'],
    });

    gate = new Gate({
      port: 0,
      vault,
      ledger,
      logLevel: 'error',
      tls: { certPath, keyPath },
      _testUpstream: { protocol: 'http', hostname: 'localhost', port: upstream.port },
    });

    await gate.start();
    gatePort = gate.listeningPort;

    const res = await httpsRequest(gatePort, '/tls-header-svc/v1/protected');
    expect(res.status).toBe(200);
    expect(upstream.requests[0].headers['x-api-key']).toBe('x-custom-secret-value');
  });

  it('domain guard works over TLS', async () => {
    vault.add({
      name: 'tls-guard-cred',
      service: 'tls-guard-svc',
      secret: 'guard-secret',
      authType: 'bearer',
      domains: ['api.allowed.com'],
    });

    gate = new Gate({
      port: 0,
      vault,
      ledger,
      logLevel: 'error',
      tls: { certPath, keyPath },
      _testUpstream: { protocol: 'http', hostname: 'localhost', port: upstream.port },
    });

    await gate.start();
    gatePort = gate.listeningPort;

    const res = await httpsRequest(gatePort, '/tls-guard-svc/v1/data', {
      headers: { 'x-target-host': 'evil.com' },
    });
    expect(res.status).toBe(403);
    const body = JSON.parse(res.body);
    expect(body.error).toContain('Domain not in credential allowlist');
  });
});

// ─── Graceful Shutdown Tests ──────────────────────────────────────────────────

describe('graceful shutdown', () => {
  const masterKey = 'test-master-key-shutdown';
  let db: ReturnType<typeof Database>;
  let vault: Vault;
  let ledger: Ledger;

  beforeEach(() => {
    db = new Database(':memory:');
    db.pragma('journal_mode = WAL');
    migrate(db);
    vault = new Vault(db, masterKey);
    ledger = new Ledger(db);
  });

  afterEach(() => {
    db.close();
  });

  it('stop() returns drained: true when no in-flight requests', async () => {
    const upstream = new UpstreamRecorder();
    await upstream.start();

    const gate = new Gate({
      port: 0,
      vault,
      ledger,
      logLevel: 'error',
      _testUpstream: { protocol: 'http', hostname: 'localhost', port: upstream.port },
    });
    await gate.start();

    const result = await gate.stop();
    expect(result.drained).toBe(true);
    expect(result.activeAtClose).toBe(0);
    await upstream.stop();
  });

  it('stop() waits for in-flight requests to drain', async () => {
    // Create a slow upstream that delays its response
    let resolveUpstream: (() => void) | undefined;
    const slowServer = http.createServer((req, res) => {
      req.on('data', () => {});
      req.on('end', () => {
        // Don't respond until we say so
        resolveUpstream = () => {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end('{"ok":true}');
        };
      });
    });

    await new Promise<void>((resolve) => {
      slowServer.listen(0, () => resolve());
    });
    const slowPort = (slowServer.address() as { port: number }).port;

    const gate = new Gate({
      port: 0,
      vault,
      ledger,
      logLevel: 'error',
      shutdownTimeoutMs: 5000,
      _testUpstream: { protocol: 'http', hostname: 'localhost', port: slowPort },
    });
    await gate.start();
    const gatePort = gate.listeningPort;

    vault.add({
      name: 'drain-cred',
      service: 'drain-svc',
      secret: 'drain-secret',
      authType: 'bearer',
      domains: ['api.drain.com'],
    });

    // Start a request but don't await it yet
    const requestPromise = gateRequest(gatePort, '/drain-svc/v1/slow');

    // Wait for the request to reach the upstream
    await new Promise<void>((resolve) => {
      const check = setInterval(() => {
        if (resolveUpstream) {
          clearInterval(check);
          resolve();
        }
      }, 10);
    });

    // Gate should have 1 active request
    expect(gate.inFlightRequests).toBe(1);

    // Start shutdown (don't await yet, it should wait for the request to drain)
    const shutdownPromise = gate.stop();
    expect(gate.isShuttingDown).toBe(true);

    // Complete the upstream response
    resolveUpstream?.();

    // Now both should resolve
    const [shutdownResult] = await Promise.all([shutdownPromise, requestPromise]);
    expect(shutdownResult.drained).toBe(true);
    expect(shutdownResult.activeAtClose).toBe(0);

    await new Promise<void>((resolve) => {
      slowServer.close(() => resolve());
    });
  });

  it('returns 503 for new requests during shutdown', async () => {
    // Create a slow upstream that delays its response
    let resolveUpstream: (() => void) | undefined;
    const slowServer = http.createServer((req, res) => {
      req.on('data', () => {});
      req.on('end', () => {
        resolveUpstream = () => {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end('{"ok":true}');
        };
      });
    });

    await new Promise<void>((resolve) => {
      slowServer.listen(0, () => resolve());
    });
    const slowPort = (slowServer.address() as { port: number }).port;

    const gate = new Gate({
      port: 0,
      vault,
      ledger,
      logLevel: 'error',
      shutdownTimeoutMs: 5000,
      _testUpstream: { protocol: 'http', hostname: 'localhost', port: slowPort },
    });
    await gate.start();
    const gatePort = gate.listeningPort;

    vault.add({
      name: 'cred-503',
      service: 'svc-503',
      secret: 'secret-503',
      authType: 'bearer',
      domains: ['api.example.com'],
    });

    // Start a slow request to keep Gate from draining immediately
    const slowRequest = gateRequest(gatePort, '/svc-503/v1/slow');

    // Wait for upstream to receive the slow request
    await new Promise<void>((resolve) => {
      const check = setInterval(() => {
        if (resolveUpstream) {
          clearInterval(check);
          resolve();
        }
      }, 10);
    });

    // Begin shutdown — server stays open during drain, but returns 503 for new requests
    const shutdownPromise = gate.stop();

    // New request should get 503
    const newRes = await gateRequest(gatePort, '/_aegis/health');
    expect(newRes.status).toBe(503);
    expect(JSON.parse(newRes.body).error).toContain('shutting down');

    // Release slow request to complete shutdown
    resolveUpstream?.();
    await Promise.all([shutdownPromise, slowRequest]);

    await new Promise<void>((resolve) => {
      slowServer.close(() => resolve());
    });
  });

  it('forces shutdown after timeout with active requests', async () => {
    // Create an upstream that never responds
    const hangServer = http.createServer(() => {
      // Intentionally never respond
    });

    await new Promise<void>((resolve) => {
      hangServer.listen(0, () => resolve());
    });
    const hangPort = (hangServer.address() as { port: number }).port;

    const gate = new Gate({
      port: 0,
      vault,
      ledger,
      logLevel: 'error',
      shutdownTimeoutMs: 200, // Very short timeout for test
      _testUpstream: { protocol: 'http', hostname: 'localhost', port: hangPort },
    });
    await gate.start();
    const gatePort = gate.listeningPort;

    vault.add({
      name: 'hang-cred',
      service: 'hang-svc',
      secret: 'hang-secret',
      authType: 'bearer',
      domains: ['api.hang.com'],
    });

    // Start a request that will never complete (upstream never responds)
    gateRequest(gatePort, '/hang-svc/v1/forever').catch(() => {
      // Expected — socket will be destroyed when gate shuts down
    });

    // Wait a bit for the request to be in-flight
    await new Promise((r) => setTimeout(r, 50));

    // Stop with the short timeout — gate will force-close after 200ms
    const result = await gate.stop();
    expect(result.drained).toBe(false);
    expect(result.activeAtClose).toBeGreaterThan(0);

    // Force-close hangServer connections so it can shut down
    hangServer.closeAllConnections();
    await new Promise<void>((resolve) => {
      hangServer.close(() => resolve());
    });
  });

  it('exposes isShuttingDown and inFlightRequests properties', async () => {
    const upstream = new UpstreamRecorder();
    await upstream.start();

    const gate = new Gate({
      port: 0,
      vault,
      ledger,
      logLevel: 'error',
      _testUpstream: { protocol: 'http', hostname: 'localhost', port: upstream.port },
    });
    await gate.start();

    expect(gate.isShuttingDown).toBe(false);
    expect(gate.inFlightRequests).toBe(0);

    await gate.stop();
    await upstream.stop();
  });

  it('stop() resolves immediately when server is null', async () => {
    const gate = new Gate({
      port: 0,
      vault,
      ledger,
      logLevel: 'error',
    });

    // Never started — server is null
    const result = await gate.stop();
    expect(result.drained).toBe(true);
    expect(result.activeAtClose).toBe(0);
  });
});
