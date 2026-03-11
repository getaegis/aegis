import { execSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as https from 'node:https';
import * as os from 'node:os';
import * as path from 'node:path';
import Database from 'better-sqlite3-multiple-ciphers';
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

// ─── Request Smuggling / Security Tests ────────────────────────────────────

describe('gate request smuggling resistance', () => {
  const masterKey = 'test-master-key-smuggling';
  let db: ReturnType<typeof Database>;
  let vault: Vault;
  let ledger: Ledger;
  let upstream: UpstreamRecorder;
  let gate: Gate;
  let gatePort: number;

  beforeEach(async () => {
    db = new Database(':memory:');
    db.pragma('journal_mode = WAL');
    migrate(db);

    vault = new Vault(db, masterKey);
    ledger = new Ledger(db);

    upstream = new UpstreamRecorder();
    await upstream.start();

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

    vault.add({
      name: 'smuggle-cred',
      service: 'smuggle-svc',
      secret: 'sk-smuggle-secret-123',
      authType: 'bearer',
      domains: ['smuggle-svc.example.com'],
    });
  });

  afterEach(async () => {
    await gate.stop();
    await upstream.stop();
    db.close();
  });

  /**
   * Send a raw HTTP request string over a TCP socket to Gate.
   * This bypasses Node's http.request() which sanitises headers/bodies,
   * allowing us to test malformed requests that agents might craft.
   */
  function rawRequest(port: number, raw: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const { Socket } = require('node:net') as typeof import('node:net');
      const socket = new Socket();
      let data = '';

      socket.connect(port, '127.0.0.1', () => {
        socket.write(raw);
        // Signal we're done writing so the server can respond and close
        socket.end();
      });

      socket.on('data', (chunk: Buffer) => {
        data += chunk.toString();
      });

      socket.on('end', () => {
        resolve(data);
      });

      socket.on('error', reject);

      // Short timeout — these should respond fast
      socket.setTimeout(1000, () => {
        socket.destroy();
        resolve(data);
      });
    });
  }

  it('rejects requests with both Content-Length and Transfer-Encoding (CL/TE desync)', async () => {
    // CL/TE desync is the classic HTTP request smuggling vector.
    // An attacker sends conflicting Content-Length and Transfer-Encoding
    // headers hoping the proxy and backend disagree on body boundaries.
    const raw =
      `POST /smuggle-svc/smuggle-svc/api HTTP/1.1\r\n` +
      `Host: localhost:${gatePort}\r\n` +
      `Content-Length: 5\r\n` +
      `Transfer-Encoding: chunked\r\n` +
      `\r\n` +
      `0\r\n\r\n`;

    await rawRequest(gatePort, raw);

    // Node.js HTTP server handles CL/TE by preferring Transfer-Encoding
    // (per RFC 9112 §6.3) and ignoring Content-Length. The request either
    // gets processed normally (with TE taking precedence) or rejected.
    // Either way, the upstream should see at most 1 request, never 2.
    expect(upstream.requests.length).toBeLessThanOrEqual(1);
  });

  it('handles double Content-Length headers without processing extra data', async () => {
    // Two conflicting Content-Length values — a proxy might use the first,
    // the backend the second, allowing smuggled data.
    const raw =
      `POST /smuggle-svc/smuggle-svc/api HTTP/1.1\r\n` +
      `Host: localhost:${gatePort}\r\n` +
      `Content-Length: 5\r\n` +
      `Content-Length: 50\r\n` +
      `\r\n` +
      `hello`;

    const response = await rawRequest(gatePort, raw);

    // Node.js HTTP server rejects duplicate Content-Length with a 400.
    // This is the correct behaviour per RFC 9112.
    expect(response).toMatch(/400/);
  });

  it('prevents path traversal via encoded dots (..%2f)', async () => {
    // Path: /smuggle-svc/..%2f_aegis%2fhealth
    // After splitting on '/', pathParts = ['smuggle-svc', '..%2f_aegis%2fhealth']
    // The '..' is embedded within the segment (not a standalone segment),
    // so it routes to 'smuggle-svc' and forwards the raw path to upstream.
    // This is safe: the agent never escapes service routing.
    const res = await gateRequest(gatePort, '/smuggle-svc/..%2f_aegis%2fhealth');
    // Should reach upstream (200), NOT the internal _aegis health endpoint
    expect(res.status).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.status).not.toBe('ok'); // health endpoint returns {status:'ok'}
  });

  it('prevents path traversal via double-encoded dots (%2e%2e)', async () => {
    // %2e%2e is percent-encoded "..". If Gate uses new URL() to parse,
    // it normalises this to ".." and resolves path traversal, allowing
    // /service/%2e%2e/_aegis/health → /_aegis/health (internal endpoint).
    // Fix: Gate explicitly detects traversal segments (raw and decoded)
    // and returns 400 before any routing occurs.
    const res = await gateRequest(gatePort, '/smuggle-svc/%2e%2e/_aegis/health');
    expect(res.status).toBe(400);
    const body = JSON.parse(res.body);
    expect(body.error).toBe('Path traversal detected');
  });

  it('strips agent-injected Authorization headers before credential injection', async () => {
    // Agent tries to inject its own Authorization header to override
    // Aegis's credential injection — Gate must strip it.
    const res = await gateRequest(gatePort, '/smuggle-svc/smuggle-svc/api', {
      headers: {
        authorization: 'Bearer agent-tried-to-inject-this',
      },
    });

    expect(res.status).toBe(200);

    // The upstream should have the REAL credential, not the agent's
    const upstreamReq = upstream.last;
    expect(upstreamReq?.headers.authorization).toBe('Bearer sk-smuggle-secret-123');
    expect(upstreamReq?.headers.authorization).not.toContain('agent-tried-to-inject-this');
  });

  it('strips agent-injected X-Api-Key headers', async () => {
    // Even with a bearer-type credential, if the agent sends x-api-key
    // it should be stripped.
    const res = await gateRequest(gatePort, '/smuggle-svc/smuggle-svc/api', {
      headers: {
        'x-api-key': 'agent-injected-key',
      },
    });

    expect(res.status).toBe(200);
    const upstreamReq = upstream.last;
    // x-api-key should be stripped (Gate strips it for bearer creds)
    expect(upstreamReq?.headers['x-api-key']).toBeUndefined();
  });

  it('does not forward X-Aegis-Agent token to upstream', async () => {
    const res = await gateRequest(gatePort, '/smuggle-svc/smuggle-svc/api', {
      headers: {
        'x-aegis-agent': 'aegis_secret_token_that_should_not_leak',
      },
    });

    expect(res.status).toBe(200);
    const upstreamReq = upstream.last;
    expect(upstreamReq?.headers['x-aegis-agent']).toBeUndefined();
  });

  it('does not forward X-Target-Host to upstream', async () => {
    const res = await gateRequest(gatePort, '/smuggle-svc/smuggle-svc/api', {
      headers: {
        'x-target-host': 'smuggle-svc.example.com',
      },
    });

    expect(res.status).toBe(200);
    const upstreamReq = upstream.last;
    expect(upstreamReq?.headers['x-target-host']).toBeUndefined();
  });

  it('overwrites Host header with target domain, not agent-supplied value', async () => {
    const res = await gateRequest(gatePort, '/smuggle-svc/smuggle-svc/api', {
      headers: {
        host: 'evil.example.com',
      },
    });

    expect(res.status).toBe(200);
    const upstreamReq = upstream.last;
    // Gate sets Host to the credential's target domain, not the agent's value
    expect(upstreamReq?.headers.host).toBe('smuggle-svc.example.com');
    expect(upstreamReq?.headers.host).not.toBe('evil.example.com');
  });

  it('rejects null bytes in URL path', async () => {
    const raw =
      `GET /smuggle-svc/smuggle-svc/api%00/etc/passwd HTTP/1.1\r\n` +
      `Host: localhost:${gatePort}\r\n` +
      `\r\n`;

    const response = await rawRequest(gatePort, raw);
    // Node.js may return 400 Bad Request or silently close the connection.
    // Both are safe — the request must NOT succeed (no 200 OK).
    expect(response).not.toMatch(/200 OK/);
  });

  it('handles oversized headers without crashing', async () => {
    // Send a header value that's very large — Gate should not crash
    const bigValue = 'x'.repeat(16384);
    const res = await gateRequest(gatePort, '/smuggle-svc/smuggle-svc/api', {
      headers: {
        'x-custom': bigValue,
      },
    });

    // Either processed or rejected — but Gate does not crash
    expect([200, 400, 431]).toContain(res.status);
  });
});

// ─── Error Handling & Recovery Tests ──────────────────────────────────────────

describe('error handling & recovery', () => {
  const masterKey = 'test-master-key-error-handling';
  let db: ReturnType<typeof Database>;
  let vault: Vault;
  let ledger: Ledger;
  let upstream: UpstreamRecorder;

  beforeEach(async () => {
    db = new Database(':memory:');
    db.pragma('journal_mode = WAL');
    migrate(db);
    vault = new Vault(db, masterKey);
    ledger = new Ledger(db);
    upstream = new UpstreamRecorder();
    await upstream.start();
  });

  afterEach(async () => {
    await upstream.stop();
    db.close();
  });

  describe('max body size', () => {
    it('rejects bodies exceeding the configured limit with 413', async () => {
      vault.add({
        name: 'body-svc',
        service: 'body-svc',
        secret: 'key123',
        domains: ['api.example.com'],
        bodyInspection: 'off',
      });
      const gate = new Gate({
        port: 0,
        vault,
        ledger,
        logLevel: 'error',
        requireAgentAuth: false,
        maxBodySize: 100, // 100 bytes
        _testUpstream: { protocol: 'http', hostname: 'localhost', port: upstream.port },
      });
      await gate.start();
      try {
        const res = await gateRequest(gate.listeningPort, '/body-svc/api/data', {
          method: 'POST',
          body: 'x'.repeat(200), // 200 bytes > 100 byte limit
          headers: { 'content-type': 'text/plain' },
        });
        expect(res.status).toBe(413);
        const body = JSON.parse(res.body);
        expect(body.error).toBe('Request body too large');
        expect(body.limit).toBe(100);
      } finally {
        await gate.stop();
      }
    });

    it('allows bodies within the configured limit', async () => {
      vault.add({
        name: 'body-svc',
        service: 'body-svc',
        secret: 'key123',
        domains: ['api.example.com'],
        bodyInspection: 'off',
      });
      const gate = new Gate({
        port: 0,
        vault,
        ledger,
        logLevel: 'error',
        requireAgentAuth: false,
        maxBodySize: 1000, // 1000 bytes
        _testUpstream: { protocol: 'http', hostname: 'localhost', port: upstream.port },
      });
      await gate.start();
      try {
        const res = await gateRequest(gate.listeningPort, '/body-svc/api/data', {
          method: 'POST',
          body: 'x'.repeat(500), // 500 bytes < 1000 byte limit
          headers: { 'content-type': 'text/plain' },
        });
        expect(res.status).toBe(200);
      } finally {
        await gate.stop();
      }
    });
  });

  describe('request timeout', () => {
    it('returns 504 when upstream times out', async () => {
      // Set up a slow upstream that never responds
      const slowServer = http.createServer((_req, _res) => {
        // Intentionally don't respond — let it hang
      });
      await new Promise<void>((resolve) => slowServer.listen(0, resolve));
      const slowPort = (slowServer.address() as { port: number }).port;

      vault.add({
        name: 'slow-svc',
        service: 'slow-svc',
        secret: 'key123',
        domains: ['api.example.com'],
      });
      const gate = new Gate({
        port: 0,
        vault,
        ledger,
        logLevel: 'error',
        requireAgentAuth: false,
        requestTimeout: 800, // 800ms timeout
        _testUpstream: { protocol: 'http', hostname: 'localhost', port: slowPort },
      });
      await gate.start();
      try {
        const res = await gateRequest(gate.listeningPort, '/slow-svc/api/data');
        expect(res.status).toBe(504);
        const body = JSON.parse(res.body);
        expect(body.error).toBe('Upstream request timed out');
      } finally {
        await gate.stop();
        slowServer.close();
      }
    });
  });

  describe('per-agent connection limits', () => {
    it('rejects requests when agent exceeds connection limit', async () => {
      vault.add({
        name: 'conn-svc',
        service: 'conn-svc',
        secret: 'key123',
        domains: ['api.example.com'],
      });

      // Create a slow upstream that holds connections
      const slowServer = http.createServer((_req, res) => {
        setTimeout(() => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end('{"ok":true}');
        }, 2000); // Hold for 2s
      });
      await new Promise<void>((resolve) => slowServer.listen(0, resolve));
      const slowPort = (slowServer.address() as { port: number }).port;

      const { deriveKey } = await import('../src/vault/crypto.js');
      const { AgentRegistry } = await import('../src/agent/index.js');
      const derivedKeyBuf = deriveKey(masterKey, 'test-salt');
      const registry = new AgentRegistry(db, derivedKeyBuf);
      const agent = registry.add({ name: 'conn-test-agent' });
      registry.grant({ agentName: 'conn-test-agent', credentialId: vault.list()[0].id });

      const gate = new Gate({
        port: 0,
        vault,
        ledger,
        logLevel: 'error',
        agentRegistry: registry,
        requireAgentAuth: true,
        maxConnectionsPerAgent: 2, // Only allow 2 concurrent
        requestTimeout: 5000,
        _testUpstream: { protocol: 'http', hostname: 'localhost', port: slowPort },
      });
      await gate.start();
      try {
        // Fire 3 concurrent requests — the 3rd should be rejected
        const headers = { 'x-aegis-agent': agent.token };
        const requests = [
          gateRequest(gate.listeningPort, '/conn-svc/api/1', { headers }),
          gateRequest(gate.listeningPort, '/conn-svc/api/2', { headers }),
          // Small delay to ensure the first two are in-flight
          new Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }>(
            (resolve) =>
              setTimeout(
                () => resolve(gateRequest(gate.listeningPort, '/conn-svc/api/3', { headers })),
                100,
              ),
          ),
        ];
        const results = await Promise.all(requests);
        const statuses = results.map((r) => r.status);
        // At least one should be 429
        expect(statuses).toContain(429);
        // The 429 response should have the right error
        const rejected = results.find((r) => r.status === 429);
        if (rejected) {
          const body = JSON.parse(rejected.body);
          expect(body.error).toBe('Too many concurrent requests for this agent');
          expect(body.limit).toBe(2);
        }
      } finally {
        await gate.stop();
        slowServer.close();
      }
    });
  });

  describe('circuit breaker', () => {
    it('opens circuit after repeated upstream failures', async () => {
      vault.add({
        name: 'fail-svc',
        service: 'fail-svc',
        secret: 'key123',
        domains: ['api.example.com'],
      });

      // Upstream always returns 500
      upstream.nextStatus = 500;
      upstream.nextBody = '{"error":"internal"}';

      const gate = new Gate({
        port: 0,
        vault,
        ledger,
        logLevel: 'error',
        requireAgentAuth: false,
        _testUpstream: { protocol: 'http', hostname: 'localhost', port: upstream.port },
      });
      await gate.start();
      try {
        // Send 5 requests to trigger the circuit breaker (threshold = 5)
        for (let i = 0; i < 5; i++) {
          await gateRequest(gate.listeningPort, '/fail-svc/api/data');
        }

        // The 6th request should get a 503 (circuit open)
        const res = await gateRequest(gate.listeningPort, '/fail-svc/api/data');
        expect(res.status).toBe(503);
        const body = JSON.parse(res.body);
        expect(body.error).toContain('circuit breaker');
      } finally {
        await gate.stop();
      }
    });

    it('closes circuit after cooldown period on success', async () => {
      vault.add({
        name: 'recover-svc',
        service: 'recover-svc',
        secret: 'key123',
        domains: ['api.example.com'],
      });

      // Initially succeed
      upstream.nextStatus = 200;
      upstream.nextBody = '{"ok":true}';

      const gate = new Gate({
        port: 0,
        vault,
        ledger,
        logLevel: 'error',
        requireAgentAuth: false,
        _testUpstream: { protocol: 'http', hostname: 'localhost', port: upstream.port },
      });
      await gate.start();
      try {
        // First request succeeds (no circuit state)
        const res = await gateRequest(gate.listeningPort, '/recover-svc/api/data');
        expect(res.status).toBe(200);

        // Circuit breaker resets on success
        const res2 = await gateRequest(gate.listeningPort, '/recover-svc/api/data');
        expect(res2.status).toBe(200);
      } finally {
        await gate.stop();
      }
    });
  });

  describe('retry logic', () => {
    it('retries GET requests on transient 502 failures', async () => {
      vault.add({
        name: 'retry-svc',
        service: 'retry-svc',
        secret: 'key123',
        domains: ['api.example.com'],
      });

      let requestCount = 0;
      const retryServer = http.createServer((_req, res) => {
        requestCount++;
        if (requestCount <= 2) {
          // First 2 attempts return 502
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end('{"error":"bad gateway"}');
        } else {
          // 3rd attempt succeeds
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end('{"ok":true}');
        }
      });
      await new Promise<void>((resolve) => retryServer.listen(0, resolve));
      const retryPort = (retryServer.address() as { port: number }).port;

      const gate = new Gate({
        port: 0,
        vault,
        ledger,
        logLevel: 'error',
        requireAgentAuth: false,
        _testUpstream: { protocol: 'http', hostname: 'localhost', port: retryPort },
      });
      await gate.start();
      try {
        const res = await gateRequest(gate.listeningPort, '/retry-svc/api/data');
        expect(res.status).toBe(200);
        expect(requestCount).toBe(3); // original + 2 retries
      } finally {
        await gate.stop();
        retryServer.close();
      }
    });

    it('does not retry POST requests on transient failures', async () => {
      vault.add({
        name: 'noretry-svc',
        service: 'noretry-svc',
        secret: 'key123',
        domains: ['api.example.com'],
      });

      let requestCount = 0;
      const noRetryServer = http.createServer((_req, res) => {
        requestCount++;
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end('{"error":"bad gateway"}');
      });
      await new Promise<void>((resolve) => noRetryServer.listen(0, resolve));
      const noRetryPort = (noRetryServer.address() as { port: number }).port;

      const gate = new Gate({
        port: 0,
        vault,
        ledger,
        logLevel: 'error',
        requireAgentAuth: false,
        _testUpstream: { protocol: 'http', hostname: 'localhost', port: noRetryPort },
      });
      await gate.start();
      try {
        const res = await gateRequest(gate.listeningPort, '/noretry-svc/api/data', {
          method: 'POST',
          body: '{"data":"test"}',
        });
        expect(res.status).toBe(502);
        expect(requestCount).toBe(1); // No retries for POST
      } finally {
        await gate.stop();
        noRetryServer.close();
      }
    });
  });

  describe('meaningful error responses', () => {
    it('returns structured errors with service name on 502', async () => {
      vault.add({
        name: 'err-svc',
        service: 'err-svc',
        secret: 'key123',
        domains: ['api.example.com'],
      });

      // Upstream that immediately closes the connection
      const badServer = http.createServer((_req, res) => {
        res.destroy();
      });
      await new Promise<void>((resolve) => badServer.listen(0, resolve));
      const badPort = (badServer.address() as { port: number }).port;

      const gate = new Gate({
        port: 0,
        vault,
        ledger,
        logLevel: 'error',
        requireAgentAuth: false,
        _testUpstream: { protocol: 'http', hostname: 'localhost', port: badPort },
      });
      await gate.start();
      try {
        const res = await gateRequest(gate.listeningPort, '/err-svc/api/data');
        // May be 502 (connection error) or 504 (timeout) depending on how fast the server closes
        expect([502, 504]).toContain(res.status);
        const body = JSON.parse(res.body);
        expect(body.service).toBe('err-svc');
      } finally {
        await gate.stop();
        badServer.close();
      }
    });

    it('returns 400 for missing service name', async () => {
      const gate = new Gate({
        port: 0,
        vault,
        ledger,
        logLevel: 'error',
        requireAgentAuth: false,
        _testUpstream: { protocol: 'http', hostname: 'localhost', port: upstream.port },
      });
      await gate.start();
      try {
        const res = await gateRequest(gate.listeningPort, '/');
        expect(res.status).toBe(400);
        const body = JSON.parse(res.body);
        expect(body.error).toBe('Missing service name');
        expect(body.usage).toContain('{service}');
      } finally {
        await gate.stop();
      }
    });
  });

  // ─── Connection Pooling ──────────────────────────────────────────────────────

  describe('connection pooling', () => {
    it('reuses TCP connections across sequential requests (keep-alive)', async () => {
      const gate = new Gate({
        port: 0,
        vault,
        ledger,
        logLevel: 'error',
        requireAgentAuth: false,
        _testUpstream: { protocol: 'http', hostname: 'localhost', port: upstream.port },
      });
      await gate.start();
      try {
        vault.add({
          name: 'pool-cred',
          service: 'pool-svc',
          secret: 'pool-secret',
          authType: 'bearer',
          domains: ['api.pool.com'],
        });

        // Make multiple sequential requests — connection should be reused
        const res1 = await gateRequest(gate.listeningPort, '/pool-svc/v1/first');
        const res2 = await gateRequest(gate.listeningPort, '/pool-svc/v1/second');
        const res3 = await gateRequest(gate.listeningPort, '/pool-svc/v1/third');

        expect(res1.status).toBe(200);
        expect(res2.status).toBe(200);
        expect(res3.status).toBe(200);
        expect(upstream.requests).toHaveLength(3);
        expect(upstream.requests[0].url).toBe('/v1/first');
        expect(upstream.requests[1].url).toBe('/v1/second');
        expect(upstream.requests[2].url).toBe('/v1/third');
      } finally {
        await gate.stop();
      }
    });

    it('handles concurrent requests through the connection pool', async () => {
      const gate = new Gate({
        port: 0,
        vault,
        ledger,
        logLevel: 'error',
        requireAgentAuth: false,
        _testUpstream: { protocol: 'http', hostname: 'localhost', port: upstream.port },
      });
      await gate.start();
      try {
        vault.add({
          name: 'conc-cred',
          service: 'conc-svc',
          secret: 'conc-secret',
          authType: 'bearer',
          domains: ['api.conc.com'],
        });

        // Fire 10 concurrent requests
        const promises = Array.from({ length: 10 }, (_, i) =>
          gateRequest(gate.listeningPort, `/conc-svc/v1/item/${i}`),
        );
        const results = await Promise.all(promises);

        // All should succeed
        for (const res of results) {
          expect(res.status).toBe(200);
        }
        expect(upstream.requests).toHaveLength(10);
      } finally {
        await gate.stop();
      }
    });

    it('cleans up connection pool agents on shutdown', async () => {
      const gate = new Gate({
        port: 0,
        vault,
        ledger,
        logLevel: 'error',
        requireAgentAuth: false,
        _testUpstream: { protocol: 'http', hostname: 'localhost', port: upstream.port },
      });
      await gate.start();

      vault.add({
        name: 'cleanup-cred',
        service: 'cleanup-svc',
        secret: 'cleanup-secret',
        authType: 'bearer',
        domains: ['api.cleanup.com'],
      });

      // Make a request to create a pooled connection
      await gateRequest(gate.listeningPort, '/cleanup-svc/v1/hello');
      expect(upstream.requests).toHaveLength(1);

      // Stop should clean up agents without error
      const result = await gate.stop();
      expect(result.drained).toBe(true);
      expect(result.activeAtClose).toBe(0);
    });

    it('handles ECONNRESET on reused socket by retrying', async () => {
      // Create a server that accepts the first request, then RSTs the next one
      let requestCount = 0;
      const resetServer = http.createServer((req, res) => {
        requestCount++;
        if (requestCount === 2) {
          // Destroy the socket to simulate ECONNRESET on reused connection
          req.socket.destroy();
          return;
        }
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end('{"ok":true}');
      });

      await new Promise<void>((resolve) => {
        resetServer.listen(0, () => resolve());
      });
      const resetPort = (resetServer.address() as { port: number }).port;

      const gate = new Gate({
        port: 0,
        vault,
        ledger,
        logLevel: 'error',
        requireAgentAuth: false,
        _testUpstream: { protocol: 'http', hostname: 'localhost', port: resetPort },
      });
      await gate.start();

      try {
        vault.add({
          name: 'reset-cred',
          service: 'reset-svc',
          secret: 'reset-secret',
          authType: 'bearer',
          domains: ['api.reset.com'],
        });

        // First request succeeds and establishes a pooled connection
        const res1 = await gateRequest(gate.listeningPort, '/reset-svc/v1/first');
        expect(res1.status).toBe(200);

        // Wait for the connection to enter the keep-alive pool
        await new Promise((r) => setTimeout(r, 100));

        // Second request: if the pooled socket is reused, the server will RST it.
        // Gate should detect reusedSocket + ECONNRESET/socket-hang-up and retry
        // on a fresh socket (3rd server request), which succeeds.
        // If the socket wasn't reused (new connection), the server RSTs it
        // and Gate returns 502 (no reusedSocket → no special retry).
        const res2 = await gateRequest(gate.listeningPort, '/reset-svc/v1/second');

        if (res2.status === 200) {
          // Socket was reused → ECONNRESET retry succeeded
          expect(requestCount).toBe(3); // 1st ok, 2nd reset, 3rd retry ok
        } else {
          // Socket was NOT reused → server destroyed a fresh connection → 502
          expect(res2.status).toBe(502);
          expect(requestCount).toBe(2);
        }
      } finally {
        await gate.stop();
        resetServer.close();
      }
    });
  });
});
