import * as fs from 'node:fs';
import * as http from 'node:http';
import * as https from 'node:https';
import type pino from 'pino';
import type { Agent, AgentRegistry } from '../agent/index.js';
import type { Ledger } from '../ledger/index.js';
import { createLogger, generateRequestId } from '../logger/index.js';
import type { AegisMetrics } from '../metrics/index.js';
import type { Policy } from '../policy/index.js';
import { buildPolicyMap, evaluatePolicy, loadPoliciesFromDirectory } from '../policy/index.js';
import type { CredentialWithSecret, Vault } from '../vault/index.js';
import { VERSION } from '../version.js';
import type { WebhookManager } from '../webhook/index.js';
import { BodyInspector } from './body-inspector.js';
import { parseRateLimit, type RateLimit, RateLimiter } from './rate-limiter.js';

// ─── Scope → HTTP Method Mapping ─────────────────────────────────────────────
// Credential scopes restrict which HTTP methods are permitted.
//   "read"  → GET, HEAD, OPTIONS  (safe/idempotent methods)
//   "write" → POST, PUT, PATCH, DELETE  (state-changing methods)
//   "*"     → all methods (default)

const READ_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Check whether an HTTP method is permitted by a credential's scopes.
 * Returns true if the method is allowed, false if blocked.
 */
export function methodMatchesScope(method: string, scopes: string[]): boolean {
  if (scopes.includes('*')) return true;
  const upper = method.toUpperCase();
  if (scopes.includes('read') && READ_METHODS.has(upper)) return true;
  if (scopes.includes('write') && WRITE_METHODS.has(upper)) return true;
  return false;
}

export interface TlsOptions {
  /** Path to the PEM-encoded certificate file */
  certPath: string;
  /** Path to the PEM-encoded private key file */
  keyPath: string;
}

export interface GateOptions {
  port: number;
  vault: Vault;
  ledger: Ledger;
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
  /** TLS configuration — if provided, Gate starts as HTTPS */
  tls?: TlsOptions;
  /** Maximum time (ms) to wait for in-flight requests during shutdown (default: 10000) */
  shutdownTimeoutMs?: number;
  /** Agent registry — required when requireAgentAuth is true */
  agentRegistry?: AgentRegistry;
  /** When true, every request must include a valid X-Aegis-Agent token */
  requireAgentAuth?: boolean;
  /** Directory containing YAML policy files — enables policy evaluation */
  policyDir?: string;
  /** Policy enforcement mode: "enforce" blocks violations, "dry-run" logs but allows (default: "enforce") */
  policyMode?: 'enforce' | 'dry-run';
  /** Prometheus metrics collector — if provided, Gate records request/block metrics */
  metrics?: AegisMetrics;
  /** Webhook manager — if provided, Gate emits webhook events on blocks */
  webhooks?: WebhookManager;
  /** Callback fired after every audit entry is logged — used by dashboard for live feed */
  onAuditEntry?: (entry: AuditBroadcast) => void;
  /** Testing: redirect outbound requests to a local server */
  _testUpstream?: { protocol: 'http' | 'https'; hostname: string; port: number };
  /** Testing: inject policies directly without loading from disk */
  _testPolicies?: Map<string, Policy>;
}

/** Shape of the audit entry broadcast to the dashboard live feed. */
export interface AuditBroadcast {
  timestamp: string;
  credentialId: string | null;
  credentialName: string | null;
  service: string;
  targetDomain: string;
  method: string;
  path: string;
  status: 'allowed' | 'blocked' | 'system';
  blockedReason: string | null;
  responseCode: number | null;
  agentName: string | null;
  agentTokenPrefix: string | null;
  channel: 'gate' | 'mcp';
}

/**
 * Aegis Gate — HTTP proxy that sits between an AI agent and external APIs.
 *
 * The agent makes requests to: http://localhost:{port}/{service}/actual/api/path
 * Gate resolves the service → looks up credential → injects auth → forwards to real API.
 *
 * The agent NEVER sees the credential.
 */
export class Gate {
  private server: http.Server | https.Server | null = null;
  private vault: Vault;
  private ledger: Ledger;
  private port: number;
  private logger: pino.Logger;
  private tlsOptions?: TlsOptions;
  private testUpstream?: { protocol: 'http' | 'https'; hostname: string; port: number };
  private rateLimiter: RateLimiter;
  private bodyInspector: BodyInspector;
  private shuttingDown = false;
  private activeRequests = 0;
  private shutdownTimeoutMs: number;
  private agentRegistry?: AgentRegistry;
  private requireAgentAuth: boolean;
  private policyMap: Map<string, Policy>;
  private policyMode: 'enforce' | 'dry-run';
  private policyDir?: string;
  private policyWatcher?: fs.FSWatcher;
  private metrics?: AegisMetrics;
  private webhooks?: WebhookManager;
  private onAuditEntry?: (entry: AuditBroadcast) => void;

  constructor(options: GateOptions) {
    this.vault = options.vault;
    this.ledger = options.ledger;
    this.port = options.port;
    this.logger = createLogger({
      module: 'gate',
      level: options.logLevel ?? 'info',
    });
    this.tlsOptions = options.tls;
    this.testUpstream = options._testUpstream;
    this.rateLimiter = new RateLimiter();
    this.bodyInspector = new BodyInspector();
    this.shutdownTimeoutMs = options.shutdownTimeoutMs ?? 10_000;
    this.agentRegistry = options.agentRegistry;
    this.requireAgentAuth = options.requireAgentAuth ?? false;
    this.policyMode = options.policyMode ?? 'enforce';
    this.policyDir = options.policyDir;
    this.metrics = options.metrics;
    this.webhooks = options.webhooks;
    this.onAuditEntry = options.onAuditEntry;

    // Load policies from disk or test injection
    if (options._testPolicies) {
      this.policyMap = options._testPolicies;
    } else if (options.policyDir) {
      this.policyMap = this.loadPolicies(options.policyDir);
    } else {
      this.policyMap = new Map();
    }
  }

  /**
   * Start the Gate proxy server.
   */
  /**
   * Whether the Gate is running with TLS.
   */
  get isTls(): boolean {
    return this.tlsOptions !== undefined;
  }

  /**
   * Whether policies are loaded and active.
   */
  get hasPolicies(): boolean {
    return this.policyMap.size > 0;
  }

  /**
   * The current policy enforcement mode.
   */
  get currentPolicyMode(): 'enforce' | 'dry-run' {
    return this.policyMode;
  }

  /**
   * Load policies from a directory.
   */
  private loadPolicies(dir: string): Map<string, Policy> {
    try {
      const results = loadPoliciesFromDirectory(dir);
      const map = buildPolicyMap(results);
      const valid = results.filter((r) => r.valid).length;
      const invalid = results.filter((r) => !r.valid).length;
      this.logger.info({ dir, valid, invalid }, `Loaded ${valid} policy file(s)`);
      return map;
    } catch (err) {
      this.logger.warn({ dir, err }, 'Failed to load policies');
      return new Map();
    }
  }

  /**
   * Reload policies from the configured directory.
   * Called on file system changes for hot-reload.
   */
  reloadPolicies(): void {
    if (!this.policyDir) return;
    this.policyMap = this.loadPolicies(this.policyDir);
    this.logger.info({ count: this.policyMap.size }, 'Policies reloaded');
  }

  /**
   * Start watching the policy directory for changes (hot-reload).
   * Debounces changes to avoid rapid reloads.
   */
  private startPolicyWatcher(): void {
    if (!this.policyDir) return;

    let debounceTimer: ReturnType<typeof setTimeout> | null = null;

    try {
      this.policyWatcher = fs.watch(this.policyDir, { persistent: false }, () => {
        if (debounceTimer) clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
          this.logger.info('Policy files changed — reloading');
          this.reloadPolicies();
        }, 500);
      });
    } catch (err) {
      this.logger.warn({ err }, 'Could not watch policy directory');
    }
  }

  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      const handler = (req: http.IncomingMessage, res: http.ServerResponse): void => {
        this.handleRequest(req, res);
      };

      if (this.tlsOptions) {
        // Validate TLS files before attempting to create the server
        for (const [label, filePath] of [
          ['certificate', this.tlsOptions.certPath],
          ['private key', this.tlsOptions.keyPath],
        ] as const) {
          if (!fs.existsSync(filePath)) {
            throw new Error(`TLS ${label} file not found: ${filePath}`);
          }
          const content = fs.readFileSync(filePath, 'utf-8');
          const expectedMarker =
            label === 'certificate' ? '-----BEGIN CERTIFICATE-----' : '-----BEGIN';
          if (!content.includes(expectedMarker)) {
            throw new Error(
              `TLS ${label} file is not valid PEM format: ${filePath}\n` +
                `  Expected a PEM file starting with "${expectedMarker}".\n` +
                `  Generate a self-signed cert with:\n` +
                `  openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=localhost'`,
            );
          }
        }
        const cert = fs.readFileSync(this.tlsOptions.certPath);
        const key = fs.readFileSync(this.tlsOptions.keyPath);
        this.server = https.createServer({ cert, key }, handler);
      } else {
        this.server = http.createServer(handler);
        this.logger.warn(
          'Gate is running without TLS — credentials are transmitted in cleartext on localhost',
        );
      }

      // Handle server errors (e.g. EADDRINUSE) before they become unhandled events
      this.server.once('error', (err: NodeJS.ErrnoException) => {
        if (err.code === 'EADDRINUSE') {
          reject(
            new Error(
              `Port ${this.port} is already in use.\n` +
                `  Another process (or another Aegis instance) is using this port.\n` +
                `  Either stop that process or use a different port:\n` +
                `    aegis gate --port <port>`,
            ),
          );
        } else {
          reject(err);
        }
      });

      this.server.listen(this.port, () => {
        // Update port in case 0 was passed (OS-assigned)
        const addr = this.server?.address();
        if (addr && typeof addr === 'object') {
          this.port = addr.port;
        }
        const protocol = this.tlsOptions ? 'https' : 'http';
        this.logger.info(
          { protocol, port: this.port },
          `Aegis Gate listening on ${protocol}://localhost:${this.port}`,
        );
        this.logger.info(
          { port: this.port },
          'Agent requests → localhost:{port}/{service}/path → credential injected → forwarded',
        );
        if (this.policyMap.size > 0) {
          this.logger.info(
            { count: this.policyMap.size, mode: this.policyMode },
            'Policy engine active',
          );
          this.startPolicyWatcher();
        }
        resolve();
      });
    });
  }

  /**
   * The port the server is listening on (may differ from constructor if 0 was passed).
   */
  get listeningPort(): number {
    return this.port;
  }

  /**
   * Stop the Gate proxy server gracefully.
   *
   * 1. Sets `shuttingDown = true` — new requests receive 503 Service Unavailable.
   * 2. Waits for in-flight requests to complete (up to `shutdownTimeoutMs`).
   * 3. Closes the server socket and returns.
   *
   * During the drain phase the server still accepts connections so clients get
   * a clean 503 rather than a connection-refused error.
   */
  stop(): Promise<{ drained: boolean; activeAtClose: number }> {
    this.shuttingDown = true;

    // Stop watching policy files
    if (this.policyWatcher) {
      this.policyWatcher.close();
      this.policyWatcher = undefined;
    }

    return new Promise((resolve) => {
      if (!this.server) {
        resolve({ drained: true, activeAtClose: 0 });
        return;
      }

      const finish = (drained: boolean): void => {
        const activeAtClose = this.activeRequests;
        if (!drained) {
          // Force-destroy remaining connections so server.close() can complete
          this.server?.closeAllConnections();
        }
        this.server?.close(() => {
          // shuttingDown stays true — a stopped Gate is permanently shut down.
          // Outbound proxy requests may still error asynchronously; keeping
          // shuttingDown=true ensures error handlers skip Ledger writes.
          this.server = null;
          resolve({ drained, activeAtClose });
        });
      };

      // If no active requests, shut down immediately
      if (this.activeRequests === 0) {
        this.logger.info('No in-flight requests — shutting down immediately');
        finish(true);
        return;
      }

      this.logger.info({ activeRequests: this.activeRequests }, 'Draining in-flight requests');

      // Poll for active requests to reach 0
      const drainInterval = setInterval(() => {
        if (this.activeRequests === 0) {
          clearInterval(drainInterval);
          clearTimeout(forceTimeout);
          this.logger.info('All in-flight requests drained — shutdown complete');
          finish(true);
        }
      }, 50);

      // Force-close after timeout
      const forceTimeout = setTimeout(() => {
        clearInterval(drainInterval);
        this.logger.warn(
          { timeoutMs: this.shutdownTimeoutMs, activeRequests: this.activeRequests },
          'Shutdown timeout — forcing close',
        );
        finish(false);
      }, this.shutdownTimeoutMs);
    });
  }

  /**
   * Whether the Gate is currently shutting down (draining in-flight requests).
   */
  get isShuttingDown(): boolean {
    return this.shuttingDown;
  }

  /**
   * The number of currently in-flight requests.
   */
  get inFlightRequests(): number {
    return this.activeRequests;
  }

  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    // Reject new requests during shutdown
    if (this.shuttingDown) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(`${JSON.stringify({ error: 'Aegis Gate is shutting down' })}\n`);
      return;
    }

    this.activeRequests++;
    const decrementActive = (): void => {
      this.activeRequests = Math.max(0, this.activeRequests - 1);
    };

    // Ensure we decrement when the response finishes (or the connection drops)
    res.on('close', decrementActive);

    // Create a per-request child logger with a correlation ID
    const requestId = generateRequestId();
    const reqLog = this.logger.child({ requestId });

    try {
      const reqUrl = new URL(req.url ?? '/', `http://localhost:${this.port}`);
      const pathParts = reqUrl.pathname.split('/').filter(Boolean);

      // Health check
      if (pathParts[0] === '_aegis' && pathParts[1] === 'health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(`${JSON.stringify({ status: 'ok', version: VERSION })}\n`);
        return;
      }

      // Stats endpoint
      if (pathParts[0] === '_aegis' && pathParts[1] === 'stats') {
        const stats = this.ledger.stats();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(`${JSON.stringify(stats)}\n`);
        return;
      }

      // Prometheus metrics endpoint
      if (pathParts[0] === '_aegis' && pathParts[1] === 'metrics') {
        if (this.metrics) {
          const metricsOutput = await this.metrics.getMetricsOutput();
          res.writeHead(200, { 'Content-Type': this.metrics.getContentType() });
          res.end(metricsOutput);
        } else {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(`${JSON.stringify({ error: 'Metrics not enabled' })}\n`);
        }
        return;
      }

      // ─── Agent Authentication ──────────────────────────────────────
      // If agent auth is required, validate the X-Aegis-Agent token.
      // The authenticated agent identity flows through to scoping,
      // rate limiting, and audit trail entries.
      let authenticatedAgent: Agent | undefined;
      if (this.requireAgentAuth && this.agentRegistry) {
        const agentToken = req.headers['x-aegis-agent'] as string | undefined;
        if (!agentToken) {
          this.auditBlocked({
            service: pathParts[0] ?? 'unknown',
            targetDomain: 'unknown',
            method: req.method ?? 'GET',
            path: req.url ?? '/',
            reason: 'Missing X-Aegis-Agent header — agent authentication required',
          });
          reqLog.warn(
            { service: pathParts[0] ?? 'unknown' },
            'Blocked: missing X-Aegis-Agent header',
          );
          this.metrics?.recordBlocked(pathParts[0] ?? 'unknown', 'agent_auth_missing');
          this.webhooks?.emit('agent_auth_failure', {
            service: pathParts[0] ?? 'unknown',
            reason: 'Missing X-Aegis-Agent header',
            method: req.method ?? 'GET',
            path: req.url ?? '/',
          });
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(
            `${JSON.stringify({
              error: 'Agent authentication required',
              hint: 'Include X-Aegis-Agent header with your agent token',
            })}\n`,
          );
          return;
        }

        const agent = this.agentRegistry.validateToken(agentToken);
        if (!agent) {
          this.auditBlocked({
            service: pathParts[0] ?? 'unknown',
            targetDomain: 'unknown',
            method: req.method ?? 'GET',
            path: req.url ?? '/',
            reason: 'Invalid agent token in X-Aegis-Agent header',
          });
          reqLog.warn({ service: pathParts[0] ?? 'unknown' }, 'Blocked: invalid agent token');
          this.metrics?.recordBlocked(pathParts[0] ?? 'unknown', 'agent_auth_invalid');
          this.webhooks?.emit('agent_auth_failure', {
            service: pathParts[0] ?? 'unknown',
            reason: 'Invalid agent token',
            method: req.method ?? 'GET',
            path: req.url ?? '/',
          });
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(
            `${JSON.stringify({
              error: 'Invalid agent token',
              hint: 'Check your X-Aegis-Agent token or register a new agent with: aegis agent add',
            })}\n`,
          );
          return;
        }

        authenticatedAgent = agent;
        reqLog.debug({ agent: agent.name, tokenPrefix: agent.tokenPrefix }, 'Authenticated agent');
      } else if (this.agentRegistry) {
        // Agent auth not required, but optionally identify the agent if a token is provided
        const agentToken = req.headers['x-aegis-agent'] as string | undefined;
        if (agentToken) {
          const agent = this.agentRegistry.validateToken(agentToken);
          if (agent) {
            authenticatedAgent = agent;
            reqLog.debug({ agent: agent.name, tokenPrefix: agent.tokenPrefix }, 'Identified agent');
          }
        }
      }

      // Route format: /{service}/rest/of/the/path
      const serviceName = pathParts[0];
      if (!serviceName) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(
          `${JSON.stringify({
            error: 'Missing service name',
            usage: 'GET http://localhost:{port}/{service}/api/path',
          })}\n`,
        );
        return;
      }

      // Look up credential for this service
      const credential = this.vault.getByService(serviceName);
      if (!credential) {
        this.auditBlocked({
          service: serviceName,
          targetDomain: 'unknown',
          method: req.method ?? 'GET',
          path: req.url ?? '/',
          reason: `No credential found for service: ${serviceName}`,
          agentName: authenticatedAgent?.name,
          agentTokenPrefix: authenticatedAgent?.tokenPrefix,
        });
        reqLog.warn({ service: serviceName }, 'Blocked: no credential found');
        this.metrics?.recordBlocked(serviceName, 'no_credential', authenticatedAgent?.name);
        this.webhooks?.emit('blocked_request', {
          service: serviceName,
          reason: 'no_credential',
          method: req.method ?? 'GET',
          path: req.url ?? '/',
          agent: authenticatedAgent?.name,
        });
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(
          `${JSON.stringify({
            error: `No credential registered for service: ${serviceName}`,
            hint: `Run: aegis vault add --name ${serviceName} --service ${serviceName} --secret YOUR_KEY --domains api.example.com`,
          })}\n`,
        );
        return;
      }

      // TTL enforcement: reject expired credentials
      if (this.vault.isExpired(credential)) {
        this.auditBlocked({
          service: serviceName,
          targetDomain: credential.domains[0] ?? 'unknown',
          method: req.method ?? 'GET',
          path: req.url ?? '/',
          reason: `Credential "${credential.name}" expired at ${credential.expiresAt}`,
          agentName: authenticatedAgent?.name,
          agentTokenPrefix: authenticatedAgent?.tokenPrefix,
        });
        reqLog.warn(
          { credential: credential.name, expiredAt: credential.expiresAt },
          'Blocked: credential expired',
        );
        this.metrics?.recordBlocked(serviceName, 'credential_expired', authenticatedAgent?.name);
        this.webhooks?.emit('credential_expiry', {
          service: serviceName,
          credential: credential.name,
          expiredAt: credential.expiresAt,
          agent: authenticatedAgent?.name,
        });
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(
          `${JSON.stringify({
            error: 'Credential has expired',
            credential: credential.name,
            expiredAt: credential.expiresAt,
            hint: `Rotate with: aegis vault rotate --name ${credential.name} --secret NEW_SECRET`,
          })}\n`,
        );
        return;
      }

      // ─── Credential Scope Enforcement ────────────────────────────────
      // If the credential has scopes (read/write/*), verify the HTTP
      // method is permitted. read → GET/HEAD/OPTIONS, write → POST/PUT/PATCH/DELETE.
      const reqMethod = req.method ?? 'GET';
      if (!methodMatchesScope(reqMethod, credential.scopes)) {
        const scopeList = credential.scopes.join(', ');
        this.auditBlocked({
          service: serviceName,
          targetDomain: credential.domains[0] ?? 'unknown',
          method: reqMethod,
          path: req.url ?? '/',
          reason: `Method "${reqMethod}" not permitted by credential scopes [${scopeList}]`,
          agentName: authenticatedAgent?.name,
          agentTokenPrefix: authenticatedAgent?.tokenPrefix,
        });
        reqLog.warn(
          { credential: credential.name, method: reqMethod, scopes: credential.scopes },
          'Blocked: credential scope violation',
        );
        this.metrics?.recordBlocked(serviceName, 'credential_scope', authenticatedAgent?.name);
        this.webhooks?.emit('blocked_request', {
          service: serviceName,
          reason: 'credential_scope',
          credential: credential.name,
          method: reqMethod,
          scopes: credential.scopes,
          agent: authenticatedAgent?.name,
          path: req.url ?? '/',
        });
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(
          `${JSON.stringify({
            error: 'Method not permitted by credential scopes',
            method: reqMethod,
            scopes: credential.scopes,
            hint: `Update scopes with: aegis vault update --name ${credential.name} --scopes ${scopeList},${reqMethod === 'GET' ? 'read' : 'write'}`,
          })}\n`,
        );
        return;
      }

      // ─── Agent Credential Scoping ──────────────────────────────────
      // If agent auth is required, verify this agent has been granted
      // access to the requested credential.
      if (authenticatedAgent && this.requireAgentAuth && this.agentRegistry) {
        if (!this.agentRegistry.hasAccess(authenticatedAgent.id, credential.id)) {
          this.auditBlocked({
            service: serviceName,
            targetDomain: credential.domains[0] ?? 'unknown',
            method: req.method ?? 'GET',
            path: req.url ?? '/',
            reason: `Agent "${authenticatedAgent.name}" not granted access to credential "${credential.name}"`,
            agentName: authenticatedAgent.name,
            agentTokenPrefix: authenticatedAgent.tokenPrefix,
          });
          reqLog.warn(
            { agent: authenticatedAgent.name, credential: credential.name },
            'Blocked: agent not scoped to credential',
          );
          this.metrics?.recordBlocked(serviceName, 'agent_scope', authenticatedAgent.name);
          this.webhooks?.emit('blocked_request', {
            service: serviceName,
            reason: 'agent_scope',
            agent: authenticatedAgent.name,
            credential: credential.name,
            method: req.method ?? 'GET',
            path: req.url ?? '/',
          });
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(
            `${JSON.stringify({
              error: 'Agent not granted access to this credential',
              agent: authenticatedAgent.name,
              credential: credential.name,
              hint: `Grant access with: aegis agent grant --agent ${authenticatedAgent.name} --credential ${credential.name}`,
            })}\n`,
          );
          return;
        }
      }

      // ─── Policy Evaluation ─────────────────────────────────────────
      // If the authenticated agent has a policy, evaluate the request
      // against it. Policy checks: service access, method restrictions,
      // path restrictions, time-of-day windows.
      if (authenticatedAgent && this.policyMap.size > 0) {
        const agentPolicy = this.policyMap.get(authenticatedAgent.name);
        if (agentPolicy) {
          const remainingPathForPolicy = `/${pathParts.slice(1).join('/')}`;
          const evaluation = evaluatePolicy(agentPolicy, {
            service: serviceName,
            method: req.method ?? 'GET',
            path: remainingPathForPolicy,
          });

          if (!evaluation.allowed) {
            const reason = `Policy violation: ${evaluation.reason}`;

            if (this.policyMode === 'enforce') {
              this.auditBlocked({
                service: serviceName,
                targetDomain: credential.domains[0] ?? 'unknown',
                method: req.method ?? 'GET',
                path: req.url ?? '/',
                reason,
                agentName: authenticatedAgent.name,
                agentTokenPrefix: authenticatedAgent.tokenPrefix,
              });
              reqLog.warn(
                {
                  agent: authenticatedAgent.name,
                  violation: evaluation.violation,
                  reason: evaluation.reason,
                },
                'Blocked: policy violation',
              );
              this.metrics?.recordBlocked(serviceName, 'policy_violation', authenticatedAgent.name);
              this.webhooks?.emit('blocked_request', {
                service: serviceName,
                reason: 'policy_violation',
                agent: authenticatedAgent.name,
                violation: evaluation.violation,
                detail: evaluation.reason,
                method: req.method ?? 'GET',
                path: req.url ?? '/',
              });
              res.writeHead(403, { 'Content-Type': 'application/json' });
              res.end(
                `${JSON.stringify({
                  error: 'Policy violation',
                  agent: authenticatedAgent.name,
                  violation: evaluation.violation,
                  reason: evaluation.reason,
                  hint: "Update the agent's policy file to permit this request",
                })}\n`,
              );
              return;
            }

            // Dry-run mode: log the would-be violation but allow the request through
            this.auditBlocked({
              service: serviceName,
              targetDomain: credential.domains[0] ?? 'unknown',
              method: req.method ?? 'GET',
              path: req.url ?? '/',
              reason: `POLICY_DRY_RUN: ${evaluation.reason}`,
              agentName: authenticatedAgent.name,
              agentTokenPrefix: authenticatedAgent.tokenPrefix,
            });
            reqLog.info(
              { agent: authenticatedAgent.name, reason: evaluation.reason },
              'Dry-run: would block',
            );
          }

          // ─── Policy Rate Limiting ────────────────────────────────
          // If the matched rule has a rateLimit, enforce it using the
          // shared rate limiter. Keyed per agent+service for isolation.
          if (evaluation.allowed && evaluation.matchedRule?.rateLimit) {
            const policyRateLimitStr = evaluation.matchedRule.rateLimit;
            let policyParsedLimit: RateLimit;
            try {
              policyParsedLimit = parseRateLimit(policyRateLimitStr);
            } catch {
              reqLog.error(
                { agent: authenticatedAgent.name, rateLimit: policyRateLimitStr },
                'Invalid policy rate limit config',
              );
              policyParsedLimit = { maxRequests: Number.MAX_SAFE_INTEGER, windowMs: 60_000 };
            }

            const policyRateKey = `policy:${authenticatedAgent.name}:${serviceName}`;
            const policyRateResult = this.rateLimiter.check(policyRateKey, policyParsedLimit);
            if (!policyRateResult.allowed) {
              const reason = `Policy rate limit exceeded: ${policyRateLimitStr} (retry after ${policyRateResult.retryAfterSeconds}s)`;

              if (this.policyMode === 'enforce') {
                this.auditBlocked({
                  service: serviceName,
                  targetDomain: credential.domains[0] ?? 'unknown',
                  method: req.method ?? 'GET',
                  path: req.url ?? '/',
                  reason,
                  agentName: authenticatedAgent.name,
                  agentTokenPrefix: authenticatedAgent.tokenPrefix,
                });
                reqLog.warn(
                  {
                    agent: authenticatedAgent.name,
                    limit: policyRateLimitStr,
                    retryAfter: policyRateResult.retryAfterSeconds,
                  },
                  'Blocked: policy rate limit exceeded',
                );
                this.metrics?.recordBlocked(
                  serviceName,
                  'policy_rate_limit',
                  authenticatedAgent.name,
                );
                this.webhooks?.emit('rate_limit_exceeded', {
                  service: serviceName,
                  type: 'policy',
                  agent: authenticatedAgent.name,
                  limit: policyRateLimitStr,
                  retryAfter: policyRateResult.retryAfterSeconds,
                });
                res.writeHead(429, {
                  'Content-Type': 'application/json',
                  'Retry-After': String(policyRateResult.retryAfterSeconds),
                });
                res.end(
                  `${JSON.stringify({
                    error: 'Policy rate limit exceeded',
                    agent: authenticatedAgent.name,
                    limit: policyRateLimitStr,
                    retryAfter: policyRateResult.retryAfterSeconds,
                  })}\n`,
                );
                return;
              }

              // Dry-run mode: log but allow through
              this.auditBlocked({
                service: serviceName,
                targetDomain: credential.domains[0] ?? 'unknown',
                method: req.method ?? 'GET',
                path: req.url ?? '/',
                reason: `POLICY_DRY_RUN: ${reason}`,
                agentName: authenticatedAgent.name,
                agentTokenPrefix: authenticatedAgent.tokenPrefix,
              });
              reqLog.info(
                { agent: authenticatedAgent.name, limit: policyRateLimitStr },
                'Dry-run: would block (policy rate limit)',
              );
            }
          }
        }
      }

      // ─── Per-Agent Rate Limiting ───────────────────────────────────
      // If the authenticated agent has a rate limit, check it before
      // the credential rate limit. More restrictive limit wins.
      if (authenticatedAgent?.rateLimit) {
        let agentParsedLimit: RateLimit;
        try {
          agentParsedLimit = parseRateLimit(authenticatedAgent.rateLimit);
        } catch {
          reqLog.error(
            { agent: authenticatedAgent.name, rateLimit: authenticatedAgent.rateLimit },
            'Invalid agent rate limit config',
          );
          agentParsedLimit = { maxRequests: Number.MAX_SAFE_INTEGER, windowMs: 60_000 };
        }

        const agentResult = this.rateLimiter.check(
          `agent:${authenticatedAgent.id}`,
          agentParsedLimit,
        );
        if (!agentResult.allowed) {
          this.auditBlocked({
            service: serviceName,
            targetDomain: credential.domains[0] ?? 'unknown',
            method: req.method ?? 'GET',
            path: req.url ?? '/',
            reason: `Agent rate limit exceeded: ${authenticatedAgent.rateLimit} (retry after ${agentResult.retryAfterSeconds}s)`,
            agentName: authenticatedAgent.name,
            agentTokenPrefix: authenticatedAgent.tokenPrefix,
          });
          reqLog.warn(
            {
              agent: authenticatedAgent.name,
              limit: authenticatedAgent.rateLimit,
              retryAfter: agentResult.retryAfterSeconds,
            },
            'Blocked: agent rate limit exceeded',
          );
          this.metrics?.recordBlocked(serviceName, 'agent_rate_limit', authenticatedAgent.name);
          this.webhooks?.emit('rate_limit_exceeded', {
            service: serviceName,
            type: 'agent',
            agent: authenticatedAgent.name,
            limit: authenticatedAgent.rateLimit,
            retryAfter: agentResult.retryAfterSeconds,
          });
          res.writeHead(429, {
            'Content-Type': 'application/json',
            'Retry-After': String(agentResult.retryAfterSeconds),
          });
          res.end(
            `${JSON.stringify({
              error: 'Agent rate limit exceeded',
              agent: authenticatedAgent.name,
              limit: authenticatedAgent.rateLimit,
              retryAfter: agentResult.retryAfterSeconds,
            })}\n`,
          );
          return;
        }
      }

      // Rate limit enforcement: check per-credential rate limit
      if (credential.rateLimit) {
        let parsedLimit: RateLimit;
        try {
          parsedLimit = parseRateLimit(credential.rateLimit);
        } catch {
          reqLog.error(
            { credential: credential.name, rateLimit: credential.rateLimit },
            'Invalid credential rate limit config',
          );
          parsedLimit = { maxRequests: Number.MAX_SAFE_INTEGER, windowMs: 60_000 };
        }

        const result = this.rateLimiter.check(credential.id, parsedLimit);
        if (!result.allowed) {
          this.auditBlocked({
            service: serviceName,
            targetDomain: credential.domains[0] ?? 'unknown',
            method: req.method ?? 'GET',
            path: req.url ?? '/',
            reason: `Rate limit exceeded: ${credential.rateLimit} (retry after ${result.retryAfterSeconds}s)`,
            agentName: authenticatedAgent?.name,
            agentTokenPrefix: authenticatedAgent?.tokenPrefix,
          });
          reqLog.warn(
            {
              credential: credential.name,
              limit: credential.rateLimit,
              retryAfter: result.retryAfterSeconds,
            },
            'Blocked: credential rate limit exceeded',
          );
          this.metrics?.recordBlocked(
            serviceName,
            'credential_rate_limit',
            authenticatedAgent?.name,
          );
          this.webhooks?.emit('rate_limit_exceeded', {
            service: serviceName,
            type: 'credential',
            credential: credential.name,
            limit: credential.rateLimit,
            retryAfter: result.retryAfterSeconds,
            agent: authenticatedAgent?.name,
          });
          res.writeHead(429, {
            'Content-Type': 'application/json',
            'Retry-After': String(result.retryAfterSeconds),
          });
          res.end(
            `${JSON.stringify({
              error: 'Rate limit exceeded',
              credential: credential.name,
              limit: credential.rateLimit,
              retryAfter: result.retryAfterSeconds,
            })}\n`,
          );
          return;
        }
      }

      // Determine target domain:
      //   1. Agent can request a specific domain via X-Target-Host header
      //   2. Otherwise, fall back to the credential's primary (first) domain
      const agentRequestedHost = (req.headers['x-target-host'] as string | undefined) ?? undefined;
      const targetDomain = agentRequestedHost ?? credential.domains[0];
      const remainingPath = `/${pathParts.slice(1).join('/')}`;
      const query = reqUrl.search ?? '';

      // Domain guard: verify target domain is in the credential's allowlist
      // This is the core security boundary — blocks agents from exfiltrating
      // credentials to domains not explicitly approved.
      if (!this.vault.domainMatches(targetDomain, credential.domains)) {
        this.auditBlocked({
          service: serviceName,
          targetDomain,
          method: req.method ?? 'GET',
          path: remainingPath,
          reason: `Domain "${targetDomain}" not in allowlist [${credential.domains.join(', ')}]`,
          agentName: authenticatedAgent?.name,
          agentTokenPrefix: authenticatedAgent?.tokenPrefix,
        });
        reqLog.warn(
          { targetDomain, allowed: credential.domains },
          'Blocked: domain guard rejected',
        );
        this.metrics?.recordBlocked(serviceName, 'domain_guard', authenticatedAgent?.name);
        this.webhooks?.emit('blocked_request', {
          service: serviceName,
          reason: 'domain_guard',
          targetDomain,
          allowedDomains: credential.domains,
          agent: authenticatedAgent?.name,
          method: req.method ?? 'GET',
          path: remainingPath,
        });
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(
          `${JSON.stringify({
            error: 'Domain not in credential allowlist',
            requested: targetDomain,
            allowed: credential.domains,
          })}\n`,
        );
        return;
      }

      // Build outbound headers — strip any auth the agent tried to add
      const outboundHeaders: http.OutgoingHttpHeaders = {};
      for (const [key, value] of Object.entries(req.headers)) {
        const lower = key.toLowerCase();
        // Strip auth headers the agent might have tried to include
        if (lower === 'authorization' || lower === 'x-api-key') continue;
        // Don't forward host, target-host override, or agent token
        if (lower === 'host' || lower === 'x-target-host' || lower === 'x-aegis-agent') continue;
        outboundHeaders[key] = value;
      }

      // Inject the real credential (query auth may modify the path)
      const injectedPath = this.injectCredential(
        outboundHeaders,
        credential,
        `${remainingPath}${query}`,
      );
      outboundHeaders.host = targetDomain;

      reqLog.debug(
        { service: serviceName, method: req.method, targetDomain, path: remainingPath },
        'Proxying request',
      );

      // Start request duration timer for Prometheus histogram
      const stopTimer = this.metrics?.startRequestTimer(serviceName);

      // Buffer the request body for inspection before forwarding
      const bodyChunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => {
        bodyChunks.push(chunk);
      });

      req.on('end', () => {
        const bodyBuffer = Buffer.concat(bodyChunks);
        const bodyString = bodyBuffer.toString('utf-8');

        // Body inspection: scan for credential-like patterns in the request body
        if (credential.bodyInspection !== 'off' && bodyString.length > 0) {
          const inspection = this.bodyInspector.inspect(bodyString);
          if (inspection.suspicious) {
            const matchSummary = inspection.matches.join('; ');

            if (credential.bodyInspection === 'block') {
              this.auditBlocked({
                service: serviceName,
                targetDomain,
                method: req.method ?? 'GET',
                path: remainingPath,
                reason: `Body inspection: potential credential exfiltration — ${matchSummary}`,
                agentName: authenticatedAgent?.name,
                agentTokenPrefix: authenticatedAgent?.tokenPrefix,
              });
              reqLog.warn(
                { credential: credential.name, matches: inspection.matches },
                'Blocked: body inspection detected exfiltration',
              );
              this.metrics?.recordBlocked(serviceName, 'body_inspection', authenticatedAgent?.name);
              this.webhooks?.emit('body_inspection', {
                service: serviceName,
                credential: credential.name,
                matches: inspection.matches,
                agent: authenticatedAgent?.name,
                method: req.method ?? 'GET',
                path: remainingPath,
              });
              res.writeHead(403, { 'Content-Type': 'application/json' });
              res.end(
                `${JSON.stringify({
                  error: 'Request body contains credential-like patterns',
                  mode: 'block',
                  matches: inspection.matches,
                  hint: "If this is intentional, set body inspection to 'warn' or 'off' for this credential",
                })}\n`,
              );
              return;
            }

            // warn mode — log but allow through
            reqLog.warn(
              { credential: credential.name, matches: inspection.matches },
              'Body inspection: credential-like patterns detected (warn mode)',
            );
          }
        }

        // Forward the request
        const upstream = this.testUpstream;
        const transport = upstream?.protocol === 'http' ? http : https;
        const proxyReq = transport.request(
          {
            hostname: upstream?.hostname ?? targetDomain,
            port: upstream?.port ?? 443,
            path: injectedPath ?? `${remainingPath}${query}`,
            method: req.method,
            headers: outboundHeaders,
          },
          (proxyRes) => {
            // Strip any credential info from response headers
            const safeHeaders = { ...proxyRes.headers };
            delete safeHeaders['set-cookie']; // Prevent session hijack via agent

            this.auditAllowed({
              credentialId: credential.id,
              credentialName: credential.name,
              service: serviceName,
              targetDomain,
              method: req.method ?? 'GET',
              path: remainingPath,
              responseCode: proxyRes.statusCode,
              agentName: authenticatedAgent?.name,
              agentTokenPrefix: authenticatedAgent?.tokenPrefix,
            });

            reqLog.info(
              {
                service: serviceName,
                method: req.method,
                path: remainingPath,
                status: proxyRes.statusCode,
              },
              'Request proxied',
            );

            stopTimer?.();
            this.metrics?.recordRequest(
              serviceName,
              req.method ?? 'GET',
              proxyRes.statusCode ?? 500,
              authenticatedAgent?.name,
            );

            res.writeHead(proxyRes.statusCode ?? 500, safeHeaders);
            proxyRes.pipe(res);
          },
        );

        proxyReq.on('error', (err) => {
          reqLog.error({ service: serviceName, err: err.message }, 'Proxy error');
          if (!this.shuttingDown) {
            try {
              this.auditBlocked({
                service: serviceName,
                targetDomain,
                method: req.method ?? 'GET',
                path: remainingPath,
                reason: `Proxy error: ${err.message}`,
              });
            } catch {
              // Ledger may be unavailable during shutdown cleanup
            }
          }
          if (!res.headersSent) {
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(`${JSON.stringify({ error: 'Failed to reach upstream service' })}\n`);
          }
        });

        // Write the buffered body and end
        if (bodyBuffer.length > 0) {
          proxyReq.write(bodyBuffer);
        }
        proxyReq.end();
      });
    } catch (err) {
      reqLog.error({ err }, 'Unhandled error');
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(`${JSON.stringify({ error: 'Internal Aegis Gate error' })}\n`);
    }
  }

  /**
   * Inject the credential into outbound request headers based on auth type.
   * For `query` auth, the secret is appended as a URL query parameter instead.
   */
  private injectCredential(
    headers: http.OutgoingHttpHeaders,
    credential: CredentialWithSecret,
    path?: string,
  ): string | undefined {
    switch (credential.authType) {
      case 'bearer':
        headers.authorization = `Bearer ${credential.secret}`;
        break;
      case 'header':
        headers[credential.headerName ?? 'x-api-key'] = credential.secret;
        break;
      case 'basic':
        headers.authorization = `Basic ${Buffer.from(credential.secret).toString('base64')}`;
        break;
      case 'query': {
        if (path !== undefined) {
          const paramName = encodeURIComponent(credential.headerName ?? 'key');
          const paramValue = encodeURIComponent(credential.secret);
          const separator = path.includes('?') ? '&' : '?';
          return `${path}${separator}${paramName}=${paramValue}`;
        }
        break;
      }
    }
    return path;
  }

  // ─── Audit Wrappers (Ledger + Dashboard Broadcast) ─────────────

  /**
   * Log an allowed request and broadcast to dashboard live feed.
   */
  private auditAllowed(params: {
    credentialId: string;
    credentialName: string;
    service: string;
    targetDomain: string;
    method: string;
    path: string;
    responseCode?: number;
    agentName?: string;
    agentTokenPrefix?: string;
  }): void {
    this.ledger.logAllowed(params);
    this.onAuditEntry?.({
      timestamp: new Date().toISOString(),
      credentialId: params.credentialId,
      credentialName: params.credentialName,
      service: params.service,
      targetDomain: params.targetDomain,
      method: params.method,
      path: params.path,
      status: 'allowed',
      blockedReason: null,
      responseCode: params.responseCode ?? null,
      agentName: params.agentName ?? null,
      agentTokenPrefix: params.agentTokenPrefix ?? null,
      channel: 'gate',
    });
  }

  /**
   * Log a blocked request and broadcast to dashboard live feed.
   */
  private auditBlocked(params: {
    service: string;
    targetDomain: string;
    method: string;
    path: string;
    reason: string;
    agentName?: string;
    agentTokenPrefix?: string;
  }): void {
    this.ledger.logBlocked(params);
    this.onAuditEntry?.({
      timestamp: new Date().toISOString(),
      credentialId: null,
      credentialName: null,
      service: params.service,
      targetDomain: params.targetDomain,
      method: params.method,
      path: params.path,
      status: 'blocked',
      blockedReason: params.reason,
      responseCode: null,
      agentName: params.agentName ?? null,
      agentTokenPrefix: params.agentTokenPrefix ?? null,
      channel: 'gate',
    });
  }
}
