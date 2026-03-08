/**
 * Aegis MCP Server — exposes Aegis credential isolation as MCP tools.
 *
 * The MCP server sits between an AI agent (MCP client) and external APIs.
 * The agent uses tools to make authenticated API calls without ever seeing credentials.
 *
 * Tools:
 *   - aegis_proxy_request: Make an authenticated API call through Aegis
 *   - aegis_list_services: List available services (names only, never secrets)
 *   - aegis_health: Check Aegis status
 *
 * Transports:
 *   - stdio: For local process-spawned integrations (Claude Desktop, Cursor, VS Code)
 *   - streamable-http: For remote server access
 */

import * as http from 'node:http';
import * as https from 'node:https';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type pino from 'pino';
import { z } from 'zod';
import type { Agent, AgentRegistry } from '../agent/index.js';
import { BodyInspector } from '../gate/body-inspector.js';
import { methodMatchesScope } from '../gate/gate.js';
import { parseRateLimit, RateLimiter } from '../gate/rate-limiter.js';
import type { Ledger } from '../ledger/index.js';
import { createLogger, generateRequestId } from '../logger/index.js';
import type { AegisMetrics } from '../metrics/index.js';
import type { Policy, PolicyValidationResult } from '../policy/index.js';
import { buildPolicyMap, evaluatePolicy } from '../policy/index.js';
import type { CredentialWithSecret, Vault } from '../vault/index.js';
import { VERSION } from '../version.js';
import type { WebhookManager } from '../webhook/index.js';

// ─── Types ───────────────────────────────────────────────────────

export interface AegisMcpServerOptions {
  /** Vault instance for credential lookup and injection. */
  vault: Vault;
  /** Ledger instance for audit logging. */
  ledger: Ledger;
  /** Agent registry — required when agentToken is provided. */
  agentRegistry?: AgentRegistry;
  /** Pre-configured agent token for this MCP session. */
  agentToken?: string;
  /** Transport type. */
  transport: 'stdio' | 'streamable-http';
  /** Port for streamable-http transport (default: 3200). */
  port?: number;
  /** Policy validation results for policy evaluation. */
  policies?: PolicyValidationResult[];
  /** Policy enforcement mode (default: "enforce"). */
  policyMode?: 'enforce' | 'dry-run';
  /** Log level (default: "info"). */
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
  /** Prometheus metrics collector. */
  metrics?: AegisMetrics;
  /** Webhook manager for alert notifications. */
  webhooks?: WebhookManager;
}

interface ProxyResult {
  status: number;
  headers: Record<string, string>;
  body: string;
}

// ─── AegisMcpServer ─────────────────────────────────────────────

/**
 * Aegis MCP Server — wraps the Aegis credential isolation layer as an MCP server.
 *
 * This gives any MCP-compatible AI agent (Claude, ChatGPT, Cursor, VS Code Copilot)
 * the ability to make authenticated API calls without ever seeing credentials.
 */
export class AegisMcpServer {
  private server: McpServer;
  private vault: Vault;
  private ledger: Ledger;
  private agentRegistry?: AgentRegistry;
  private authenticatedAgent?: Agent;
  private transportType: 'stdio' | 'streamable-http';
  private port: number;
  private policyMap: Map<string, Policy>;
  private policyMode: 'enforce' | 'dry-run';
  private logger: pino.Logger;
  private rateLimiter: RateLimiter;
  private bodyInspector: BodyInspector;
  private httpServer?: http.Server;
  private metrics?: AegisMetrics;
  private webhooks?: WebhookManager;

  constructor(options: AegisMcpServerOptions) {
    this.vault = options.vault;
    this.ledger = options.ledger;
    this.agentRegistry = options.agentRegistry;
    this.transportType = options.transport;
    this.port = options.port ?? 3200;
    this.policyMode = options.policyMode ?? 'enforce';
    this.logger = createLogger({
      module: 'mcp',
      level: options.logLevel ?? 'info',
      // stdio transport: logs must go to stderr (stdout is reserved for MCP protocol messages)
      stderr: options.transport === 'stdio',
    });
    this.rateLimiter = new RateLimiter();
    this.bodyInspector = new BodyInspector();
    this.metrics = options.metrics;
    this.webhooks = options.webhooks;

    // Build policy map from provided policies
    if (options.policies && options.policies.length > 0) {
      this.policyMap = buildPolicyMap(options.policies);
    } else {
      this.policyMap = new Map();
    }

    // Authenticate the agent if a token was provided
    if (options.agentToken && options.agentRegistry) {
      const agent = options.agentRegistry.validateToken(options.agentToken);
      if (!agent) {
        throw new Error(
          'Invalid agent token provided for MCP server. Check your token or register a new agent with: aegis agent add',
        );
      }
      this.authenticatedAgent = agent;
    }

    // Create the MCP server
    this.server = new McpServer({
      name: 'aegis',
      version: VERSION,
    });

    // Register tools
    this.registerTools();
  }

  // ─── Tool Registration ─────────────────────────────────────────

  private registerTools(): void {
    this.registerProxyRequestTool();
    this.registerListServicesTool();
    this.registerHealthTool();
  }

  /**
   * aegis_proxy_request — Make an authenticated API call through Aegis.
   *
   * The agent provides service, path, method, headers, and body.
   * Aegis injects credentials, enforces domain guard, rate limits, body inspection,
   * and policy evaluation — then returns the response.
   */
  private registerProxyRequestTool(): void {
    this.server.registerTool(
      'aegis_proxy_request',
      {
        title: 'Aegis Proxy Request',
        description:
          'Make an authenticated API call through Aegis. Credentials are injected automatically — you never see them. Provide the service name and API path; Aegis handles authentication.',
        inputSchema: {
          service: z
            .string()
            .describe('The service name (must match a registered credential in Aegis)'),
          path: z.string().describe('The API path to call (e.g. "/v1/chat/completions")'),
          method: z
            .enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])
            .optional()
            .default('GET')
            .describe('HTTP method (default: GET)'),
          headers: z
            .record(z.string(), z.string())
            .optional()
            .describe('Additional request headers (auth headers are injected automatically)'),
          body: z.string().optional().describe('Request body (for POST/PUT/PATCH)'),
          targetHost: z
            .string()
            .optional()
            .describe(
              "Override the target domain (must be in the credential's allowlist). Defaults to the credential's primary domain.",
            ),
        },
      },
      async (args: {
        service: string;
        path: string;
        method?: string;
        headers?: Record<string, string>;
        body?: string;
        targetHost?: string;
      }) => {
        try {
          const result = await this.proxyRequest(args);
          return {
            content: [
              {
                type: 'text' as const,
                text: JSON.stringify(
                  {
                    status: result.status,
                    headers: result.headers,
                    body: result.body,
                  },
                  null,
                  2,
                ),
              },
            ],
          };
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          return {
            content: [{ type: 'text' as const, text: `Error: ${message}` }],
            isError: true,
          };
        }
      },
    );
  }

  /**
   * aegis_list_services — List available services the agent can use.
   *
   * Returns service names and domains only — never secrets.
   */
  private registerListServicesTool(): void {
    this.server.registerTool(
      'aegis_list_services',
      {
        title: 'Aegis List Services',
        description:
          'List all available services registered in Aegis. Returns service names, auth types, and allowed domains — never secrets.',
        inputSchema: {},
      },
      async () => {
        const credentials = this.vault.list();

        // If an agent is authenticated, filter to only their granted credentials
        let filtered = credentials;
        if (this.authenticatedAgent && this.agentRegistry) {
          const grantedIds = this.agentRegistry.listGrants(this.authenticatedAgent.name);
          if (grantedIds.length > 0) {
            filtered = credentials.filter((c) => grantedIds.includes(c.id));
          }
        }

        const services = filtered.map((c) => ({
          name: c.name,
          service: c.service,
          authType: c.authType,
          domains: c.domains,
          scopes: c.scopes,
          expiresAt: c.expiresAt ?? null,
          rateLimit: c.rateLimit ?? null,
        }));

        return {
          content: [
            {
              type: 'text' as const,
              text: JSON.stringify({ services, total: services.length }, null, 2),
            },
          ],
        };
      },
    );
  }

  /**
   * aegis_health — Check Aegis status.
   */
  private registerHealthTool(): void {
    this.server.registerTool(
      'aegis_health',
      {
        title: 'Aegis Health Check',
        description: 'Check the health status of Aegis, including credential and agent counts.',
        inputSchema: {},
      },
      async () => {
        const credentials = this.vault.list();
        const stats = this.ledger.stats();
        const agents = this.agentRegistry?.list() ?? [];

        const health = {
          status: 'ok',
          version: VERSION,
          credentials: {
            total: credentials.length,
            expired: credentials.filter((c) => c.expiresAt && new Date(c.expiresAt) < new Date())
              .length,
            active: credentials.filter((c) => !c.expiresAt || new Date(c.expiresAt) >= new Date())
              .length,
          },
          agents: {
            total: agents.length,
          },
          audit: stats,
          authenticatedAgent: this.authenticatedAgent
            ? {
                name: this.authenticatedAgent.name,
                tokenPrefix: this.authenticatedAgent.tokenPrefix,
              }
            : null,
        };

        return {
          content: [{ type: 'text' as const, text: JSON.stringify(health, null, 2) }],
        };
      },
    );
  }

  // ─── Proxy Logic ───────────────────────────────────────────────

  /**
   * Execute an authenticated proxy request through Aegis.
   *
   * This replicates the Gate's security pipeline:
   * 1. Credential lookup
   * 2. TTL check
   * 3. Agent credential scoping
   * 4. Policy evaluation
   * 5. Agent rate limiting
   * 6. Credential rate limiting
   * 7. Domain guard
   * 8. Body inspection
   * 9. Credential injection + forward
   * 10. Audit logging
   */
  private async proxyRequest(params: {
    service: string;
    path: string;
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    targetHost?: string;
  }): Promise<ProxyResult> {
    const method = params.method ?? 'GET';
    const path = params.path.startsWith('/') ? params.path : `/${params.path}`;
    const requestId = generateRequestId();

    // 1. Credential lookup
    const credential = this.vault.getByService(params.service);
    if (!credential) {
      this.metrics?.recordBlocked(params.service, 'no_credential', this.authenticatedAgent?.name);
      this.webhooks?.emit('blocked_request', {
        service: params.service,
        reason: 'no_credential',
        method,
        path,
        agent: this.authenticatedAgent?.name,
      });
      this.ledger.logBlocked({
        service: params.service,
        targetDomain: 'unknown',
        method,
        path,
        reason: `No credential found for service: ${params.service}`,
        agentName: this.authenticatedAgent?.name,
        agentTokenPrefix: this.authenticatedAgent?.tokenPrefix,
        channel: 'mcp',
      });
      throw new Error(
        `No credential registered for service: ${params.service}. ` +
          `Register one with: aegis vault add --name ${params.service} --service ${params.service} --secret YOUR_KEY --domains api.example.com`,
      );
    }

    // 2. TTL enforcement
    if (this.vault.isExpired(credential)) {
      this.metrics?.recordBlocked(
        params.service,
        'credential_expired',
        this.authenticatedAgent?.name,
      );
      this.webhooks?.emit('credential_expiry', {
        service: params.service,
        credential: credential.name,
        expiredAt: credential.expiresAt,
        agent: this.authenticatedAgent?.name,
      });
      this.ledger.logBlocked({
        service: params.service,
        targetDomain: credential.domains[0] ?? 'unknown',
        method,
        path,
        reason: `Credential "${credential.name}" expired at ${credential.expiresAt}`,
        agentName: this.authenticatedAgent?.name,
        agentTokenPrefix: this.authenticatedAgent?.tokenPrefix,
        channel: 'mcp',
      });
      throw new Error(
        `Credential "${credential.name}" has expired at ${credential.expiresAt}. ` +
          `Rotate with: aegis vault rotate --name ${credential.name} --secret NEW_SECRET`,
      );
    }

    // 3. Agent credential scoping
    if (this.authenticatedAgent && this.agentRegistry) {
      if (!this.agentRegistry.hasAccess(this.authenticatedAgent.id, credential.id)) {
        this.metrics?.recordBlocked(params.service, 'agent_scope', this.authenticatedAgent.name);
        this.webhooks?.emit('blocked_request', {
          service: params.service,
          reason: 'agent_scope',
          agent: this.authenticatedAgent.name,
          credential: credential.name,
          method,
          path,
        });
        this.ledger.logBlocked({
          service: params.service,
          targetDomain: credential.domains[0] ?? 'unknown',
          method,
          path,
          reason: `Agent "${this.authenticatedAgent.name}" not granted access to credential "${credential.name}"`,
          agentName: this.authenticatedAgent.name,
          agentTokenPrefix: this.authenticatedAgent.tokenPrefix,
          channel: 'mcp',
        });
        throw new Error(
          `Agent "${this.authenticatedAgent.name}" is not granted access to credential "${credential.name}". ` +
            `Grant access with: aegis agent grant --agent ${this.authenticatedAgent.name} --credential ${credential.name}`,
        );
      }
    }

    // 4. Credential scope enforcement
    if (!methodMatchesScope(method, credential.scopes)) {
      const scopeList = credential.scopes.join(', ');
      this.metrics?.recordBlocked(
        params.service,
        'credential_scope',
        this.authenticatedAgent?.name,
      );
      this.webhooks?.emit('blocked_request', {
        service: params.service,
        reason: 'credential_scope',
        credential: credential.name,
        method,
        scopes: credential.scopes,
        agent: this.authenticatedAgent?.name,
        path,
      });
      this.ledger.logBlocked({
        service: params.service,
        targetDomain: credential.domains[0] ?? 'unknown',
        method,
        path,
        reason: `Method "${method}" not permitted by credential scopes [${scopeList}]`,
        agentName: this.authenticatedAgent?.name,
        agentTokenPrefix: this.authenticatedAgent?.tokenPrefix,
        channel: 'mcp',
      });
      throw new Error(
        `Method "${method}" is not permitted by credential scopes [${scopeList}]. ` +
          `Update scopes with: aegis vault update --name ${credential.name} --scopes ${scopeList},${method === 'GET' ? 'read' : 'write'}`,
      );
    }

    // 5. Policy evaluation
    if (this.authenticatedAgent && this.policyMap.size > 0) {
      const agentPolicy = this.policyMap.get(this.authenticatedAgent.name);
      if (agentPolicy) {
        const evaluation = evaluatePolicy(agentPolicy, {
          service: params.service,
          method,
          path,
        });

        if (!evaluation.allowed) {
          const reason = `Policy violation: ${evaluation.reason}`;

          if (this.policyMode === 'enforce') {
            this.metrics?.recordBlocked(
              params.service,
              'policy_violation',
              this.authenticatedAgent.name,
            );
            this.webhooks?.emit('blocked_request', {
              service: params.service,
              reason: 'policy_violation',
              agent: this.authenticatedAgent.name,
              violation: evaluation.violation,
              detail: evaluation.reason,
              method,
              path,
            });
            this.ledger.logBlocked({
              service: params.service,
              targetDomain: credential.domains[0] ?? 'unknown',
              method,
              path,
              reason,
              agentName: this.authenticatedAgent.name,
              agentTokenPrefix: this.authenticatedAgent.tokenPrefix,
              channel: 'mcp',
            });
            throw new Error(
              `Policy violation for agent "${this.authenticatedAgent.name}": ${evaluation.reason}`,
            );
          }

          // Dry-run: log but allow
          this.ledger.logBlocked({
            service: params.service,
            targetDomain: credential.domains[0] ?? 'unknown',
            method,
            path,
            reason: `POLICY_DRY_RUN: ${evaluation.reason}`,
            agentName: this.authenticatedAgent.name,
            agentTokenPrefix: this.authenticatedAgent.tokenPrefix,
            channel: 'mcp',
          });
          this.logger.info(
            { agent: this.authenticatedAgent.name, reason: evaluation.reason, requestId },
            'Dry-run: would block',
          );
        }
      }
    }

    // 6. Agent rate limiting
    if (this.authenticatedAgent?.rateLimit) {
      try {
        const agentParsedLimit = parseRateLimit(this.authenticatedAgent.rateLimit);
        const agentResult = this.rateLimiter.check(
          `agent:${this.authenticatedAgent.id}`,
          agentParsedLimit,
        );
        if (!agentResult.allowed) {
          this.metrics?.recordBlocked(
            params.service,
            'agent_rate_limit',
            this.authenticatedAgent.name,
          );
          this.webhooks?.emit('rate_limit_exceeded', {
            service: params.service,
            type: 'agent',
            agent: this.authenticatedAgent.name,
            limit: this.authenticatedAgent.rateLimit,
            retryAfter: agentResult.retryAfterSeconds,
          });
          this.ledger.logBlocked({
            service: params.service,
            targetDomain: credential.domains[0] ?? 'unknown',
            method,
            path,
            reason: `Agent rate limit exceeded: ${this.authenticatedAgent.rateLimit} (retry after ${agentResult.retryAfterSeconds}s)`,
            agentName: this.authenticatedAgent.name,
            agentTokenPrefix: this.authenticatedAgent.tokenPrefix,
            channel: 'mcp',
          });
          throw new Error(
            `Agent rate limit exceeded (${this.authenticatedAgent.rateLimit}). Retry after ${agentResult.retryAfterSeconds} seconds.`,
          );
        }
      } catch (err) {
        // Re-throw rate limit errors, ignore parse errors
        if (err instanceof Error && err.message.includes('rate limit')) {
          throw err;
        }
        this.logger.error(
          {
            agent: this.authenticatedAgent.name,
            rateLimit: this.authenticatedAgent.rateLimit,
            requestId,
          },
          'Invalid agent rate limit config',
        );
      }
    }

    // 7. Credential rate limiting
    if (credential.rateLimit) {
      try {
        const parsedLimit = parseRateLimit(credential.rateLimit);
        const result = this.rateLimiter.check(credential.id, parsedLimit);
        if (!result.allowed) {
          this.metrics?.recordBlocked(
            params.service,
            'credential_rate_limit',
            this.authenticatedAgent?.name,
          );
          this.webhooks?.emit('rate_limit_exceeded', {
            service: params.service,
            type: 'credential',
            credential: credential.name,
            limit: credential.rateLimit,
            retryAfter: result.retryAfterSeconds,
            agent: this.authenticatedAgent?.name,
          });
          this.ledger.logBlocked({
            service: params.service,
            targetDomain: credential.domains[0] ?? 'unknown',
            method,
            path,
            reason: `Rate limit exceeded: ${credential.rateLimit} (retry after ${result.retryAfterSeconds}s)`,
            agentName: this.authenticatedAgent?.name,
            agentTokenPrefix: this.authenticatedAgent?.tokenPrefix,
            channel: 'mcp',
          });
          throw new Error(
            `Rate limit exceeded for "${credential.name}" (${credential.rateLimit}). Retry after ${result.retryAfterSeconds} seconds.`,
          );
        }
      } catch (err) {
        if (err instanceof Error && err.message.includes('Rate limit')) {
          throw err;
        }
        this.logger.error(
          { credential: credential.name, rateLimit: credential.rateLimit, requestId },
          'Invalid credential rate limit config',
        );
      }
    }

    // 8. Domain guard
    const targetDomain = params.targetHost ?? credential.domains[0];
    if (!this.vault.domainMatches(targetDomain, credential.domains)) {
      this.metrics?.recordBlocked(params.service, 'domain_guard', this.authenticatedAgent?.name);
      this.webhooks?.emit('blocked_request', {
        service: params.service,
        reason: 'domain_guard',
        targetDomain,
        allowedDomains: credential.domains,
        agent: this.authenticatedAgent?.name,
        method,
        path,
      });
      this.ledger.logBlocked({
        service: params.service,
        targetDomain,
        method,
        path,
        reason: `Domain "${targetDomain}" not in allowlist [${credential.domains.join(', ')}]`,
        agentName: this.authenticatedAgent?.name,
        agentTokenPrefix: this.authenticatedAgent?.tokenPrefix,
        channel: 'mcp',
      });
      throw new Error(
        `Domain "${targetDomain}" is not in the credential's allowlist [${credential.domains.join(', ')}].`,
      );
    }

    // 9. Body inspection
    if (credential.bodyInspection !== 'off' && params.body && params.body.length > 0) {
      const inspection = this.bodyInspector.inspect(params.body);
      if (inspection.suspicious) {
        const matchSummary = inspection.matches.join('; ');

        if (credential.bodyInspection === 'block') {
          this.metrics?.recordBlocked(
            params.service,
            'body_inspection',
            this.authenticatedAgent?.name,
          );
          this.webhooks?.emit('body_inspection', {
            service: params.service,
            credential: credential.name,
            matches: inspection.matches,
            agent: this.authenticatedAgent?.name,
            method,
            path,
          });
          this.ledger.logBlocked({
            service: params.service,
            targetDomain,
            method,
            path,
            reason: `Body inspection: potential credential exfiltration — ${matchSummary}`,
            agentName: this.authenticatedAgent?.name,
            agentTokenPrefix: this.authenticatedAgent?.tokenPrefix,
            channel: 'mcp',
          });
          throw new Error(
            `Request body contains credential-like patterns: ${matchSummary}. ` +
              "If this is intentional, set body inspection to 'warn' or 'off' for this credential.",
          );
        }

        // Warn mode
        this.logger.warn(
          { credential: credential.name, matches: inspection.matches, requestId },
          'Body inspection: credential-like patterns detected (warn mode)',
        );
      }
    }

    // 10. Make the outbound request with credential injection
    const result = await this.makeOutboundRequest(credential, {
      targetDomain,
      path,
      method,
      headers: params.headers,
      body: params.body,
    });

    // 11. Audit log
    this.ledger.logAllowed({
      credentialId: credential.id,
      credentialName: credential.name,
      service: params.service,
      targetDomain,
      method,
      path,
      responseCode: result.status,
      agentName: this.authenticatedAgent?.name,
      agentTokenPrefix: this.authenticatedAgent?.tokenPrefix,
      channel: 'mcp',
    });

    this.logger.info(
      { service: params.service, method, path, status: result.status, requestId },
      'MCP request proxied',
    );

    this.metrics?.recordRequest(
      params.service,
      method,
      result.status,
      this.authenticatedAgent?.name,
    );

    return result;
  }

  /**
   * Make the actual outbound HTTP request with credential injection.
   */
  private makeOutboundRequest(
    credential: CredentialWithSecret,
    params: {
      targetDomain: string;
      path: string;
      method: string;
      headers?: Record<string, string>;
      body?: string;
    },
  ): Promise<ProxyResult> {
    return new Promise((resolve, reject) => {
      const outboundHeaders: http.OutgoingHttpHeaders = {
        host: params.targetDomain,
      };

      // Add user-provided headers (but strip any auth headers the agent tried to add)
      if (params.headers) {
        for (const [key, value] of Object.entries(params.headers)) {
          const lower = key.toLowerCase();
          if (
            lower === 'authorization' ||
            lower === 'x-api-key' ||
            lower === 'x-aegis-agent' ||
            lower === 'x-target-host'
          ) {
            continue; // Strip auth headers — Aegis injects the real ones
          }
          outboundHeaders[key] = value;
        }
      }

      // Set content-type for bodies if not already set
      if (params.body && !outboundHeaders['content-type'] && !outboundHeaders['Content-Type']) {
        outboundHeaders['content-type'] = 'application/json';
      }

      // Inject the real credential
      this.injectCredential(outboundHeaders, credential);

      const proxyReq = https.request(
        {
          hostname: params.targetDomain,
          port: 443,
          path: params.path,
          method: params.method,
          headers: outboundHeaders,
        },
        (proxyRes) => {
          const chunks: Buffer[] = [];
          proxyRes.on('data', (chunk: Buffer) => chunks.push(chunk));
          proxyRes.on('end', () => {
            const body = Buffer.concat(chunks).toString('utf-8');

            // Build clean response headers (strip set-cookie for security)
            const responseHeaders: Record<string, string> = {};
            for (const [key, value] of Object.entries(proxyRes.headers)) {
              if (key.toLowerCase() === 'set-cookie') continue;
              if (value !== undefined) {
                responseHeaders[key] = Array.isArray(value) ? value.join(', ') : value;
              }
            }

            resolve({
              status: proxyRes.statusCode ?? 500,
              headers: responseHeaders,
              body,
            });
          });
          proxyRes.on('error', (err) => reject(new Error(`Response error: ${err.message}`)));
        },
      );

      proxyReq.on('error', (err) => {
        this.ledger.logBlocked({
          service: credential.service,
          targetDomain: params.targetDomain,
          method: params.method,
          path: params.path,
          reason: `Proxy error: ${err.message}`,
          agentName: this.authenticatedAgent?.name,
          agentTokenPrefix: this.authenticatedAgent?.tokenPrefix,
          channel: 'mcp',
        });
        reject(new Error(`Failed to reach upstream service: ${err.message}`));
      });

      if (params.body) {
        proxyReq.write(params.body);
      }
      proxyReq.end();
    });
  }

  /**
   * Inject the credential into outbound request headers based on auth type.
   */
  private injectCredential(
    headers: http.OutgoingHttpHeaders,
    credential: CredentialWithSecret,
  ): void {
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
      case 'query':
        // Query params would need URL modification — v0.4 limitation
        break;
    }
  }

  // ─── Transport & Lifecycle ─────────────────────────────────────

  /**
   * Start the MCP server with the configured transport.
   */
  async start(): Promise<void> {
    if (this.transportType === 'stdio') {
      await this.startStdio();
    } else {
      await this.startStreamableHttp();
    }
  }

  /**
   * Start with stdio transport (for local integrations).
   */
  private async startStdio(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    this.logger.info({ transport: 'stdio' }, 'Aegis MCP server started');
  }

  /**
   * Start with Streamable HTTP transport (for remote access).
   */
  private async startStreamableHttp(): Promise<void> {
    // Track active transports for stateful sessions
    const transports = new Map<string, StreamableHTTPServerTransport>();

    this.httpServer = http.createServer(async (req, res) => {
      const url = new URL(req.url ?? '/', `http://localhost:${this.port}`);

      // Only handle /mcp endpoint
      if (url.pathname !== '/mcp') {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not found. MCP endpoint is at /mcp' }));
        return;
      }

      // Handle session management
      const sessionId = req.headers['mcp-session-id'] as string | undefined;

      if (req.method === 'POST') {
        // Check for existing session
        if (sessionId && transports.has(sessionId)) {
          const transport = transports.get(sessionId);
          if (transport) {
            await transport.handleRequest(req, res);
            return;
          }
        }

        // New session — create a new transport
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => crypto.randomUUID(),
          onsessioninitialized: (newSessionId) => {
            transports.set(newSessionId, transport);
            this.logger.debug({ sessionId: newSessionId }, 'MCP session started');
          },
        });

        // Clean up on session close
        transport.onclose = () => {
          const sid = Array.from(transports.entries()).find(([, t]) => t === transport)?.[0];
          if (sid) {
            transports.delete(sid);
            this.logger.debug({ sessionId: sid }, 'MCP session closed');
          }
        };

        await this.server.connect(transport);
        await transport.handleRequest(req, res);
      } else if (req.method === 'GET') {
        // SSE stream for server-to-client notifications
        if (sessionId && transports.has(sessionId)) {
          const transport = transports.get(sessionId);
          if (transport) {
            await transport.handleRequest(req, res);
            return;
          }
        }
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Missing or invalid session ID' }));
      } else if (req.method === 'DELETE') {
        // Session termination
        if (sessionId && transports.has(sessionId)) {
          const transport = transports.get(sessionId);
          if (transport) {
            await transport.handleRequest(req, res);
            transports.delete(sessionId);
            this.logger.debug({ sessionId }, 'MCP session terminated');
            return;
          }
        }
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Session not found' }));
      } else {
        res.writeHead(405, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Method not allowed' }));
      }
    });

    await new Promise<void>((resolve) => {
      this.httpServer?.listen(this.port, '127.0.0.1', () => {
        this.logger.info(
          { transport: 'streamable-http', host: '127.0.0.1', port: this.port, endpoint: '/mcp' },
          'Aegis MCP server started',
        );
        resolve();
      });
    });
  }

  /**
   * Stop the MCP server.
   */
  async stop(): Promise<void> {
    if (this.httpServer) {
      await new Promise<void>((resolve, reject) => {
        this.httpServer?.close((err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      this.httpServer = undefined;
    }
    await this.server.close();
    this.logger.info('Aegis MCP server stopped');
  }
}
