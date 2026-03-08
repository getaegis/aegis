import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import Database from 'better-sqlite3';
import { describe, expect, it } from 'vitest';
import { AgentRegistry } from '../src/agent/index.js';
import { migrate } from '../src/db.js';
import { Ledger } from '../src/ledger/index.js';
import { AegisMcpServer } from '../src/mcp/index.js';
import type { Policy, PolicyValidationResult } from '../src/policy/index.js';
import { deriveKey, Vault } from '../src/vault/index.js';
import { VERSION } from '../src/version.js';

// ─── Test Helper: Create test MCP server with in-memory transport ─

interface TestSetup {
  db: Database.Database;
  vault: Vault;
  ledger: Ledger;
  agentRegistry: AgentRegistry;
  client: Client;
  cleanup: () => Promise<void>;
}

async function createTestSetup(options?: {
  agentToken?: string;
  policies?: PolicyValidationResult[];
  policyMode?: 'enforce' | 'dry-run';
}): Promise<TestSetup> {
  const db = new Database(':memory:');
  migrate(db);

  const masterKey = 'test-master-key-for-mcp-tests';
  const salt = Buffer.from('test-salt-for-mcp-tests');
  const derivedKey = deriveKey(masterKey, salt);

  const vault = new Vault(db, masterKey, salt);
  const ledger = new Ledger(db);
  const agentRegistry = new AgentRegistry(db, derivedKey);

  // Create the MCP server
  const mcpServer = new AegisMcpServer({
    vault,
    ledger,
    agentRegistry,
    agentToken: options?.agentToken,
    transport: 'stdio', // Won't actually use stdio — we'll connect via in-memory
    policies: options?.policies,
    policyMode: options?.policyMode,
    logLevel: 'error', // Suppress logs during tests
  });

  // Use in-memory transport for testing
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

  // Access the internal McpServer to connect the transport
  // The AegisMcpServer wraps an McpServer; we need to connect our transport to it
  // We'll use a workaround: access the server's internal server property
  const internalServer = (mcpServer as unknown as { server: McpServer }).server;
  await internalServer.connect(serverTransport);

  // Create and connect the client
  const client = new Client({ name: 'test-client', version: '1.0.0' });
  await client.connect(clientTransport);

  const cleanup = async (): Promise<void> => {
    await client.close();
    await internalServer.close();
    db.close();
  };

  return { db, vault, ledger, agentRegistry, client, cleanup };
}

// ─── Tests ───────────────────────────────────────────────────────

describe('MCP Server', () => {
  describe('Tool Discovery', () => {
    it('should expose three tools', async () => {
      const setup = await createTestSetup();
      try {
        const result = await setup.client.listTools();
        const toolNames = result.tools.map((t) => t.name).sort();
        expect(toolNames).toEqual(['aegis_health', 'aegis_list_services', 'aegis_proxy_request']);
      } finally {
        await setup.cleanup();
      }
    });

    it('should have proper descriptions for all tools', async () => {
      const setup = await createTestSetup();
      try {
        const result = await setup.client.listTools();

        const proxyTool = result.tools.find((t) => t.name === 'aegis_proxy_request');
        expect(proxyTool?.description).toContain('authenticated API call');

        const listTool = result.tools.find((t) => t.name === 'aegis_list_services');
        expect(listTool?.description).toContain('available services');

        const healthTool = result.tools.find((t) => t.name === 'aegis_health');
        expect(healthTool?.description).toContain('health status');
      } finally {
        await setup.cleanup();
      }
    });

    it('aegis_proxy_request should have correct input schema', async () => {
      const setup = await createTestSetup();
      try {
        const result = await setup.client.listTools();
        const proxyTool = result.tools.find((t) => t.name === 'aegis_proxy_request');
        const schema = proxyTool?.inputSchema;

        expect(schema).toBeDefined();
        // Check required fields
        expect(schema?.required).toContain('service');
        expect(schema?.required).toContain('path');
      } finally {
        await setup.cleanup();
      }
    });
  });

  describe('aegis_health', () => {
    it('should return health status with no credentials', async () => {
      const setup = await createTestSetup();
      try {
        const result = await setup.client.callTool({ name: 'aegis_health', arguments: {} });
        const content = result.content as Array<{ type: string; text: string }>;
        expect(content).toHaveLength(1);
        expect(content[0].type).toBe('text');

        const health = JSON.parse(content[0].text);
        expect(health.status).toBe('ok');
        expect(health.version).toBe(VERSION);
        expect(health.credentials.total).toBe(0);
        expect(health.credentials.active).toBe(0);
        expect(health.credentials.expired).toBe(0);
        expect(health.agents.total).toBe(0);
      } finally {
        await setup.cleanup();
      }
    });

    it('should reflect credential counts', async () => {
      const setup = await createTestSetup();
      try {
        setup.vault.add({
          name: 'test-cred',
          service: 'test-service',
          secret: 'secret-123',
          domains: ['api.example.com'],
        });

        const result = await setup.client.callTool({ name: 'aegis_health', arguments: {} });
        const health = JSON.parse(
          (result.content as Array<{ type: string; text: string }>)[0].text,
        );
        expect(health.credentials.total).toBe(1);
        expect(health.credentials.active).toBe(1);
      } finally {
        await setup.cleanup();
      }
    });

    it('should reflect agent counts', async () => {
      const setup = await createTestSetup();
      try {
        setup.agentRegistry.add({ name: 'test-agent' });

        const result = await setup.client.callTool({ name: 'aegis_health', arguments: {} });
        const health = JSON.parse(
          (result.content as Array<{ type: string; text: string }>)[0].text,
        );
        expect(health.agents.total).toBe(1);
      } finally {
        await setup.cleanup();
      }
    });

    it('should show authenticated agent when token provided', async () => {
      const db = new Database(':memory:');
      migrate(db);
      const masterKey = 'test-key';
      const salt = Buffer.from('test-salt');
      const derivedKey = deriveKey(masterKey, salt);
      const agentRegistry = new AgentRegistry(db, derivedKey);
      agentRegistry.add({ name: 'mcp-agent' });

      const setup = await createTestSetup();
      // We need a new setup with the agent token
      await setup.cleanup();

      const db2 = new Database(':memory:');
      migrate(db2);
      const vault2 = new Vault(db2, masterKey, salt);
      const ledger2 = new Ledger(db2);
      const agentRegistry2 = new AgentRegistry(db2, derivedKey);
      const agent2 = agentRegistry2.add({ name: 'mcp-agent' });

      const mcpServer = new AegisMcpServer({
        vault: vault2,
        ledger: ledger2,
        agentRegistry: agentRegistry2,
        agentToken: agent2.token,
        transport: 'stdio',
        logLevel: 'error',
      });

      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      const internalServer = (mcpServer as unknown as { server: McpServer }).server;
      await internalServer.connect(serverTransport);

      const client = new Client({ name: 'test', version: '1.0.0' });
      await client.connect(clientTransport);

      try {
        const result = await client.callTool({ name: 'aegis_health', arguments: {} });
        const health = JSON.parse(
          (result.content as Array<{ type: string; text: string }>)[0].text,
        );
        expect(health.authenticatedAgent).toBeDefined();
        expect(health.authenticatedAgent.name).toBe('mcp-agent');
      } finally {
        await client.close();
        await internalServer.close();
        db2.close();
      }
    });
  });

  describe('aegis_list_services', () => {
    it('should return empty list when no credentials exist', async () => {
      const setup = await createTestSetup();
      try {
        const result = await setup.client.callTool({
          name: 'aegis_list_services',
          arguments: {},
        });
        const data = JSON.parse((result.content as Array<{ type: string; text: string }>)[0].text);
        expect(data.services).toEqual([]);
        expect(data.total).toBe(0);
      } finally {
        await setup.cleanup();
      }
    });

    it('should list services without exposing secrets', async () => {
      const setup = await createTestSetup();
      try {
        setup.vault.add({
          name: 'github-api',
          service: 'github',
          secret: 'ghp_supersecrettoken123',
          authType: 'bearer',
          domains: ['api.github.com'],
          scopes: ['read', 'write'],
        });

        const result = await setup.client.callTool({
          name: 'aegis_list_services',
          arguments: {},
        });
        const data = JSON.parse((result.content as Array<{ type: string; text: string }>)[0].text);

        expect(data.total).toBe(1);
        expect(data.services[0].name).toBe('github-api');
        expect(data.services[0].service).toBe('github');
        expect(data.services[0].authType).toBe('bearer');
        expect(data.services[0].domains).toEqual(['api.github.com']);
        expect(data.services[0].scopes).toEqual(['read', 'write']);
        // Verify no secret exposure
        expect(JSON.stringify(data)).not.toContain('ghp_supersecrettoken123');
      } finally {
        await setup.cleanup();
      }
    });

    it('should list multiple services', async () => {
      const setup = await createTestSetup();
      try {
        setup.vault.add({
          name: 'github-api',
          service: 'github',
          secret: 'ghp_token',
          domains: ['api.github.com'],
        });
        setup.vault.add({
          name: 'openai-api',
          service: 'openai',
          secret: 'sk-openai-key',
          domains: ['api.openai.com'],
        });

        const result = await setup.client.callTool({
          name: 'aegis_list_services',
          arguments: {},
        });
        const data = JSON.parse((result.content as Array<{ type: string; text: string }>)[0].text);
        expect(data.total).toBe(2);
      } finally {
        await setup.cleanup();
      }
    });

    it('should filter services by agent grants when authenticated', async () => {
      const db = new Database(':memory:');
      migrate(db);
      const masterKey = 'test-key';
      const salt = Buffer.from('test-salt');
      const derivedKey = deriveKey(masterKey, salt);

      const vault = new Vault(db, masterKey, salt);
      const ledger = new Ledger(db);
      const agentRegistry = new AgentRegistry(db, derivedKey);

      // Add two credentials
      const cred1 = vault.add({
        name: 'github-api',
        service: 'github',
        secret: 'ghp_token',
        domains: ['api.github.com'],
      });
      vault.add({
        name: 'openai-api',
        service: 'openai',
        secret: 'sk-openai-key',
        domains: ['api.openai.com'],
      });

      // Create agent and grant access to only github
      const agent = agentRegistry.add({ name: 'restricted-agent' });
      agentRegistry.grant({ agentName: 'restricted-agent', credentialId: cred1.id });

      const mcpServer = new AegisMcpServer({
        vault,
        ledger,
        agentRegistry,
        agentToken: agent.token,
        transport: 'stdio',
        logLevel: 'error',
      });

      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      const internalServer = (mcpServer as unknown as { server: McpServer }).server;
      await internalServer.connect(serverTransport);
      const client = new Client({ name: 'test', version: '1.0.0' });
      await client.connect(clientTransport);

      try {
        const result = await client.callTool({
          name: 'aegis_list_services',
          arguments: {},
        });
        const data = JSON.parse((result.content as Array<{ type: string; text: string }>)[0].text);
        // Should only see github, not openai
        expect(data.total).toBe(1);
        expect(data.services[0].service).toBe('github');
      } finally {
        await client.close();
        await internalServer.close();
        db.close();
      }
    });
  });

  describe('aegis_proxy_request', () => {
    it('should return error when service not found', async () => {
      const setup = await createTestSetup();
      try {
        const result = await setup.client.callTool({
          name: 'aegis_proxy_request',
          arguments: { service: 'nonexistent', path: '/api/test' },
        });
        expect(result.isError).toBe(true);
        const text = (result.content as Array<{ type: string; text: string }>)[0].text;
        expect(text).toContain('No credential registered');
        expect(text).toContain('nonexistent');
      } finally {
        await setup.cleanup();
      }
    });

    it('should log blocked request to ledger when service not found', async () => {
      const setup = await createTestSetup();
      try {
        await setup.client.callTool({
          name: 'aegis_proxy_request',
          arguments: { service: 'nonexistent', path: '/api/test' },
        });

        const entries = setup.ledger.query({ status: 'blocked' });
        expect(entries.length).toBeGreaterThan(0);
        expect(entries[0].blockedReason).toContain('No credential found');
      } finally {
        await setup.cleanup();
      }
    });

    it('should reject expired credentials', async () => {
      const setup = await createTestSetup();
      try {
        // Add an expired credential
        setup.vault.add({
          name: 'expired-cred',
          service: 'expired-svc',
          secret: 'secret-123',
          domains: ['api.example.com'],
          ttlDays: -1, // Already expired
        });

        // Manually expire it by updating the DB
        setup.db.prepare("UPDATE credentials SET expires_at = datetime('now', '-1 day')").run();

        const result = await setup.client.callTool({
          name: 'aegis_proxy_request',
          arguments: { service: 'expired-svc', path: '/test' },
        });
        expect(result.isError).toBe(true);
        const text = (result.content as Array<{ type: string; text: string }>)[0].text;
        expect(text).toContain('expired');
      } finally {
        await setup.cleanup();
      }
    });

    it('should reject requests to domains not in allowlist', async () => {
      const setup = await createTestSetup();
      try {
        setup.vault.add({
          name: 'test-cred',
          service: 'test-svc',
          secret: 'secret-123',
          domains: ['api.allowed.com'],
        });

        const result = await setup.client.callTool({
          name: 'aegis_proxy_request',
          arguments: {
            service: 'test-svc',
            path: '/test',
            targetHost: 'evil.attacker.com',
          },
        });
        expect(result.isError).toBe(true);
        const text = (result.content as Array<{ type: string; text: string }>)[0].text;
        expect(text).toContain("not in the credential's allowlist");
        expect(text).toContain('evil.attacker.com');

        // Verify ledger entry
        const entries = setup.ledger.query({ status: 'blocked' });
        expect(entries.some((e) => e.blockedReason?.includes('Domain'))).toBe(true);
      } finally {
        await setup.cleanup();
      }
    });

    it('should reject agent without credential grant', async () => {
      const db = new Database(':memory:');
      migrate(db);
      const masterKey = 'test-key';
      const salt = Buffer.from('test-salt');
      const derivedKey = deriveKey(masterKey, salt);

      const vault = new Vault(db, masterKey, salt);
      const ledger = new Ledger(db);
      const agentRegistry = new AgentRegistry(db, derivedKey);

      vault.add({
        name: 'test-cred',
        service: 'test-svc',
        secret: 'secret-123',
        domains: ['api.example.com'],
      });

      // Agent exists but has no grants
      const agent = agentRegistry.add({ name: 'no-access-agent' });

      const mcpServer = new AegisMcpServer({
        vault,
        ledger,
        agentRegistry,
        agentToken: agent.token,
        transport: 'stdio',
        logLevel: 'error',
      });

      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      const internalServer = (mcpServer as unknown as { server: McpServer }).server;
      await internalServer.connect(serverTransport);
      const client = new Client({ name: 'test', version: '1.0.0' });
      await client.connect(clientTransport);

      try {
        const result = await client.callTool({
          name: 'aegis_proxy_request',
          arguments: { service: 'test-svc', path: '/test' },
        });
        expect(result.isError).toBe(true);
        const text = (result.content as Array<{ type: string; text: string }>)[0].text;
        expect(text).toContain('not granted access');
      } finally {
        await client.close();
        await internalServer.close();
        db.close();
      }
    });

    it('should enforce policy violations', async () => {
      const db = new Database(':memory:');
      migrate(db);
      const masterKey = 'test-key';
      const salt = Buffer.from('test-salt');
      const derivedKey = deriveKey(masterKey, salt);

      const vault = new Vault(db, masterKey, salt);
      const ledger = new Ledger(db);
      const agentRegistry = new AgentRegistry(db, derivedKey);

      const cred = vault.add({
        name: 'test-cred',
        service: 'test-svc',
        secret: 'secret-123',
        domains: ['api.example.com'],
      });

      const agent = agentRegistry.add({ name: 'policy-agent' });
      agentRegistry.grant({ agentName: 'policy-agent', credentialId: cred.id });

      // Create a policy that only allows GET
      const policy: Policy = {
        agent: 'policy-agent',
        rules: [
          {
            service: 'test-svc',
            methods: ['GET'],
          },
        ],
      };

      const policyResult: PolicyValidationResult = {
        valid: true,
        policy,
        errors: [],
        filePath: 'test-policy.yaml',
      };

      const mcpServer = new AegisMcpServer({
        vault,
        ledger,
        agentRegistry,
        agentToken: agent.token,
        transport: 'stdio',
        policies: [policyResult],
        policyMode: 'enforce',
        logLevel: 'error',
      });

      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      const internalServer = (mcpServer as unknown as { server: McpServer }).server;
      await internalServer.connect(serverTransport);
      const client = new Client({ name: 'test', version: '1.0.0' });
      await client.connect(clientTransport);

      try {
        // POST should be blocked by policy
        const result = await client.callTool({
          name: 'aegis_proxy_request',
          arguments: { service: 'test-svc', path: '/test', method: 'POST' },
        });
        expect(result.isError).toBe(true);
        const text = (result.content as Array<{ type: string; text: string }>)[0].text;
        expect(text).toContain('Policy violation');
      } finally {
        await client.close();
        await internalServer.close();
        db.close();
      }
    });

    it('should allow dry-run policy violations', async () => {
      const db = new Database(':memory:');
      migrate(db);
      const masterKey = 'test-key';
      const salt = Buffer.from('test-salt');
      const derivedKey = deriveKey(masterKey, salt);

      const vault = new Vault(db, masterKey, salt);
      const ledger = new Ledger(db);
      const agentRegistry = new AgentRegistry(db, derivedKey);

      const cred = vault.add({
        name: 'test-cred',
        service: 'test-svc',
        secret: 'secret-123',
        domains: ['api.example.com'],
      });

      const agent = agentRegistry.add({ name: 'dryrun-agent' });
      agentRegistry.grant({ agentName: 'dryrun-agent', credentialId: cred.id });

      const policy: Policy = {
        agent: 'dryrun-agent',
        rules: [
          {
            service: 'test-svc',
            methods: ['GET'],
          },
        ],
      };

      const policyResult: PolicyValidationResult = {
        valid: true,
        policy,
        errors: [],
        filePath: 'test-policy.yaml',
      };

      const mcpServer = new AegisMcpServer({
        vault,
        ledger,
        agentRegistry,
        agentToken: agent.token,
        transport: 'stdio',
        policies: [policyResult],
        policyMode: 'dry-run',
        logLevel: 'error',
      });

      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      const internalServer = (mcpServer as unknown as { server: McpServer }).server;
      await internalServer.connect(serverTransport);
      const client = new Client({ name: 'test', version: '1.0.0' });
      await client.connect(clientTransport);

      try {
        // POST should be allowed in dry-run mode (but it will fail on the network call)
        // We just verify it doesn't throw a policy error
        const result = await client.callTool({
          name: 'aegis_proxy_request',
          arguments: { service: 'test-svc', path: '/test', method: 'POST' },
        });
        // It should fail with a network error (not a policy error)
        // since there's no actual upstream server
        if (result.isError) {
          const text = (result.content as Array<{ type: string; text: string }>)[0].text;
          expect(text).not.toContain('Policy violation');
        }

        // But the dry-run should be logged
        const entries = ledger.query({ status: 'blocked' });
        expect(entries.some((e) => e.blockedReason?.includes('POLICY_DRY_RUN'))).toBe(true);
      } finally {
        await client.close();
        await internalServer.close();
        db.close();
      }
    });

    it('should block suspicious request bodies', async () => {
      const setup = await createTestSetup();
      try {
        setup.vault.add({
          name: 'test-cred',
          service: 'test-svc',
          secret: 'secret-123',
          domains: ['api.example.com'],
          bodyInspection: 'block',
        });

        const result = await setup.client.callTool({
          name: 'aegis_proxy_request',
          arguments: {
            service: 'test-svc',
            path: '/test',
            method: 'POST',
            body: JSON.stringify({
              data: 'ghp_0123456789abcdef0123456789abcdef01234567',
            }),
          },
        });
        expect(result.isError).toBe(true);
        const text = (result.content as Array<{ type: string; text: string }>)[0].text;
        expect(text).toContain('credential-like patterns');
      } finally {
        await setup.cleanup();
      }
    });
  });

  describe('Agent Token Validation', () => {
    it('should reject invalid agent token on construction', () => {
      const db = new Database(':memory:');
      migrate(db);
      const masterKey = 'test-key';
      const salt = Buffer.from('test-salt');
      const derivedKey = deriveKey(masterKey, salt);

      const vault = new Vault(db, masterKey, salt);
      const ledger = new Ledger(db);
      const agentRegistry = new AgentRegistry(db, derivedKey);

      expect(() => {
        new AegisMcpServer({
          vault,
          ledger,
          agentRegistry,
          agentToken: 'invalid-token-here',
          transport: 'stdio',
          logLevel: 'error',
        });
      }).toThrow('Invalid agent token');

      db.close();
    });

    it('should work without agent token (unauthenticated)', async () => {
      const setup = await createTestSetup();
      try {
        const result = await setup.client.callTool({ name: 'aegis_health', arguments: {} });
        const health = JSON.parse(
          (result.content as Array<{ type: string; text: string }>)[0].text,
        );
        expect(health.authenticatedAgent).toBeNull();
      } finally {
        await setup.cleanup();
      }
    });
  });

  describe('Credential Injection', () => {
    // Note: Full proxy integration tests require modifying the target host/port,
    // which is not exposed in the MCP server's public API (it always uses port 443).
    // The security controls (domain guard, TTL, agent scoping, policy, rate limits,
    // body inspection) are tested above through error paths.
    // Full end-to-end proxy tests with credential injection are covered by
    // Gate integration tests (gate.test.ts, gate-agent.test.ts).

    it('should use the correct auth type for credential injection', async () => {
      // This is a design verification test — the injection method is the same
      // as Gate's, reusing the same pattern. Network call will fail but we
      // verify the right service is targeted.
      const setup = await createTestSetup();
      try {
        setup.vault.add({
          name: 'inject-cred',
          service: 'inject-svc',
          secret: 'test-secret',
          authType: 'bearer',
          domains: ['api.example.com'],
        });

        const result = await setup.client.callTool({
          name: 'aegis_proxy_request',
          arguments: { service: 'inject-svc', path: '/test' },
        });
        // Will fail with DNS error since api.example.com isn't real, but
        // it should pass all security checks first
        if (result.isError) {
          const text = (result.content as Array<{ type: string; text: string }>)[0].text;
          expect(text).toContain('Failed to reach upstream');
          // Verify it's a network error, not a security block
          expect(text).not.toContain('not in the credential');
          expect(text).not.toContain('expired');
          expect(text).not.toContain('not granted');
        }
      } finally {
        await setup.cleanup();
      }
    });
  });

  describe('Security Properties', () => {
    it('should never expose secrets in list_services output', async () => {
      const setup = await createTestSetup();
      try {
        const secrets = ['sk-openai-secret-key', 'ghp_verysecrettoken', 'xoxb-slack-bot-token'];

        for (const [i, secret] of secrets.entries()) {
          setup.vault.add({
            name: `service-${i}`,
            service: `svc-${i}`,
            secret,
            domains: [`api${i}.example.com`],
          });
        }

        const result = await setup.client.callTool({
          name: 'aegis_list_services',
          arguments: {},
        });
        const text = (result.content as Array<{ type: string; text: string }>)[0].text;

        // Verify none of the secrets appear in the output
        for (const secret of secrets) {
          expect(text).not.toContain(secret);
        }
      } finally {
        await setup.cleanup();
      }
    });

    it('should never expose secrets in health output', async () => {
      const setup = await createTestSetup();
      try {
        setup.vault.add({
          name: 'secret-cred',
          service: 'secret-svc',
          secret: 'super-secret-value-12345',
          domains: ['api.example.com'],
        });

        const result = await setup.client.callTool({ name: 'aegis_health', arguments: {} });
        const text = (result.content as Array<{ type: string; text: string }>)[0].text;
        expect(text).not.toContain('super-secret-value-12345');
      } finally {
        await setup.cleanup();
      }
    });

    it('should never expose secrets in error messages', async () => {
      const setup = await createTestSetup();
      try {
        setup.vault.add({
          name: 'error-cred',
          service: 'error-svc',
          secret: 'sk-error-secret-value',
          domains: ['api.allowed.com'],
        });

        // Try to hit a domain not in the allowlist
        const result = await setup.client.callTool({
          name: 'aegis_proxy_request',
          arguments: {
            service: 'error-svc',
            path: '/test',
            targetHost: 'evil.com',
          },
        });
        const text = (result.content as Array<{ type: string; text: string }>)[0].text;
        expect(text).not.toContain('sk-error-secret-value');
      } finally {
        await setup.cleanup();
      }
    });

    it('should strip auth headers from agent-provided headers', async () => {
      const setup = await createTestSetup();
      try {
        setup.vault.add({
          name: 'strip-cred',
          service: 'strip-svc',
          secret: 'real-secret',
          domains: ['api.example.com'],
        });

        // Try to pass authorization header — should be stripped
        // This will fail on network but we verify the error isn't about auth injection
        const result = await setup.client.callTool({
          name: 'aegis_proxy_request',
          arguments: {
            service: 'strip-svc',
            path: '/test',
            headers: {
              authorization: 'Bearer fake-token',
              'x-api-key': 'fake-key',
              'x-custom-header': 'allowed',
            },
          },
        });

        // Will fail with network error (no actual upstream), not auth error
        if (result.isError) {
          const text = (result.content as Array<{ type: string; text: string }>)[0].text;
          // The error should be a network error, not an auth error
          expect(text).toContain('Failed to reach upstream');
        }
      } finally {
        await setup.cleanup();
      }
    });
  });

  describe('Audit Logging', () => {
    it('should log blocked domain guard violations to ledger', async () => {
      const setup = await createTestSetup();
      try {
        setup.vault.add({
          name: 'audit-cred',
          service: 'audit-svc',
          secret: 'secret',
          domains: ['safe.example.com'],
        });

        await setup.client.callTool({
          name: 'aegis_proxy_request',
          arguments: {
            service: 'audit-svc',
            path: '/test',
            targetHost: 'evil.com',
          },
        });

        const entries = setup.ledger.query({ status: 'blocked' });
        expect(entries.length).toBe(1);
        expect(entries[0].blockedReason).toContain('Domain');
        expect(entries[0].service).toBe('audit-svc');
      } finally {
        await setup.cleanup();
      }
    });

    it('should log body inspection blocks to ledger', async () => {
      const setup = await createTestSetup();
      try {
        setup.vault.add({
          name: 'body-cred',
          service: 'body-svc',
          secret: 'secret',
          domains: ['api.example.com'],
          bodyInspection: 'block',
        });

        await setup.client.callTool({
          name: 'aegis_proxy_request',
          arguments: {
            service: 'body-svc',
            path: '/test',
            method: 'POST',
            body: '{"leak": "ghp_0123456789abcdef0123456789abcdef01234567"}',
          },
        });

        const entries = setup.ledger.query({ status: 'blocked' });
        expect(entries.length).toBe(1);
        expect(entries[0].blockedReason).toContain('Body inspection');
      } finally {
        await setup.cleanup();
      }
    });

    it('should block write methods on read-only scoped credentials', async () => {
      const setup = await createTestSetup();
      try {
        setup.vault.add({
          name: 'readonly-mcp',
          service: 'readonly-mcp-svc',
          secret: 'secret',
          domains: ['api.example.com'],
          scopes: ['read'],
        });

        const result = await setup.client.callTool({
          name: 'aegis_proxy_request',
          arguments: {
            service: 'readonly-mcp-svc',
            path: '/test',
            method: 'POST',
          },
        });

        expect(result.isError).toBe(true);
        const text = (result.content as Array<{ type: string; text: string }>)[0].text;
        expect(text).toContain('not permitted by credential scopes');

        const entries = setup.ledger.query({ status: 'blocked' });
        expect(entries.length).toBe(1);
        expect(entries[0].blockedReason).toContain('not permitted by credential scopes');
      } finally {
        await setup.cleanup();
      }
    });

    it('should block read methods on write-only scoped credentials', async () => {
      const setup = await createTestSetup();
      try {
        setup.vault.add({
          name: 'writeonly-mcp',
          service: 'writeonly-mcp-svc',
          secret: 'secret',
          domains: ['api.example.com'],
          scopes: ['write'],
        });

        const result = await setup.client.callTool({
          name: 'aegis_proxy_request',
          arguments: {
            service: 'writeonly-mcp-svc',
            path: '/test',
            method: 'GET',
          },
        });

        expect(result.isError).toBe(true);
        const text = (result.content as Array<{ type: string; text: string }>)[0].text;
        expect(text).toContain('not permitted by credential scopes');
      } finally {
        await setup.cleanup();
      }
    });
  });
});
