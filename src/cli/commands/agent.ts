/**
 * Agent commands: add, list, remove, regenerate, grant, revoke, set-rate-limit.
 */

import type { Command } from 'commander';
import { AgentRegistry } from '../../agent/index.js';
import { getConfig } from '../../config.js';
import { getDb, getVaultSalt, migrate } from '../../db.js';
import { deriveKey, Vault } from '../../vault/index.js';
import { requireUserAuth } from '../auth.js';
import { localTime, validateIdentifier, validateRateLimit } from '../validation.js';

export function register(program: Command): void {
  const agentCmd = program.command('agent').description('Manage agent identities and access');

  agentCmd
    .command('add')
    .description('Register a new agent and generate its token')
    .requiredOption('-n, --name <name>', 'Unique name for the agent')
    .option('--rate-limit <limit>', 'Agent-level rate limit (e.g. 50/min, 500/hour)')
    .action((opts: { name: string; rateLimit?: string }) => {
      // ── Validate CLI flags ──
      validateIdentifier(opts.name, 'agent name');
      if (opts.rateLimit) {
        validateRateLimit(opts.rateLimit);
      }

      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'agent:write');
      const registry = new AgentRegistry(db, key);

      try {
        const agent = registry.add({ name: opts.name, rateLimit: opts.rateLimit });

        console.log(`\n✓ Agent registered\n`);
        console.log(`  Name:   ${agent.name}`);
        console.log(`  Prefix: ${agent.tokenPrefix}...`);
        if (agent.rateLimit) {
          console.log(`  Rate:   ${agent.rateLimit}`);
        }
        console.log(`\n  ⚠  Save this token — it will NOT be shown again:\n`);
        console.log(`  ${agent.token}\n`);
        console.log(`  Set it in your agent's requests:`);
        console.log(`    X-Aegis-Agent: ${agent.token}\n`);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        if (message.includes('UNIQUE')) {
          console.error(`\n✗ An agent named "${opts.name}" already exists.\n`);
        } else {
          console.error(`\n✗ Error: ${message}\n`);
        }
        process.exit(1);
      } finally {
        db.close();
      }
    });

  agentCmd
    .command('list')
    .description('List all registered agents')
    .action(() => {
      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'agent:read');
      const registry = new AgentRegistry(db, key);
      const vaultInstance = new Vault(db, config.masterKey, getVaultSalt(config));

      const agents = registry.list();
      if (agents.length === 0) {
        console.log('\n  No agents registered. Add one with: aegis agent add --name my-bot\n');
        db.close();
        return;
      }

      console.log(`\n  Aegis Agents — ${agents.length} registered\n`);
      for (const agent of agents) {
        const grants = registry.listGrants(agent.name);
        const grantNames = grants
          .map((credId) => {
            const creds = vaultInstance.list();
            const cred = creds.find((c) => c.id === credId);
            return cred?.name ?? credId.slice(0, 8);
          })
          .join(', ');

        console.log(`  ┌ ${agent.name} (${agent.tokenPrefix}...)`);
        console.log(`  │ Created: ${localTime(agent.createdAt)}`);
        if (agent.rateLimit) {
          console.log(`  │ Rate:    ${agent.rateLimit}`);
        }
        console.log(`  │ Grants:  ${grantNames || '(none)'}`);
        console.log(`  └`);
      }
      console.log();
      db.close();
    });

  agentCmd
    .command('remove')
    .description('Remove an agent and all its credential grants')
    .requiredOption('-n, --name <name>', 'Name of the agent to remove')
    .action((opts: { name: string }) => {
      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'agent:write');
      const registry = new AgentRegistry(db, key);

      const removed = registry.remove(opts.name);
      if (removed) {
        console.log(`\n✓ Agent "${opts.name}" removed (all credential grants revoked).\n`);
      } else {
        console.error(`\n✗ No agent found with name "${opts.name}".\n`);
        process.exit(1);
      }
      db.close();
    });

  agentCmd
    .command('regenerate')
    .description("Regenerate an agent's token (invalidates the old token)")
    .requiredOption('-n, --name <name>', 'Agent name')
    .action((opts: { name: string }) => {
      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'agent:write');
      const registry = new AgentRegistry(db, key);

      const result = registry.regenerateToken(opts.name);
      if (!result) {
        console.error(`\n✗ No agent found with name "${opts.name}".\n`);
        process.exit(1);
      }

      console.log(`\n✓ Token regenerated for agent "${result.name}".`);
      console.log(`\n⚠  The old token is now invalid. Update all clients using this agent.\n`);
      console.log(`  New Token:  ${result.token}`);
      console.log(`  Prefix:     ${result.tokenPrefix}`);
      console.log(`\n  Save this token — it cannot be recovered.\n`);

      db.close();
    });

  agentCmd
    .command('grant')
    .description('Grant an agent access to a credential')
    .requiredOption('--agent <name>', 'Agent name')
    .requiredOption('--credential <name>', 'Credential name')
    .action((opts: { agent: string; credential: string }) => {
      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'agent:write');
      const registry = new AgentRegistry(db, key);
      const vaultInstance = new Vault(db, config.masterKey, getVaultSalt(config));

      try {
        const cred = vaultInstance.getByName(opts.credential);
        if (!cred) {
          console.error(`\n✗ No credential found with name "${opts.credential}".\n`);
          process.exit(1);
        }

        registry.grant({ agentName: opts.agent, credentialId: cred.id });
        console.log(
          `\n✓ Agent "${opts.agent}" granted access to credential "${opts.credential}"\n`,
        );
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n✗ ${message}\n`);
        process.exit(1);
      } finally {
        db.close();
      }
    });

  agentCmd
    .command('revoke')
    .description("Revoke an agent's access to a credential")
    .requiredOption('--agent <name>', 'Agent name')
    .requiredOption('--credential <name>', 'Credential name')
    .action((opts: { agent: string; credential: string }) => {
      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'agent:write');
      const registry = new AgentRegistry(db, key);
      const vaultInstance = new Vault(db, config.masterKey, getVaultSalt(config));

      try {
        const cred = vaultInstance.getByName(opts.credential);
        if (!cred) {
          console.error(`\n✗ No credential found with name "${opts.credential}".\n`);
          process.exit(1);
        }

        const revoked = registry.revoke({ agentName: opts.agent, credentialId: cred.id });
        if (revoked) {
          console.log(
            `\n✓ Agent "${opts.agent}" access to credential "${opts.credential}" revoked.\n`,
          );
        } else {
          console.log(`\n  Agent "${opts.agent}" did not have access to "${opts.credential}".\n`);
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n✗ ${message}\n`);
        process.exit(1);
      } finally {
        db.close();
      }
    });

  agentCmd
    .command('set-rate-limit')
    .description('Set or remove an agent-level rate limit')
    .requiredOption('--agent <name>', 'Agent name')
    .requiredOption('--limit <limit>', "Rate limit (e.g. 50/min) or 'none' to remove")
    .action((opts: { agent: string; limit: string }) => {
      // ── Validate CLI flags ──
      if (opts.limit.toLowerCase() !== 'none') {
        validateRateLimit(opts.limit);
      }

      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'agent:write');
      const registry = new AgentRegistry(db, key);

      try {
        const rateLimit = opts.limit.toLowerCase() === 'none' ? null : opts.limit;
        const agent = registry.setRateLimit({ agentName: opts.agent, rateLimit });
        if (rateLimit) {
          console.log(`\n✓ Agent "${agent.name}" rate limit set to ${rateLimit}\n`);
        } else {
          console.log(`\n✓ Agent "${agent.name}" rate limit removed\n`);
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n✗ ${message}\n`);
        process.exit(1);
      } finally {
        db.close();
      }
    });
}
