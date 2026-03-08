/**
 * User commands: add, list, remove, role, regenerate-token.
 */

import type { Command } from 'commander';
import { getConfig } from '../../config.js';
import { getDb, getVaultSalt, migrate } from '../../db.js';
import { UserRegistry } from '../../user/index.js';
import { deriveKey } from '../../vault/index.js';
import { requireUserAuth } from '../auth.js';
import { localTime, validateEnum, validateIdentifier } from '../validation.js';

export function register(program: Command): void {
  const userCmd = program.command('user').description('Manage users and roles (RBAC)');

  userCmd
    .command('add')
    .description('Add a new user with a role')
    .requiredOption('-n, --name <name>', 'Unique username')
    .requiredOption('-r, --role <role>', 'Role: admin, operator, or viewer')
    .action((opts: { name: string; role: string }) => {
      // ── Validate CLI flags ──
      validateIdentifier(opts.name, 'username');
      const validatedRole = validateEnum(
        opts.role,
        ['admin', 'operator', 'viewer'] as const,
        'role',
      );

      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'user:write');
      const registry = new UserRegistry(db, key);

      try {
        const user = registry.add({
          name: opts.name,
          role: validatedRole,
        });

        console.log(`\n✓ User added to Aegis\n`);
        console.log(`  Name:   ${user.name}`);
        console.log(`  Role:   ${user.role}`);
        console.log(`  Prefix: ${user.tokenPrefix}`);
        console.log(`\n  API Key (shown ONCE — save it now):`);
        console.log(`  ${user.token}\n`);
        console.log(`  Use AEGIS_USER_TOKEN=<key> to authenticate CLI commands.\n`);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n✗ ${message}\n`);
        process.exit(1);
      }

      db.close();
    });

  userCmd
    .command('list')
    .description('List all users')
    .action(() => {
      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'user:read');
      const registry = new UserRegistry(db, key);

      const users = registry.list();
      if (users.length === 0) {
        console.log('\n  No users registered. Use `aegis user add` to create one.\n');
      } else {
        console.log(`\n  Users (${users.length}):\n`);
        for (const u of users) {
          console.log(
            `    ${u.name} [${u.role}] — prefix: ${u.tokenPrefix} — created: ${localTime(u.createdAt)}`,
          );
        }
        console.log('');
      }

      db.close();
    });

  userCmd
    .command('remove')
    .description('Remove a user')
    .requiredOption('-n, --name <name>', 'Username to remove')
    .option('--confirm', 'Skip confirmation')
    .action((opts: { name: string; confirm?: boolean }) => {
      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'user:write');
      const registry = new UserRegistry(db, key);

      if (!opts.confirm) {
        console.error(`\n✗ Add --confirm to permanently remove user "${opts.name}"\n`);
        process.exit(1);
      }

      const removed = registry.remove(opts.name);
      if (removed) {
        console.log(`\n✓ User "${opts.name}" removed\n`);
      } else {
        console.error(`\n✗ No user found with name "${opts.name}"\n`);
        process.exit(1);
      }

      db.close();
    });

  userCmd
    .command('role')
    .description("Update a user's role")
    .requiredOption('-n, --name <name>', 'Username to update')
    .requiredOption('-r, --role <role>', 'New role: admin, operator, or viewer')
    .action((opts: { name: string; role: string }) => {
      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'user:write');
      const registry = new UserRegistry(db, key);

      const validRoles = ['admin', 'operator', 'viewer'];
      if (!validRoles.includes(opts.role)) {
        console.error(
          `\n✗ Invalid role "${opts.role}". Must be one of: ${validRoles.join(', ')}\n`,
        );
        process.exit(1);
      }

      try {
        const updated = registry.updateRole({
          name: opts.name,
          role: opts.role as 'admin' | 'operator' | 'viewer',
        });
        console.log(`\n✓ User "${updated.name}" role updated to "${updated.role}"\n`);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n✗ ${message}\n`);
        process.exit(1);
      }

      db.close();
    });

  userCmd
    .command('regenerate-token')
    .description("Regenerate a user's API key (invalidates the old one)")
    .requiredOption('-n, --name <name>', 'Username')
    .action((opts: { name: string }) => {
      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'user:write');
      const registry = new UserRegistry(db, key);

      const result = registry.regenerateToken(opts.name);
      if (!result) {
        console.error(`\n✗ No user found with name "${opts.name}"\n`);
        process.exit(1);
      }

      console.log(`\n✓ Token regenerated for "${result.name}"\n`);
      console.log(`  New API Key (shown ONCE — save it now):`);
      console.log(`  ${result.token}\n`);
      console.log(`  The previous key is now invalid.\n`);

      db.close();
    });
}
