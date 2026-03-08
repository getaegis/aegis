/**
 * RBAC enforcement helper for CLI commands.
 *
 * Authenticates the current user via AEGIS_USER_TOKEN and checks
 * whether they have the required permission.
 */

import type { getDb } from '../db.js';
import type { Permission } from '../user/index.js';
import { hasPermission, UserRegistry } from '../user/index.js';

/**
 * Authenticate the current user via AEGIS_USER_TOKEN and check permission.
 *
 * Always enforced once users exist. If no users have been created yet
 * (bootstrap mode), all commands are allowed — `aegis init` creates the
 * first admin user.
 *
 * Returns true if allowed. Calls process.exit(1) if denied.
 */
export function requireUserAuth(
  db: ReturnType<typeof getDb>,
  derivedKey: Buffer,
  permission: Permission,
): boolean {
  const registry = new UserRegistry(db, derivedKey);

  // Bootstrap mode: no users exist yet — allow everything so init can create the first admin
  if (registry.count() === 0) return true;

  const token = process.env.AEGIS_USER_TOKEN;
  if (!token) {
    console.error('\n✗ Authentication required. Set AEGIS_USER_TOKEN=<your-api-key>\n');
    console.error('  Get an API key from your admin, or regenerate with:');
    console.error('  aegis user regenerate-token --name <name>\n');
    process.exit(1);
  }

  const user = registry.validateToken(token);

  if (!user) {
    console.error('\n✗ Invalid API key. Token not recognized.\n');
    console.error('  Regenerate with: aegis user regenerate-token --name <name>\n');
    process.exit(1);
  }

  if (!hasPermission(user.role, permission)) {
    console.error(`\n✗ Permission denied. Role "${user.role}" does not have "${permission}".\n`);
    console.error(`  Required permission: ${permission}`);
    console.error(`  Your role: ${user.role}`);
    console.error(`  Contact an admin to upgrade your role.\n`);
    process.exit(1);
  }

  return true;
}
