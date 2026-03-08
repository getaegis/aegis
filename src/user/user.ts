import * as crypto from 'node:crypto';
import type Database from 'better-sqlite3';

// ─── Roles ───────────────────────────────────────────────────────

/**
 * Aegis user roles — three tiers of access control:
 * - **admin**: Full access — manage credentials, agents, policies, users, webhooks, vaults
 * - **operator**: Operational access — start/stop Gate, view Ledger, manage agents
 * - **viewer**: Read-only — view Ledger, stats, and credential metadata (no secrets)
 */
export type UserRole = 'admin' | 'operator' | 'viewer';

export const VALID_ROLES: readonly UserRole[] = ['admin', 'operator', 'viewer'] as const;

/**
 * Permission categories that map to CLI commands/actions.
 * Each role grants a different set of permissions.
 */
export type Permission =
  | 'vault:read'
  | 'vault:write'
  | 'vault:manage'
  | 'agent:read'
  | 'agent:write'
  | 'ledger:read'
  | 'ledger:export'
  | 'gate:start'
  | 'policy:read'
  | 'policy:write'
  | 'webhook:read'
  | 'webhook:write'
  | 'user:read'
  | 'user:write'
  | 'dashboard:view'
  | 'doctor:run';

/**
 * Role → permission mapping.
 * More privileged roles include all permissions from less privileged ones.
 */
const ROLE_PERMISSIONS: Record<UserRole, ReadonlySet<Permission>> = {
  admin: new Set<Permission>([
    'vault:read',
    'vault:write',
    'vault:manage',
    'agent:read',
    'agent:write',
    'ledger:read',
    'ledger:export',
    'gate:start',
    'policy:read',
    'policy:write',
    'webhook:read',
    'webhook:write',
    'user:read',
    'user:write',
    'dashboard:view',
    'doctor:run',
  ]),
  operator: new Set<Permission>([
    'vault:read',
    'agent:read',
    'agent:write',
    'ledger:read',
    'ledger:export',
    'gate:start',
    'policy:read',
    'webhook:read',
    'dashboard:view',
    'doctor:run',
  ]),
  viewer: new Set<Permission>(['vault:read', 'ledger:read', 'dashboard:view', 'doctor:run']),
};

/**
 * Check if a role has a specific permission.
 */
export function hasPermission(role: UserRole, permission: Permission): boolean {
  return ROLE_PERMISSIONS[role].has(permission);
}

/**
 * Get all permissions for a role.
 */
export function getPermissions(role: UserRole): ReadonlySet<Permission> {
  return ROLE_PERMISSIONS[role];
}

// ─── Types ───────────────────────────────────────────────────────

export interface User {
  id: string;
  name: string;
  role: UserRole;
  tokenPrefix: string;
  createdAt: string;
  updatedAt: string;
}

export interface UserWithToken extends User {
  token: string;
}

interface UserRow {
  id: string;
  name: string;
  role: string;
  token_hash: string;
  token_prefix: string;
  created_at: string;
  updated_at: string;
}

// ─── User Registry ──────────────────────────────────────────────

/**
 * User Registry — manages user identities, authentication, and role-based access control.
 *
 * Users are authenticated via API keys (same pattern as agent tokens):
 * - Token format: aegis_user_{uuid}_{hmac_prefix}
 * - Tokens are SHA-256 hashed for fast lookup — hash-only, no recovery
 * - Prefixed (first 17 chars: "aegis_user_" + 6) for safe logging
 *
 * Security: Same hash-only storage as agent tokens. If a token is lost,
 * use regenerateToken() to issue a new one.
 */
export class UserRegistry {
  private derivedKey: Buffer;

  constructor(
    private db: Database.Database,
    derivedKey: Buffer,
  ) {
    this.derivedKey = derivedKey;
  }

  /**
   * Register a new user. Returns the user with their API key (shown once).
   *
   * Token format: aegis_user_{uuid}_{hmac_prefix}
   */
  add(params: { name: string; role: UserRole }): UserWithToken {
    if (!VALID_ROLES.includes(params.role)) {
      throw new Error(`Invalid role "${params.role}". Must be one of: ${VALID_ROLES.join(', ')}`);
    }

    const id = crypto.randomUUID();
    const uuid = crypto.randomUUID();

    // Create HMAC of the UUID using the derived key for token integrity
    const hmac = crypto
      .createHmac('sha256', this.derivedKey)
      .update(uuid)
      .digest('hex')
      .slice(0, 16);
    const token = `aegis_user_${uuid}_${hmac}`;

    // Hash the full token for fast lookup (hash-only — no recovery, only regeneration)
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const tokenPrefix = token.slice(0, 17); // "aegis_user_" + 6 chars

    this.db
      .prepare(
        `INSERT INTO users (id, name, role, token_hash, token_prefix)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(id, params.name, params.role, tokenHash, tokenPrefix);

    return {
      id,
      name: params.name,
      role: params.role,
      tokenPrefix,
      token,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
  }

  /**
   * List all registered users (without tokens).
   */
  list(): User[] {
    const rows = this.db.prepare('SELECT * FROM users ORDER BY created_at DESC').all() as UserRow[];

    return rows.map((row) => this.rowToUser(row));
  }

  /**
   * Get a user by name (without token).
   */
  getByName(name: string): User | null {
    const row = this.db.prepare('SELECT * FROM users WHERE name = ?').get(name) as
      | UserRow
      | undefined;
    return row ? this.rowToUser(row) : null;
  }

  /**
   * Validate a user API key. Returns the user if the token is valid, null otherwise.
   *
   * Uses SHA-256 hash comparison for O(1) lookup.
   */
  validateToken(token: string): User | null {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const row = this.db.prepare('SELECT * FROM users WHERE token_hash = ?').get(tokenHash) as
      | UserRow
      | undefined;

    return row ? this.rowToUser(row) : null;
  }

  /**
   * Remove a user by name.
   */
  remove(name: string): boolean {
    const result = this.db.prepare('DELETE FROM users WHERE name = ?').run(name);
    return result.changes > 0;
  }

  /**
   * Update a user's role.
   */
  updateRole(params: { name: string; role: UserRole }): User {
    if (!VALID_ROLES.includes(params.role)) {
      throw new Error(`Invalid role "${params.role}". Must be one of: ${VALID_ROLES.join(', ')}`);
    }

    const user = this.getByName(params.name);
    if (!user) {
      throw new Error(`No user found with name "${params.name}"`);
    }

    this.db
      .prepare("UPDATE users SET role = ?, updated_at = datetime('now') WHERE name = ?")
      .run(params.role, params.name);

    return {
      ...user,
      role: params.role,
      updatedAt: new Date().toISOString(),
    };
  }

  /**
   * Regenerate a user's token. Issues a new token, invalidates the old one.
   *
   * The user keeps their identity (id, name, role).
   * Only the token changes.
   *
   * Returns the user with the new token (shown once), or null if not found.
   */
  regenerateToken(name: string): UserWithToken | null {
    const user = this.getByName(name);
    if (!user) return null;

    const uuid = crypto.randomUUID();
    const hmac = crypto
      .createHmac('sha256', this.derivedKey)
      .update(uuid)
      .digest('hex')
      .slice(0, 16);
    const token = `aegis_user_${uuid}_${hmac}`;

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const tokenPrefix = token.slice(0, 17);

    this.db
      .prepare(
        `UPDATE users SET token_hash = ?, token_prefix = ?, updated_at = datetime('now') WHERE id = ?`,
      )
      .run(tokenHash, tokenPrefix, user.id);

    return {
      ...user,
      tokenPrefix,
      token,
      updatedAt: new Date().toISOString(),
    };
  }

  /**
   * Check if a user has a specific permission.
   */
  checkPermission(name: string, permission: Permission): boolean {
    const user = this.getByName(name);
    if (!user) return false;
    return hasPermission(user.role, permission);
  }

  /**
   * Count users. Used by init to determine if initial admin setup is needed.
   */
  count(): number {
    const row = this.db.prepare('SELECT COUNT(*) as count FROM users').get() as { count: number };
    return row.count;
  }

  // ─── Internal ───────────────────────────────────────────────────

  private rowToUser(row: UserRow): User {
    return {
      id: row.id,
      name: row.name,
      role: row.role as UserRole,
      tokenPrefix: row.token_prefix,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
