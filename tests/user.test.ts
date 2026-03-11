import Database from 'better-sqlite3-multiple-ciphers';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { migrate } from '../src/db.js';
import type { Permission, UserRole } from '../src/user/index.js';
import { getPermissions, hasPermission, UserRegistry, VALID_ROLES } from '../src/user/index.js';
import { deriveKey } from '../src/vault/crypto.js';

describe('User & RBAC', () => {
  const masterKey = 'test-rbac-master-key';
  const salt = 'test-rbac-salt-hex';
  let db: ReturnType<typeof Database>;
  let derivedKey: Buffer;
  let registry: UserRegistry;

  beforeEach(() => {
    db = new Database(':memory:');
    migrate(db);
    derivedKey = deriveKey(masterKey, salt);
    registry = new UserRegistry(db, derivedKey);
  });

  afterEach(() => {
    db.close();
  });

  // ─── User CRUD ─────────────────────────────────────────────────

  describe('add', () => {
    it('creates a user with a token', () => {
      const user = registry.add({ name: 'alice', role: 'admin' });

      expect(user.name).toBe('alice');
      expect(user.role).toBe('admin');
      expect(user.token).toMatch(/^aegis_user_.+_.+$/);
      expect(user.tokenPrefix).toHaveLength(17);
      expect(user.id).toBeDefined();
      expect(user.createdAt).toBeDefined();
    });

    it('rejects invalid roles', () => {
      expect(() => registry.add({ name: 'bob', role: 'superadmin' as UserRole })).toThrow(
        'Invalid role',
      );
    });

    it('rejects duplicate names', () => {
      registry.add({ name: 'alice', role: 'admin' });
      expect(() => registry.add({ name: 'alice', role: 'viewer' })).toThrow();
    });

    it('generates unique tokens for each user', () => {
      const a = registry.add({ name: 'alice', role: 'admin' });
      const b = registry.add({ name: 'bob', role: 'operator' });

      expect(a.token).not.toBe(b.token);
      expect(a.tokenPrefix).not.toBe(b.tokenPrefix);
    });
  });

  describe('list', () => {
    it('returns all users', () => {
      registry.add({ name: 'alice', role: 'admin' });
      registry.add({ name: 'bob', role: 'viewer' });

      const users = registry.list();
      expect(users).toHaveLength(2);
      // Should not expose tokens
      for (const u of users) {
        expect(u).not.toHaveProperty('token');
      }
    });

    it('returns empty array when no users exist', () => {
      expect(registry.list()).toHaveLength(0);
    });
  });

  describe('getByName', () => {
    it('returns user by name', () => {
      registry.add({ name: 'alice', role: 'operator' });
      const user = registry.getByName('alice');

      expect(user).not.toBeNull();
      expect(user?.name).toBe('alice');
      expect(user?.role).toBe('operator');
    });

    it('returns null for unknown name', () => {
      expect(registry.getByName('nonexistent')).toBeNull();
    });
  });

  describe('validateToken', () => {
    it('validates a correct token', () => {
      const created = registry.add({ name: 'alice', role: 'admin' });
      const user = registry.validateToken(created.token);

      expect(user).not.toBeNull();
      expect(user?.name).toBe('alice');
      expect(user?.role).toBe('admin');
    });

    it('rejects invalid tokens', () => {
      registry.add({ name: 'alice', role: 'admin' });
      expect(registry.validateToken('aegis_user_fake_token')).toBeNull();
    });

    it('rejects empty tokens', () => {
      expect(registry.validateToken('')).toBeNull();
    });
  });

  describe('remove', () => {
    it('removes an existing user', () => {
      registry.add({ name: 'alice', role: 'admin' });
      expect(registry.remove('alice')).toBe(true);
      expect(registry.getByName('alice')).toBeNull();
    });

    it('returns false for non-existent user', () => {
      expect(registry.remove('nonexistent')).toBe(false);
    });
  });

  describe('updateRole', () => {
    it('changes a user role', () => {
      registry.add({ name: 'alice', role: 'viewer' });
      const updated = registry.updateRole({ name: 'alice', role: 'admin' });

      expect(updated.role).toBe('admin');
      expect(registry.getByName('alice')?.role).toBe('admin');
    });

    it('rejects invalid role', () => {
      registry.add({ name: 'alice', role: 'viewer' });
      expect(() => registry.updateRole({ name: 'alice', role: 'superadmin' as UserRole })).toThrow(
        'Invalid role',
      );
    });

    it('throws for non-existent user', () => {
      expect(() => registry.updateRole({ name: 'ghost', role: 'admin' })).toThrow('No user found');
    });
  });

  describe('regenerateToken', () => {
    it('issues a new token and invalidates the old one', () => {
      const original = registry.add({ name: 'alice', role: 'admin' });
      const regenerated = registry.regenerateToken('alice');

      expect(regenerated).not.toBeNull();
      expect(regenerated?.token).not.toBe(original.token);
      expect(regenerated?.tokenPrefix).not.toBe(original.tokenPrefix);

      // Old token no longer works
      expect(registry.validateToken(original.token)).toBeNull();

      // New token works
      expect(registry.validateToken(regenerated?.token)).not.toBeNull();
    });

    it('returns null for non-existent user', () => {
      expect(registry.regenerateToken('ghost')).toBeNull();
    });

    it('preserves user identity after regeneration', () => {
      const original = registry.add({ name: 'alice', role: 'operator' });
      const regenerated = registry.regenerateToken('alice');

      expect(regenerated?.id).toBe(original.id);
      expect(regenerated?.name).toBe('alice');
      expect(regenerated?.role).toBe('operator');
    });
  });

  describe('count', () => {
    it('returns 0 when no users exist', () => {
      expect(registry.count()).toBe(0);
    });

    it('counts all users', () => {
      registry.add({ name: 'alice', role: 'admin' });
      registry.add({ name: 'bob', role: 'viewer' });
      expect(registry.count()).toBe(2);
    });

    it('decrements after removal', () => {
      registry.add({ name: 'alice', role: 'admin' });
      registry.add({ name: 'bob', role: 'viewer' });
      registry.remove('bob');
      expect(registry.count()).toBe(1);
    });
  });

  // ─── Permissions ───────────────────────────────────────────────

  describe('permissions', () => {
    it('admin has all permissions', () => {
      const all: Permission[] = [
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
      ];

      for (const perm of all) {
        expect(hasPermission('admin', perm)).toBe(true);
      }
    });

    it('operator has operational permissions but not vault:write', () => {
      expect(hasPermission('operator', 'gate:start')).toBe(true);
      expect(hasPermission('operator', 'agent:read')).toBe(true);
      expect(hasPermission('operator', 'agent:write')).toBe(true);
      expect(hasPermission('operator', 'ledger:read')).toBe(true);
      expect(hasPermission('operator', 'ledger:export')).toBe(true);
      expect(hasPermission('operator', 'dashboard:view')).toBe(true);
      expect(hasPermission('operator', 'doctor:run')).toBe(true);

      // Should NOT have
      expect(hasPermission('operator', 'vault:write')).toBe(false);
      expect(hasPermission('operator', 'vault:manage')).toBe(false);
      expect(hasPermission('operator', 'policy:write')).toBe(false);
      expect(hasPermission('operator', 'webhook:write')).toBe(false);
      expect(hasPermission('operator', 'user:write')).toBe(false);
      expect(hasPermission('operator', 'user:read')).toBe(false);
    });

    it('viewer has read-only permissions only', () => {
      expect(hasPermission('viewer', 'vault:read')).toBe(true);
      expect(hasPermission('viewer', 'ledger:read')).toBe(true);
      expect(hasPermission('viewer', 'dashboard:view')).toBe(true);
      expect(hasPermission('viewer', 'doctor:run')).toBe(true);

      // Should NOT have
      expect(hasPermission('viewer', 'vault:write')).toBe(false);
      expect(hasPermission('viewer', 'vault:manage')).toBe(false);
      expect(hasPermission('viewer', 'agent:read')).toBe(false);
      expect(hasPermission('viewer', 'agent:write')).toBe(false);
      expect(hasPermission('viewer', 'gate:start')).toBe(false);
      expect(hasPermission('viewer', 'ledger:export')).toBe(false);
      expect(hasPermission('viewer', 'policy:read')).toBe(false);
      expect(hasPermission('viewer', 'webhook:read')).toBe(false);
      expect(hasPermission('viewer', 'user:read')).toBe(false);
      expect(hasPermission('viewer', 'user:write')).toBe(false);
    });

    it('getPermissions returns a readonly set', () => {
      const perms = getPermissions('admin');
      expect(perms).toBeInstanceOf(Set);
      expect(perms.size).toBeGreaterThan(0);
    });
  });

  describe('VALID_ROLES', () => {
    it('contains all three roles', () => {
      expect(VALID_ROLES).toEqual(['admin', 'operator', 'viewer']);
    });
  });

  // ─── checkPermission ──────────────────────────────────────────

  describe('checkPermission', () => {
    it('returns true when user has the permission', () => {
      registry.add({ name: 'alice', role: 'admin' });
      expect(registry.checkPermission('alice', 'vault:write')).toBe(true);
    });

    it('returns false when user lacks the permission', () => {
      registry.add({ name: 'bob', role: 'viewer' });
      expect(registry.checkPermission('bob', 'vault:write')).toBe(false);
    });

    it('returns false for non-existent user', () => {
      expect(registry.checkPermission('ghost', 'vault:read')).toBe(false);
    });
  });

  // ─── Token format ─────────────────────────────────────────────

  describe('token format', () => {
    it('follows aegis_user_{uuid}_{hmac} pattern', () => {
      const user = registry.add({ name: 'alice', role: 'admin' });
      const parts = user.token.split('_');

      // aegis_user_{uuid}_{hmac} splits into:
      // parts[0] = "aegis", parts[1] = "user", parts[2..6] = uuid parts, parts[7] = hmac
      expect(parts[0]).toBe('aegis');
      expect(parts[1]).toBe('user');
      expect(user.token.startsWith('aegis_user_')).toBe(true);
    });

    it('prefix is 17 chars (aegis_user_ + 6 chars)', () => {
      const user = registry.add({ name: 'alice', role: 'admin' });
      expect(user.tokenPrefix).toHaveLength(17);
      expect(user.tokenPrefix.startsWith('aegis_user_')).toBe(true);
    });
  });

  // ─── Security properties ──────────────────────────────────────

  describe('security properties', () => {
    it('does not store tokens in recoverable form', () => {
      const user = registry.add({ name: 'alice', role: 'admin' });

      // Query the raw database — should only have hash, not the token
      const row = db.prepare('SELECT * FROM users WHERE name = ?').get('alice') as Record<
        string,
        unknown
      >;
      expect(row.token_hash).toBeDefined();
      expect(typeof row.token_hash).toBe('string');
      // Hash should not equal the token
      expect(row.token_hash).not.toBe(user.token);
      // No column for the raw token
      expect(row).not.toHaveProperty('token');
      expect(row).not.toHaveProperty('encrypted_token');
    });

    it('different users with same role have different tokens', () => {
      const a = registry.add({ name: 'alice', role: 'admin' });
      const b = registry.add({ name: 'bob', role: 'admin' });

      expect(a.token).not.toBe(b.token);

      const rowA = db.prepare('SELECT token_hash FROM users WHERE name = ?').get('alice') as {
        token_hash: string;
      };
      const rowB = db.prepare('SELECT token_hash FROM users WHERE name = ?').get('bob') as {
        token_hash: string;
      };
      expect(rowA.token_hash).not.toBe(rowB.token_hash);
    });
  });
});
