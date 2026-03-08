import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { Ledger } from '../src/ledger/index.js';
import { Vault, VaultManager } from '../src/vault/index.js';

describe('VaultManager', () => {
  let tmpDir: string;
  let manager: VaultManager;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-vault-test-'));
    manager = new VaultManager(tmpDir);
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // ─── Create ──────────────────────────────────────────────────────

  describe('create', () => {
    it('creates a vault with a unique salt and database', () => {
      const result = manager.create('production');

      expect(result.salt).toBeDefined();
      expect(result.salt.length).toBe(64); // 32 bytes hex
      expect(result.dbPath).toBe(path.join('vaults', 'production.db'));

      // Database file should exist
      const dbPath = path.join(tmpDir, result.dbPath);
      expect(fs.existsSync(dbPath)).toBe(true);
    });

    it('creates the vaults directory if it does not exist', () => {
      manager.create('staging');
      expect(fs.existsSync(path.join(tmpDir, 'vaults'))).toBe(true);
    });

    it('initializes the database with the full schema', () => {
      manager.create('test-vault');
      const db = manager.openDb('test-vault');

      // Verify tables exist by querying them
      const tables = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .all() as Array<{ name: string }>;
      const tableNames = tables.map((t) => t.name);

      expect(tableNames).toContain('credentials');
      expect(tableNames).toContain('audit_log');
      expect(tableNames).toContain('agents');
      expect(tableNames).toContain('agent_credentials');
      expect(tableNames).toContain('webhooks');

      db.close();
    });

    it('rejects empty vault names', () => {
      expect(() => manager.create('')).toThrow('Vault name is required');
    });

    it('rejects invalid characters in vault names', () => {
      expect(() => manager.create('my vault')).toThrow('letters, numbers');
      expect(() => manager.create('vault/prod')).toThrow('letters, numbers');
      expect(() => manager.create('vault.prod')).toThrow('letters, numbers');
    });

    it('rejects duplicate vault names', () => {
      manager.create('production');
      expect(() => manager.create('production')).toThrow('already exists');
    });

    it('generates unique salts for each vault', () => {
      const v1 = manager.create('vault-1');
      const v2 = manager.create('vault-2');
      expect(v1.salt).not.toBe(v2.salt);
    });

    it('allows "default" as a vault name', () => {
      const result = manager.create('default');
      expect(result.dbPath).toBe(path.join('vaults', 'default.db'));
    });
  });

  // ─── List ────────────────────────────────────────────────────────

  describe('list', () => {
    it('returns empty array when no vaults exist', () => {
      expect(manager.list()).toEqual([]);
    });

    it('returns all created vaults', () => {
      manager.create('production');
      manager.create('staging');

      const vaults = manager.list();
      expect(vaults).toHaveLength(2);
      expect(vaults.map((v) => v.name)).toContain('production');
      expect(vaults.map((v) => v.name)).toContain('staging');
    });

    it('includes metadata for each vault', () => {
      manager.create('production');
      const vaults = manager.list();

      expect(vaults[0].name).toBe('production');
      expect(vaults[0].dbPath).toBe(path.join('vaults', 'production.db'));
      expect(vaults[0].salt.length).toBe(64);
      expect(vaults[0].createdAt).toBeDefined();
    });
  });

  // ─── Remove ──────────────────────────────────────────────────────

  describe('remove', () => {
    it('removes a vault and deletes its database', () => {
      manager.create('staging');
      const dbPath = path.join(tmpDir, 'vaults', 'staging.db');
      expect(fs.existsSync(dbPath)).toBe(true);

      manager.remove('staging');
      expect(fs.existsSync(dbPath)).toBe(false);
      expect(manager.list()).toHaveLength(0);
    });

    it('throws when removing a non-existent vault', () => {
      expect(() => manager.remove('nonexistent')).toThrow('not found');
    });

    it('throws on empty name', () => {
      expect(() => manager.remove('')).toThrow('Vault name is required');
    });

    it('does not affect other vaults', () => {
      manager.create('production');
      manager.create('staging');
      manager.remove('staging');

      const vaults = manager.list();
      expect(vaults).toHaveLength(1);
      expect(vaults[0].name).toBe('production');
    });
  });

  // ─── Get Vault Info ──────────────────────────────────────────────

  describe('getVaultInfo', () => {
    it('returns vault metadata by name', () => {
      manager.create('production');
      const info = manager.getVaultInfo('production');

      expect(info).toBeDefined();
      expect(info?.name).toBe('production');
      expect(info?.salt.length).toBe(64);
    });

    it('returns undefined for non-existent vault', () => {
      expect(manager.getVaultInfo('nonexistent')).toBeUndefined();
    });
  });

  // ─── Open Database ──────────────────────────────────────────────

  describe('openDb', () => {
    it('opens a working database connection', () => {
      manager.create('test-db');
      const db = manager.openDb('test-db');

      // Should be able to run queries
      const result = db.prepare('SELECT 1 as val').get() as { val: number };
      expect(result.val).toBe(1);

      db.close();
    });

    it('throws for non-existent vault', () => {
      expect(() => manager.openDb('nonexistent')).toThrow('not found');
    });
  });

  // ─── Get Salt ────────────────────────────────────────────────────

  describe('getSalt', () => {
    it('returns the salt for a named vault', () => {
      const { salt } = manager.create('production');
      expect(manager.getSalt('production')).toBe(salt);
    });

    it('throws for non-existent vault', () => {
      expect(() => manager.getSalt('nonexistent')).toThrow('not found');
    });
  });

  // ─── Vault Isolation ────────────────────────────────────────────

  describe('vault isolation', () => {
    it('vaults have separate databases with no data leakage', () => {
      manager.create('vault-a');
      manager.create('vault-b');

      const dbA = manager.openDb('vault-a');
      const dbB = manager.openDb('vault-b');

      const saltA = manager.getSalt('vault-a');
      const saltB = manager.getSalt('vault-b');

      // Store a credential in vault A
      const vaultA = new Vault(dbA, 'master-key-a', saltA);
      vaultA.add({
        name: 'secret-a',
        service: 'svc-a',
        secret: 'value-a',
        authType: 'bearer',
        domains: ['a.com'],
      });

      // Vault B should have no credentials
      const vaultB = new Vault(dbB, 'master-key-b', saltB);
      expect(vaultB.list()).toHaveLength(0);
      expect(vaultA.list()).toHaveLength(1);

      dbA.close();
      dbB.close();
    });

    it('vaults have separate audit logs', () => {
      manager.create('prod');
      manager.create('staging');

      const dbProd = manager.openDb('prod');
      const dbStaging = manager.openDb('staging');

      const ledgerProd = new Ledger(dbProd);
      const ledgerStaging = new Ledger(dbStaging);

      ledgerProd.logAllowed({
        credentialId: 'c1',
        credentialName: 'prod-cred',
        service: 'svc',
        targetDomain: 'api.com',
        method: 'GET',
        path: '/',
        responseCode: 200,
      });

      expect(ledgerProd.query()).toHaveLength(1);
      expect(ledgerStaging.query()).toHaveLength(0);

      dbProd.close();
      dbStaging.close();
    });

    it('each vault uses its own encryption salt', () => {
      manager.create('vault-x');
      manager.create('vault-y');

      const saltX = manager.getSalt('vault-x');
      const saltY = manager.getSalt('vault-y');

      // Different salts mean different derived keys — encryption isolation
      expect(saltX).not.toBe(saltY);
      expect(saltX.length).toBe(64);
      expect(saltY.length).toBe(64);
    });

    it('credential encrypted in one vault cannot be decrypted with another vault salt', () => {
      manager.create('alpha');
      manager.create('beta');

      const dbAlpha = manager.openDb('alpha');
      const masterKey = 'shared-master-key';

      // Encrypt with alpha's salt
      const vaultAlpha = new Vault(dbAlpha, masterKey, manager.getSalt('alpha'));
      vaultAlpha.add({
        name: 'secret',
        service: 'svc',
        secret: 'my-secret-value',
        authType: 'bearer',
        domains: ['api.com'],
      });

      // Try to open alpha's DB using beta's salt — key verification catches the mismatch
      expect(() => new Vault(dbAlpha, masterKey, manager.getSalt('beta'))).toThrow(
        'Invalid master key',
      );

      dbAlpha.close();
    });
  });

  // ─── Registry Persistence ───────────────────────────────────────

  describe('registry persistence', () => {
    it('persists vault list across VaultManager instances', () => {
      manager.create('persistent-vault');

      // Create a new manager instance pointing to the same directory
      const manager2 = new VaultManager(tmpDir);
      const vaults = manager2.list();

      expect(vaults).toHaveLength(1);
      expect(vaults[0].name).toBe('persistent-vault');
    });

    it('stores registry as JSON file', () => {
      manager.create('test');
      const registryPath = path.join(tmpDir, 'vaults.json');
      expect(fs.existsSync(registryPath)).toBe(true);

      const content = JSON.parse(fs.readFileSync(registryPath, 'utf-8'));
      expect(content.vaults).toHaveLength(1);
      expect(content.vaults[0].name).toBe('test');
    });
  });
});
