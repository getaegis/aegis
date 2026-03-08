import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { AegisConfig } from '../src/config.js';
import { migrate } from '../src/db.js';
import type { DoctorOptions } from '../src/doctor.js';
import { runDoctor } from '../src/doctor.js';
import { Vault } from '../src/vault/index.js';

describe('doctor', () => {
  const masterKey = 'test-doctor-master-key';
  const salt = 'test-doctor-salt-hex-value';
  let db: ReturnType<typeof Database>;

  beforeEach(() => {
    db = new Database(':memory:');
    migrate(db);
  });

  afterEach(() => {
    db.close();
  });

  function makeConfig(overrides: Partial<AegisConfig> = {}): AegisConfig {
    return {
      port: 3100,
      masterKey,
      salt,
      dataDir: '/tmp/aegis-doctor-test',
      logLevel: 'info',
      logFormat: 'json',
      vaultName: 'default',
      requireAgentAuth: false,
      policyMode: 'enforce',
      metricsEnabled: true,
      dashboard: { enabled: false, port: 3200 },
      mcp: { transport: 'stdio', port: 3200 },
      webhooks: [],
      ...overrides,
    };
  }

  function makeOpts(overrides: Partial<DoctorOptions> = {}): DoctorOptions {
    return {
      config: makeConfig(),
      db,
      ...overrides,
    };
  }

  // ─── Configuration checks ─────────────────────────────────────

  describe('configuration checks', () => {
    it('warns when config file is missing', () => {
      const report = runDoctor(makeOpts({ config: makeConfig({ configFilePath: undefined }) }));
      const configCheck = report.checks.find((c) => c.label === 'Config file');
      expect(configCheck).toBeDefined();
      expect(configCheck?.status).toBe('warn');
    });

    it('passes when config file is present', () => {
      const report = runDoctor(
        makeOpts({ config: makeConfig({ configFilePath: '/path/to/aegis.config.yaml' }) }),
      );
      const configCheck = report.checks.find((c) => c.label === 'Config file');
      expect(configCheck).toBeDefined();
      expect(configCheck?.status).toBe('pass');
    });

    it('fails when master key is missing', () => {
      const report = runDoctor(makeOpts({ config: makeConfig({ masterKey: '' }) }));
      const keyCheck = report.checks.find((c) => c.label === 'Master key');
      expect(keyCheck).toBeDefined();
      expect(keyCheck?.status).toBe('fail');
      expect(report.overall).toBe('fail');
    });

    it('passes when master key is set', () => {
      const report = runDoctor(makeOpts());
      const keyCheck = report.checks.find((c) => c.label === 'Master key');
      expect(keyCheck?.status).toBe('pass');
    });

    it('warns when salt is the default value', () => {
      const report = runDoctor(makeOpts({ config: makeConfig({ salt: 'aegis-vault-v1' }) }));
      const saltCheck = report.checks.find((c) => c.label === 'Salt');
      expect(saltCheck?.status).toBe('warn');
    });

    it('passes when salt is a custom value', () => {
      const report = runDoctor(makeOpts());
      const saltCheck = report.checks.find((c) => c.label === 'Salt');
      expect(saltCheck?.status).toBe('pass');
    });
  });

  // ─── Database checks ──────────────────────────────────────────

  describe('database checks', () => {
    it('fails when database is null', () => {
      const report = runDoctor(makeOpts({ db: null }));
      const dbCheck = report.checks.find((c) => c.label === 'Database');
      expect(dbCheck?.status).toBe('fail');
      expect(report.overall).toBe('fail');
    });

    it('passes when database is accessible with correct schema', () => {
      const report = runDoctor(makeOpts());
      const dbCheck = report.checks.find((c) => c.label === 'Database');
      expect(dbCheck?.status).toBe('pass');
      const schemaCheck = report.checks.find((c) => c.label === 'Schema');
      expect(schemaCheck?.status).toBe('pass');
      expect(schemaCheck?.detail).toContain('credentials');
    });
  });

  // ─── Decrypt test ─────────────────────────────────────────────

  describe('decrypt test', () => {
    it('warns when no credentials are stored (cannot verify)', () => {
      const report = runDoctor(makeOpts());
      const decryptCheck = report.checks.find((c) => c.label === 'Decrypt test');
      expect(decryptCheck?.status).toBe('warn');
      expect(decryptCheck?.detail).toContain('No credentials stored');
    });

    it('passes when a credential can be decrypted', () => {
      const vault = new Vault(db, masterKey, salt);
      vault.add({
        name: 'test-cred',
        service: 'test-svc',
        secret: 'my-secret-value',
        domains: ['api.example.com'],
      });

      const report = runDoctor(makeOpts());
      const decryptCheck = report.checks.find((c) => c.label === 'Decrypt test');
      expect(decryptCheck?.status).toBe('pass');
      expect(decryptCheck?.detail).toContain('test-cred');
    });

    it('fails when master key is wrong (decryption fails)', () => {
      // Add a credential with the correct key
      const vault = new Vault(db, masterKey, salt);
      vault.add({
        name: 'locked-cred',
        service: 'locked-svc',
        secret: 'secret-data',
        domains: ['api.example.com'],
      });

      // Run doctor with a WRONG master key
      const report = runDoctor(
        makeOpts({ config: makeConfig({ masterKey: 'wrong-key-entirely' }) }),
      );
      const decryptCheck = report.checks.find((c) => c.label === 'Decrypt test');
      expect(decryptCheck?.status).toBe('fail');
      expect(decryptCheck?.detail).toContain('Decryption failed');
    });
  });

  // ─── Credential health ────────────────────────────────────────

  describe('credential health', () => {
    it('reports no expired credentials when all are active', () => {
      const vault = new Vault(db, masterKey, salt);
      vault.add({
        name: 'active-cred',
        service: 'active-svc',
        secret: 'secret',
        domains: ['api.example.com'],
        ttlDays: 30,
      });

      const report = runDoctor(makeOpts());
      const expiredCheck = report.checks.find((c) => c.label === 'Expired creds');
      expect(expiredCheck?.status).toBe('pass');
      expect(expiredCheck?.detail).toContain('No expired');
    });

    it('warns about expired credentials', () => {
      const vault = new Vault(db, masterKey, salt);
      vault.add({
        name: 'old-cred',
        service: 'old-svc',
        secret: 'secret',
        domains: ['api.example.com'],
      });

      // Manually set expiry in the past
      db.prepare(
        "UPDATE credentials SET expires_at = datetime('now', '-1 day') WHERE name = ?",
      ).run('old-cred');

      const report = runDoctor(makeOpts());
      const expiredCheck = report.checks.find((c) => c.label === 'Expired creds');
      expect(expiredCheck?.status).toBe('warn');
      expect(expiredCheck?.detail).toContain('old-cred');
    });

    it('warns about credentials expiring within 7 days', () => {
      const vault = new Vault(db, masterKey, salt);
      vault.add({
        name: 'expiring-cred',
        service: 'expiring-svc',
        secret: 'secret',
        domains: ['api.example.com'],
      });

      // Set expiry to 3 days from now
      db.prepare(
        "UPDATE credentials SET expires_at = datetime('now', '+3 days') WHERE name = ?",
      ).run('expiring-cred');

      const report = runDoctor(makeOpts());
      const expiringCheck = report.checks.find((c) => c.label === 'Expiring soon');
      expect(expiringCheck).toBeDefined();
      expect(expiringCheck?.status).toBe('warn');
      expect(expiringCheck?.detail).toContain('expiring-cred');
    });

    it('reports credential summary stats', () => {
      const vault = new Vault(db, masterKey, salt);
      vault.add({
        name: 'cred-1',
        service: 'svc-1',
        secret: 's1',
        domains: ['api.one.com'],
      });
      vault.add({
        name: 'cred-2',
        service: 'svc-2',
        secret: 's2',
        domains: ['api.two.com'],
      });

      const report = runDoctor(makeOpts());
      const summaryCheck = report.checks.find((c) => c.label === 'Credentials');
      expect(summaryCheck?.status).toBe('pass');
      expect(summaryCheck?.detail).toContain('2 stored');
      expect(summaryCheck?.detail).toContain('2 active');
    });
  });

  // ─── Overall status ───────────────────────────────────────────

  describe('overall status', () => {
    it('returns pass when everything is healthy', () => {
      const vault = new Vault(db, masterKey, salt);
      vault.add({
        name: 'healthy',
        service: 'healthy-svc',
        secret: 'secret',
        domains: ['api.example.com'],
      });

      // No config file path → warn, so overall is at least warn
      const report = runDoctor(makeOpts());
      expect(report.overall).toBe('warn');
    });

    it('returns fail when a critical check fails', () => {
      const report = runDoctor(makeOpts({ db: null, config: makeConfig({ masterKey: '' }) }));
      expect(report.overall).toBe('fail');
    });

    it('returns warn when there are only warnings', () => {
      // No config file → warn, default salt → warn
      const report = runDoctor(makeOpts({ config: makeConfig({ salt: 'aegis-vault-v1' }) }));
      // No failures, just warnings
      const hasFailure = report.checks.some((c) => c.status === 'fail');
      expect(hasFailure).toBe(false);
      expect(report.overall).toBe('warn');
    });
  });
});
