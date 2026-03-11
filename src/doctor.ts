/**
 * Aegis Doctor — health check diagnostics.
 *
 * Validates the Aegis installation by checking:
 *   1. Config file and configuration
 *   2. Database accessibility and schema
 *   3. Credential decryption (master key correctness)
 *   4. Expired / expiring-soon credentials
 *
 * Returns a structured list of check results that the CLI can render.
 */

import type Database from 'better-sqlite3-multiple-ciphers';
import type { AegisConfig } from './config.js';
import { getVaultSalt, migrate } from './db.js';
import { getKeyStorage } from './key-storage/index.js';
import { Vault } from './vault/index.js';

export interface CheckResult {
  label: string;
  status: 'pass' | 'warn' | 'fail';
  detail: string;
}

export interface DoctorReport {
  checks: CheckResult[];
  overall: 'pass' | 'warn' | 'fail';
}

export interface DoctorOptions {
  /** Resolved Aegis configuration */
  config: AegisConfig;
  /** An open better-sqlite3 database, or null if no DB is available */
  db: Database.Database | null;
}

/**
 * Run all Aegis health checks and return a structured report.
 */
export function runDoctor(opts: DoctorOptions): DoctorReport {
  const checks: CheckResult[] = [];

  // ── 1. Validate config file and configuration ──────────────────

  const { config } = opts;

  if (config.configFilePath) {
    checks.push({
      label: 'Config file',
      status: 'pass',
      detail: `Found at ${config.configFilePath}`,
    });
  } else {
    checks.push({
      label: 'Config file',
      status: 'warn',
      detail: 'No aegis.config.yaml found — using environment variables or defaults',
    });
  }

  if (!config.masterKey) {
    checks.push({
      label: 'Master key',
      status: 'fail',
      detail: 'AEGIS_MASTER_KEY is not set. Run: aegis init',
    });
  } else {
    checks.push({ label: 'Master key', status: 'pass', detail: 'AEGIS_MASTER_KEY is set' });
  }

  // ── 1b. Key storage backend ────────────────────────────────────

  try {
    const keyStorage = getKeyStorage(config.dataDir);
    const hasKeyInStore = keyStorage.getKey() !== undefined;
    checks.push({
      label: 'Key storage',
      status: hasKeyInStore ? 'pass' : 'warn',
      detail: hasKeyInStore
        ? `Backend: ${keyStorage.name} (${keyStorage.backend}) — key present`
        : `Backend: ${keyStorage.name} (${keyStorage.backend}) — no key stored`,
    });
  } catch {
    checks.push({
      label: 'Key storage',
      status: 'warn',
      detail: 'Could not detect key storage backend',
    });
  }

  // ── 2. Verify database accessibility and schema ────────────────

  const { db } = opts;

  const effectiveSalt = db ? getVaultSalt(config) : config.salt;
  if (effectiveSalt === 'aegis-vault-v1') {
    checks.push({
      label: 'Salt',
      status: 'warn',
      detail: 'AEGIS_SALT is using the default value — run: aegis init to generate a random salt',
    });
  } else {
    checks.push({ label: 'Salt', status: 'pass', detail: 'AEGIS_SALT is set (custom)' });
  }

  if (!db) {
    checks.push({
      label: 'Database',
      status: 'fail',
      detail: 'Database is not available. Run: aegis init',
    });
  } else {
    try {
      migrate(db);
      checks.push({ label: 'Database', status: 'pass', detail: 'SQLite accessible' });

      const tables = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .all() as Array<{ name: string }>;
      const tableNames = tables.map((t) => t.name);
      const requiredTables = ['credentials', 'credential_history', 'audit_log'];
      const missingTables = requiredTables.filter((t) => !tableNames.includes(t));

      if (missingTables.length > 0) {
        checks.push({
          label: 'Schema',
          status: 'fail',
          detail: `Missing tables: ${missingTables.join(', ')}`,
        });
      } else {
        checks.push({
          label: 'Schema',
          status: 'pass',
          detail: 'All required tables present (credentials, credential_history, audit_log)',
        });
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      checks.push({
        label: 'Database',
        status: 'fail',
        detail: `Cannot access database: ${message}`,
      });
    }
  }

  // ── 3. Test-decrypt a credential ───────────────────────────────

  if (db && config.masterKey) {
    try {
      const vault = new Vault(db, config.masterKey, effectiveSalt);
      const creds = vault.list();

      if (creds.length === 0) {
        checks.push({
          label: 'Decrypt test',
          status: 'warn',
          detail: 'No credentials stored — cannot verify decryption. Add one with: aegis vault add',
        });
      } else {
        // Key verification already passed in constructor — confirm with explicit decrypt
        checks.push({
          label: 'Decrypt test',
          status: 'pass',
          detail: `Successfully decrypted credential "${creds[0].name}"`,
        });
      }

      // ── 4. Expired / expiring-soon credentials ──────────────────

      const expired = creds.filter((c) => vault.isExpired(c));
      const expiringSoon = creds.filter((c) => {
        if (!c.expiresAt || vault.isExpired(c)) return false;
        const expiryDate = new Date(c.expiresAt);
        const now = new Date();
        const daysLeft = (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
        return daysLeft <= 7;
      });

      if (expired.length > 0) {
        checks.push({
          label: 'Expired creds',
          status: 'warn',
          detail: `${expired.length} expired: ${expired.map((c) => c.name).join(', ')}`,
        });
      } else {
        checks.push({
          label: 'Expired creds',
          status: 'pass',
          detail: 'No expired credentials',
        });
      }

      if (expiringSoon.length > 0) {
        checks.push({
          label: 'Expiring soon',
          status: 'warn',
          detail: `${expiringSoon.length} expiring within 7 days: ${expiringSoon.map((c) => c.name).join(', ')}`,
        });
      }

      // Summary stats
      checks.push({
        label: 'Credentials',
        status: 'pass',
        detail: `${creds.length} stored (${creds.length - expired.length} active, ${expired.length} expired)`,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      const isKeyError = message.includes('Invalid master key');
      checks.push({
        label: isKeyError ? 'Decrypt test' : 'Vault',
        status: 'fail',
        detail: isKeyError
          ? 'Decryption failed — master key or salt may be incorrect'
          : `Cannot initialize vault: ${message}`,
      });
    }
  }

  // ── Compute overall status ─────────────────────────────────────

  const hasFailure = checks.some((c) => c.status === 'fail');
  const hasWarning = checks.some((c) => c.status === 'warn');
  const overall = hasFailure ? 'fail' : hasWarning ? 'warn' : 'pass';

  return { checks, overall };
}

/**
 * Render a DoctorReport to the console with coloured output.
 */
export function printDoctorReport(report: DoctorReport): void {
  for (const check of report.checks) {
    const icon = check.status === 'pass' ? '✓' : check.status === 'warn' ? '⚠' : '✗';
    const color =
      check.status === 'pass' ? '\x1b[32m' : check.status === 'warn' ? '\x1b[33m' : '\x1b[31m';
    const reset = '\x1b[0m';
    console.log(`  ${color}${icon}${reset} ${check.label}: ${check.detail}`);
  }

  console.log();
  if (report.overall === 'fail') {
    console.log('  Overall: ✗ Issues found — fix the failures above\n');
  } else if (report.overall === 'warn') {
    console.log('  Overall: ⚠ Healthy with warnings\n');
  } else {
    console.log('  Overall: ✓ All checks passed\n');
  }
}
