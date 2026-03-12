import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import Database from 'better-sqlite3-multiple-ciphers';
import type { AegisConfig } from './config.js';
import { VaultManager } from './vault/vault-manager.js';

const DB_KEY_LENGTH = 32;
const DB_KEY_ITERATIONS = 210_000;

/**
 * Derive a 256-bit database encryption key from the master key and salt.
 * Uses a separate derivation context ("-db" suffix on salt) so the DB key
 * is independent from the credential encryption key, even though both
 * originate from the same master secret.
 */
export function deriveDbKey(masterKey: string, salt: string): Buffer {
  return crypto.pbkdf2Sync(masterKey, `${salt}-db`, DB_KEY_ITERATIONS, DB_KEY_LENGTH, 'sha512');
}

/**
 * Open the SQLite database for the active vault.
 * Uses VaultManager to resolve vault name → database path.
 * Falls back to `.aegis/aegis.db` only if no vaults exist (pre-init state).
 *
 * When a master key is available, the database is encrypted at rest using
 * ChaCha20-Poly1305 (sqleet cipher via SQLite3MultipleCiphers). The encryption
 * key is derived from the master key using PBKDF2-SHA512 with a separate
 * salt context ("-db") to isolate it from credential encryption keys.
 */
export function getDb(config: AegisConfig): Database.Database {
  const manager = new VaultManager(config.dataDir);
  const info = manager.getVaultInfo(config.vaultName);

  let dbPath: string;
  if (info) {
    dbPath = path.join(config.dataDir, info.dbPath);
  } else {
    // Fallback for commands that run before vault creation (e.g. doctor, init)
    dbPath = path.join(config.dataDir, 'aegis.db');
  }

  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  try {
    const db = new Database(dbPath);

    // Encrypt the database when a master key is available.
    // Pre-init commands (doctor, init) run without a master key — those
    // databases remain unencrypted (and are replaced during init anyway).
    if (config.masterKey) {
      const salt = info ? info.salt : config.salt;
      const dbKey = deriveDbKey(config.masterKey, salt);
      db.pragma(`key="x'${dbKey.toString('hex')}'"`);
    }

    db.pragma('journal_mode = WAL');
    return db;
  } catch (err: unknown) {
    const sqliteErr = err as { code?: string; message?: string };
    if (sqliteErr.code === 'SQLITE_NOTADB') {
      throw new Error(
        `Database file is corrupted or not a valid SQLite database: ${dbPath}\n` +
          `  Back up the file and reinitialize with: aegis init`,
      );
    }
    throw err;
  }
}

/**
 * Get the salt for the active vault.
 * Returns the vault-specific salt from the registry, or the env salt for fallback.
 */
export function getVaultSalt(config: AegisConfig): string {
  const manager = new VaultManager(config.dataDir);
  const info = manager.getVaultInfo(config.vaultName);
  return info ? info.salt : config.salt;
}

export function migrate(db: Database.Database): void {
  // ── Schema versioning ────────────────────────────────────────────
  // Create the version table if it doesn't exist. This is always safe
  // because CREATE TABLE IF NOT EXISTS is idempotent.
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_version (
      version     INTEGER PRIMARY KEY,
      applied_at  TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);

  const currentVersion = (
    db.prepare('SELECT COALESCE(MAX(version), 0) AS v FROM schema_version').get() as { v: number }
  ).v;

  // Run all migrations that haven't been applied yet
  const pending = MIGRATIONS.filter((m) => m.version > currentVersion);
  if (pending.length === 0) return;

  const runMigrations = db.transaction(() => {
    for (const migration of pending) {
      db.exec(migration.sql);
      db.prepare('INSERT INTO schema_version (version) VALUES (?)').run(migration.version);
    }
  });

  runMigrations();
}

// ─── Migration definitions ──────────────────────────────────────────

interface Migration {
  version: number;
  sql: string;
}

/**
 * Ordered list of schema migrations. Each migration is applied exactly once.
 * The version number must be strictly increasing.
 *
 * To add a new migration:
 * 1. Add a new entry with the next version number
 * 2. Write the SQL (ALTER TABLE, CREATE TABLE, CREATE INDEX, etc.)
 * 3. Run `yarn build && yarn test` to verify
 */
const MIGRATIONS: Migration[] = [
  {
    // v1: Baseline schema — all tables from v0.1 through v0.8
    version: 1,
    sql: `
    CREATE TABLE IF NOT EXISTS credentials (
      id          TEXT PRIMARY KEY,
      name        TEXT NOT NULL UNIQUE,
      service     TEXT NOT NULL UNIQUE,
      encrypted   BLOB NOT NULL,
      iv          BLOB NOT NULL,
      auth_tag    BLOB NOT NULL,
      auth_type   TEXT NOT NULL DEFAULT 'bearer',
      header_name TEXT,
      domains     TEXT NOT NULL,
      scopes      TEXT NOT NULL DEFAULT '*',
      expires_at  TEXT,
      rate_limit  TEXT,
      body_inspection TEXT NOT NULL DEFAULT 'block',
      created_at  TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS credential_history (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      credential_id   TEXT NOT NULL,
      encrypted       BLOB NOT NULL,
      iv              BLOB NOT NULL,
      auth_tag        BLOB NOT NULL,
      rotated_at      TEXT NOT NULL DEFAULT (datetime('now')),
      grace_expires   TEXT,
      FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp     TEXT NOT NULL DEFAULT (datetime('now')),
      credential_id TEXT,
      credential_name TEXT,
      service       TEXT NOT NULL,
      target_domain TEXT NOT NULL,
      method        TEXT NOT NULL,
      path          TEXT NOT NULL,
      status        TEXT NOT NULL DEFAULT 'allowed',
      blocked_reason TEXT,
      response_code INTEGER,
      agent_name    TEXT,
      agent_token_prefix TEXT,
      channel       TEXT NOT NULL DEFAULT 'gate'
    );

    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_credential ON audit_log(credential_id);
    CREATE INDEX IF NOT EXISTS idx_audit_service ON audit_log(service);
    CREATE INDEX IF NOT EXISTS idx_history_credential ON credential_history(credential_id);

    CREATE TABLE IF NOT EXISTS agents (
      id              TEXT PRIMARY KEY,
      name            TEXT NOT NULL UNIQUE,
      token_hash      TEXT NOT NULL,
      token_prefix    TEXT NOT NULL,
      rate_limit      TEXT,
      created_at      TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS agent_credentials (
      agent_id        TEXT NOT NULL,
      credential_id   TEXT NOT NULL,
      granted_at      TEXT NOT NULL DEFAULT (datetime('now')),
      PRIMARY KEY (agent_id, credential_id),
      FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE,
      FOREIGN KEY (credential_id) REFERENCES credentials(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_agents_token_hash ON agents(token_hash);
    CREATE INDEX IF NOT EXISTS idx_agent_creds_agent ON agent_credentials(agent_id);
    CREATE INDEX IF NOT EXISTS idx_agent_creds_cred ON agent_credentials(credential_id);

    CREATE TABLE IF NOT EXISTS webhooks (
      id          TEXT PRIMARY KEY,
      url         TEXT NOT NULL,
      events      TEXT NOT NULL,
      label       TEXT,
      secret      TEXT NOT NULL,
      created_at  TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS users (
      id              TEXT PRIMARY KEY,
      name            TEXT NOT NULL UNIQUE,
      role            TEXT NOT NULL DEFAULT 'viewer',
      token_hash      TEXT NOT NULL,
      token_prefix    TEXT NOT NULL,
      created_at      TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_users_token_hash ON users(token_hash);
    `,
  },
  // Future migrations go here:
  // { version: 2, sql: `ALTER TABLE ...` },
];
