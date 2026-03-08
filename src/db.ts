import * as fs from 'node:fs';
import * as path from 'node:path';
import Database from 'better-sqlite3';
import type { AegisConfig } from './config.js';
import { VaultManager } from './vault/vault-manager.js';

/**
 * Open the SQLite database for the active vault.
 * Uses VaultManager to resolve vault name → database path.
 * Falls back to `.aegis/aegis.db` only if no vaults exist (pre-init state).
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
  db.exec(`
    CREATE TABLE IF NOT EXISTS credentials (
      id          TEXT PRIMARY KEY,
      name        TEXT NOT NULL UNIQUE,
      service     TEXT NOT NULL,
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
  `);

  // Migration: add expires_at column if not present (for pre-v0.2 databases)
  const cols = db.prepare('PRAGMA table_info(credentials)').all() as Array<{ name: string }>;
  const colNames = cols.map((c) => c.name);
  if (!colNames.includes('expires_at')) {
    db.exec('ALTER TABLE credentials ADD COLUMN expires_at TEXT');
  }
  if (!colNames.includes('rate_limit')) {
    db.exec('ALTER TABLE credentials ADD COLUMN rate_limit TEXT');
  }
  if (!colNames.includes('body_inspection')) {
    db.exec("ALTER TABLE credentials ADD COLUMN body_inspection TEXT NOT NULL DEFAULT 'block'");
  }

  // Migration: add agent identity columns to audit_log (for pre-v0.3 databases)
  const auditCols = db.prepare('PRAGMA table_info(audit_log)').all() as Array<{ name: string }>;
  const auditColNames = auditCols.map((c) => c.name);
  if (!auditColNames.includes('agent_name')) {
    db.exec('ALTER TABLE audit_log ADD COLUMN agent_name TEXT');
  }
  if (!auditColNames.includes('agent_token_prefix')) {
    db.exec('ALTER TABLE audit_log ADD COLUMN agent_token_prefix TEXT');
  }
  if (!auditColNames.includes('channel')) {
    db.exec("ALTER TABLE audit_log ADD COLUMN channel TEXT NOT NULL DEFAULT 'gate'");
  }

  // Migration: drop encrypted token columns from agents table (v0.3 security hardening)
  // SQLite 3.35.0+ supports DROP COLUMN. For older versions, we recreate the table.
  const agentCols = db.prepare('PRAGMA table_info(agents)').all() as Array<{ name: string }>;
  const agentColNames = agentCols.map((c) => c.name);
  if (agentColNames.includes('encrypted_token')) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS agents_new (
        id              TEXT PRIMARY KEY,
        name            TEXT NOT NULL UNIQUE,
        token_hash      TEXT NOT NULL,
        token_prefix    TEXT NOT NULL,
        rate_limit      TEXT,
        created_at      TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
      );
      INSERT OR IGNORE INTO agents_new (id, name, token_hash, token_prefix, rate_limit, created_at, updated_at)
        SELECT id, name, token_hash, token_prefix, rate_limit, created_at, updated_at FROM agents;
      DROP TABLE agents;
      ALTER TABLE agents_new RENAME TO agents;
      CREATE INDEX IF NOT EXISTS idx_agents_token_hash ON agents(token_hash);
    `);
  }
}
