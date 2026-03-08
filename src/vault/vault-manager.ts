import * as fs from 'node:fs';
import * as path from 'node:path';
import Database from 'better-sqlite3';
import { migrate } from '../db.js';
import { generateSalt } from './crypto.js';

/**
 * Metadata for a named vault (stored in the registry).
 * Master keys are NEVER stored — the user must provide them.
 */
export interface VaultInfo {
  /** Unique vault name (e.g. "production", "staging") */
  name: string;
  /** Database file path relative to the data directory */
  dbPath: string;
  /** Hex-encoded PBKDF2 salt (unique per vault) */
  salt: string;
  /** ISO timestamp of when the vault was created */
  createdAt: string;
}

interface VaultRegistry {
  vaults: VaultInfo[];
}

/**
 * Manages multiple named vaults, each with its own SQLite database
 * and encryption key. The registry tracks vault metadata but NEVER
 * stores master keys.
 *
 * Layout:
 *   .aegis/vaults/<name>.db    — all vaults (including "default")
 *   .aegis/vaults.json         — vault registry
 */
export class VaultManager {
  private registryPath: string;
  private vaultsDir: string;

  constructor(private dataDir: string) {
    this.registryPath = path.join(dataDir, 'vaults.json');
    this.vaultsDir = path.join(dataDir, 'vaults');
  }

  /**
   * Create a new named vault with its own database and salt.
   * Returns the generated salt (the caller provides the master key).
   */
  create(name: string): { salt: string; dbPath: string } {
    if (!name) {
      throw new Error('Vault name is required.');
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
      throw new Error('Vault name must contain only letters, numbers, hyphens, and underscores.');
    }

    const registry = this.loadRegistry();
    if (registry.vaults.some((v) => v.name === name)) {
      throw new Error(`Vault "${name}" already exists.`);
    }

    // Ensure vaults directory exists
    if (!fs.existsSync(this.vaultsDir)) {
      fs.mkdirSync(this.vaultsDir, { recursive: true });
    }

    const dbPath = path.join('vaults', `${name}.db`);
    const absoluteDbPath = path.join(this.dataDir, dbPath);
    const salt = generateSalt();

    // Create and initialize the database with the full schema
    const db = new Database(absoluteDbPath);
    db.pragma('journal_mode = WAL');
    migrate(db);
    db.close();

    // Register the vault
    const info: VaultInfo = {
      name,
      dbPath,
      salt,
      createdAt: new Date().toISOString(),
    };
    registry.vaults.push(info);
    this.saveRegistry(registry);

    return { salt, dbPath };
  }

  /**
   * List all registered vaults.
   */
  list(): VaultInfo[] {
    return this.loadRegistry().vaults;
  }

  /**
   * Remove a named vault and delete its database file.
   */
  remove(name: string): void {
    if (!name) {
      throw new Error('Vault name is required.');
    }

    const registry = this.loadRegistry();
    const index = registry.vaults.findIndex((v) => v.name === name);
    if (index === -1) {
      throw new Error(`Vault "${name}" not found.`);
    }

    const vaultInfo = registry.vaults[index];
    const absoluteDbPath = path.join(this.dataDir, vaultInfo.dbPath);

    // Remove database files (main, WAL, SHM)
    for (const suffix of ['', '-wal', '-shm']) {
      const filePath = `${absoluteDbPath}${suffix}`;
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    }

    // Remove from registry
    registry.vaults.splice(index, 1);
    this.saveRegistry(registry);
  }

  /**
   * Get metadata for a named vault.
   */
  getVaultInfo(name: string): VaultInfo | undefined {
    return this.loadRegistry().vaults.find((v) => v.name === name);
  }

  /**
   * Open the SQLite database for a named vault.
   * Caller is responsible for closing the returned database.
   */
  openDb(name: string): Database.Database {
    const info = this.getVaultInfo(name);
    if (!info) {
      throw new Error(
        `Vault "${name}" not found. Create it with: aegis vault create --name ${name}`,
      );
    }

    const absoluteDbPath = path.join(this.dataDir, info.dbPath);
    if (!fs.existsSync(absoluteDbPath)) {
      throw new Error(`Vault database file not found: ${absoluteDbPath}`);
    }

    const db = new Database(absoluteDbPath);
    db.pragma('journal_mode = WAL');
    migrate(db);
    return db;
  }

  /**
   * Get the salt for a named vault.
   */
  getSalt(name: string): string {
    const info = this.getVaultInfo(name);
    if (!info) {
      throw new Error(
        `Vault "${name}" not found. Create it with: aegis vault create --name ${name}`,
      );
    }
    return info.salt;
  }

  private loadRegistry(): VaultRegistry {
    if (!fs.existsSync(this.registryPath)) {
      return { vaults: [] };
    }
    const content = fs.readFileSync(this.registryPath, 'utf-8');
    return JSON.parse(content) as VaultRegistry;
  }

  private saveRegistry(registry: VaultRegistry): void {
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }
    fs.writeFileSync(this.registryPath, JSON.stringify(registry, null, 2), 'utf-8');
  }
}
