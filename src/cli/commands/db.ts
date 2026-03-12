/**
 * Database commands: backup, restore.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import Database from 'better-sqlite3-multiple-ciphers';
import type { Command } from 'commander';
import { getConfig } from '../../config.js';
import { deriveDbKey, getDb, getVaultSalt, migrate } from '../../db.js';
import { deriveKey } from '../../vault/index.js';
import { VaultManager } from '../../vault/vault-manager.js';
import { requireUserAuth } from '../auth.js';

export function register(program: Command): void {
  const dbCmd = program.command('db').description('Database backup and restore');

  dbCmd
    .command('backup')
    .description('Create a backup of the current vault database')
    .option('-o, --output <path>', 'Output file path', './aegis-backup.db')
    .action((opts: { output: string }) => {
      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'vault:manage');

      const outputPath = path.resolve(opts.output);
      const outputDir = path.dirname(outputPath);
      if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
      }

      if (fs.existsSync(outputPath)) {
        console.error(`\n✗ Backup file already exists: ${outputPath}`);
        console.error(`  Remove it first or choose a different path.\n`);
        db.close();
        process.exit(1);
      }

      // Resolve the actual database file path (same logic as getDb)
      const manager = new VaultManager(config.dataDir);
      const info = manager.getVaultInfo(config.vaultName);
      const dbPath = info
        ? path.join(config.dataDir, info.dbPath)
        : path.join(config.dataDir, 'aegis.db');

      try {
        // Checkpoint WAL to flush all pending writes into the main database file,
        // then close the connection before copying to avoid partial-page reads.
        db.pragma('wal_checkpoint(TRUNCATE)');
        db.close();

        // Copy the raw encrypted file — this preserves ChaCha20-Poly1305
        // encryption intact. The SQLite online backup API (db.backup()) creates
        // an unencrypted target, which is incompatible with an encrypted source.
        // After TRUNCATE checkpoint + close, all data is in the main file —
        // WAL/SHM files are empty and not needed for the backup.
        console.log(`\n  Backing up database to: ${outputPath}`);
        fs.copyFileSync(dbPath, outputPath);
        fs.chmodSync(outputPath, 0o600); // owner-only — backup contains encrypted secrets

        // Verify the backup is valid by opening it with the same key.
        // Use fileMustExist to prevent creating a new DB if something went wrong.
        const backupDb = new Database(outputPath, { readonly: true, fileMustExist: true });
        if (config.masterKey) {
          const salt = getVaultSalt(config);
          const dbKey = deriveDbKey(config.masterKey, salt);
          backupDb.pragma(`key="x'${dbKey.toString('hex')}'"`);
        }
        const tables = backupDb
          .prepare("SELECT count(*) as cnt FROM sqlite_master WHERE type='table'")
          .get() as { cnt: number };
        backupDb.close();

        // Clean up any WAL/SHM files the verification may have created
        for (const suffix of ['-wal', '-shm']) {
          const f = `${outputPath}${suffix}`;
          if (fs.existsSync(f)) fs.unlinkSync(f);
        }

        const stats = fs.statSync(outputPath);
        const sizeKb = (stats.size / 1024).toFixed(1);

        console.log(`  ✓ Backup complete (${sizeKb} KB, ${tables.cnt} tables)\n`);
      } catch (err) {
        // Clean up partial backup on failure
        if (fs.existsSync(outputPath)) fs.unlinkSync(outputPath);
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n✗ Backup failed: ${message}\n`);
        process.exit(1);
      }
    });

  dbCmd
    .command('restore')
    .description('Restore a vault database from a backup file')
    .requiredOption('-i, --input <path>', 'Backup file to restore from')
    .option('--force', 'Overwrite the current database without confirmation')
    .action((opts: { input: string; force?: boolean }) => {
      const config = getConfig();
      const inputPath = path.resolve(opts.input);

      if (!fs.existsSync(inputPath)) {
        console.error(`\n✗ Backup file not found: ${inputPath}\n`);
        process.exit(1);
      }

      // Verify the backup is a valid (possibly encrypted) SQLite database
      try {
        const backupDb = new Database(inputPath, { readonly: true, fileMustExist: true });
        if (config.masterKey) {
          const salt = getVaultSalt(config);
          const dbKey = deriveDbKey(config.masterKey, salt);
          backupDb.pragma(`key="x'${dbKey.toString('hex')}'"`);
        }
        const tables = backupDb
          .prepare("SELECT count(*) as cnt FROM sqlite_master WHERE type='table'")
          .get() as { cnt: number };
        if (tables.cnt === 0) {
          backupDb.close();
          // Clean up any WAL/SHM files the verification may have created
          for (const suffix of ['-wal', '-shm']) {
            const f = `${inputPath}${suffix}`;
            if (fs.existsSync(f)) fs.unlinkSync(f);
          }
          console.error(
            '\n✗ Backup file contains no tables — this does not look like an Aegis database.\n',
          );
          process.exit(1);
        }
        backupDb.close();

        // Clean up any WAL/SHM files the verification may have created
        for (const suffix of ['-wal', '-shm']) {
          const f = `${inputPath}${suffix}`;
          if (fs.existsSync(f)) fs.unlinkSync(f);
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n✗ Backup file is not a valid Aegis database: ${message}\n`);
        process.exit(1);
      }

      // Resolve the current database path
      const manager = new VaultManager(config.dataDir);
      const info = manager.getVaultInfo(config.vaultName);
      const dbPath = info
        ? path.join(config.dataDir, info.dbPath)
        : path.join(config.dataDir, 'aegis.db');

      if (fs.existsSync(dbPath) && !opts.force) {
        console.error(`\n✗ Database already exists at: ${dbPath}`);
        console.error(`  Use --force to overwrite, or back up first with: aegis db backup\n`);
        process.exit(1);
      }

      try {
        // Ensure directory exists
        const dir = path.dirname(dbPath);
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }

        // Remove WAL and SHM files from the target (stale journal files cause issues)
        for (const suffix of ['-wal', '-shm']) {
          const walPath = `${dbPath}${suffix}`;
          if (fs.existsSync(walPath)) {
            fs.unlinkSync(walPath);
          }
        }

        // Copy the backup file to the database path
        fs.copyFileSync(inputPath, dbPath);

        // Verify the restored database works
        const db = getDb(config);
        migrate(db);
        const tables = db
          .prepare("SELECT count(*) as cnt FROM sqlite_master WHERE type='table'")
          .get() as { cnt: number };
        db.close();

        console.log(`\n  ✓ Database restored from: ${inputPath}`);
        console.log(`  ✓ ${tables.cnt} tables verified\n`);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n✗ Restore failed: ${message}\n`);
        process.exit(1);
      }
    });
}
