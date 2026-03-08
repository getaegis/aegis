/**
 * Doctor command: run health checks on the Aegis installation.
 */

import type { Command } from 'commander';
import { getConfig } from '../../config.js';
import { getDb, getVaultSalt, migrate } from '../../db.js';
import { printDoctorReport, runDoctor } from '../../doctor.js';
import { deriveKey, VaultManager } from '../../vault/index.js';
import { requireUserAuth } from '../auth.js';

export function register(program: Command): void {
  program
    .command('doctor')
    .description('Run health checks on your Aegis installation')
    .action(() => {
      console.log('\n  Aegis Doctor — running health checks...\n');

      const config = getConfig();
      const manager = new VaultManager(config.dataDir);
      const vaultInfo = manager.getVaultInfo(config.vaultName);

      let db: ReturnType<typeof getDb> | null = null;
      if (vaultInfo) {
        try {
          db = getDb(config);
        } catch {
          // db stays null — runDoctor handles that case
        }
      }

      if (db) {
        migrate(db);
        const key = deriveKey(config.masterKey, getVaultSalt(config));
        requireUserAuth(db, key, 'doctor:run');
      }

      const report = runDoctor({ config, db });
      printDoctorReport(report);

      if (report.overall === 'fail') {
        process.exit(1);
      }
    });
}
