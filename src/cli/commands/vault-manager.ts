/**
 * Vault management commands: create, vaults (list), destroy, split, unseal, seal.
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Command } from 'commander';
import { getConfig } from '../../config.js';
import { getDb, getVaultSalt, migrate } from '../../db.js';
import {
  combine,
  decodeShare,
  deriveKey,
  encodeShare,
  SealManager,
  split,
  VaultManager,
} from '../../vault/index.js';
import { requireUserAuth } from '../auth.js';
import { localTime } from '../validation.js';

function collectShares(value: string, previous: string[]): string[] {
  return [...previous, value];
}

export function register(parent: Command): void {
  // These are subcommands of the 'vault' command, which is already
  // registered by vault.ts.  We look it up so we can attach to it.
  const vault = parent.commands.find((c) => c.name() === 'vault');
  if (!vault) throw new Error('vault command must be registered before vault-manager');

  vault
    .command('create')
    .description('Create a new named vault with its own database and encryption salt')
    .requiredOption('-n, --name <name>', 'Name for the new vault')
    .option(
      '--master-key <key>',
      'Master key for the vault (if not provided, prompts or uses AEGIS_MASTER_KEY)',
    )
    .action((opts: { name: string; masterKey?: string }) => {
      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'vault:manage');
      db.close();
      const manager = new VaultManager(config.dataDir);

      try {
        const { salt } = manager.create(opts.name, config.masterKey || undefined);

        console.log(`\n  ✓ Vault "${opts.name}" created\n`);
        console.log(`  Salt:     ${salt}`);
        console.log(`  Database: .aegis/vaults/${opts.name}.db\n`);
        console.log(`  To use this vault:`);
        console.log(`    AEGIS_VAULT=${opts.name} aegis vault list`);
        console.log(`    AEGIS_VAULT=${opts.name} aegis gate\n`);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n✗ ${message}\n`);
        process.exit(1);
      }
    });

  vault
    .command('vaults')
    .description('List all named vaults')
    .action(() => {
      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'vault:read');
      db.close();
      const manager = new VaultManager(config.dataDir);
      const vaults = manager.list();

      if (vaults.length === 0) {
        console.log('\n  No vaults found. Create one with: aegis vault create --name <name>\n');
        return;
      }

      console.log(`\n  Aegis Vaults — ${vaults.length} vault(s)\n`);
      const active = config.vaultName;
      for (const v of vaults) {
        const marker = v.name === active ? ' ← active' : '';
        console.log(`  • ${v.name}${marker}`);
        console.log(`    Database:   ${v.dbPath}`);
        console.log(`    Created:    ${localTime(v.createdAt)}`);
        console.log();
      }
    });

  vault
    .command('destroy')
    .description('Permanently delete a named vault and its database')
    .requiredOption('-n, --name <name>', 'Name of the vault to delete')
    .option('--confirm', 'Skip confirmation prompt')
    .action((opts: { name: string; confirm?: boolean }) => {
      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'vault:manage');
      db.close();
      const manager = new VaultManager(config.dataDir);

      if (!opts.confirm) {
        console.log(`\n  ⚠  This will permanently delete vault "${opts.name}" and all its data.`);
        console.log(`  Run again with --confirm to proceed.\n`);
        return;
      }

      try {
        manager.remove(opts.name);
        console.log(`\n  ✓ Vault "${opts.name}" deleted.\n`);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n✗ ${message}\n`);
        process.exit(1);
      }
    });

  vault
    .command('split')
    .description("Split the master key into M-of-N shares using Shamir's Secret Sharing")
    .requiredOption('-t, --threshold <n>', 'Minimum shares needed to reconstruct (≥ 2)')
    .requiredOption('-s, --shares <n>', 'Total shares to generate (≥ threshold, ≤ 255)')
    .option('--remove-env-key', 'Remove AEGIS_MASTER_KEY from .env after splitting', false)
    .action((opts: { threshold: string; shares: string; removeEnvKey: boolean }) => {
      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'vault:manage');
      db.close();

      if (!config.masterKey) {
        console.error(
          '\n✗ AEGIS_MASTER_KEY is required to split. Set it in .env or as an env var.\n',
        );
        process.exit(1);
      }

      const threshold = Number.parseInt(opts.threshold, 10);
      const totalShares = Number.parseInt(opts.shares, 10);

      if (Number.isNaN(threshold) || Number.isNaN(totalShares)) {
        console.error('\n✗ Threshold and shares must be numbers.\n');
        process.exit(1);
      }

      try {
        const secretBuf = Buffer.from(config.masterKey, 'utf-8');
        const shares = split(secretBuf, threshold, totalShares);

        // Store seal config (threshold + key hash for verification)
        const sealMgr = new SealManager(config.dataDir);
        sealMgr.enableSplit(threshold, totalShares, config.masterKey);

        console.log(`\n  ╔══════════════════════════════════════════╗`);
        console.log(`  ║     Master Key Split — ${threshold}-of-${totalShares} Scheme      ║`);
        console.log(`  ╚══════════════════════════════════════════╝\n`);
        console.log(`  ⚠  Store each share with a different key holder.`);
        console.log(`  ⚠  These shares will NOT be shown again.\n`);

        for (const share of shares) {
          console.log(`  Share ${share.index}:  ${encodeShare(share)}`);
        }

        console.log(`\n  Threshold: ${threshold} of ${totalShares} shares required to unseal.`);
        console.log(
          `  Key hash:  ${crypto.createHash('sha256').update(config.masterKey).digest('hex').slice(0, 16)}...`,
        );

        // Optionally remove the master key from .env
        if (opts.removeEnvKey) {
          const envPath = path.join(process.cwd(), '.env');
          if (fs.existsSync(envPath)) {
            const envContent = fs.readFileSync(envPath, 'utf-8');
            const filtered = envContent
              .split('\n')
              .filter((line) => !line.trim().startsWith('AEGIS_MASTER_KEY'))
              .join('\n');
            fs.writeFileSync(envPath, filtered, { mode: 0o600 });
            console.log(`\n  ✓ Removed AEGIS_MASTER_KEY from .env`);
          }
        } else {
          console.log(`\n  Note: AEGIS_MASTER_KEY is still in .env / environment.`);
          console.log(`  Use --remove-env-key to remove it after distributing shares.`);
        }

        console.log(`\n  To unseal later:`);
        console.log(`    aegis vault unseal --key-share <share1> --key-share <share2> ...`);
        console.log(`  To seal (remove reconstructed key):`);
        console.log(`    aegis vault seal\n`);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n✗ ${message}\n`);
        process.exit(1);
      }
    });

  vault
    .command('unseal')
    .description('Reconstruct the master key from Shamir shares')
    .option('--key-share <share>', 'Provide a key share (repeat for each share)', collectShares, [])
    .action((opts: { keyShare: string[] }) => {
      const config = getConfig();

      if (opts.keyShare.length === 0) {
        console.error('\n✗ Provide at least one share: --key-share <share>\n');
        console.error('  Example:');
        console.error(
          '    aegis vault unseal --key-share aegis_share_01_... --key-share aegis_share_02_...\n',
        );
        process.exit(1);
      }

      const sealMgr = new SealManager(config.dataDir);
      const sealConfig = sealMgr.getSealConfig();

      if (!sealConfig) {
        console.error('\n✗ Key splitting is not configured. Run `aegis vault split` first.\n');
        process.exit(1);
      }

      if (opts.keyShare.length < sealConfig.threshold) {
        console.error(
          `\n✗ Not enough shares. Provided ${opts.keyShare.length}, need ${sealConfig.threshold}.\n`,
        );
        process.exit(1);
      }

      try {
        // Decode all shares
        const shares = opts.keyShare.map((s) => decodeShare(s));

        // Reconstruct the master key
        const reconstructed = combine(shares);
        const masterKey = reconstructed.toString('utf-8');

        // Verify against stored hash
        if (!sealMgr.verifyKey(masterKey)) {
          console.error(
            '\n✗ Key verification failed. The provided shares do not reconstruct the correct master key.\n',
          );
          console.error('  Possible causes:');
          console.error('  • Wrong shares provided');
          console.error(`  • Not enough valid shares (need at least ${sealConfig.threshold})`);
          console.error('  • Shares from different split operations\n');
          process.exit(1);
        }

        // Write the unseal key
        sealMgr.writeUnsealKey(masterKey);

        console.log(`\n  ✓ Vault unsealed successfully.\n`);
        console.log(`  Master key reconstructed and stored in .aegis/.unseal-key (mode 0600).`);
        console.log(`  All Aegis commands will use the reconstructed key.\n`);
        console.log(`  To seal the vault again: aegis vault seal\n`);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n✗ ${message}\n`);
        process.exit(1);
      }
    });

  vault
    .command('seal')
    .description('Seal the vault — securely remove the reconstructed master key')
    .action(() => {
      const config = getConfig();
      const sealMgr = new SealManager(config.dataDir);

      if (!sealMgr.isSplitEnabled()) {
        console.error('\n✗ Key splitting is not configured. Nothing to seal.\n');
        process.exit(1);
      }

      if (!sealMgr.isUnsealed()) {
        console.log('\n  Vault is already sealed.\n');
        return;
      }

      sealMgr.seal();

      console.log(`\n  ✓ Vault sealed.\n`);
      console.log(`  The reconstructed master key has been securely removed.`);
      console.log(
        `  To unseal: aegis vault unseal --key-share <share1> --key-share <share2> ...\n`,
      );
    });
}
