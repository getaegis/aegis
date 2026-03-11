/**
 * Key management commands: aegis key where
 */

import * as path from 'node:path';
import type { Command } from 'commander';
import { getConfig, parseConfigFile } from '../../config.js';
import { getKeyStorage } from '../../key-storage/index.js';

export function register(program: Command): void {
  const key = program.command('key').description('Manage the Aegis master key');

  key
    .command('where')
    .description('Show where the master key is currently stored and resolved from')
    .action(() => {
      const config = getConfig();
      const dataDir = config.dataDir;
      const storage = getKeyStorage(dataDir);

      console.log('\n  Master Key Storage\n');
      console.log(`  Active backend:  ${storage.name} (${storage.backend})`);
      console.log(`  Available:       ${storage.isAvailable() ? 'yes' : 'no'}`);

      const hasKey = storage.getKey() !== undefined;
      console.log(`  Key stored:      ${hasKey ? 'yes' : 'no'}`);

      // Check all resolution sources
      console.log('\n  Resolution chain (highest priority first):\n');

      const envKey = process.env.AEGIS_MASTER_KEY;
      console.log(`    1. AEGIS_MASTER_KEY env var:  ${envKey ? '✓ set' : '✗ not set'}`);

      // Check config file
      const configFile = config.configFilePath;
      if (configFile) {
        try {
          const fileConfig = parseConfigFile(configFile);
          const inFile = !!fileConfig.vault?.master_key;
          console.log(
            `    2. Config file (${path.basename(configFile)}):  ${inFile ? '✓ set' : '✗ not set'}`,
          );
        } catch {
          console.log('    2. Config file:               ✗ error reading');
        }
      } else {
        console.log('    2. Config file:               ✗ no config file found');
      }

      console.log(`    3. OS keychain (${storage.name}):  ${hasKey ? '✓ stored' : '✗ not stored'}`);

      if (config.masterKey) {
        console.log('\n  ✓ Master key is resolved and available.\n');
      } else {
        console.log('\n  ✗ No master key found. Run "aegis init" to generate one.\n');
      }
    });
}
