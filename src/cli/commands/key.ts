/**
 * Key management commands: aegis key where
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { Command } from 'commander';
import { findConfigFile, getConfig, loadEnv, parseConfigFile } from '../../config.js';
import {
  FileFallbackStorage,
  getKeyStorage,
  LinuxSecretServiceStorage,
  MacOSKeychainStorage,
  WindowsCredentialStorage,
} from '../../key-storage/index.js';

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

      // 1. Shell environment variable (process.env)
      const envKey = process.env.AEGIS_MASTER_KEY;
      console.log(`    1. Env var (AEGIS_MASTER_KEY):     ${envKey ? '✓ set' : '✗ not set'}`);

      // 2. .env file (loaded by getConfig but not visible in process.env)
      const configFilePath = findConfigFile();
      const baseDir = configFilePath ? path.dirname(path.resolve(configFilePath)) : process.cwd();
      const dotEnvPath = path.join(baseDir, '.env');
      const hasDotEnv = fs.existsSync(dotEnvPath);
      if (hasDotEnv) {
        const dotenv = loadEnv(dotEnvPath);
        const inDotEnv = !!dotenv.AEGIS_MASTER_KEY;
        console.log(`    2. .env file:                     ${inDotEnv ? '✓ set' : '✗ not set'}`);
      } else {
        console.log('    2. .env file:                     ✗ no .env file');
      }

      // 3. Config file (aegis.config.yaml vault.master_key)
      if (configFilePath) {
        try {
          const fileConfig = parseConfigFile(configFilePath);
          const inFile = !!fileConfig.vault?.master_key;
          console.log(
            `    3. Config file (${path.basename(configFilePath)}):  ${inFile ? '✓ set' : '✗ not set'}`,
          );
        } catch {
          console.log('    3. Config file:                   ✗ error reading');
        }
      } else {
        console.log('    3. Config file:                   ✗ no config file found');
      }

      // 4. OS keychain (platform-specific)
      const platform = os.platform();
      let osKeychainName = 'OS keychain';
      let osKeychainHasKey = false;
      if (platform === 'darwin') {
        const kc = new MacOSKeychainStorage();
        osKeychainName = kc.name;
        osKeychainHasKey = kc.isAvailable() && kc.getKey() !== undefined;
      } else if (platform === 'win32') {
        const wc = new WindowsCredentialStorage();
        osKeychainName = wc.name;
        osKeychainHasKey = wc.isAvailable() && wc.getKey() !== undefined;
      } else if (platform === 'linux') {
        const ls = new LinuxSecretServiceStorage();
        osKeychainName = ls.name;
        osKeychainHasKey = ls.isAvailable() && ls.getKey() !== undefined;
      }
      console.log(
        `    4. OS keychain (${osKeychainName}):  ${osKeychainHasKey ? '✓ stored' : '✗ not stored'}`,
      );

      // 5. File fallback (.aegis/.master-key)
      const fileFallback = new FileFallbackStorage(dataDir);
      const fileHasKey = fileFallback.getKey() !== undefined;
      const masterKeyPath = path.join(dataDir, '.master-key');
      console.log(
        `    5. File fallback (${masterKeyPath}):  ${fileHasKey ? '✓ stored' : '✗ not stored'}`,
      );

      if (config.masterKey) {
        console.log('\n  ✓ Master key is resolved and available.\n');
      } else {
        console.log('\n  ✗ No master key found. Run "aegis init" to generate one.\n');
      }
    });
}
