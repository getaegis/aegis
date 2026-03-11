/**
 * macOS Keychain backend via the `security` CLI.
 *
 * Uses `security add-generic-password` / `find-generic-password` /
 * `delete-generic-password` which ship with every macOS install.
 *
 * The key is stored in the user's login keychain under:
 *   service: "aegis"   account: "master-key"
 */

import { execFileSync } from 'node:child_process';
import type { KeyStorage, KeyStorageBackend } from './key-storage.js';
import { commandExists } from './key-storage.js';

const SERVICE = 'aegis';
const ACCOUNT = 'master-key';

export class MacOSKeychainStorage implements KeyStorage {
  readonly name = 'macOS Keychain';
  readonly backend: KeyStorageBackend = 'macos-keychain';

  isAvailable(): boolean {
    return process.platform === 'darwin' && commandExists('security');
  }

  getKey(): string | undefined {
    try {
      const result = execFileSync(
        'security',
        ['find-generic-password', '-a', ACCOUNT, '-s', SERVICE, '-w'],
        { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf-8' },
      );
      const key = result.trim();
      return key || undefined;
    } catch {
      // Item not found (exit code 44) or other error
      return undefined;
    }
  }

  setKey(key: string): void {
    // -U flag updates if the item already exists (prevents "already exists" error)
    try {
      execFileSync(
        'security',
        ['add-generic-password', '-a', ACCOUNT, '-s', SERVICE, '-w', key, '-U'],
        { stdio: 'pipe' },
      );
    } catch (err) {
      throw new Error(`Failed to store key in macOS Keychain: ${(err as Error).message}`);
    }
  }

  deleteKey(): void {
    try {
      execFileSync('security', ['delete-generic-password', '-a', ACCOUNT, '-s', SERVICE], {
        stdio: 'pipe',
      });
    } catch {
      // Item not found — nothing to delete
    }
  }
}
