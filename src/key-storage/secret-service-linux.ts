/**
 * Linux Secret Service backend via `secret-tool` (libsecret).
 *
 * Works with GNOME Keyring, KDE Wallet, KeePassXC, or any implementation
 * of the freedesktop.org Secret Service D-Bus API.
 *
 * The key is stored with attributes:
 *   application=aegis  type=master-key
 */

import { execFileSync } from 'node:child_process';
import type { KeyStorage, KeyStorageBackend } from './key-storage.js';
import { commandExists } from './key-storage.js';

const ATTRS = ['application', 'aegis', 'type', 'master-key'];
const LABEL = 'Aegis Master Key';

export class LinuxSecretServiceStorage implements KeyStorage {
  readonly name = 'Linux Secret Service';
  readonly backend: KeyStorageBackend = 'linux-secret-service';

  isAvailable(): boolean {
    return process.platform === 'linux' && commandExists('secret-tool');
  }

  getKey(): string | undefined {
    try {
      const result = execFileSync('secret-tool', ['lookup', ...ATTRS], {
        stdio: ['pipe', 'pipe', 'pipe'],
        encoding: 'utf-8',
      });
      const key = result.trim();
      return key || undefined;
    } catch {
      // Secret not found or D-Bus not available
      return undefined;
    }
  }

  setKey(key: string): void {
    try {
      // secret-tool reads the password from stdin
      execFileSync('secret-tool', ['store', '--label', LABEL, ...ATTRS], {
        input: key,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } catch (err) {
      throw new Error(`Failed to store key in Secret Service: ${(err as Error).message}`);
    }
  }

  deleteKey(): void {
    try {
      execFileSync('secret-tool', ['clear', ...ATTRS], { stdio: 'pipe' });
    } catch {
      // Secret not found — nothing to delete
    }
  }
}
