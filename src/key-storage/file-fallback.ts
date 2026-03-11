/**
 * File-based fallback key storage.
 *
 * Stores the master key in `.aegis/.master-key` with mode 0600.
 * Used for headless/CI environments where no OS keychain is available.
 *
 * Note: `.aegis/.unseal-key` is reserved for SealManager (Shamir
 * reconstructed key). This file uses a distinct name to avoid collision.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { KeyStorage, KeyStorageBackend } from './key-storage.js';

export class FileFallbackStorage implements KeyStorage {
  readonly name = 'File';
  readonly backend: KeyStorageBackend = 'file';
  private readonly keyPath: string;

  constructor(dataDir: string) {
    this.keyPath = path.join(dataDir, '.master-key');
  }

  isAvailable(): boolean {
    // File fallback is always available
    return true;
  }

  getKey(): string | undefined {
    try {
      if (!fs.existsSync(this.keyPath)) return undefined;

      // Warn if file permissions are too open (not relevant on Windows)
      if (os.platform() !== 'win32') {
        const stat = fs.statSync(this.keyPath);
        const mode = stat.mode & 0o777;
        if (mode !== 0o600) {
          process.stderr.write(
            `⚠  ${this.keyPath} has mode ${mode.toString(8).padStart(4, '0')} — expected 0600.\n` +
              `   Run: chmod 600 ${this.keyPath}\n`,
          );
        }
      }

      const key = fs.readFileSync(this.keyPath, 'utf-8').trim();
      return key || undefined;
    } catch {
      return undefined;
    }
  }

  setKey(key: string): void {
    const dir = path.dirname(this.keyPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(this.keyPath, key, { mode: 0o600 });
  }

  deleteKey(): void {
    try {
      if (fs.existsSync(this.keyPath)) {
        fs.unlinkSync(this.keyPath);
      }
    } catch {
      // File doesn't exist — nothing to delete
    }
  }
}
