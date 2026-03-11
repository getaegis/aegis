/**
 * Cross-platform key storage abstraction.
 *
 * Provides a unified interface for storing the Aegis master key in
 * OS-managed credential stores, keeping it out of plaintext files.
 *
 * Resolution order (auto-detect):
 *   macOS   → Keychain (`security` CLI)
 *   Windows → Credential Manager (`cmdkey` + PowerShell)
 *   Linux   → Secret Service (`secret-tool` / libsecret)
 *   Fallback → File (.aegis/.master-key, mode 0600)
 */

import { execFileSync } from 'node:child_process';
import * as os from 'node:os';
import { WindowsCredentialStorage } from './credential-manager-windows.js';
import { FileFallbackStorage } from './file-fallback.js';
import { MacOSKeychainStorage } from './keychain-macos.js';
import { LinuxSecretServiceStorage } from './secret-service-linux.js';

// ─── Interface ────────────────────────────────────────────────────

/** Backend identifier for display and diagnostics. */
export type KeyStorageBackend =
  | 'macos-keychain'
  | 'windows-credential-manager'
  | 'linux-secret-service'
  | 'file';

/** Abstract key storage interface. All methods are synchronous to keep config loading simple. */
export interface KeyStorage {
  /** Human-readable backend name (e.g. "macOS Keychain"). */
  readonly name: string;

  /** Machine-readable backend identifier. */
  readonly backend: KeyStorageBackend;

  /** Check whether this backend is available on the current system. */
  isAvailable(): boolean;

  /** Retrieve the master key. Returns undefined if not stored. */
  getKey(): string | undefined;

  /** Store the master key (creates or replaces). */
  setKey(key: string): void;

  /** Delete the stored master key. No-op if not present. */
  deleteKey(): void;
}

// ─── Helpers ──────────────────────────────────────────────────────

/** Cache for commandExists results — avoids redundant subprocess calls. */
const commandExistsCache = new Map<string, boolean>();

/** Check whether a CLI tool exists on PATH. Results are cached per process. */
export function commandExists(command: string): boolean {
  const cached = commandExistsCache.get(command);
  if (cached !== undefined) return cached;

  let exists: boolean;
  try {
    const which = os.platform() === 'win32' ? 'where' : 'which';
    execFileSync(which, [command], { stdio: 'pipe' });
    exists = true;
  } catch {
    exists = false;
  }

  commandExistsCache.set(command, exists);
  return exists;
}

/** Clear the commandExists cache (for testing). */
export function clearCommandExistsCache(): void {
  commandExistsCache.clear();
}

// ─── Factory ──────────────────────────────────────────────────────

/**
 * Auto-detect the best available key storage backend for the current platform.
 *
 * @param dataDir  Path to the .aegis data directory (used by file fallback).
 * @returns        A KeyStorage implementation.
 */
export function getKeyStorage(dataDir: string): KeyStorage {
  const platform = os.platform();

  if (platform === 'darwin') {
    const backend = new MacOSKeychainStorage();
    if (backend.isAvailable()) return backend;
  }

  if (platform === 'win32') {
    const backend = new WindowsCredentialStorage();
    if (backend.isAvailable()) return backend;
  }

  if (platform === 'linux') {
    const backend = new LinuxSecretServiceStorage();
    if (backend.isAvailable()) return backend;
  }

  // Fallback: file-based storage
  return new FileFallbackStorage(dataDir);
}
