import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { WindowsCredentialStorage } from '../src/key-storage/credential-manager-windows.js';
import { FileFallbackStorage } from '../src/key-storage/file-fallback.js';
import {
  clearCommandExistsCache,
  commandExists,
  getKeyStorage,
  type KeyStorage,
} from '../src/key-storage/key-storage.js';

// Also mock node:os so we can override os.platform() in factory tests
vi.mock('node:os', async (importOriginal) => {
  const mod = await importOriginal<typeof import('node:os')>();
  return { ...mod, platform: vi.fn(mod.platform) };
});

const mockedPlatform = vi.mocked(os.platform);

import { MacOSKeychainStorage } from '../src/key-storage/keychain-macos.js';
import { LinuxSecretServiceStorage } from '../src/key-storage/secret-service-linux.js';

// ─── Module-level mock ────────────────────────────────────────────
// ESM module namespaces are sealed — vi.spyOn cannot redefine exports.
// vi.mock() is hoisted and replaces the module for ALL importers in
// this test file, including the source modules under test.
//
// By default we wrap the real execFileSync so that non-mocked tests
// (commandExists with real binaries, factory auto-detect, isAvailable)
// still work. Individual tests override with mockReturnValue /
// mockImplementation and afterEach resets back to the real function.
vi.mock('node:child_process', async (importOriginal) => {
  const mod = await importOriginal<typeof import('node:child_process')>();
  return { ...mod, execFileSync: vi.fn(mod.execFileSync) };
});

/** Convenience alias — `execFileSync` from the mocked module. */
const mockedExec = vi.mocked(execFileSync);

/**
 * Reset the mock back to calling the real execFileSync.
 * We capture the real implementation from `mockRestore()` behaviour:
 * vi.fn(impl) stores `impl` as the initial implementation and
 * mockReset clears overrides but leaves the fn callable (returns undefined).
 * So we re-wrap manually.
 */
function resetExecMock(): void {
  mockedExec.mockReset();
  mockedExec.mockRestore();
  clearCommandExistsCache();
  mockedPlatform.mockRestore();
  // Restore process.platform if it was overridden
  restoreProcessPlatform();
}

// ─── process.platform override ────────────────────────────────────
// process.platform is a read-only property. We override it with
// Object.defineProperty for factory tests that need cross-platform
// branch coverage, then restore it after each test.

const realPlatform = process.platform;

function setProcessPlatform(platform: NodeJS.Platform): void {
  Object.defineProperty(process, 'platform', { value: platform, configurable: true });
}

function restoreProcessPlatform(): void {
  Object.defineProperty(process, 'platform', { value: realPlatform, configurable: true });
}

// ─── FileFallbackStorage (real filesystem) ────────────────────────

describe('FileFallbackStorage', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-key-storage-test-'));
  });

  afterEach(() => {
    resetExecMock();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('has correct name and backend', () => {
    const storage = new FileFallbackStorage(tmpDir);
    expect(storage.name).toBe('File');
    expect(storage.backend).toBe('file');
  });

  it('isAvailable returns true always', () => {
    const storage = new FileFallbackStorage(tmpDir);
    expect(storage.isAvailable()).toBe(true);
  });

  it('getKey returns undefined when no key is stored', () => {
    const storage = new FileFallbackStorage(tmpDir);
    expect(storage.getKey()).toBeUndefined();
  });

  it('setKey stores a key and getKey retrieves it', () => {
    const storage = new FileFallbackStorage(tmpDir);
    const key = 'a'.repeat(64);
    storage.setKey(key);
    expect(storage.getKey()).toBe(key);
  });

  it('setKey creates the data directory if it does not exist', () => {
    const nestedDir = path.join(tmpDir, 'nested', 'data');
    const storage = new FileFallbackStorage(nestedDir);
    storage.setKey('test-key');
    expect(fs.existsSync(path.join(nestedDir, '.master-key'))).toBe(true);
  });

  it('setKey writes the file with mode 0600', () => {
    const storage = new FileFallbackStorage(tmpDir);
    storage.setKey('secret');
    const stat = fs.statSync(path.join(tmpDir, '.master-key'));
    // 0o600 = 384 decimal. On macOS/Linux this is enforced.
    expect(stat.mode & 0o777).toBe(0o600);
  });

  it('setKey overwrites an existing key', () => {
    const storage = new FileFallbackStorage(tmpDir);
    storage.setKey('old-key');
    storage.setKey('new-key');
    expect(storage.getKey()).toBe('new-key');
  });

  it('deleteKey removes the stored key', () => {
    const storage = new FileFallbackStorage(tmpDir);
    storage.setKey('to-delete');
    expect(storage.getKey()).toBe('to-delete');
    storage.deleteKey();
    expect(storage.getKey()).toBeUndefined();
  });

  it('deleteKey is a no-op when no key exists', () => {
    const storage = new FileFallbackStorage(tmpDir);
    expect(() => storage.deleteKey()).not.toThrow();
  });

  it('getKey trims whitespace from stored key', () => {
    const storage = new FileFallbackStorage(tmpDir);
    fs.writeFileSync(path.join(tmpDir, '.master-key'), '  key-with-spaces  \n');
    const spy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    expect(storage.getKey()).toBe('key-with-spaces');
    spy.mockRestore();
  });

  it('getKey returns undefined for empty file', () => {
    const storage = new FileFallbackStorage(tmpDir);
    fs.writeFileSync(path.join(tmpDir, '.master-key'), '');
    const spy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    expect(storage.getKey()).toBeUndefined();
    spy.mockRestore();
  });

  it('getKey returns undefined for whitespace-only file', () => {
    const storage = new FileFallbackStorage(tmpDir);
    fs.writeFileSync(path.join(tmpDir, '.master-key'), '   \n  \n');
    const spy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    expect(storage.getKey()).toBeUndefined();
    spy.mockRestore();
  });

  it('getKey warns to stderr when file permissions are too open', () => {
    if (os.platform() === 'win32') return; // permissions not enforced on Windows
    const storage = new FileFallbackStorage(tmpDir);
    fs.writeFileSync(path.join(tmpDir, '.master-key'), 'secret-key', { mode: 0o644 });
    const stderrSpy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    const key = storage.getKey();
    expect(key).toBe('secret-key');
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining('expected 0600'));
    stderrSpy.mockRestore();
  });
});

// ─── MacOSKeychainStorage (mocked execFileSync) ──────────────────

describe('MacOSKeychainStorage', () => {
  afterEach(() => {
    resetExecMock();
  });

  it('has correct name and backend', () => {
    const storage = new MacOSKeychainStorage();
    expect(storage.name).toBe('macOS Keychain');
    expect(storage.backend).toBe('macos-keychain');
  });

  it('isAvailable checks platform and security command', () => {
    const storage = new MacOSKeychainStorage();
    // Uses real execFileSync via the passthrough mock.
    if (process.platform === 'darwin') {
      expect(storage.isAvailable()).toBe(true);
    } else {
      expect(storage.isAvailable()).toBe(false);
    }
  });

  it('getKey returns the key from security output', () => {
    mockedExec.mockReturnValue('test-key-value\n');
    const storage = new MacOSKeychainStorage();
    expect(storage.getKey()).toBe('test-key-value');
    expect(mockedExec).toHaveBeenCalledWith(
      'security',
      ['find-generic-password', '-a', 'master-key', '-s', 'aegis', '-w'],
      expect.objectContaining({ encoding: 'utf-8' }),
    );
  });

  it('getKey returns undefined when security command fails', () => {
    mockedExec.mockImplementation(() => {
      throw new Error('Item not found');
    });
    const storage = new MacOSKeychainStorage();
    expect(storage.getKey()).toBeUndefined();
  });

  it('getKey returns undefined for empty output', () => {
    mockedExec.mockReturnValue('\n');
    const storage = new MacOSKeychainStorage();
    expect(storage.getKey()).toBeUndefined();
  });

  it('setKey calls security add-generic-password with -U flag', () => {
    mockedExec.mockReturnValue(Buffer.from(''));
    const storage = new MacOSKeychainStorage();
    storage.setKey('my-secret');
    expect(mockedExec).toHaveBeenCalledWith(
      'security',
      ['add-generic-password', '-a', 'master-key', '-s', 'aegis', '-w', 'my-secret', '-U'],
      expect.objectContaining({ stdio: 'pipe' }),
    );
  });

  it('setKey throws on failure', () => {
    mockedExec.mockImplementation(() => {
      throw new Error('Permission denied');
    });
    const storage = new MacOSKeychainStorage();
    expect(() => storage.setKey('fail')).toThrow('Failed to store key in macOS Keychain');
  });

  it('setKey handles keys with special characters', () => {
    mockedExec.mockReturnValue(Buffer.from(''));
    const storage = new MacOSKeychainStorage();
    const specialKey = 'key$with"special\'chars&pipes|and<redirects>';
    expect(() => storage.setKey(specialKey)).not.toThrow();
    expect(mockedExec).toHaveBeenCalledWith(
      'security',
      ['add-generic-password', '-a', 'master-key', '-s', 'aegis', '-w', specialKey, '-U'],
      expect.objectContaining({ stdio: 'pipe' }),
    );
  });

  it('deleteKey calls security delete-generic-password', () => {
    mockedExec.mockReturnValue(Buffer.from(''));
    const storage = new MacOSKeychainStorage();
    storage.deleteKey();
    expect(mockedExec).toHaveBeenCalledWith(
      'security',
      ['delete-generic-password', '-a', 'master-key', '-s', 'aegis'],
      expect.objectContaining({ stdio: 'pipe' }),
    );
  });

  it('deleteKey does not throw when item not found', () => {
    mockedExec.mockImplementation(() => {
      throw new Error('Item not found');
    });
    const storage = new MacOSKeychainStorage();
    expect(() => storage.deleteKey()).not.toThrow();
  });
});

// ─── LinuxSecretServiceStorage (mocked execFileSync) ─────────────

describe('LinuxSecretServiceStorage', () => {
  afterEach(() => {
    resetExecMock();
  });

  it('has correct name and backend', () => {
    const storage = new LinuxSecretServiceStorage();
    expect(storage.name).toBe('Linux Secret Service');
    expect(storage.backend).toBe('linux-secret-service');
  });

  it('isAvailable returns false on non-Linux', () => {
    const storage = new LinuxSecretServiceStorage();
    if (process.platform !== 'linux') {
      expect(storage.isAvailable()).toBe(false);
    }
  });

  it('getKey returns the key from secret-tool output', () => {
    mockedExec.mockReturnValue('linux-secret\n');
    const storage = new LinuxSecretServiceStorage();
    expect(storage.getKey()).toBe('linux-secret');
    expect(mockedExec).toHaveBeenCalledWith(
      'secret-tool',
      ['lookup', 'application', 'aegis', 'type', 'master-key'],
      expect.objectContaining({ encoding: 'utf-8' }),
    );
  });

  it('getKey returns undefined when secret-tool fails', () => {
    mockedExec.mockImplementation(() => {
      throw new Error('No matching secret');
    });
    const storage = new LinuxSecretServiceStorage();
    expect(storage.getKey()).toBeUndefined();
  });

  it('getKey returns undefined for empty output', () => {
    mockedExec.mockReturnValue('\n');
    const storage = new LinuxSecretServiceStorage();
    expect(storage.getKey()).toBeUndefined();
  });

  it('setKey calls secret-tool store with input on stdin', () => {
    mockedExec.mockReturnValue(Buffer.from(''));
    const storage = new LinuxSecretServiceStorage();
    storage.setKey('linux-key');
    expect(mockedExec).toHaveBeenCalledWith(
      'secret-tool',
      ['store', '--label', 'Aegis Master Key', 'application', 'aegis', 'type', 'master-key'],
      expect.objectContaining({ input: 'linux-key' }),
    );
  });

  it('setKey passes key via stdin, not as a CLI argument', () => {
    mockedExec.mockReturnValue(Buffer.from(''));
    const storage = new LinuxSecretServiceStorage();
    const sensitiveKey = 'super-secret-key-value-abc123';
    storage.setKey(sensitiveKey);
    // Verify key is in the input option, NOT in the args array
    const storeCall = mockedExec.mock.calls.find(
      (c) => c[0] === 'secret-tool' && Array.isArray(c[1]) && c[1][0] === 'store',
    );
    expect(storeCall).toBeDefined();
    if (!storeCall) return; // type narrowing — already asserted above
    const args = storeCall[1] as string[];
    expect(args).not.toContain(sensitiveKey);
    const opts = storeCall[2] as Record<string, unknown>;
    expect(opts.input).toBe(sensitiveKey);
  });

  it('setKey handles keys with special characters', () => {
    mockedExec.mockReturnValue(Buffer.from(''));
    const storage = new LinuxSecretServiceStorage();
    const specialKey = 'key$with"special\'chars&pipes|and<redirects>';
    expect(() => storage.setKey(specialKey)).not.toThrow();
    expect(mockedExec).toHaveBeenCalledWith(
      'secret-tool',
      expect.any(Array),
      expect.objectContaining({ input: specialKey }),
    );
  });

  it('setKey throws on failure', () => {
    mockedExec.mockImplementation(() => {
      throw new Error('D-Bus not available');
    });
    const storage = new LinuxSecretServiceStorage();
    expect(() => storage.setKey('fail')).toThrow('Failed to store key in Secret Service');
  });

  it('deleteKey calls secret-tool clear', () => {
    mockedExec.mockReturnValue(Buffer.from(''));
    const storage = new LinuxSecretServiceStorage();
    storage.deleteKey();
    expect(mockedExec).toHaveBeenCalledWith(
      'secret-tool',
      ['clear', 'application', 'aegis', 'type', 'master-key'],
      expect.objectContaining({ stdio: 'pipe' }),
    );
  });

  it('deleteKey does not throw when secret not found', () => {
    mockedExec.mockImplementation(() => {
      throw new Error('No matching secret');
    });
    const storage = new LinuxSecretServiceStorage();
    expect(() => storage.deleteKey()).not.toThrow();
  });
});

// ─── WindowsCredentialStorage (mocked execFileSync) ──────────────

describe('WindowsCredentialStorage', () => {
  afterEach(() => {
    resetExecMock();
  });

  it('has correct name and backend', () => {
    const storage = new WindowsCredentialStorage();
    expect(storage.name).toBe('Windows Credential Manager');
    expect(storage.backend).toBe('windows-credential-manager');
  });

  it('isAvailable returns false on non-Windows', () => {
    const storage = new WindowsCredentialStorage();
    if (process.platform !== 'win32') {
      expect(storage.isAvailable()).toBe(false);
    }
  });

  it('getKey returns the key from PowerShell output', () => {
    mockedExec.mockReturnValue('win-secret\n');
    const storage = new WindowsCredentialStorage();
    expect(storage.getKey()).toBe('win-secret');
  });

  it('getKey returns undefined when PowerShell fails', () => {
    mockedExec.mockImplementation(() => {
      throw new Error('Credential not found');
    });
    const storage = new WindowsCredentialStorage();
    expect(storage.getKey()).toBeUndefined();
  });

  it('getKey returns undefined for empty output', () => {
    mockedExec.mockReturnValue('\n');
    const storage = new WindowsCredentialStorage();
    expect(storage.getKey()).toBeUndefined();
  });

  it('setKey handles keys with special characters', () => {
    mockedExec.mockReturnValue(Buffer.from(''));
    const storage = new WindowsCredentialStorage();
    const specialKey = 'key$with"special\'chars&pipes|and<redirects>';
    expect(() => storage.setKey(specialKey)).not.toThrow();
    expect(mockedExec).toHaveBeenCalledWith(
      'cmdkey',
      [`/generic:aegis/master-key`, `/user:aegis`, `/pass:${specialKey}`],
      expect.objectContaining({ stdio: 'pipe' }),
    );
  });

  it('setKey calls cmdkey with /generic, /user, /pass', () => {
    mockedExec.mockReturnValue(Buffer.from(''));
    const storage = new WindowsCredentialStorage();
    storage.setKey('win-key');
    expect(mockedExec).toHaveBeenCalledWith(
      'cmdkey',
      ['/generic:aegis/master-key', '/user:aegis', '/pass:win-key'],
      expect.objectContaining({ stdio: 'pipe' }),
    );
  });

  it('setKey throws on failure', () => {
    mockedExec.mockImplementation(() => {
      throw new Error('Access denied');
    });
    const storage = new WindowsCredentialStorage();
    expect(() => storage.setKey('fail')).toThrow(
      'Failed to store key in Windows Credential Manager',
    );
  });

  it('deleteKey calls cmdkey /delete', () => {
    mockedExec.mockReturnValue(Buffer.from(''));
    const storage = new WindowsCredentialStorage();
    storage.deleteKey();
    expect(mockedExec).toHaveBeenCalledWith(
      'cmdkey',
      ['/delete:aegis/master-key'],
      expect.objectContaining({ stdio: 'pipe' }),
    );
  });

  it('deleteKey does not throw when credential not found', () => {
    mockedExec.mockImplementation(() => {
      throw new Error('Not found');
    });
    const storage = new WindowsCredentialStorage();
    expect(() => storage.deleteKey()).not.toThrow();
  });
});

// ─── commandExists ───────────────────────────────────────────────

describe('commandExists', () => {
  afterEach(() => {
    resetExecMock();
  });

  it('returns true for a known command (node)', () => {
    // Uses real execFileSync passthrough — `which node` should succeed
    expect(commandExists('node')).toBe(true);
  });

  it('returns false for a nonexistent command', () => {
    // Uses real execFileSync passthrough — `which xyz...` throws
    expect(commandExists('this-command-definitely-does-not-exist-xyz')).toBe(false);
  });

  it('calls the correct which-equivalent for the platform', () => {
    mockedExec.mockReturnValue(Buffer.from('/usr/bin/test-cmd\n'));
    commandExists('test-cmd');
    const expectedBin = process.platform === 'win32' ? 'where' : 'which';
    expect(mockedExec).toHaveBeenCalledWith(
      expectedBin,
      ['test-cmd'],
      expect.objectContaining({ stdio: 'pipe' }),
    );
  });

  it('caches results to avoid redundant subprocess calls', () => {
    mockedExec.mockReturnValue(Buffer.from('/usr/bin/cached-cmd\n'));
    expect(commandExists('cached-cmd')).toBe(true);
    expect(commandExists('cached-cmd')).toBe(true);
    // execFileSync should only be called once due to caching
    const calls = mockedExec.mock.calls.filter(
      (c) => Array.isArray(c[1]) && c[1][0] === 'cached-cmd',
    );
    expect(calls).toHaveLength(1);
  });

  it('clearCommandExistsCache resets the cache', () => {
    mockedExec.mockReturnValue(Buffer.from('/usr/bin/clear-test\n'));
    commandExists('clear-test');
    clearCommandExistsCache();
    commandExists('clear-test');
    const calls = mockedExec.mock.calls.filter(
      (c) => Array.isArray(c[1]) && c[1][0] === 'clear-test',
    );
    expect(calls).toHaveLength(2);
  });
});

// ─── getKeyStorage factory ───────────────────────────────────────

describe('getKeyStorage', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-key-factory-test-'));
  });

  afterEach(() => {
    resetExecMock();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns a KeyStorage implementation', () => {
    const storage = getKeyStorage(tmpDir);
    expect(storage).toBeDefined();
    expect(storage.name).toBeTruthy();
    expect(storage.backend).toBeTruthy();
    expect(typeof storage.isAvailable).toBe('function');
    expect(typeof storage.getKey).toBe('function');
    expect(typeof storage.setKey).toBe('function');
    expect(typeof storage.deleteKey).toBe('function');
  });

  it('returns a platform-appropriate backend', () => {
    const storage = getKeyStorage(tmpDir);
    if (process.platform === 'darwin') {
      expect(storage.backend).toBe('macos-keychain');
    } else if (process.platform === 'win32') {
      expect(storage.backend).toBe('windows-credential-manager');
    } else if (process.platform === 'linux') {
      // Depends on whether secret-tool is installed
      expect(['linux-secret-service', 'file']).toContain(storage.backend);
    } else {
      expect(storage.backend).toBe('file');
    }
  });

  it('returned storage is always available', () => {
    const storage = getKeyStorage(tmpDir);
    expect(storage.isAvailable()).toBe(true);
  });

  it('falls back to file when no OS backend is available', () => {
    // Make all execFileSync calls throw — simulates no CLI tools found
    mockedExec.mockImplementation(() => {
      throw new Error('command not found');
    });
    const storage = getKeyStorage(tmpDir);
    expect(storage.backend).toBe('file');
    expect(storage.isAvailable()).toBe(true);
  });

  it('selects macOS Keychain on darwin when security exists', () => {
    setProcessPlatform('darwin');
    mockedPlatform.mockReturnValue('darwin');
    // Allow `which security` to succeed
    mockedExec.mockReturnValue(Buffer.from('/usr/bin/security\n'));
    const storage = getKeyStorage(tmpDir);
    expect(storage.backend).toBe('macos-keychain');
  });

  it('selects Linux Secret Service on linux when secret-tool exists', () => {
    setProcessPlatform('linux');
    mockedPlatform.mockReturnValue('linux');
    mockedExec.mockReturnValue(Buffer.from('/usr/bin/secret-tool\n'));
    const storage = getKeyStorage(tmpDir);
    expect(storage.backend).toBe('linux-secret-service');
  });

  it('selects Windows Credential Manager on win32 when cmdkey and powershell exist', () => {
    setProcessPlatform('win32');
    mockedPlatform.mockReturnValue('win32');
    mockedExec.mockReturnValue(Buffer.from('C:\\Windows\\System32\\cmdkey.exe\n'));
    const storage = getKeyStorage(tmpDir);
    expect(storage.backend).toBe('windows-credential-manager');
  });

  it('falls back to file on darwin when security command is missing', () => {
    setProcessPlatform('darwin');
    mockedPlatform.mockReturnValue('darwin');
    mockedExec.mockImplementation(() => {
      throw new Error('command not found');
    });
    const storage = getKeyStorage(tmpDir);
    expect(storage.backend).toBe('file');
  });

  it('falls back to file on linux when secret-tool is missing', () => {
    setProcessPlatform('linux');
    mockedPlatform.mockReturnValue('linux');
    mockedExec.mockImplementation(() => {
      throw new Error('command not found');
    });
    const storage = getKeyStorage(tmpDir);
    expect(storage.backend).toBe('file');
  });

  it('falls back to file on win32 when cmdkey or powershell is missing', () => {
    setProcessPlatform('win32');
    mockedPlatform.mockReturnValue('win32');
    mockedExec.mockImplementation(() => {
      throw new Error('command not found');
    });
    const storage = getKeyStorage(tmpDir);
    expect(storage.backend).toBe('file');
  });

  it('falls back to file on unknown platform', () => {
    mockedPlatform.mockReturnValue('freebsd' as NodeJS.Platform);
    const storage = getKeyStorage(tmpDir);
    expect(storage.backend).toBe('file');
  });
});

// ─── KeyStorage interface conformance ────────────────────────────

describe('KeyStorage interface conformance', () => {
  afterEach(() => {
    resetExecMock();
  });

  it('FileFallbackStorage implements all required methods', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-iface-test-'));
    try {
      const storage: KeyStorage = new FileFallbackStorage(tmpDir);
      expect(storage.name).toEqual(expect.any(String));
      expect(storage.backend).toEqual(expect.any(String));
      expect(storage.isAvailable()).toEqual(expect.any(Boolean));
      expect(storage.getKey()).toBeUndefined();
      storage.setKey('test');
      expect(storage.getKey()).toBe('test');
      storage.deleteKey();
      expect(storage.getKey()).toBeUndefined();
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('MacOSKeychainStorage implements all required interface properties', () => {
    const storage: KeyStorage = new MacOSKeychainStorage();
    expect(storage.name).toEqual(expect.any(String));
    expect(storage.backend).toEqual(expect.any(String));
    expect(typeof storage.isAvailable).toBe('function');
    expect(typeof storage.getKey).toBe('function');
    expect(typeof storage.setKey).toBe('function');
    expect(typeof storage.deleteKey).toBe('function');
  });

  it('LinuxSecretServiceStorage implements all required interface properties', () => {
    const storage: KeyStorage = new LinuxSecretServiceStorage();
    expect(storage.name).toEqual(expect.any(String));
    expect(storage.backend).toEqual(expect.any(String));
    expect(typeof storage.isAvailable).toBe('function');
    expect(typeof storage.getKey).toBe('function');
    expect(typeof storage.setKey).toBe('function');
    expect(typeof storage.deleteKey).toBe('function');
  });

  it('WindowsCredentialStorage implements all required interface properties', () => {
    const storage: KeyStorage = new WindowsCredentialStorage();
    expect(storage.name).toEqual(expect.any(String));
    expect(storage.backend).toEqual(expect.any(String));
    expect(typeof storage.isAvailable).toBe('function');
    expect(typeof storage.getKey).toBe('function');
    expect(typeof storage.setKey).toBe('function');
    expect(typeof storage.deleteKey).toBe('function');
  });
});
