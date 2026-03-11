/**
 * Windows Credential Manager backend.
 *
 * Uses `cmdkey` (ships with Windows) for store/delete and PowerShell
 * for retrieval (cmdkey cannot retrieve passwords, only list targets).
 *
 * The key is stored as a generic credential:
 *   target: "aegis/master-key"   user: "aegis"
 */

import { execFileSync } from 'node:child_process';
import type { KeyStorage, KeyStorageBackend } from './key-storage.js';
import { commandExists } from './key-storage.js';

const TARGET = 'aegis/master-key';
const USERNAME = 'aegis';

/**
 * PowerShell script to read a generic credential's password via Win32 CredRead.
 * Returns the password as UTF-8 text, or exits with code 1 if not found.
 */
const PS_READ_SCRIPT = `
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class CredManager {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredRead(string target, int type, int reserved, out IntPtr credential);
    [DllImport("advapi32.dll")]
    public static extern void CredFree(IntPtr credential);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL {
        public int Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public long LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }
}
"@
$ptr = [IntPtr]::Zero
$result = [CredManager]::CredRead("${TARGET}", 1, 0, [ref]$ptr)
if (-not $result) { exit 1 }
$cred = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [Type][CredManager+CREDENTIAL])
$secret = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($cred.CredentialBlob, $cred.CredentialBlobSize / 2)
[CredManager]::CredFree($ptr)
Write-Host -NoNewline $secret
`;

export class WindowsCredentialStorage implements KeyStorage {
  readonly name = 'Windows Credential Manager';
  readonly backend: KeyStorageBackend = 'windows-credential-manager';

  isAvailable(): boolean {
    return process.platform === 'win32' && commandExists('cmdkey') && commandExists('powershell');
  }

  getKey(): string | undefined {
    try {
      const result = execFileSync(
        'powershell',
        ['-NoProfile', '-NonInteractive', '-Command', PS_READ_SCRIPT],
        { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf-8' },
      );
      const key = result.trim();
      return key || undefined;
    } catch {
      return undefined;
    }
  }

  setKey(key: string): void {
    try {
      execFileSync('cmdkey', [`/generic:${TARGET}`, `/user:${USERNAME}`, `/pass:${key}`], {
        stdio: 'pipe',
      });
    } catch (err) {
      throw new Error(
        `Failed to store key in Windows Credential Manager: ${(err as Error).message}`,
      );
    }
  }

  deleteKey(): void {
    try {
      execFileSync('cmdkey', [`/delete:${TARGET}`], { stdio: 'pipe' });
    } catch {
      // Credential not found — nothing to delete
    }
  }
}
