import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * Persistent seal configuration (stored in .aegis/.seal-config.json).
 * Tracks threshold, total share count, and a key hash for verification.
 * Never stores the master key or shares.
 */
export interface SealConfig {
  /** Minimum shares required to reconstruct the master key. */
  threshold: number;
  /** Total shares that were generated. */
  totalShares: number;
  /** SHA-256 hash of the master key (hex) — used to verify reconstruction. */
  keyHash: string;
  /** ISO timestamp of when key splitting was configured. */
  createdAt: string;
}

/**
 * Manages vault seal state — key splitting configuration, unseal key
 * storage, and sealed/unsealed transitions.
 *
 * Modelled after HashiCorp Vault's seal/unseal mechanism, adapted for
 * CLI (non-daemon) usage: the reconstructed key is persisted to a
 * restricted file instead of held in memory.
 *
 * Files managed:
 *   .aegis/.seal-config.json  — threshold, share count, key hash
 *   .aegis/.unseal-key        — reconstructed master key (mode 0600)
 */
export class SealManager {
  private configPath: string;
  private unsealKeyPath: string;

  constructor(private dataDir: string) {
    this.configPath = path.join(dataDir, '.seal-config.json');
    this.unsealKeyPath = path.join(dataDir, '.unseal-key');
  }

  /**
   * Enable key splitting — stores threshold, share count, and a SHA-256
   * hash of the master key for post-reconstruction verification.
   */
  enableSplit(threshold: number, totalShares: number, masterKey: string): void {
    if (threshold < 2) throw new Error('Threshold must be at least 2.');
    if (totalShares < threshold) throw new Error('Total shares must be ≥ threshold.');

    const config: SealConfig = {
      threshold,
      totalShares,
      keyHash: crypto.createHash('sha256').update(masterKey).digest('hex'),
      createdAt: new Date().toISOString(),
    };

    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }
    fs.writeFileSync(this.configPath, JSON.stringify(config, null, 2), { mode: 0o600 });
  }

  /** Read seal configuration, or null if key splitting is not configured. */
  getSealConfig(): SealConfig | null {
    if (!fs.existsSync(this.configPath)) return null;
    const content = fs.readFileSync(this.configPath, 'utf-8');
    return JSON.parse(content) as SealConfig;
  }

  /** Whether key splitting has been configured for this deployment. */
  isSplitEnabled(): boolean {
    return this.getSealConfig() !== null;
  }

  /**
   * Verify a reconstructed master key against the stored hash.
   * Uses timing-safe comparison to prevent side-channel leaks.
   */
  verifyKey(masterKey: string): boolean {
    const config = this.getSealConfig();
    if (!config) return false;
    const hash = crypto.createHash('sha256').update(masterKey).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(config.keyHash, 'hex'));
  }

  /**
   * Write the reconstructed master key to the unseal key file.
   * File is created with mode 0600 (owner read/write only).
   */
  writeUnsealKey(masterKey: string): void {
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }
    fs.writeFileSync(this.unsealKeyPath, masterKey, { mode: 0o600 });
  }

  /** Read the unseal key, or null if the vault is sealed. */
  readUnsealKey(): string | null {
    if (!fs.existsSync(this.unsealKeyPath)) return null;
    return fs.readFileSync(this.unsealKeyPath, 'utf-8').trim();
  }

  /** Whether the vault is currently unsealed (unseal key file exists). */
  isUnsealed(): boolean {
    return fs.existsSync(this.unsealKeyPath);
  }

  /**
   * Seal the vault — securely remove the unseal key file.
   * Overwrites the file with zeros before unlinking (defense in depth
   * against filesystem journal recovery).
   */
  seal(): void {
    if (fs.existsSync(this.unsealKeyPath)) {
      const stat = fs.statSync(this.unsealKeyPath);
      fs.writeFileSync(this.unsealKeyPath, Buffer.alloc(stat.size, 0));
      fs.unlinkSync(this.unsealKeyPath);
    }
  }

  /**
   * Remove seal configuration entirely — reverts to standard master key mode.
   * Also removes any existing unseal key.
   */
  removeSealConfig(): void {
    if (fs.existsSync(this.configPath)) {
      fs.unlinkSync(this.configPath);
    }
    this.seal();
  }
}
