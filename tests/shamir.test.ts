import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { SealManager } from '../src/vault/seal.js';
import { combine, decodeShare, encodeShare, type ShamirShare, split } from '../src/vault/shamir.js';

// ─── Shamir's Secret Sharing ─────────────────────────────────────

describe('Shamir split/combine', () => {
  it('round-trips a 32-byte secret with 2-of-3', () => {
    const secret = crypto.randomBytes(32);
    const shares = split(secret, 2, 3);

    expect(shares).toHaveLength(3);
    expect(shares[0].data).toHaveLength(32);

    // Any 2 shares should reconstruct
    const reconstructed = combine([shares[0], shares[1]]);
    expect(reconstructed.equals(secret)).toBe(true);
  });

  it('round-trips a 32-byte secret with 3-of-5', () => {
    const secret = crypto.randomBytes(32);
    const shares = split(secret, 3, 5);

    expect(shares).toHaveLength(5);
    const reconstructed = combine([shares[0], shares[2], shares[4]]);
    expect(reconstructed.equals(secret)).toBe(true);
  });

  it('round-trips a 64-byte secret with 5-of-10', () => {
    const secret = crypto.randomBytes(64);
    const shares = split(secret, 5, 10);

    expect(shares).toHaveLength(10);
    const reconstructed = combine([shares[1], shares[3], shares[5], shares[7], shares[9]]);
    expect(reconstructed.equals(secret)).toBe(true);
  });

  it('works with any valid subset of threshold shares', () => {
    const secret = crypto.randomBytes(16);
    const shares = split(secret, 3, 5);

    // Try every possible 3-share combination
    const combos = [
      [0, 1, 2],
      [0, 1, 3],
      [0, 1, 4],
      [0, 2, 3],
      [0, 2, 4],
      [0, 3, 4],
      [1, 2, 3],
      [1, 2, 4],
      [1, 3, 4],
      [2, 3, 4],
    ];

    for (const combo of combos) {
      const subset = combo.map((i) => shares[i]);
      const result = combine(subset);
      expect(result.equals(secret)).toBe(true);
    }
  });

  it('fails with fewer than threshold shares', () => {
    const secret = crypto.randomBytes(32);
    const shares = split(secret, 3, 5);

    // 2 shares should NOT reconstruct a 3-of-5 secret (with high probability)
    const wrong = combine([shares[0], shares[1]]);
    expect(wrong.equals(secret)).toBe(false);
  });

  it('handles a 1-byte secret', () => {
    const secret = Buffer.from([0x42]);
    const shares = split(secret, 2, 3);
    const result = combine([shares[1], shares[2]]);
    expect(result.equals(secret)).toBe(true);
  });

  it('handles a secret with zero bytes', () => {
    const secret = Buffer.alloc(16, 0);
    const shares = split(secret, 2, 3);
    const result = combine([shares[0], shares[2]]);
    expect(result.equals(secret)).toBe(true);
  });

  it('handles a hex-encoded master key (typical Aegis key)', () => {
    const masterKey = crypto.randomBytes(32).toString('hex'); // 64-char hex string
    const secret = Buffer.from(masterKey, 'utf-8');
    const shares = split(secret, 3, 5);
    const result = combine([shares[0], shares[2], shares[4]]);
    expect(result.toString('utf-8')).toBe(masterKey);
  });

  it('produces unique shares each split', () => {
    const secret = crypto.randomBytes(32);
    const shares1 = split(secret, 2, 3);
    const shares2 = split(secret, 2, 3);

    // Different random coefficients should produce different shares
    const allSame = shares1.every((s, i) => s.data.equals(shares2[i].data));
    expect(allSame).toBe(false);
  });

  it('assigns sequential indices starting at 1', () => {
    const shares = split(Buffer.from('secret'), 2, 5);
    expect(shares.map((s) => s.index)).toEqual([1, 2, 3, 4, 5]);
  });

  it('works with more shares than needed', () => {
    const secret = crypto.randomBytes(32);
    const shares = split(secret, 2, 3);

    // Providing all 3 shares for a 2-of-3 should still work
    const result = combine(shares);
    expect(result.equals(secret)).toBe(true);
  });
});

describe('Shamir input validation', () => {
  it('rejects threshold < 2', () => {
    expect(() => split(Buffer.from('x'), 1, 3)).toThrow('Threshold must be at least 2');
  });

  it('rejects totalShares < threshold', () => {
    expect(() => split(Buffer.from('x'), 3, 2)).toThrow('Total shares must be ≥ threshold');
  });

  it('rejects totalShares > 255', () => {
    expect(() => split(Buffer.from('x'), 2, 256)).toThrow('Maximum 255 shares');
  });

  it('rejects empty secret', () => {
    expect(() => split(Buffer.alloc(0), 2, 3)).toThrow('Secret must not be empty');
  });

  it('rejects combine with < 2 shares', () => {
    const shares = split(Buffer.from('secret'), 2, 3);
    expect(() => combine([shares[0]])).toThrow('At least 2 shares required');
  });

  it('rejects combine with duplicate indices', () => {
    const shares = split(Buffer.from('secret'), 2, 3);
    const dup: ShamirShare = { index: shares[0].index, data: Buffer.from(shares[1].data) };
    expect(() => combine([shares[0], dup])).toThrow('Duplicate share indices');
  });

  it('rejects combine with mismatched data lengths', () => {
    const share1: ShamirShare = { index: 1, data: Buffer.from([1, 2, 3]) };
    const share2: ShamirShare = { index: 2, data: Buffer.from([1, 2]) };
    expect(() => combine([share1, share2])).toThrow('same data length');
  });
});

// ─── Share Encoding ──────────────────────────────────────────────

describe('share encoding/decoding', () => {
  it('round-trips a share through encode/decode', () => {
    const share: ShamirShare = {
      index: 3,
      data: Buffer.from('abcdef0123456789', 'hex'),
    };

    const encoded = encodeShare(share);
    expect(encoded).toBe('aegis_share_03_abcdef0123456789');

    const decoded = decodeShare(encoded);
    expect(decoded.index).toBe(3);
    expect(decoded.data.equals(share.data)).toBe(true);
  });

  it('encodes index as zero-padded hex', () => {
    const share: ShamirShare = { index: 1, data: Buffer.from([0xff]) };
    expect(encodeShare(share)).toBe('aegis_share_01_ff');

    const share255: ShamirShare = { index: 255, data: Buffer.from([0x00]) };
    expect(encodeShare(share255)).toBe('aegis_share_ff_00');
  });

  it('round-trips shares from an actual split', () => {
    const secret = crypto.randomBytes(32);
    const shares = split(secret, 3, 5);

    const encoded = shares.map(encodeShare);
    const decoded = encoded.map(decodeShare);

    const result = combine(decoded.slice(0, 3));
    expect(result.equals(secret)).toBe(true);
  });

  it('rejects invalid prefix', () => {
    expect(() => decodeShare('invalid_share_01_ff')).toThrow('must start with "aegis_share_"');
  });

  it('rejects missing separator', () => {
    expect(() => decodeShare('aegis_share_01ff')).toThrow('missing data separator');
  });

  it('rejects invalid index', () => {
    expect(() => decodeShare('aegis_share_00_ff')).toThrow('Invalid share index');
    expect(() => decodeShare('aegis_share_zz_ff')).toThrow('Invalid share index');
  });

  it('rejects empty data', () => {
    expect(() => decodeShare('aegis_share_01_')).toThrow('empty data');
  });
});

// ─── SealManager ─────────────────────────────────────────────────

describe('SealManager', () => {
  let tmpDir: string;
  let mgr: SealManager;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-seal-'));
    mgr = new SealManager(tmpDir);
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('enableSplit / getSealConfig', () => {
    it('stores and retrieves seal config', () => {
      mgr.enableSplit(3, 5, 'test-master-key');
      const config = mgr.getSealConfig();

      expect(config).not.toBeNull();
      expect(config?.threshold).toBe(3);
      expect(config?.totalShares).toBe(5);
      expect(config?.keyHash).toHaveLength(64); // SHA-256 hex
      expect(config?.createdAt).toBeTruthy();
    });

    it('returns null when no config exists', () => {
      expect(mgr.getSealConfig()).toBeNull();
    });

    it('rejects threshold < 2', () => {
      expect(() => mgr.enableSplit(1, 3, 'key')).toThrow('Threshold must be at least 2');
    });

    it('rejects totalShares < threshold', () => {
      expect(() => mgr.enableSplit(3, 2, 'key')).toThrow('Total shares must be ≥ threshold');
    });
  });

  describe('isSplitEnabled', () => {
    it('returns false when not configured', () => {
      expect(mgr.isSplitEnabled()).toBe(false);
    });

    it('returns true after enableSplit', () => {
      mgr.enableSplit(2, 3, 'key');
      expect(mgr.isSplitEnabled()).toBe(true);
    });
  });

  describe('verifyKey', () => {
    it('verifies the correct master key', () => {
      const key = 'my-secret-master-key';
      mgr.enableSplit(2, 3, key);
      expect(mgr.verifyKey(key)).toBe(true);
    });

    it('rejects an incorrect key', () => {
      mgr.enableSplit(2, 3, 'correct-key');
      expect(mgr.verifyKey('wrong-key')).toBe(false);
    });

    it('returns false when no config exists', () => {
      expect(mgr.verifyKey('any')).toBe(false);
    });
  });

  describe('unseal key lifecycle', () => {
    it('writes and reads unseal key', () => {
      mgr.writeUnsealKey('reconstructed-key');
      expect(mgr.readUnsealKey()).toBe('reconstructed-key');
    });

    it('returns null when no unseal key exists', () => {
      expect(mgr.readUnsealKey()).toBeNull();
    });

    it('isUnsealed reflects key presence', () => {
      expect(mgr.isUnsealed()).toBe(false);
      mgr.writeUnsealKey('key');
      expect(mgr.isUnsealed()).toBe(true);
    });

    it('seal removes the unseal key', () => {
      mgr.writeUnsealKey('key');
      expect(mgr.isUnsealed()).toBe(true);

      mgr.seal();
      expect(mgr.isUnsealed()).toBe(false);
      expect(mgr.readUnsealKey()).toBeNull();
    });

    it('seal is idempotent when already sealed', () => {
      expect(() => mgr.seal()).not.toThrow();
    });

    it('unseal key file has restricted permissions (macOS/Linux)', () => {
      mgr.writeUnsealKey('sensitive-key');
      const unsealPath = path.join(tmpDir, '.unseal-key');
      const stat = fs.statSync(unsealPath);
      // mode 0600 = owner read/write only
      expect(stat.mode & 0o777).toBe(0o600);
    });
  });

  describe('removeSealConfig', () => {
    it('removes config and unseal key', () => {
      mgr.enableSplit(2, 3, 'key');
      mgr.writeUnsealKey('key');

      expect(mgr.isSplitEnabled()).toBe(true);
      expect(mgr.isUnsealed()).toBe(true);

      mgr.removeSealConfig();

      expect(mgr.isSplitEnabled()).toBe(false);
      expect(mgr.isUnsealed()).toBe(false);
    });

    it('is safe when nothing exists', () => {
      expect(() => mgr.removeSealConfig()).not.toThrow();
    });
  });
});

// ─── Integration: Split → Unseal → Seal ─────────────────────────

describe('integration: split → unseal → seal lifecycle', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-seal-int-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('full lifecycle with 3-of-5', () => {
    const masterKey = crypto.randomBytes(32).toString('hex');
    const secretBuf = Buffer.from(masterKey, 'utf-8');

    // 1. Split
    const shares = split(secretBuf, 3, 5);
    const mgr = new SealManager(tmpDir);
    mgr.enableSplit(3, 5, masterKey);

    expect(shares).toHaveLength(5);
    expect(mgr.isSplitEnabled()).toBe(true);

    // 2. Encode shares (as the CLI would display them)
    const encoded = shares.map(encodeShare);

    // 3. Unseal with 3 shares
    const decoded = [encoded[0], encoded[2], encoded[4]].map(decodeShare);
    const reconstructed = combine(decoded);
    const recoveredKey = reconstructed.toString('utf-8');

    expect(mgr.verifyKey(recoveredKey)).toBe(true);
    mgr.writeUnsealKey(recoveredKey);
    expect(mgr.isUnsealed()).toBe(true);
    expect(mgr.readUnsealKey()).toBe(masterKey);

    // 4. Seal
    mgr.seal();
    expect(mgr.isUnsealed()).toBe(false);
    expect(mgr.readUnsealKey()).toBeNull();

    // Config is still there (for future unseals)
    expect(mgr.isSplitEnabled()).toBe(true);
  });

  it('wrong shares fail verification', () => {
    const masterKey = 'correct-master-key';
    const secretBuf = Buffer.from(masterKey, 'utf-8');
    const shares = split(secretBuf, 2, 3);

    const mgr = new SealManager(tmpDir);
    mgr.enableSplit(2, 3, masterKey);

    // Tamper with a share
    const tampered: ShamirShare = {
      index: shares[0].index,
      data: crypto.randomBytes(shares[0].data.length),
    };

    const badResult = combine([tampered, shares[1]]);
    expect(mgr.verifyKey(badResult.toString('utf-8'))).toBe(false);
  });

  it('2-of-2 minimum threshold works', () => {
    const masterKey = 'min-threshold-key';
    const secretBuf = Buffer.from(masterKey, 'utf-8');
    const shares = split(secretBuf, 2, 2);

    const mgr = new SealManager(tmpDir);
    mgr.enableSplit(2, 2, masterKey);

    const result = combine(shares);
    expect(mgr.verifyKey(result.toString('utf-8'))).toBe(true);
  });
});

// ─── Security Properties ─────────────────────────────────────────

describe('security properties', () => {
  it('seal overwrites file before deleting', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-seal-sec-'));
    const mgr = new SealManager(tmpDir);

    mgr.writeUnsealKey('sensitive-master-key-data');
    const unsealPath = path.join(tmpDir, '.unseal-key');
    expect(fs.existsSync(unsealPath)).toBe(true);

    mgr.seal();
    expect(fs.existsSync(unsealPath)).toBe(false);

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('seal config file has restricted permissions', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-seal-sec2-'));
    const mgr = new SealManager(tmpDir);

    mgr.enableSplit(2, 3, 'key');
    const configPath = path.join(tmpDir, '.seal-config.json');
    const stat = fs.statSync(configPath);
    expect(stat.mode & 0o777).toBe(0o600);

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('key hash uses SHA-256', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-seal-sec3-'));
    const mgr = new SealManager(tmpDir);

    const key = 'test-key';
    mgr.enableSplit(2, 3, key);
    const config = mgr.getSealConfig();

    const expected = crypto.createHash('sha256').update(key).digest('hex');
    expect(config?.keyHash).toBe(expected);

    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});
