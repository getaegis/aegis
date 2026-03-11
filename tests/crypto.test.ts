import { describe, expect, it } from 'vitest';
import { deriveDbKey } from '../src/db.js';
import { decrypt, deriveKey, encrypt, generateSalt } from '../src/vault/crypto.js';

describe('crypto', () => {
  const masterKey = 'test-master-key-for-unit-tests-only';
  const testSalt = 'test-salt-value';

  it('deriveKey returns a 32-byte buffer', () => {
    const key = deriveKey(masterKey, testSalt);
    expect(key).toBeInstanceOf(Buffer);
    expect(key.length).toBe(32);
  });

  it('deriveKey is deterministic', () => {
    const k1 = deriveKey(masterKey, testSalt);
    const k2 = deriveKey(masterKey, testSalt);
    expect(k1.equals(k2)).toBe(true);
  });

  it('different salts produce different keys', () => {
    const k1 = deriveKey(masterKey, 'salt-a');
    const k2 = deriveKey(masterKey, 'salt-b');
    expect(k1.equals(k2)).toBe(false);
  });

  it('generateSalt returns a 64-char hex string', () => {
    const salt = generateSalt();
    expect(salt).toMatch(/^[0-9a-f]{64}$/);
  });

  it('encrypt then decrypt round-trips', () => {
    const key = deriveKey(masterKey, testSalt);
    const plaintext = 'sk-live-super-secret-api-key-12345';
    const encrypted = encrypt(plaintext, key);
    expect(encrypted.encrypted).toBeTruthy();
    expect(encrypted.iv).toBeTruthy();
    expect(encrypted.authTag).toBeTruthy();
    // ciphertext should not contain the plaintext
    expect(encrypted.encrypted.toString('utf8')).not.toContain(plaintext);

    const decrypted = decrypt(encrypted, key);
    expect(decrypted).toBe(plaintext);
  });

  it('decrypt fails with wrong key', () => {
    const key = deriveKey(masterKey, testSalt);
    const wrongKey = deriveKey('wrong-key-entirely-different', testSalt);
    const plaintext = 'secret-value';
    const encrypted = encrypt(plaintext, key);
    expect(() => decrypt(encrypted, wrongKey)).toThrow();
  });

  it('decrypt fails with tampered ciphertext', () => {
    const key = deriveKey(masterKey, testSalt);
    const encrypted = encrypt('secret', key);
    // Flip the last byte of the ciphertext
    const flipped = Buffer.from(encrypted.encrypted);
    flipped[flipped.length - 1] ^= 0xff;
    const tampered = { ...encrypted, encrypted: flipped };
    expect(() => decrypt(tampered, key)).toThrow();
  });

  it('each encryption produces unique iv and ciphertext', () => {
    const key = deriveKey(masterKey, testSalt);
    const plaintext = 'same-input';
    const a = encrypt(plaintext, key);
    const b = encrypt(plaintext, key);
    expect(a.iv.equals(b.iv)).toBe(false);
    expect(a.encrypted.equals(b.encrypted)).toBe(false);
  });
});

describe('deriveDbKey', () => {
  const masterKey = 'test-master-key-for-db-encryption';
  const salt = 'test-salt-value';

  it('returns a 32-byte buffer', () => {
    const key = deriveDbKey(masterKey, salt);
    expect(key).toBeInstanceOf(Buffer);
    expect(key.length).toBe(32);
  });

  it('is deterministic', () => {
    const k1 = deriveDbKey(masterKey, salt);
    const k2 = deriveDbKey(masterKey, salt);
    expect(k1.equals(k2)).toBe(true);
  });

  it('produces a different key from deriveKey with the same inputs', () => {
    const credKey = deriveKey(masterKey, salt);
    const dbKey = deriveDbKey(masterKey, salt);
    expect(credKey.equals(dbKey)).toBe(false);
  });

  it('different salts produce different DB keys', () => {
    const k1 = deriveDbKey(masterKey, 'salt-a');
    const k2 = deriveDbKey(masterKey, 'salt-b');
    expect(k1.equals(k2)).toBe(false);
  });

  it('different master keys produce different DB keys', () => {
    const k1 = deriveDbKey('key-a', salt);
    const k2 = deriveDbKey('key-b', salt);
    expect(k1.equals(k2)).toBe(false);
  });
});
