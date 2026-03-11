import * as crypto from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const IV_LENGTH = 16;

/** Default salt kept for backward-compatibility with pre-v0.2 vaults. */
const DEFAULT_SALT = 'aegis-vault-v1';

/**
 * Generate a cryptographically random salt for PBKDF2 key derivation.
 * Should be called once during `aegis init` and persisted alongside the master key.
 */
export function generateSalt(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Derives a 256-bit encryption key from the master key using PBKDF2.
 *
 * @param masterKey  High-entropy master secret
 * @param salt       Per-deployment salt (use {@link generateSalt} to create one)
 */
export function deriveKey(masterKey: string, salt: Buffer | string = DEFAULT_SALT): Buffer {
  return crypto.pbkdf2Sync(masterKey, salt, 210_000, KEY_LENGTH, 'sha512');
}

export interface EncryptedData {
  encrypted: Buffer;
  iv: Buffer;
  authTag: Buffer;
}

/**
 * Encrypts a plaintext credential using AES-256-GCM.
 * Accepts a pre-derived key so callers can cache the expensive PBKDF2 result.
 */
export function encrypt(plaintext: string, key: Buffer): EncryptedData {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf-8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return { encrypted, iv, authTag };
}

/**
 * Decrypts an AES-256-GCM encrypted credential.
 * Accepts a pre-derived key so callers can cache the expensive PBKDF2 result.
 */
export function decrypt(data: EncryptedData, key: Buffer): string {
  const decipher = crypto.createDecipheriv(ALGORITHM, key, data.iv);
  decipher.setAuthTag(data.authTag);

  const decrypted = Buffer.concat([decipher.update(data.encrypted), decipher.final()]);
  return decrypted.toString('utf-8');
}
