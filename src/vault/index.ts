export { decrypt, deriveKey, encrypt, generateSalt } from './crypto.js';
export type { SealConfig } from './seal.js';
export { SealManager } from './seal.js';
export type { ShamirShare } from './shamir.js';
export { combine, decodeShare, encodeShare, split } from './shamir.js';
export type {
  AuthType,
  Credential,
  CredentialWithSecret,
} from './vault.js';
export { Vault } from './vault.js';
export type { VaultInfo } from './vault-manager.js';
export { VaultManager } from './vault-manager.js';
