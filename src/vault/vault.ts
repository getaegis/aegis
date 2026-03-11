import * as crypto from 'node:crypto';
import type Database from 'better-sqlite3-multiple-ciphers';
import type { BodyInspectionMode } from '../gate/body-inspector.js';
import { decrypt, deriveKey, encrypt } from './crypto.js';

// How the credential is injected into the outbound request
export type AuthType = 'bearer' | 'header' | 'query' | 'basic';

export interface Credential {
  id: string;
  name: string;
  service: string;
  authType: AuthType;
  headerName?: string; // Custom header name (for authType: "header")
  domains: string[]; // Allowed domains this credential can be sent to
  scopes: string[]; // Allowed actions: "read", "write", "*"
  expiresAt?: string; // ISO date string — credential expires after this time
  rateLimit?: string; // e.g. "100/min", "1000/hour"
  bodyInspection: BodyInspectionMode; // "off" | "warn" | "block"
  createdAt: string;
  updatedAt: string;
}

export interface CredentialWithSecret extends Credential {
  secret: string;
}

interface CredentialRow {
  id: string;
  name: string;
  service: string;
  encrypted: Buffer;
  iv: Buffer;
  auth_tag: Buffer;
  auth_type: string;
  header_name: string | null;
  domains: string;
  scopes: string;
  expires_at: string | null;
  rate_limit: string | null;
  body_inspection: string;
  created_at: string;
  updated_at: string;
}

export class Vault {
  /** Cached derived key — PBKDF2 runs once in the constructor. */
  private derivedKey: Buffer;

  constructor(
    private db: Database.Database,
    masterKey: string,
    salt: Buffer | string = 'aegis-vault-v1',
  ) {
    if (!masterKey) {
      throw new Error(
        'AEGIS_MASTER_KEY is not set. Run `aegis init` to generate a config and master key.',
      );
    }
    this.derivedKey = deriveKey(masterKey, salt);
    this.verifyKey();
  }

  /**
   * Verify the master key by attempting to decrypt the first stored credential.
   * Throws a clear error if the key is wrong (AES-256-GCM auth tag mismatch).
   * Silently succeeds if the vault is empty (nothing to verify against).
   */
  private verifyKey(): void {
    const row = this.db.prepare('SELECT encrypted, iv, auth_tag FROM credentials LIMIT 1').get() as
      | Pick<CredentialRow, 'encrypted' | 'iv' | 'auth_tag'>
      | undefined;

    if (!row) return; // Empty vault — nothing to verify

    try {
      decrypt({ encrypted: row.encrypted, iv: row.iv, authTag: row.auth_tag }, this.derivedKey);
    } catch {
      throw new Error(
        'Invalid master key — cannot decrypt vault credentials.\n' +
          '  The AEGIS_MASTER_KEY does not match the key used to encrypt this vault.\n' +
          '  Check your config file or environment variable.',
      );
    }
  }

  /**
   * Store a new credential in the vault.
   */
  /** Maximum credential secret size: 512 KB. */
  static readonly MAX_SECRET_BYTES = 512 * 1024;

  /** Maximum credential name length: 128 characters. */
  static readonly MAX_NAME_LENGTH = 128;

  add(params: {
    name: string;
    service: string;
    secret: string;
    authType?: AuthType;
    headerName?: string;
    domains: string[];
    scopes?: string[];
    ttlDays?: number;
    rateLimit?: string;
    bodyInspection?: BodyInspectionMode;
  }): Credential {
    // Validate name length
    if (params.name.length > Vault.MAX_NAME_LENGTH) {
      throw new Error(
        `Credential name is too long (${params.name.length} chars). Maximum is ${Vault.MAX_NAME_LENGTH} characters.`,
      );
    }

    // Validate secret size
    const secretBytes = Buffer.byteLength(params.secret, 'utf-8');
    if (secretBytes > Vault.MAX_SECRET_BYTES) {
      const sizeKB = Math.round(secretBytes / 1024);
      throw new Error(
        `Credential value is too large (${sizeKB} KB). Maximum is ${Vault.MAX_SECRET_BYTES / 1024} KB.`,
      );
    }

    const id = crypto.randomUUID();
    const { encrypted, iv, authTag } = encrypt(params.secret, this.derivedKey);

    let expiresAt: string | null = null;
    if (params.ttlDays !== undefined && params.ttlDays > 0) {
      const expiry = new Date();
      expiry.setDate(expiry.getDate() + params.ttlDays);
      expiresAt = expiry.toISOString();
    }

    const stmt = this.db.prepare(`
      INSERT INTO credentials (id, name, service, encrypted, iv, auth_tag, auth_type, header_name, domains, scopes, expires_at, rate_limit, body_inspection)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      id,
      params.name,
      params.service,
      encrypted,
      iv,
      authTag,
      params.authType ?? 'bearer',
      params.headerName ?? null,
      JSON.stringify(params.domains),
      JSON.stringify(params.scopes ?? ['*']),
      expiresAt,
      params.rateLimit ?? null,
      params.bodyInspection ?? 'block',
    );

    return {
      id,
      name: params.name,
      service: params.service,
      authType: params.authType ?? 'bearer',
      headerName: params.headerName,
      domains: params.domains,
      scopes: params.scopes ?? ['*'],
      expiresAt: expiresAt ?? undefined,
      rateLimit: params.rateLimit,
      bodyInspection: params.bodyInspection ?? 'block',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
  }

  /**
   * Rotate a credential's secret. The old secret is saved to credential_history
   * with an optional grace period during which it remains valid.
   */
  rotate(params: { name: string; newSecret: string; gracePeriodHours?: number }): Credential {
    // Validate secret size
    const secretBytes = Buffer.byteLength(params.newSecret, 'utf-8');
    if (secretBytes > Vault.MAX_SECRET_BYTES) {
      const sizeKB = Math.round(secretBytes / 1024);
      throw new Error(
        `Credential value is too large (${sizeKB} KB). Maximum is ${Vault.MAX_SECRET_BYTES / 1024} KB.`,
      );
    }

    const row = this.db.prepare('SELECT * FROM credentials WHERE name = ?').get(params.name) as
      | CredentialRow
      | undefined;

    if (!row) {
      throw new Error(`No credential found with name "${params.name}"`);
    }

    // Save old encrypted secret to history
    let graceExpires: string | null = null;
    if (params.gracePeriodHours !== undefined && params.gracePeriodHours > 0) {
      const grace = new Date();
      grace.setTime(grace.getTime() + params.gracePeriodHours * 60 * 60 * 1000);
      graceExpires = grace.toISOString();
    }

    this.db
      .prepare(
        `INSERT INTO credential_history (credential_id, encrypted, iv, auth_tag, grace_expires)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(row.id, row.encrypted, row.iv, row.auth_tag, graceExpires);

    // Encrypt and store new secret
    const { encrypted, iv, authTag } = encrypt(params.newSecret, this.derivedKey);

    this.db
      .prepare(
        `UPDATE credentials SET encrypted = ?, iv = ?, auth_tag = ?, updated_at = datetime('now')
         WHERE id = ?`,
      )
      .run(encrypted, iv, authTag, row.id);

    return this.rowToCredential({
      ...row,
      encrypted,
      iv,
      auth_tag: authTag,
      updated_at: new Date().toISOString(),
    });
  }

  /**
   * Update a credential's metadata (domains, scopes, auth type, header name)
   * without re-entering the secret.
   */
  update(params: {
    name: string;
    domains?: string[];
    scopes?: string[];
    authType?: AuthType;
    headerName?: string;
    rateLimit?: string | null;
    bodyInspection?: BodyInspectionMode;
  }): Credential {
    const row = this.db.prepare('SELECT * FROM credentials WHERE name = ?').get(params.name) as
      | CredentialRow
      | undefined;

    if (!row) {
      throw new Error(`No credential found with name "${params.name}"`);
    }

    const newDomains = params.domains ?? JSON.parse(row.domains);
    const newScopes = params.scopes ?? JSON.parse(row.scopes);
    const newAuthType = params.authType ?? row.auth_type;
    const newHeaderName = params.headerName !== undefined ? params.headerName : row.header_name;
    const newRateLimit = params.rateLimit !== undefined ? params.rateLimit : row.rate_limit;
    const newBodyInspection = params.bodyInspection ?? row.body_inspection;

    this.db
      .prepare(
        `UPDATE credentials SET domains = ?, scopes = ?, auth_type = ?, header_name = ?, rate_limit = ?, body_inspection = ?, updated_at = datetime('now')
         WHERE id = ?`,
      )
      .run(
        JSON.stringify(newDomains),
        JSON.stringify(newScopes),
        newAuthType,
        newHeaderName,
        newRateLimit,
        newBodyInspection,
        row.id,
      );

    return {
      ...this.rowToCredential(row),
      domains: newDomains,
      scopes: newScopes,
      authType: newAuthType as AuthType,
      headerName: newHeaderName ?? undefined,
      rateLimit: newRateLimit ?? undefined,
      bodyInspection: newBodyInspection as BodyInspectionMode,
      updatedAt: new Date().toISOString(),
    };
  }

  /**
   * Check if a credential has expired based on its expiresAt field.
   */
  isExpired(credential: Credential): boolean {
    if (!credential.expiresAt) return false;
    return new Date(credential.expiresAt) <= new Date();
  }

  /**
   * List all credentials (without secrets).
   */
  list(): Credential[] {
    const rows = this.db
      .prepare('SELECT * FROM credentials ORDER BY created_at DESC')
      .all() as CredentialRow[];

    return rows.map((row) => this.rowToCredential(row));
  }

  /**
   * Get a credential by name, including the decrypted secret.
   */
  getByName(name: string): CredentialWithSecret | null {
    const row = this.db.prepare('SELECT * FROM credentials WHERE name = ?').get(name) as
      | CredentialRow
      | undefined;

    if (!row) return null;

    const secret = decrypt(
      {
        encrypted: row.encrypted,
        iv: row.iv,
        authTag: row.auth_tag,
      },
      this.derivedKey,
    );

    return { ...this.rowToCredential(row), secret };
  }

  /**
   * Get a credential by service name, including the decrypted secret.
   */
  getByService(service: string): CredentialWithSecret | null {
    const row = this.db
      .prepare('SELECT * FROM credentials WHERE service = ? LIMIT 1')
      .get(service) as CredentialRow | undefined;

    if (!row) return null;

    const secret = decrypt(
      {
        encrypted: row.encrypted,
        iv: row.iv,
        authTag: row.auth_tag,
      },
      this.derivedKey,
    );

    return { ...this.rowToCredential(row), secret };
  }

  /**
   * Find a credential whose allowed domains match a given hostname.
   */
  findByDomain(hostname: string): CredentialWithSecret | null {
    const all = this.db.prepare('SELECT * FROM credentials').all() as CredentialRow[];

    for (const row of all) {
      const domains: string[] = JSON.parse(row.domains);
      if (this.domainMatches(hostname, domains)) {
        const secret = decrypt(
          {
            encrypted: row.encrypted,
            iv: row.iv,
            authTag: row.auth_tag,
          },
          this.derivedKey,
        );
        return { ...this.rowToCredential(row), secret };
      }
    }

    return null;
  }

  /**
   * Remove a credential by name.
   */
  remove(name: string): boolean {
    const result = this.db.prepare('DELETE FROM credentials WHERE name = ?').run(name);
    return result.changes > 0;
  }

  /**
   * Check if a hostname matches any of the allowed domain patterns.
   * Supports wildcards: *.slack.com matches api.slack.com
   */
  domainMatches(hostname: string, allowedDomains: string[]): boolean {
    for (const pattern of allowedDomains) {
      if (pattern === hostname) return true;

      // Wildcard: *.example.com matches sub.example.com (single level only)
      if (pattern.startsWith('*.')) {
        const suffix = pattern.slice(1); // .example.com
        if (hostname.endsWith(suffix)) {
          const prefix = hostname.slice(0, -suffix.length);
          // Only match single-level: "api" is OK, "deep.api" is not
          if (prefix.length > 0 && !prefix.includes('.')) return true;
        }
      }
    }
    return false;
  }

  private rowToCredential(row: CredentialRow): Credential {
    return {
      id: row.id,
      name: row.name,
      service: row.service,
      authType: row.auth_type as AuthType,
      headerName: row.header_name ?? undefined,
      domains: JSON.parse(row.domains),
      scopes: JSON.parse(row.scopes),
      expiresAt: row.expires_at ?? undefined,
      rateLimit: row.rate_limit ?? undefined,
      bodyInspection: (row.body_inspection ?? 'block') as BodyInspectionMode,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
