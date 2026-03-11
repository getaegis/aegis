import * as crypto from 'node:crypto';
import type Database from 'better-sqlite3-multiple-ciphers';

// ─── Types ───────────────────────────────────────────────────────

export interface Agent {
  id: string;
  name: string;
  tokenPrefix: string;
  rateLimit?: string;
  createdAt: string;
  updatedAt: string;
}

export interface AgentWithToken extends Agent {
  token: string;
}

interface AgentRow {
  id: string;
  name: string;
  token_hash: string;
  token_prefix: string;
  rate_limit: string | null;
  created_at: string;
  updated_at: string;
}

// ─── Agent Registry ──────────────────────────────────────────────

/**
 * Agent Registry — manages agent identities and their credential access grants.
 *
 * Agents are identified by tokens (UUID v4 + HMAC suffix). Tokens are:
 * - Hashed (SHA-256) for fast lookup during request validation — hash-only, no recovery
 * - Prefixed (first 12 chars) for safe display in logs and audit entries
 *
 * Security: Tokens are never stored in recoverable form. If a token is lost,
 * use regenerateToken() to issue a new one (same pattern as GitHub/Stripe key rotation).
 */
export class AgentRegistry {
  private derivedKey: Buffer;

  constructor(
    private db: Database.Database,
    derivedKey: Buffer,
  ) {
    this.derivedKey = derivedKey;
  }

  /**
   * Register a new agent. Returns the agent with its token (shown once).
   *
   * Token format: aegis_{uuid}_{hmac_prefix}
   * The HMAC is derived from the UUID using the master key, making tokens
   * verifiable as Aegis-generated.
   */
  add(params: { name: string; rateLimit?: string }): AgentWithToken {
    const id = crypto.randomUUID();
    const uuid = crypto.randomUUID();

    // Create HMAC of the UUID using the derived key for token integrity
    const hmac = crypto
      .createHmac('sha256', this.derivedKey)
      .update(uuid)
      .digest('hex')
      .slice(0, 16);
    const token = `aegis_${uuid}_${hmac}`;

    // Hash the full token for fast lookup (hash-only — no recovery, only regeneration)
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const tokenPrefix = token.slice(0, 12);

    this.db
      .prepare(
        `INSERT INTO agents (id, name, token_hash, token_prefix, rate_limit)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(id, params.name, tokenHash, tokenPrefix, params.rateLimit ?? null);

    return {
      id,
      name: params.name,
      tokenPrefix,
      token,
      rateLimit: params.rateLimit,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
  }

  /**
   * List all registered agents (without tokens).
   */
  list(): Agent[] {
    const rows = this.db
      .prepare('SELECT * FROM agents ORDER BY created_at DESC')
      .all() as AgentRow[];

    return rows.map((row) => this.rowToAgent(row));
  }

  /**
   * Get an agent by name (without token).
   */
  getByName(name: string): Agent | null {
    const row = this.db.prepare('SELECT * FROM agents WHERE name = ?').get(name) as
      | AgentRow
      | undefined;
    return row ? this.rowToAgent(row) : null;
  }

  /**
   * Validate an agent token. Returns the agent if the token is valid, null otherwise.
   *
   * Uses SHA-256 hash comparison for constant-time-safe lookup.
   */
  validateToken(token: string): Agent | null {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const row = this.db.prepare('SELECT * FROM agents WHERE token_hash = ?').get(tokenHash) as
      | AgentRow
      | undefined;

    return row ? this.rowToAgent(row) : null;
  }

  /**
   * Remove an agent by name. Also removes all credential grants.
   */
  remove(name: string): boolean {
    const agent = this.getByName(name);
    if (!agent) return false;

    // Foreign key CASCADE handles agent_credentials cleanup
    const result = this.db.prepare('DELETE FROM agents WHERE name = ?').run(name);
    return result.changes > 0;
  }

  /**
   * Regenerate an agent's token. Issues a new token, invalidates the old one.
   *
   * The agent keeps its identity (id, name), credential grants, and rate limits.
   * Only the token changes. This follows the same pattern as GitHub personal
   * access token rotation or Stripe API key rolling.
   *
   * Returns the agent with the new token (shown once), or null if not found.
   */
  regenerateToken(name: string): AgentWithToken | null {
    const agent = this.getByName(name);
    if (!agent) return null;

    // Generate a new token with the same UUID+HMAC format
    const uuid = crypto.randomUUID();
    const hmac = crypto
      .createHmac('sha256', this.derivedKey)
      .update(uuid)
      .digest('hex')
      .slice(0, 16);
    const token = `aegis_${uuid}_${hmac}`;

    // Compute new hash and prefix
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const tokenPrefix = token.slice(0, 12);

    // Update only the token fields — identity, grants, and rate limits are preserved
    this.db
      .prepare(
        `UPDATE agents SET token_hash = ?, token_prefix = ?, updated_at = datetime('now') WHERE id = ?`,
      )
      .run(tokenHash, tokenPrefix, agent.id);

    return {
      ...agent,
      tokenPrefix,
      token,
      updatedAt: new Date().toISOString(),
    };
  }

  // ─── Credential Grants ──────────────────────────────────────────

  /**
   * Grant an agent access to a credential.
   */
  grant(params: { agentName: string; credentialId: string }): void {
    const agent = this.getByName(params.agentName);
    if (!agent) {
      throw new Error(`No agent found with name "${params.agentName}"`);
    }

    // Check if already granted
    const existing = this.db
      .prepare('SELECT 1 FROM agent_credentials WHERE agent_id = ? AND credential_id = ?')
      .get(agent.id, params.credentialId);

    if (existing) {
      return; // Already granted — idempotent
    }

    this.db
      .prepare('INSERT INTO agent_credentials (agent_id, credential_id) VALUES (?, ?)')
      .run(agent.id, params.credentialId);
  }

  /**
   * Revoke an agent's access to a credential.
   */
  revoke(params: { agentName: string; credentialId: string }): boolean {
    const agent = this.getByName(params.agentName);
    if (!agent) {
      throw new Error(`No agent found with name "${params.agentName}"`);
    }

    const result = this.db
      .prepare('DELETE FROM agent_credentials WHERE agent_id = ? AND credential_id = ?')
      .run(agent.id, params.credentialId);

    return result.changes > 0;
  }

  /**
   * Check if an agent has access to a specific credential.
   */
  hasAccess(agentId: string, credentialId: string): boolean {
    const row = this.db
      .prepare('SELECT 1 FROM agent_credentials WHERE agent_id = ? AND credential_id = ?')
      .get(agentId, credentialId);

    return row !== undefined;
  }

  /**
   * List all credential IDs an agent has access to.
   */
  listGrants(agentName: string): string[] {
    const agent = this.getByName(agentName);
    if (!agent) {
      throw new Error(`No agent found with name "${agentName}"`);
    }

    const rows = this.db
      .prepare('SELECT credential_id FROM agent_credentials WHERE agent_id = ?')
      .all(agent.id) as Array<{ credential_id: string }>;

    return rows.map((r) => r.credential_id);
  }

  // ─── Per-Agent Rate Limits ──────────────────────────────────────

  /**
   * Set or update an agent's rate limit for a specific service.
   * This is stored as a general rate limit on the agent record.
   */
  setRateLimit(params: { agentName: string; rateLimit: string | null }): Agent {
    const agent = this.getByName(params.agentName);
    if (!agent) {
      throw new Error(`No agent found with name "${params.agentName}"`);
    }

    this.db
      .prepare("UPDATE agents SET rate_limit = ?, updated_at = datetime('now') WHERE id = ?")
      .run(params.rateLimit, agent.id);

    return {
      ...agent,
      rateLimit: params.rateLimit ?? undefined,
      updatedAt: new Date().toISOString(),
    };
  }

  // ─── Internal ───────────────────────────────────────────────────

  private rowToAgent(row: AgentRow): Agent {
    return {
      id: row.id,
      name: row.name,
      tokenPrefix: row.token_prefix,
      rateLimit: row.rate_limit ?? undefined,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
