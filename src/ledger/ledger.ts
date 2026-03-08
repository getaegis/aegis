import type Database from 'better-sqlite3';

export type AuditChannel = 'gate' | 'mcp';

export interface AuditEntry {
  id: number;
  timestamp: string;
  credentialId: string | null;
  credentialName: string | null;
  service: string;
  targetDomain: string;
  method: string;
  path: string;
  status: 'allowed' | 'blocked' | 'system';
  blockedReason: string | null;
  responseCode: number | null;
  agentName: string | null;
  agentTokenPrefix: string | null;
  channel: AuditChannel;
}

export interface LedgerQuery {
  service?: string;
  credentialName?: string;
  status?: 'allowed' | 'blocked' | 'system';
  since?: string; // ISO date string
  limit?: number;
  agentName?: string;
}

export class Ledger {
  constructor(private db: Database.Database) {}

  /**
   * Record an allowed request.
   */
  logAllowed(params: {
    credentialId: string;
    credentialName: string;
    service: string;
    targetDomain: string;
    method: string;
    path: string;
    responseCode?: number;
    agentName?: string;
    agentTokenPrefix?: string;
    channel?: AuditChannel;
  }): void {
    this.db
      .prepare(
        `INSERT INTO audit_log (credential_id, credential_name, service, target_domain, method, path, status, response_code, agent_name, agent_token_prefix, channel)
       VALUES (?, ?, ?, ?, ?, ?, 'allowed', ?, ?, ?, ?)`,
      )
      .run(
        params.credentialId,
        params.credentialName,
        params.service,
        params.targetDomain,
        params.method,
        params.path,
        params.responseCode ?? null,
        params.agentName ?? null,
        params.agentTokenPrefix ?? null,
        params.channel ?? 'gate',
      );
  }

  /**
   * Record a blocked request.
   */
  logBlocked(params: {
    service: string;
    targetDomain: string;
    method: string;
    path: string;
    reason: string;
    agentName?: string;
    agentTokenPrefix?: string;
    channel?: AuditChannel;
  }): void {
    this.db
      .prepare(
        `INSERT INTO audit_log (service, target_domain, method, path, status, blocked_reason, agent_name, agent_token_prefix, channel)
       VALUES (?, ?, ?, ?, 'blocked', ?, ?, ?, ?)`,
      )
      .run(
        params.service,
        params.targetDomain,
        params.method,
        params.path,
        params.reason,
        params.agentName ?? null,
        params.agentTokenPrefix ?? null,
        params.channel ?? 'gate',
      );
  }

  /**
   * Record a system lifecycle event (startup, shutdown, seal/unseal).
   */
  logSystem(params: {
    service: string;
    targetDomain: string;
    method: string;
    path: string;
    reason: string;
    channel?: AuditChannel;
  }): void {
    this.db
      .prepare(
        `INSERT INTO audit_log (service, target_domain, method, path, status, blocked_reason, channel)
       VALUES (?, ?, ?, ?, 'system', ?, ?)`,
      )
      .run(
        params.service,
        params.targetDomain,
        params.method,
        params.path,
        params.reason,
        params.channel ?? 'gate',
      );
  }

  /**
   * Query the audit log with optional filters.
   */
  query(params: LedgerQuery = {}): AuditEntry[] {
    const conditions: string[] = [];
    const values: unknown[] = [];

    if (params.service) {
      conditions.push('service = ?');
      values.push(params.service);
    }
    if (params.credentialName) {
      conditions.push('credential_name = ?');
      values.push(params.credentialName);
    }
    if (params.status) {
      conditions.push('status = ?');
      values.push(params.status);
    }
    if (params.since) {
      conditions.push('timestamp >= ?');
      values.push(params.since);
    }
    if (params.agentName) {
      conditions.push('agent_name = ?');
      values.push(params.agentName);
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = params.limit ?? 50;

    const rows = this.db
      .prepare(`SELECT * FROM audit_log ${where} ORDER BY timestamp DESC LIMIT ?`)
      .all(...values, limit) as Array<{
      id: number;
      timestamp: string;
      credential_id: string | null;
      credential_name: string | null;
      service: string;
      target_domain: string;
      method: string;
      path: string;
      status: string;
      blocked_reason: string | null;
      response_code: number | null;
      agent_name: string | null;
      agent_token_prefix: string | null;
      channel: string;
    }>;

    return rows.map((row) => ({
      id: row.id,
      timestamp: row.timestamp,
      credentialId: row.credential_id,
      credentialName: row.credential_name,
      service: row.service,
      targetDomain: row.target_domain,
      method: row.method,
      path: row.path,
      status: row.status as 'allowed' | 'blocked' | 'system',
      blockedReason: row.blocked_reason,
      responseCode: row.response_code,
      agentName: row.agent_name,
      agentTokenPrefix: row.agent_token_prefix,
      channel: (row.channel ?? 'gate') as AuditChannel,
    }));
  }

  /**
   * Get summary stats for a time period, optionally filtered by agent.
   */
  stats(
    since?: string,
    agentName?: string,
  ): {
    total: number;
    allowed: number;
    blocked: number;
    system: number;
    byService: Record<string, number>;
  } {
    const conditions: string[] = [];
    const params: string[] = [];

    if (since) {
      conditions.push('timestamp >= ?');
      params.push(since);
    }
    if (agentName) {
      conditions.push('agent_name = ?');
      params.push(agentName);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const totals = this.db
      .prepare(
        `SELECT
        COUNT(*) as total,
        SUM(CASE WHEN status = 'allowed' THEN 1 ELSE 0 END) as allowed,
        SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked,
        SUM(CASE WHEN status = 'system' THEN 1 ELSE 0 END) as system
       FROM audit_log ${whereClause}`,
      )
      .get(...params) as { total: number; allowed: number; blocked: number; system: number };

    const services = this.db
      .prepare(`SELECT service, COUNT(*) as count FROM audit_log ${whereClause} GROUP BY service`)
      .all(...params) as Array<{ service: string; count: number }>;

    const byService: Record<string, number> = {};
    for (const row of services) {
      byService[row.service] = row.count;
    }

    return {
      total: totals.total ?? 0,
      allowed: totals.allowed ?? 0,
      blocked: totals.blocked ?? 0,
      system: totals.system ?? 0,
      byService,
    };
  }

  /**
   * Export audit log as CSV.
   */
  exportCsv(params: LedgerQuery = {}): string {
    const entries = this.query({ ...params, limit: params.limit ?? Number.MAX_SAFE_INTEGER });
    const header =
      'timestamp,credential,service,domain,method,path,status,reason,response_code,channel';
    const rows = entries.map(
      (e) =>
        `${e.timestamp},${e.credentialName ?? ''},${e.service},${e.targetDomain},${e.method},${e.path},${e.status},${e.blockedReason ?? ''},${e.responseCode ?? ''},${e.channel}`,
    );
    return [header, ...rows].join('\n');
  }

  /**
   * Export audit log as a JSON array string.
   */
  exportJson(params: LedgerQuery = {}): string {
    const entries = this.query({ ...params, limit: params.limit ?? Number.MAX_SAFE_INTEGER });
    return JSON.stringify(entries, null, 2);
  }

  /**
   * Export audit log as streaming JSON Lines (one JSON object per line).
   * Each line is a self-contained JSON object — ideal for piping into
   * SIEM systems, log aggregators, or processing with tools like jq.
   */
  exportJsonLines(params: LedgerQuery = {}): string {
    const entries = this.query({ ...params, limit: params.limit ?? Number.MAX_SAFE_INTEGER });
    return entries.map((e) => JSON.stringify(e)).join('\n');
  }
}
