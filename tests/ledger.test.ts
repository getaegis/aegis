import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { migrate } from '../src/db.js';
import { Ledger } from '../src/ledger/index.js';

describe('ledger', () => {
  let db: ReturnType<typeof Database>;
  let ledger: Ledger;

  beforeEach(() => {
    db = new Database(':memory:');
    db.pragma('journal_mode = WAL');
    migrate(db);
    ledger = new Ledger(db);
  });

  afterEach(() => {
    db.close();
  });

  it('logs an allowed request', () => {
    ledger.logAllowed({
      credentialId: 'cred-001',
      credentialName: 'slack-bot',
      service: 'slack',
      targetDomain: 'api.slack.com',
      method: 'POST',
      path: '/api/chat.postMessage',
      responseCode: 200,
    });

    const entries = ledger.query({ limit: 10 });
    expect(entries).toHaveLength(1);
    expect(entries[0].status).toBe('allowed');
    expect(entries[0].service).toBe('slack');
    expect(entries[0].method).toBe('POST');
  });

  it('logs a blocked request', () => {
    ledger.logBlocked({
      service: 'openai',
      targetDomain: 'evil.com',
      method: 'GET',
      path: '/steal',
      reason: 'domain_not_allowed',
    });

    const entries = ledger.query({ limit: 10 });
    expect(entries).toHaveLength(1);
    expect(entries[0].status).toBe('blocked');
    expect(entries[0].blockedReason).toBe('domain_not_allowed');
  });

  it('query filters by service', () => {
    ledger.logAllowed({
      credentialId: 'cred-001',
      credentialName: 'slack-bot',
      service: 'slack',
      targetDomain: 'api.slack.com',
      method: 'POST',
      path: '/api/chat.postMessage',
      responseCode: 200,
    });
    ledger.logAllowed({
      credentialId: 'cred-002',
      credentialName: 'gh-pat',
      service: 'github',
      targetDomain: 'api.github.com',
      method: 'GET',
      path: '/repos',
      responseCode: 200,
    });

    const slack = ledger.query({ service: 'slack', limit: 10 });
    expect(slack).toHaveLength(1);
    expect(slack[0].service).toBe('slack');
  });

  it('query filters by blocked status', () => {
    ledger.logAllowed({
      credentialId: 'cred-001',
      credentialName: 'ok',
      service: 'svc',
      targetDomain: 'ok.com',
      method: 'GET',
      path: '/',
      responseCode: 200,
    });
    ledger.logBlocked({
      service: 'svc',
      targetDomain: 'evil.com',
      method: 'GET',
      path: '/',
      reason: 'domain_not_allowed',
    });

    const blocked = ledger.query({ status: 'blocked', limit: 10 });
    expect(blocked).toHaveLength(1);
    expect(blocked[0].status).toBe('blocked');
  });

  it('logSystem records a system lifecycle event', () => {
    ledger.logSystem({
      service: '_aegis',
      targetDomain: 'localhost',
      method: 'SHUTDOWN',
      path: '/',
      reason: 'Graceful shutdown — all requests drained',
    });

    const all = ledger.query({ limit: 10 });
    expect(all).toHaveLength(1);
    expect(all[0].status).toBe('system');
    expect(all[0].method).toBe('SHUTDOWN');
    expect(all[0].blockedReason).toBe('Graceful shutdown — all requests drained');
  });

  it('defaults channel to gate', () => {
    ledger.logAllowed({
      credentialId: 'cred-001',
      credentialName: 'test',
      service: 'svc',
      targetDomain: 'api.test.com',
      method: 'GET',
      path: '/',
      responseCode: 200,
    });

    const entries = ledger.query({ limit: 10 });
    expect(entries[0].channel).toBe('gate');
  });

  it('records mcp channel on logAllowed', () => {
    ledger.logAllowed({
      credentialId: 'cred-001',
      credentialName: 'test',
      service: 'svc',
      targetDomain: 'api.test.com',
      method: 'GET',
      path: '/',
      responseCode: 200,
      channel: 'mcp',
    });

    const entries = ledger.query({ limit: 10 });
    expect(entries[0].channel).toBe('mcp');
  });

  it('records mcp channel on logBlocked', () => {
    ledger.logBlocked({
      service: 'svc',
      targetDomain: 'evil.com',
      method: 'GET',
      path: '/',
      reason: 'domain_guard',
      channel: 'mcp',
    });

    const entries = ledger.query({ limit: 10 });
    expect(entries[0].channel).toBe('mcp');
  });

  it('system events are excluded from blocked filter', () => {
    ledger.logBlocked({
      service: 'svc',
      targetDomain: 'evil.com',
      method: 'GET',
      path: '/',
      reason: 'domain_not_allowed',
    });
    ledger.logSystem({
      service: '_aegis',
      targetDomain: 'localhost',
      method: 'SHUTDOWN',
      path: '/',
      reason: 'Graceful shutdown',
    });

    const blocked = ledger.query({ status: 'blocked', limit: 10 });
    expect(blocked).toHaveLength(1);
    expect(blocked[0].status).toBe('blocked');

    const system = ledger.query({ status: 'system', limit: 10 });
    expect(system).toHaveLength(1);
    expect(system[0].status).toBe('system');
  });

  it('stats returns correct totals', () => {
    ledger.logAllowed({
      credentialId: 'cred-001',
      credentialName: 'a',
      service: 'svc1',
      targetDomain: 'a.com',
      method: 'GET',
      path: '/',
      responseCode: 200,
    });
    ledger.logAllowed({
      credentialId: 'cred-002',
      credentialName: 'b',
      service: 'svc2',
      targetDomain: 'b.com',
      method: 'GET',
      path: '/',
      responseCode: 200,
    });
    ledger.logBlocked({
      service: 'svc1',
      targetDomain: 'evil.com',
      method: 'POST',
      path: '/',
      reason: 'domain_not_allowed',
    });

    const stats = ledger.stats();
    expect(stats.total).toBe(3);
    expect(stats.allowed).toBe(2);
    expect(stats.blocked).toBe(1);
    expect(stats.system).toBe(0);
    expect(stats.byService.svc1).toBe(2);
    expect(stats.byService.svc2).toBe(1);
  });

  it('stats counts system events separately', () => {
    ledger.logAllowed({
      credentialId: 'cred-001',
      credentialName: 'a',
      service: 'svc1',
      targetDomain: 'a.com',
      method: 'GET',
      path: '/',
      responseCode: 200,
    });
    ledger.logSystem({
      service: '_aegis',
      targetDomain: 'localhost',
      method: 'SHUTDOWN',
      path: '/',
      reason: 'Graceful shutdown',
    });

    const stats = ledger.stats();
    expect(stats.total).toBe(2);
    expect(stats.allowed).toBe(1);
    expect(stats.blocked).toBe(0);
    expect(stats.system).toBe(1);
  });

  it('exportCsv produces valid CSV', () => {
    ledger.logAllowed({
      credentialId: 'cred-001',
      credentialName: 'a',
      service: 'svc',
      targetDomain: 'a.com',
      method: 'GET',
      path: '/test',
      responseCode: 200,
    });

    const csv = ledger.exportCsv({});
    const lines = csv.trim().split('\n');
    expect(lines.length).toBe(2); // header + 1 data row
    expect(lines[0]).toContain('timestamp');
    expect(lines[0]).toContain('service');
    expect(lines[1]).toContain('svc');
    expect(lines[1]).toContain('200');
  });

  it('query respects limit', () => {
    for (let i = 0; i < 10; i++) {
      ledger.logAllowed({
        credentialId: 'cred-001',
        credentialName: 'a',
        service: 'svc',
        targetDomain: 'a.com',
        method: 'GET',
        path: `/${i}`,
        responseCode: 200,
      });
    }

    const limited = ledger.query({ limit: 3 });
    expect(limited).toHaveLength(3);
  });

  // ─── Agent Identity in Audit Trail (Phase 2.5) ─────────────────

  describe('agent identity', () => {
    it('logs agent name and token prefix in allowed entries', () => {
      ledger.logAllowed({
        credentialId: 'cred-001',
        credentialName: 'slack-bot',
        service: 'slack',
        targetDomain: 'api.slack.com',
        method: 'POST',
        path: '/api/chat.postMessage',
        responseCode: 200,
        agentName: 'research-bot',
        agentTokenPrefix: 'aegis_abc123',
      });

      const entries = ledger.query({ limit: 10 });
      expect(entries).toHaveLength(1);
      expect(entries[0].agentName).toBe('research-bot');
      expect(entries[0].agentTokenPrefix).toBe('aegis_abc123');
    });

    it('logs agent name and token prefix in blocked entries', () => {
      ledger.logBlocked({
        service: 'openai',
        targetDomain: 'evil.com',
        method: 'GET',
        path: '/steal',
        reason: 'domain_not_allowed',
        agentName: 'evil-bot',
        agentTokenPrefix: 'aegis_evil12',
      });

      const entries = ledger.query({ limit: 10 });
      expect(entries).toHaveLength(1);
      expect(entries[0].agentName).toBe('evil-bot');
      expect(entries[0].agentTokenPrefix).toBe('aegis_evil12');
    });

    it('stores null when agent identity not provided', () => {
      ledger.logAllowed({
        credentialId: 'cred-001',
        credentialName: 'test',
        service: 'svc',
        targetDomain: 'a.com',
        method: 'GET',
        path: '/',
        responseCode: 200,
      });

      const entries = ledger.query({ limit: 10 });
      expect(entries[0].agentName).toBeNull();
      expect(entries[0].agentTokenPrefix).toBeNull();
    });

    it('filters audit entries by agent name', () => {
      ledger.logAllowed({
        credentialId: 'cred-001',
        credentialName: 'a',
        service: 'svc',
        targetDomain: 'a.com',
        method: 'GET',
        path: '/',
        responseCode: 200,
        agentName: 'bot-alpha',
        agentTokenPrefix: 'aegis_alpha1',
      });
      ledger.logAllowed({
        credentialId: 'cred-002',
        credentialName: 'b',
        service: 'svc',
        targetDomain: 'b.com',
        method: 'POST',
        path: '/',
        responseCode: 200,
        agentName: 'bot-beta',
        agentTokenPrefix: 'aegis_beta12',
      });
      ledger.logAllowed({
        credentialId: 'cred-001',
        credentialName: 'a',
        service: 'svc',
        targetDomain: 'a.com',
        method: 'GET',
        path: '/other',
        responseCode: 200,
        agentName: 'bot-alpha',
        agentTokenPrefix: 'aegis_alpha1',
      });

      const alpha = ledger.query({ agentName: 'bot-alpha', limit: 10 });
      expect(alpha).toHaveLength(2);
      expect(alpha.every((e) => e.agentName === 'bot-alpha')).toBe(true);

      const beta = ledger.query({ agentName: 'bot-beta', limit: 10 });
      expect(beta).toHaveLength(1);
    });

    it('stats can filter by agent name', () => {
      ledger.logAllowed({
        credentialId: 'cred-001',
        credentialName: 'a',
        service: 'svc1',
        targetDomain: 'a.com',
        method: 'GET',
        path: '/',
        responseCode: 200,
        agentName: 'agent-x',
        agentTokenPrefix: 'aegis_x12345',
      });
      ledger.logAllowed({
        credentialId: 'cred-002',
        credentialName: 'b',
        service: 'svc2',
        targetDomain: 'b.com',
        method: 'GET',
        path: '/',
        responseCode: 200,
        agentName: 'agent-y',
        agentTokenPrefix: 'aegis_y12345',
      });
      ledger.logBlocked({
        service: 'svc1',
        targetDomain: 'evil.com',
        method: 'POST',
        path: '/',
        reason: 'blocked',
        agentName: 'agent-x',
        agentTokenPrefix: 'aegis_x12345',
      });

      const allStats = ledger.stats();
      expect(allStats.total).toBe(3);

      const xStats = ledger.stats(undefined, 'agent-x');
      expect(xStats.total).toBe(2);
      expect(xStats.allowed).toBe(1);
      expect(xStats.blocked).toBe(1);
    });
  });

  // ─── JSON Export (Phase 5.5) ────────────────────────────────────

  describe('JSON export', () => {
    beforeEach(() => {
      ledger.logAllowed({
        credentialId: 'cred-001',
        credentialName: 'slack-bot',
        service: 'slack',
        targetDomain: 'api.slack.com',
        method: 'POST',
        path: '/api/chat.postMessage',
        responseCode: 200,
        agentName: 'research-bot',
        agentTokenPrefix: 'aegis_abc123',
      });
      ledger.logBlocked({
        service: 'openai',
        targetDomain: 'evil.com',
        method: 'GET',
        path: '/steal',
        reason: 'domain_not_allowed',
        agentName: 'evil-bot',
        agentTokenPrefix: 'aegis_evil12',
      });
    });

    it('exportJson returns valid JSON array', () => {
      const json = ledger.exportJson();
      const parsed = JSON.parse(json);
      expect(Array.isArray(parsed)).toBe(true);
      expect(parsed).toHaveLength(2);
    });

    it('exportJson entries have correct structure', () => {
      const entries = JSON.parse(ledger.exportJson());
      const allowed = entries.find((e: Record<string, unknown>) => e.status === 'allowed');
      expect(allowed.service).toBe('slack');
      expect(allowed.method).toBe('POST');
      expect(allowed.credentialName).toBe('slack-bot');
      expect(allowed.agentName).toBe('research-bot');
      expect(allowed.responseCode).toBe(200);

      const blocked = entries.find((e: Record<string, unknown>) => e.status === 'blocked');
      expect(blocked.service).toBe('openai');
      expect(blocked.blockedReason).toBe('domain_not_allowed');
    });

    it('exportJson respects query filters', () => {
      const json = ledger.exportJson({ status: 'blocked' });
      const entries = JSON.parse(json);
      expect(entries).toHaveLength(1);
      expect(entries[0].status).toBe('blocked');
    });

    it('exportJson returns empty array when no entries match', () => {
      const json = ledger.exportJson({ service: 'nonexistent' });
      const entries = JSON.parse(json);
      expect(entries).toHaveLength(0);
    });

    it('exportJsonLines returns one JSON object per line', () => {
      const jsonl = ledger.exportJsonLines();
      const lines = jsonl.split('\n');
      expect(lines).toHaveLength(2);
      // Each line must be valid JSON individually
      for (const line of lines) {
        const parsed = JSON.parse(line);
        expect(parsed).toHaveProperty('id');
        expect(parsed).toHaveProperty('timestamp');
        expect(parsed).toHaveProperty('service');
        expect(parsed).toHaveProperty('status');
      }
    });

    it('exportJsonLines entries are complete audit entries', () => {
      const lines = ledger.exportJsonLines().split('\n');
      const first = JSON.parse(lines[0]);
      expect(first).toHaveProperty('credentialId');
      expect(first).toHaveProperty('credentialName');
      expect(first).toHaveProperty('targetDomain');
      expect(first).toHaveProperty('method');
      expect(first).toHaveProperty('path');
      expect(first).toHaveProperty('blockedReason');
      expect(first).toHaveProperty('responseCode');
      expect(first).toHaveProperty('agentName');
      expect(first).toHaveProperty('agentTokenPrefix');
    });

    it('exportJsonLines respects query filters', () => {
      const jsonl = ledger.exportJsonLines({ service: 'slack' });
      const lines = jsonl.split('\n');
      expect(lines).toHaveLength(1);
      expect(JSON.parse(lines[0]).service).toBe('slack');
    });

    it('exportJsonLines returns empty string when no entries match', () => {
      const jsonl = ledger.exportJsonLines({ service: 'nonexistent' });
      expect(jsonl).toBe('');
    });
  });
});
