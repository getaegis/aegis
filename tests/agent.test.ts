import Database from 'better-sqlite3-multiple-ciphers';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AgentRegistry } from '../src/agent/index.js';
import { migrate } from '../src/db.js';
import { deriveKey, Vault } from '../src/vault/index.js';

describe('agent registry', () => {
  const masterKey = 'test-master-key-agents';
  const salt = 'test-salt-agents';
  let db: ReturnType<typeof Database>;
  let derivedKeyBuf: Buffer;
  let registry: AgentRegistry;
  let vault: Vault;

  beforeEach(() => {
    db = new Database(':memory:');
    db.pragma('journal_mode = WAL');
    migrate(db);
    derivedKeyBuf = deriveKey(masterKey, salt);
    registry = new AgentRegistry(db, derivedKeyBuf);
    vault = new Vault(db, masterKey, salt);
  });

  afterEach(() => {
    db.close();
  });

  // ─── Agent Registration (2.1) ───────────────────────────────────

  describe('add', () => {
    it('creates an agent with a unique token', () => {
      const agent = registry.add({ name: 'research-bot' });

      expect(agent.name).toBe('research-bot');
      expect(agent.token).toMatch(/^aegis_/);
      expect(agent.tokenPrefix.length).toBeGreaterThan(0);
      expect(agent.id).toBeDefined();
    });

    it('generates different tokens for different agents', () => {
      const a1 = registry.add({ name: 'bot-1' });
      const a2 = registry.add({ name: 'bot-2' });

      expect(a1.token).not.toBe(a2.token);
      expect(a1.id).not.toBe(a2.id);
    });

    it('rejects duplicate agent names', () => {
      registry.add({ name: 'unique-bot' });
      expect(() => registry.add({ name: 'unique-bot' })).toThrow();
    });

    it('stores rate limit when provided', () => {
      const agent = registry.add({ name: 'rate-bot', rateLimit: '50/min' });
      expect(agent.rateLimit).toBe('50/min');
    });
  });

  // ─── Agent Listing ──────────────────────────────────────────────

  describe('list', () => {
    it('returns empty array when no agents', () => {
      expect(registry.list()).toEqual([]);
    });

    it('returns all registered agents', () => {
      registry.add({ name: 'bot-a' });
      registry.add({ name: 'bot-b' });

      const agents = registry.list();
      expect(agents).toHaveLength(2);
      expect(agents.map((a) => a.name).sort()).toEqual(['bot-a', 'bot-b']);
    });

    it('does not include tokens in list output', () => {
      registry.add({ name: 'secret-bot' });
      const agents = registry.list();
      // Agent type doesn't have token field
      expect('token' in agents[0]).toBe(false);
    });
  });

  // ─── Agent Lookup ───────────────────────────────────────────────

  describe('getByName', () => {
    it('returns agent by name', () => {
      registry.add({ name: 'lookup-bot' });
      const agent = registry.getByName('lookup-bot');
      expect(agent).not.toBeNull();
      expect(agent?.name).toBe('lookup-bot');
    });

    it('returns null for unknown name', () => {
      expect(registry.getByName('nonexistent')).toBeNull();
    });
  });

  // ─── Token Validation (2.2) ─────────────────────────────────────

  describe('validateToken', () => {
    it('validates a correct token', () => {
      const created = registry.add({ name: 'auth-bot' });
      const validated = registry.validateToken(created.token);

      expect(validated).not.toBeNull();
      expect(validated?.name).toBe('auth-bot');
      expect(validated?.id).toBe(created.id);
    });

    it('rejects an invalid token', () => {
      expect(registry.validateToken('aegis_fake_token')).toBeNull();
    });

    it('rejects empty token', () => {
      expect(registry.validateToken('')).toBeNull();
    });

    it('rejects a token with tampered characters', () => {
      const created = registry.add({ name: 'tamper-bot' });
      const tampered = `${created.token}x`;
      expect(registry.validateToken(tampered)).toBeNull();
    });
  });

  // ─── Agent Removal ──────────────────────────────────────────────

  describe('remove', () => {
    it('removes an existing agent', () => {
      registry.add({ name: 'doomed-bot' });
      expect(registry.remove('doomed-bot')).toBe(true);
      expect(registry.getByName('doomed-bot')).toBeNull();
    });

    it('returns false for unknown agent', () => {
      expect(registry.remove('ghost-bot')).toBe(false);
    });

    it('removes credential grants when agent is removed', () => {
      const agent = registry.add({ name: 'grant-bot' });
      const cred = vault.add({
        name: 'test-cred',
        service: 'test-svc',
        secret: 'test-secret',
        domains: ['api.test.com'],
      });

      registry.grant({ agentName: 'grant-bot', credentialId: cred.id });
      expect(registry.hasAccess(agent.id, cred.id)).toBe(true);

      registry.remove('grant-bot');

      // Verify grants are also removed (need to re-add to check, since agent is gone)
      const newAgent = registry.add({ name: 'grant-bot' });
      expect(registry.hasAccess(newAgent.id, cred.id)).toBe(false);
    });
  });

  // ─── Token Regeneration ──────────────────────────────────────────

  describe('regenerateToken', () => {
    it('generates a new valid token for an existing agent', () => {
      const created = registry.add({ name: 'regen-bot' });
      const regenerated = registry.regenerateToken('regen-bot');

      expect(regenerated).not.toBeNull();
      if (!regenerated) return;
      expect(regenerated.name).toBe('regen-bot');
      expect(regenerated.token).toMatch(/^aegis_/);
      expect(regenerated.token).not.toBe(created.token);
      expect(regenerated.id).toBe(created.id);
    });

    it('invalidates the old token after regeneration', () => {
      const created = registry.add({ name: 'old-token-bot' });
      registry.regenerateToken('old-token-bot');

      // Old token should no longer validate
      expect(registry.validateToken(created.token)).toBeNull();
    });

    it('new token validates successfully', () => {
      registry.add({ name: 'new-token-bot' });
      const regenerated = registry.regenerateToken('new-token-bot');
      if (!regenerated) throw new Error('expected regenerated token');

      const validated = registry.validateToken(regenerated.token);
      expect(validated).not.toBeNull();
      if (!validated) return;
      expect(validated.name).toBe('new-token-bot');
    });

    it('preserves credential grants after regeneration', () => {
      const agent = registry.add({ name: 'grant-regen-bot' });
      const cred = vault.add({
        name: 'regen-cred',
        service: 'regen-svc',
        secret: 'secret',
        domains: ['api.regen.com'],
      });

      registry.grant({ agentName: 'grant-regen-bot', credentialId: cred.id });
      expect(registry.hasAccess(agent.id, cred.id)).toBe(true);

      const regenerated = registry.regenerateToken('grant-regen-bot');
      expect(regenerated).not.toBeNull();

      // Grants should still be intact
      expect(registry.hasAccess(agent.id, cred.id)).toBe(true);
    });

    it('preserves rate limit after regeneration', () => {
      registry.add({ name: 'rate-regen-bot', rateLimit: '100/min' });
      const regenerated = registry.regenerateToken('rate-regen-bot');

      expect(regenerated).not.toBeNull();
      if (!regenerated) return;
      expect(regenerated.rateLimit).toBe('100/min');
    });

    it('returns null for unknown agent', () => {
      expect(registry.regenerateToken('nonexistent')).toBeNull();
    });
  });

  // ─── Credential Grants (2.3) ────────────────────────────────────

  describe('grant / revoke / hasAccess', () => {
    it('grants access to a credential', () => {
      const agent = registry.add({ name: 'scope-bot' });
      const cred = vault.add({
        name: 'slack-cred',
        service: 'slack',
        secret: 'xoxb-test',
        domains: ['api.slack.com'],
      });

      registry.grant({ agentName: 'scope-bot', credentialId: cred.id });
      expect(registry.hasAccess(agent.id, cred.id)).toBe(true);
    });

    it('grant is idempotent', () => {
      const cred = vault.add({
        name: 'idem-cred',
        service: 'idem',
        secret: 'secret',
        domains: ['api.idem.com'],
      });

      registry.add({ name: 'idem-bot' });
      registry.grant({ agentName: 'idem-bot', credentialId: cred.id });
      // Second grant should not throw
      registry.grant({ agentName: 'idem-bot', credentialId: cred.id });
    });

    it('revokes access to a credential', () => {
      const agent = registry.add({ name: 'revoke-bot' });
      const cred = vault.add({
        name: 'revoke-cred',
        service: 'revoke-svc',
        secret: 'secret',
        domains: ['api.revoke.com'],
      });

      registry.grant({ agentName: 'revoke-bot', credentialId: cred.id });
      expect(registry.hasAccess(agent.id, cred.id)).toBe(true);

      const revoked = registry.revoke({ agentName: 'revoke-bot', credentialId: cred.id });
      expect(revoked).toBe(true);
      expect(registry.hasAccess(agent.id, cred.id)).toBe(false);
    });

    it('revoke returns false when no grant exists', () => {
      registry.add({ name: 'no-grant-bot' });
      const cred = vault.add({
        name: 'no-grant-cred',
        service: 'no-grant',
        secret: 'secret',
        domains: ['api.example.com'],
      });

      const revoked = registry.revoke({ agentName: 'no-grant-bot', credentialId: cred.id });
      expect(revoked).toBe(false);
    });

    it('hasAccess returns false for ungrantedcredential', () => {
      const agent = registry.add({ name: 'check-bot' });
      const cred = vault.add({
        name: 'check-cred',
        service: 'check',
        secret: 'secret',
        domains: ['api.check.com'],
      });

      expect(registry.hasAccess(agent.id, cred.id)).toBe(false);
    });

    it('throws when granting to unknown agent', () => {
      expect(() => registry.grant({ agentName: 'ghost', credentialId: 'fake-id' })).toThrow(
        'No agent found',
      );
    });

    it('throws when revoking from unknown agent', () => {
      expect(() => registry.revoke({ agentName: 'ghost', credentialId: 'fake-id' })).toThrow(
        'No agent found',
      );
    });
  });

  // ─── List Grants ────────────────────────────────────────────────

  describe('listGrants', () => {
    it('lists all credential IDs for an agent', () => {
      registry.add({ name: 'multi-bot' });
      const c1 = vault.add({
        name: 'cred-1',
        service: 'svc-1',
        secret: 's1',
        domains: ['api1.com'],
      });
      const c2 = vault.add({
        name: 'cred-2',
        service: 'svc-2',
        secret: 's2',
        domains: ['api2.com'],
      });

      registry.grant({ agentName: 'multi-bot', credentialId: c1.id });
      registry.grant({ agentName: 'multi-bot', credentialId: c2.id });

      const grants = registry.listGrants('multi-bot');
      expect(grants).toHaveLength(2);
      expect(grants).toContain(c1.id);
      expect(grants).toContain(c2.id);
    });

    it('returns empty array when no grants', () => {
      registry.add({ name: 'empty-bot' });
      expect(registry.listGrants('empty-bot')).toEqual([]);
    });

    it('throws for unknown agent', () => {
      expect(() => registry.listGrants('ghost')).toThrow('No agent found');
    });
  });

  // ─── Per-Agent Rate Limits (2.4) ────────────────────────────────

  describe('setRateLimit', () => {
    it('sets a rate limit on an agent', () => {
      registry.add({ name: 'rate-bot' });
      const updated = registry.setRateLimit({ agentName: 'rate-bot', rateLimit: '100/hour' });
      expect(updated.rateLimit).toBe('100/hour');
    });

    it('removes rate limit when set to null', () => {
      registry.add({ name: 'clear-bot', rateLimit: '50/min' });
      const updated = registry.setRateLimit({ agentName: 'clear-bot', rateLimit: null });
      expect(updated.rateLimit).toBeUndefined();
    });

    it('persists rate limit in database', () => {
      registry.add({ name: 'persist-bot' });
      registry.setRateLimit({ agentName: 'persist-bot', rateLimit: '200/hour' });

      const agent = registry.getByName('persist-bot');
      expect(agent?.rateLimit).toBe('200/hour');
    });

    it('throws for unknown agent', () => {
      expect(() => registry.setRateLimit({ agentName: 'ghost', rateLimit: '10/sec' })).toThrow(
        'No agent found',
      );
    });
  });
});
