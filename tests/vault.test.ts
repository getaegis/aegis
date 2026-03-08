import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { migrate } from '../src/db.js';
import type { Credential } from '../src/vault/index.js';
import { Vault } from '../src/vault/index.js';

describe('vault', () => {
  const masterKey = 'test-master-key-vault';
  let db: ReturnType<typeof Database>;
  let vault: Vault;

  beforeEach(() => {
    db = new Database(':memory:');
    db.pragma('journal_mode = WAL');
    migrate(db);
    vault = new Vault(db, masterKey);
  });

  afterEach(() => {
    db.close();
  });

  it('add and list a credential', () => {
    vault.add({
      name: 'slack-bot',
      service: 'slack',
      secret: 'xoxb-secret-token',
      authType: 'bearer',
      domains: ['api.slack.com'],
      scopes: ['*'],
    });

    const creds = vault.list();
    expect(creds).toHaveLength(1);
    expect(creds[0].name).toBe('slack-bot');
    expect(creds[0].service).toBe('slack');
    expect(creds[0].authType).toBe('bearer');
    expect(creds[0].domains).toEqual(['api.slack.com']);
  });

  it('getByName retrieves the stored secret', () => {
    vault.add({
      name: 'openai-key',
      service: 'openai',
      secret: 'sk-live-key-123',
      authType: 'bearer',
      domains: ['api.openai.com'],
      scopes: ['*'],
    });

    const cred = vault.getByName('openai-key');
    expect(cred).toBeDefined();
    expect(cred?.secret).toBe('sk-live-key-123');
  });

  it('getByService retrieves by service name', () => {
    vault.add({
      name: 'github-pat',
      service: 'github',
      secret: 'ghp_xxx',
      authType: 'bearer',
      domains: ['api.github.com'],
      scopes: ['read'],
    });

    const cred = vault.getByService('github');
    expect(cred).toBeDefined();
    expect(cred?.name).toBe('github-pat');
  });

  it('remove deletes a credential', () => {
    vault.add({
      name: 'temp',
      service: 'temp-service',
      secret: 'temp-secret',
      authType: 'bearer',
      domains: ['example.com'],
      scopes: ['*'],
    });

    expect(vault.list()).toHaveLength(1);
    const removed = vault.remove('temp');
    expect(removed).toBe(true);
    expect(vault.list()).toHaveLength(0);
  });

  it('remove returns false for non-existent credential', () => {
    expect(vault.remove('does-not-exist')).toBe(false);
  });

  it('rejects duplicate names', () => {
    vault.add({
      name: 'dup',
      service: 'svc',
      secret: 's1',
      authType: 'bearer',
      domains: ['a.com'],
      scopes: ['*'],
    });

    expect(() =>
      vault.add({
        name: 'dup',
        service: 'svc2',
        secret: 's2',
        authType: 'bearer',
        domains: ['b.com'],
        scopes: ['*'],
      }),
    ).toThrow();
  });

  // ─── Domain matching ───────────────────────────────────────────

  describe('domainMatches', () => {
    it('exact domain match', () => {
      expect(vault.domainMatches('api.slack.com', ['api.slack.com'])).toBe(true);
    });

    it('no match on different domain', () => {
      expect(vault.domainMatches('evil.com', ['api.slack.com'])).toBe(false);
    });

    it('wildcard matches subdomains', () => {
      expect(vault.domainMatches('api.slack.com', ['*.slack.com'])).toBe(true);
      expect(vault.domainMatches('hooks.slack.com', ['*.slack.com'])).toBe(true);
    });

    it('wildcard does not match bare domain', () => {
      expect(vault.domainMatches('slack.com', ['*.slack.com'])).toBe(false);
    });

    it('wildcard does not match deeper nesting', () => {
      expect(vault.domainMatches('deep.api.slack.com', ['*.slack.com'])).toBe(false);
    });
  });

  describe('findByDomain', () => {
    it('finds credential matching a target domain', () => {
      vault.add({
        name: 'slack-cred',
        service: 'slack',
        secret: 'tok',
        authType: 'bearer',
        domains: ['api.slack.com', '*.slack.com'],
        scopes: ['*'],
      });

      const found = vault.findByDomain('hooks.slack.com');
      expect(found).toBeDefined();
      expect(found?.name).toBe('slack-cred');
    });

    it('returns undefined when no domain matches', () => {
      vault.add({
        name: 'locked',
        service: 'locked-svc',
        secret: 's',
        authType: 'bearer',
        domains: ['only-this.com'],
        scopes: ['*'],
      });

      expect(vault.findByDomain('other.com')).toBeNull();
    });
  });

  // ─── Credential Rotation ───────────────────────────────────────

  describe('credential rotation', () => {
    it("rotates a credential's secret", () => {
      vault.add({
        name: 'rotate-test',
        service: 'rotate-svc',
        secret: 'old-secret-123',
        authType: 'bearer',
        domains: ['api.rotate.com'],
      });

      vault.rotate({ name: 'rotate-test', newSecret: 'new-secret-456' });

      const cred = vault.getByName('rotate-test');
      expect(cred).toBeDefined();
      expect(cred?.secret).toBe('new-secret-456');
    });

    it('saves old secret to credential_history', () => {
      vault.add({
        name: 'history-test',
        service: 'history-svc',
        secret: 'original-secret',
        authType: 'bearer',
        domains: ['api.history.com'],
      });

      vault.rotate({ name: 'history-test', newSecret: 'rotated-secret' });

      // Check history table directly
      const history = db
        .prepare(
          'SELECT * FROM credential_history WHERE credential_id = (SELECT id FROM credentials WHERE name = ?)',
        )
        .all('history-test') as Array<{ credential_id: string; grace_expires: string | null }>;

      expect(history).toHaveLength(1);
    });

    it('supports grace period on rotation', () => {
      vault.add({
        name: 'grace-test',
        service: 'grace-svc',
        secret: 'old-grace-secret',
        authType: 'bearer',
        domains: ['api.grace.com'],
      });

      vault.rotate({
        name: 'grace-test',
        newSecret: 'new-grace-secret',
        gracePeriodHours: 24,
      });

      const history = db
        .prepare(
          'SELECT * FROM credential_history WHERE credential_id = (SELECT id FROM credentials WHERE name = ?)',
        )
        .all('grace-test') as Array<{ grace_expires: string | null }>;

      expect(history).toHaveLength(1);
      expect(history[0].grace_expires).toBeDefined();
      // Grace expiry should be ~24 hours from now
      const graceExpiry = new Date(history[0].grace_expires as string);
      const now = new Date();
      const diffHours = (graceExpiry.getTime() - now.getTime()) / (1000 * 60 * 60);
      expect(diffHours).toBeGreaterThan(23);
      expect(diffHours).toBeLessThan(25);
    });

    it('throws when rotating a non-existent credential', () => {
      expect(() => vault.rotate({ name: 'nonexistent', newSecret: 'new' })).toThrow(
        'No credential found with name "nonexistent"',
      );
    });

    it('preserves all metadata after rotation', () => {
      vault.add({
        name: 'meta-rotate',
        service: 'meta-svc',
        secret: 'old-meta-secret',
        authType: 'header',
        headerName: 'x-custom',
        domains: ['api.meta.com', '*.meta.com'],
        scopes: ['read', 'write'],
      });

      vault.rotate({ name: 'meta-rotate', newSecret: 'new-meta-secret' });

      const cred = vault.getByName('meta-rotate');
      expect(cred?.secret).toBe('new-meta-secret');
      expect(cred?.authType).toBe('header');
      expect(cred?.headerName).toBe('x-custom');
      expect(cred?.domains).toEqual(['api.meta.com', '*.meta.com']);
      expect(cred?.scopes).toEqual(['read', 'write']);
    });
  });

  // ─── Credential TTL ────────────────────────────────────────────

  describe('credential TTL', () => {
    it('adds a credential with TTL', () => {
      const cred = vault.add({
        name: 'ttl-test',
        service: 'ttl-svc',
        secret: 'ttl-secret',
        authType: 'bearer',
        domains: ['api.ttl.com'],
        ttlDays: 30,
      });

      expect(cred.expiresAt).toBeDefined();
      const expiry = new Date(cred.expiresAt as string);
      const now = new Date();
      const diffDays = (expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
      expect(diffDays).toBeGreaterThan(29);
      expect(diffDays).toBeLessThan(31);
    });

    it('adds a credential without TTL (no expiry)', () => {
      const cred = vault.add({
        name: 'no-ttl',
        service: 'no-ttl-svc',
        secret: 'no-ttl-secret',
        authType: 'bearer',
        domains: ['api.nottl.com'],
      });

      expect(cred.expiresAt).toBeUndefined();
    });

    it('isExpired returns false for non-expired credential', () => {
      const cred = vault.add({
        name: 'fresh',
        service: 'fresh-svc',
        secret: 'fresh-secret',
        authType: 'bearer',
        domains: ['api.fresh.com'],
        ttlDays: 30,
      });

      expect(vault.isExpired(cred)).toBe(false);
    });

    it('isExpired returns true for expired credential', () => {
      // Manually insert a credential with a past expiry
      vault.add({
        name: 'expired',
        service: 'expired-svc',
        secret: 'expired-secret',
        authType: 'bearer',
        domains: ['api.expired.com'],
      });

      // Manually set expiry to the past
      db.prepare('UPDATE credentials SET expires_at = ? WHERE name = ?').run(
        '2020-01-01T00:00:00.000Z',
        'expired',
      );

      const reloaded = vault.getByName('expired');
      expect(reloaded).toBeDefined();
      expect(vault.isExpired(reloaded as Credential)).toBe(true);
    });

    it('isExpired returns false for credential with no TTL', () => {
      const cred = vault.add({
        name: 'forever',
        service: 'forever-svc',
        secret: 'forever-secret',
        authType: 'bearer',
        domains: ['api.forever.com'],
      });

      expect(vault.isExpired(cred)).toBe(false);
    });
  });

  // ─── Credential Update ─────────────────────────────────────────

  describe('credential update', () => {
    it('updates domains without re-entering secret', () => {
      vault.add({
        name: 'update-domains',
        service: 'update-svc',
        secret: 'update-secret',
        authType: 'bearer',
        domains: ['old.domain.com'],
      });

      vault.update({ name: 'update-domains', domains: ['new.domain.com', 'alt.domain.com'] });

      const cred = vault.getByName('update-domains');
      expect(cred?.secret).toBe('update-secret'); // secret unchanged
      expect(cred?.domains).toEqual(['new.domain.com', 'alt.domain.com']);
    });

    it('updates scopes without changing domains', () => {
      vault.add({
        name: 'update-scopes',
        service: 'scope-svc',
        secret: 'scope-secret',
        authType: 'bearer',
        domains: ['api.scope.com'],
        scopes: ['read'],
      });

      vault.update({ name: 'update-scopes', scopes: ['read', 'write'] });

      const cred = vault.getByName('update-scopes');
      expect(cred?.scopes).toEqual(['read', 'write']);
      expect(cred?.domains).toEqual(['api.scope.com']); // domains unchanged
    });

    it('updates auth type', () => {
      vault.add({
        name: 'update-auth',
        service: 'auth-svc',
        secret: 'auth-secret',
        authType: 'bearer',
        domains: ['api.auth.com'],
      });

      vault.update({ name: 'update-auth', authType: 'header', headerName: 'x-custom-key' });

      const cred = vault.getByName('update-auth');
      expect(cred?.authType).toBe('header');
      expect(cred?.headerName).toBe('x-custom-key');
    });

    it('throws when updating a non-existent credential', () => {
      expect(() => vault.update({ name: 'ghost', domains: ['new.com'] })).toThrow(
        'No credential found with name "ghost"',
      );
    });
  });

  // ─── Rate Limit Storage ─────────────────────────────────────────

  describe('credential rate limit', () => {
    it('stores rate limit on add', () => {
      vault.add({
        name: 'rate-cred',
        service: 'rate-svc',
        secret: 'rate-secret',
        authType: 'bearer',
        domains: ['api.rate.com'],
        rateLimit: '100/min',
      });

      const cred = vault.getByName('rate-cred');
      expect(cred?.rateLimit).toBe('100/min');
    });

    it('defaults to no rate limit', () => {
      vault.add({
        name: 'no-rate-cred',
        service: 'no-rate-svc',
        secret: 'no-rate-secret',
        authType: 'bearer',
        domains: ['api.norate.com'],
      });

      const cred = vault.getByName('no-rate-cred');
      expect(cred?.rateLimit).toBeUndefined();
    });

    it('updates rate limit via update()', () => {
      vault.add({
        name: 'update-rate',
        service: 'update-rate-svc',
        secret: 'update-rate-secret',
        authType: 'bearer',
        domains: ['api.updaterate.com'],
      });

      vault.update({ name: 'update-rate', rateLimit: '50/hour' });
      const cred = vault.getByName('update-rate');
      expect(cred?.rateLimit).toBe('50/hour');
    });

    it('removes rate limit when set to null', () => {
      vault.add({
        name: 'remove-rate',
        service: 'remove-rate-svc',
        secret: 'remove-rate-secret',
        authType: 'bearer',
        domains: ['api.removerate.com'],
        rateLimit: '10/sec',
      });

      vault.update({ name: 'remove-rate', rateLimit: null });
      const cred = vault.getByName('remove-rate');
      expect(cred?.rateLimit).toBeUndefined();
    });

    it('preserves rate limit across list()', () => {
      vault.add({
        name: 'list-rate',
        service: 'list-rate-svc',
        secret: 'list-rate-secret',
        authType: 'bearer',
        domains: ['api.listrate.com'],
        rateLimit: '1000/hour',
      });

      const creds = vault.list();
      const cred = creds.find((c) => c.name === 'list-rate');
      expect(cred?.rateLimit).toBe('1000/hour');
    });
  });

  // ─── Body Inspection Storage ────────────────────────────────────

  describe('credential body inspection', () => {
    it('defaults to block mode', () => {
      vault.add({
        name: 'body-default',
        service: 'body-default-svc',
        secret: 'body-default-secret',
        authType: 'bearer',
        domains: ['api.bodydefault.com'],
      });

      const cred = vault.getByName('body-default');
      expect(cred?.bodyInspection).toBe('block');
    });

    it('stores custom body inspection mode on add', () => {
      vault.add({
        name: 'body-warn',
        service: 'body-warn-svc',
        secret: 'body-warn-secret',
        authType: 'bearer',
        domains: ['api.bodywarn.com'],
        bodyInspection: 'warn',
      });

      const cred = vault.getByName('body-warn');
      expect(cred?.bodyInspection).toBe('warn');
    });

    it('stores off mode', () => {
      vault.add({
        name: 'body-off',
        service: 'body-off-svc',
        secret: 'body-off-secret',
        authType: 'bearer',
        domains: ['api.bodyoff.com'],
        bodyInspection: 'off',
      });

      const cred = vault.getByName('body-off');
      expect(cred?.bodyInspection).toBe('off');
    });

    it('updates body inspection mode via update()', () => {
      vault.add({
        name: 'body-update',
        service: 'body-update-svc',
        secret: 'body-update-secret',
        authType: 'bearer',
        domains: ['api.bodyupdate.com'],
      });

      expect(vault.getByName('body-update')?.bodyInspection).toBe('block');

      vault.update({ name: 'body-update', bodyInspection: 'off' });
      expect(vault.getByName('body-update')?.bodyInspection).toBe('off');
    });

    it('preserves body inspection mode across list()', () => {
      vault.add({
        name: 'body-list',
        service: 'body-list-svc',
        secret: 'body-list-secret',
        authType: 'bearer',
        domains: ['api.bodylist.com'],
        bodyInspection: 'warn',
      });

      const creds = vault.list();
      const cred = creds.find((c) => c.name === 'body-list');
      expect(cred?.bodyInspection).toBe('warn');
    });
  });
});
