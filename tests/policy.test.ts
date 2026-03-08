import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  buildPolicyMap,
  evaluatePolicy,
  loadPoliciesFromDirectory,
  loadPolicyFile,
  parsePolicy,
} from '../src/policy/index.js';

describe('policy engine', () => {
  // ─── YAML Parsing ──────────────────────────────────────────────

  describe('parsePolicy', () => {
    it('parses a valid minimal policy', () => {
      const yaml = `
agent: research-bot
rules:
  - service: slack
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
      expect(result.policy).toBeDefined();
      expect(result.policy?.agent).toBe('research-bot');
      expect(result.policy?.rules).toHaveLength(1);
      expect(result.policy?.rules[0].service).toBe('slack');
    });

    it('parses a fully specified policy', () => {
      const yaml = `
agent: deploy-bot
rules:
  - service: github
    methods: [GET, POST]
    paths:
      - /repos/myorg/.*
      - /issues/.*
    rate_limit: 200/hour
    time_window:
      start: "09:00"
      end: "18:00"
      timezone: "America/New_York"
  - service: slack
    methods: [POST]
    paths:
      - /api/chat.postMessage
    rate_limit: 50/min
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(true);
      expect(result.policy?.agent).toBe('deploy-bot');
      expect(result.policy?.rules).toHaveLength(2);

      const githubRule = result.policy?.rules[0];
      expect(githubRule?.service).toBe('github');
      expect(githubRule?.methods).toEqual(['GET', 'POST']);
      expect(githubRule?.paths).toEqual(['/repos/myorg/.*', '/issues/.*']);
      expect(githubRule?.rateLimit).toBe('200/hour');
      expect(githubRule?.timeWindow).toEqual({
        start: '09:00',
        end: '18:00',
        timezone: 'America/New_York',
      });

      const slackRule = result.policy?.rules[1];
      expect(slackRule?.service).toBe('slack');
      expect(slackRule?.methods).toEqual(['POST']);
      expect(slackRule?.rateLimit).toBe('50/min');
      expect(slackRule?.timeWindow).toBeUndefined();
    });

    it('normalizes method names to uppercase', () => {
      const yaml = `
agent: bot
rules:
  - service: api
    methods: [get, Post, DELETE]
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(true);
      expect(result.policy?.rules[0].methods).toEqual(['GET', 'POST', 'DELETE']);
    });

    it('defaults timezone to UTC when not specified', () => {
      const yaml = `
agent: bot
rules:
  - service: api
    time_window:
      start: "08:00"
      end: "17:00"
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(true);
      expect(result.policy?.rules[0].timeWindow?.timezone).toBe('UTC');
    });

    it('treats omitted methods as allowing all methods', () => {
      const yaml = `
agent: bot
rules:
  - service: api
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(true);
      expect(result.policy?.rules[0].methods).toBeUndefined();
    });

    it('treats omitted paths as allowing all paths', () => {
      const yaml = `
agent: bot
rules:
  - service: api
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(true);
      expect(result.policy?.rules[0].paths).toBeUndefined();
    });
  });

  // ─── Validation Errors ─────────────────────────────────────────

  describe('validation errors', () => {
    it('rejects invalid YAML syntax', () => {
      const yaml = 'agent: [invalid yaml\n  broken:';
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(false);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].message).toContain('YAML parse error');
    });

    it('rejects non-object YAML', () => {
      const yaml = 'just a string';
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(false);
      expect(result.errors[0].message).toContain('must be a YAML object');
    });

    it('rejects missing agent field', () => {
      const yaml = `
rules:
  - service: slack
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path === 'agent')).toBe(true);
    });

    it('rejects empty agent name', () => {
      const yaml = `
agent: ""
rules:
  - service: slack
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path === 'agent')).toBe(true);
    });

    it('rejects missing rules', () => {
      const yaml = `
agent: bot
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path === 'rules')).toBe(true);
    });

    it('rejects empty rules array', () => {
      const yaml = `
agent: bot
rules: []
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.message.includes('at least one rule'))).toBe(true);
    });

    it('rejects rules that are not objects', () => {
      const yaml = `
agent: bot
rules:
  - "not an object"
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.message.includes('must be an object'))).toBe(true);
    });

    it('rejects missing service in a rule', () => {
      const yaml = `
agent: bot
rules:
  - methods: [GET]
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path === 'rules[0].service')).toBe(true);
    });

    it('rejects invalid HTTP methods', () => {
      const yaml = `
agent: bot
rules:
  - service: api
    methods: [GET, INVALID, POST]
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path === 'rules[0].methods[1]')).toBe(true);
      expect(result.errors[0].message).toContain('INVALID');
    });

    it('rejects methods that is not an array', () => {
      const yaml = `
agent: bot
rules:
  - service: api
    methods: GET
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.message.includes('must be an array'))).toBe(true);
    });

    it('rejects invalid regex in paths', () => {
      const yaml = `
agent: bot
rules:
  - service: api
    paths:
      - "[invalid regex"
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.message.includes('not a valid regular expression'))).toBe(
        true,
      );
    });

    it('rejects paths that is not an array', () => {
      const yaml = `
agent: bot
rules:
  - service: api
    paths: /single/path
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.message.includes('must be an array'))).toBe(true);
    });

    it('rejects invalid rate limit format', () => {
      const yaml = `
agent: bot
rules:
  - service: api
    rate_limit: "100 per hour"
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.path === 'rules[0].rate_limit')).toBe(true);
    });

    it('rejects invalid time window start format', () => {
      const yaml = `
agent: bot
rules:
  - service: api
    time_window:
      start: "9am"
      end: "18:00"
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.message.includes('HH:MM'))).toBe(true);
    });

    it('rejects invalid time window end format', () => {
      const yaml = `
agent: bot
rules:
  - service: api
    time_window:
      start: "09:00"
      end: "25:00"
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.message.includes('HH:MM'))).toBe(true);
    });

    it('rejects invalid timezone', () => {
      const yaml = `
agent: bot
rules:
  - service: api
    time_window:
      start: "09:00"
      end: "18:00"
      timezone: "Not/A/Timezone"
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.message.includes('not a valid IANA timezone'))).toBe(true);
    });

    it('rejects time_window that is not an object', () => {
      const yaml = `
agent: bot
rules:
  - service: api
    time_window: "09:00-18:00"
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.message.includes('must be an object'))).toBe(true);
    });

    it('collects multiple errors from a single policy', () => {
      const yaml = `
agent: ""
rules:
  - methods: [INVALID]
    rate_limit: bad
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(false);
      // Should have errors for: agent, service, methods[0], rate_limit
      expect(result.errors.length).toBeGreaterThanOrEqual(4);
    });

    it('includes file path in error when provided', () => {
      const yaml = `
agent: bot
rules: []
`;
      const result = parsePolicy(yaml, 'policies/test.yaml');
      expect(result.valid).toBe(false);
      expect(result.errors[0].file).toBe('policies/test.yaml');
    });
  });

  // ─── Rate Limit Formats ────────────────────────────────────────

  describe('rate limit validation', () => {
    const validLimits = [
      '100/hour',
      '50/min',
      '10/second',
      '1000/day',
      '5/sec',
      '30/minute',
      '1/hr',
    ];
    for (const limit of validLimits) {
      it(`accepts valid rate limit: ${limit}`, () => {
        const yaml = `
agent: bot
rules:
  - service: api
    rate_limit: "${limit}"
`;
        const result = parsePolicy(yaml);
        expect(result.valid).toBe(true);
      });
    }

    const invalidLimits = ['100', 'fast', '100/week', '100 per hour', '/min', '100/'];
    for (const limit of invalidLimits) {
      it(`rejects invalid rate limit: ${limit}`, () => {
        const yaml = `
agent: bot
rules:
  - service: api
    rate_limit: "${limit}"
`;
        const result = parsePolicy(yaml);
        expect(result.valid).toBe(false);
      });
    }
  });

  // ─── File Loading ──────────────────────────────────────────────

  describe('loadPolicyFile', () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-policy-test-'));
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('loads and validates a policy file', () => {
      const filePath = path.join(tmpDir, 'bot.yaml');
      fs.writeFileSync(
        filePath,
        `
agent: test-bot
rules:
  - service: slack
    methods: [GET]
`,
      );

      const result = loadPolicyFile(filePath);
      expect(result.valid).toBe(true);
      expect(result.policy?.agent).toBe('test-bot');
    });

    it('returns error for non-existent file', () => {
      const result = loadPolicyFile('/nonexistent/path/bot.yaml');
      expect(result.valid).toBe(false);
      expect(result.errors[0].message).toContain('Failed to read file');
    });

    it('returns error for invalid YAML content', () => {
      const filePath = path.join(tmpDir, 'bad.yaml');
      fs.writeFileSync(filePath, 'agent: [broken');

      const result = loadPolicyFile(filePath);
      expect(result.valid).toBe(false);
    });
  });

  // ─── Directory Loading ─────────────────────────────────────────

  describe('loadPoliciesFromDirectory', () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-policy-dir-'));
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('loads all .yaml and .yml files from a directory', () => {
      fs.writeFileSync(
        path.join(tmpDir, 'bot-a.yaml'),
        'agent: bot-a\nrules:\n  - service: slack\n',
      );
      fs.writeFileSync(
        path.join(tmpDir, 'bot-b.yml'),
        'agent: bot-b\nrules:\n  - service: github\n',
      );
      // Non-YAML file should be ignored
      fs.writeFileSync(path.join(tmpDir, 'readme.md'), '# not a policy');

      const results = loadPoliciesFromDirectory(tmpDir);
      expect(results).toHaveLength(2);
      expect(results.every((r) => r.valid)).toBe(true);
    });

    it('returns empty array for empty directory', () => {
      const results = loadPoliciesFromDirectory(tmpDir);
      expect(results).toHaveLength(0);
    });

    it('returns error for non-existent directory', () => {
      const results = loadPoliciesFromDirectory('/nonexistent/dir');
      expect(results).toHaveLength(1);
      expect(results[0].valid).toBe(false);
      expect(results[0].errors[0].message).toContain('does not exist');
    });

    it('returns error when path is a file, not a directory', () => {
      const filePath = path.join(tmpDir, 'file.yaml');
      fs.writeFileSync(filePath, 'agent: bot\nrules:\n  - service: api\n');

      const results = loadPoliciesFromDirectory(filePath);
      expect(results).toHaveLength(1);
      expect(results[0].valid).toBe(false);
      expect(results[0].errors[0].message).toContain('Not a directory');
    });

    it('detects duplicate agent names across files', () => {
      fs.writeFileSync(
        path.join(tmpDir, 'bot-1.yaml'),
        'agent: same-bot\nrules:\n  - service: slack\n',
      );
      fs.writeFileSync(
        path.join(tmpDir, 'bot-2.yaml'),
        'agent: same-bot\nrules:\n  - service: github\n',
      );

      const results = loadPoliciesFromDirectory(tmpDir);
      const invalid = results.filter((r) => !r.valid);
      expect(invalid.length).toBeGreaterThan(0);
      expect(
        invalid.some((r) => r.errors.some((e) => e.message.includes('Duplicate policy'))),
      ).toBe(true);
    });

    it('reports validation errors for individual files', () => {
      fs.writeFileSync(
        path.join(tmpDir, 'good.yaml'),
        'agent: good-bot\nrules:\n  - service: slack\n',
      );
      fs.writeFileSync(path.join(tmpDir, 'bad.yaml'), 'agent: ""\nrules:\n  - service: slack\n');

      const results = loadPoliciesFromDirectory(tmpDir);
      expect(results).toHaveLength(2);
      const valid = results.filter((r) => r.valid);
      const invalid = results.filter((r) => !r.valid);
      expect(valid).toHaveLength(1);
      expect(invalid).toHaveLength(1);
    });
  });

  // ─── Policy Map Building ───────────────────────────────────────

  describe('buildPolicyMap', () => {
    it('builds a map from valid results only', () => {
      const yaml1 = `
agent: bot-a
rules:
  - service: slack
`;
      const yaml2 = `
agent: bot-b
rules:
  - service: github
`;
      const invalid = `
agent: ""
rules: []
`;
      const results = [parsePolicy(yaml1), parsePolicy(yaml2), parsePolicy(invalid)];
      const map = buildPolicyMap(results);

      expect(map.size).toBe(2);
      expect(map.has('bot-a')).toBe(true);
      expect(map.has('bot-b')).toBe(true);
      expect(map.get('bot-a')?.rules[0].service).toBe('slack');
    });

    it('returns empty map when all results are invalid', () => {
      const result = parsePolicy('not valid yaml at all [[[');
      const map = buildPolicyMap([result]);
      expect(map.size).toBe(0);
    });
  });

  // ─── Edge Cases ────────────────────────────────────────────────

  describe('edge cases', () => {
    it('handles policy with multiple rules for same service', () => {
      const yaml = `
agent: multi-rule-bot
rules:
  - service: github
    methods: [GET]
    paths:
      - /repos/.*
  - service: github
    methods: [POST]
    paths:
      - /repos/.*/issues
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(true);
      expect(result.policy?.rules).toHaveLength(2);
    });

    it('accepts all valid HTTP methods', () => {
      const yaml = `
agent: bot
rules:
  - service: api
    methods: [GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS]
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(true);
      expect(result.policy?.rules[0].methods).toHaveLength(7);
    });

    it('accepts midnight-spanning time windows', () => {
      const yaml = `
agent: night-bot
rules:
  - service: api
    time_window:
      start: "22:00"
      end: "06:00"
      timezone: "UTC"
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(true);
    });

    it('accepts complex regex paths', () => {
      const yaml = `
agent: bot
rules:
  - service: api
    paths:
      - "^/api/v[12]/users/\\\\d+$"
      - "/repos/[^/]+/[^/]+/pulls"
`;
      const result = parsePolicy(yaml);
      expect(result.valid).toBe(true);
    });
  });

  // ─── Policy Evaluation ─────────────────────────────────────────

  describe('evaluatePolicy', () => {
    // Helper to build a quick policy
    function makePolicy(
      agent: string,
      rules: Array<Record<string, unknown>>,
    ): ReturnType<typeof parsePolicy>['policy'] {
      const yaml = `agent: ${agent}\nrules:\n${rules
        .map((r) => {
          let s = `  - service: ${r.service}`;
          if (r.methods) s += `\n    methods: [${(r.methods as string[]).join(', ')}]`;
          if (r.paths)
            s += `\n    paths:\n${(r.paths as string[]).map((p) => `      - "${p}"`).join('\n')}`;
          if (r.rate_limit) s += `\n    rate_limit: ${r.rate_limit}`;
          if (r.time_window) {
            const tw = r.time_window as Record<string, string>;
            s += `\n    time_window:\n      start: "${tw.start}"\n      end: "${tw.end}"`;
            if (tw.timezone) s += `\n      timezone: "${tw.timezone}"`;
          }
          return s;
        })
        .join('\n')}`;

      const result = parsePolicy(yaml);
      return result.policy;
    }

    // ─── Basic Access ────────────────────────────────────────────

    describe('service access', () => {
      it('allows a request matching a service rule', () => {
        const policy = makePolicy('bot', [{ service: 'slack' }]);
        if (!policy) throw new Error('Policy setup failed');

        const result = evaluatePolicy(policy, {
          service: 'slack',
          method: 'GET',
          path: '/api/chat.postMessage',
        });
        expect(result.allowed).toBe(true);
      });

      it('denies a request with no matching service rule', () => {
        const policy = makePolicy('bot', [{ service: 'slack' }]);
        if (!policy) throw new Error('Policy setup failed');

        const result = evaluatePolicy(policy, {
          service: 'github',
          method: 'GET',
          path: '/repos',
        });
        expect(result.allowed).toBe(false);
        expect(result.violation).toBe('no_matching_rule');
        expect(result.reason).toContain('github');
        expect(result.reason).toContain('bot');
      });

      it('allows access to any of multiple service rules', () => {
        const policy = makePolicy('bot', [{ service: 'slack' }, { service: 'github' }]);
        if (!policy) throw new Error('Policy setup failed');

        expect(evaluatePolicy(policy, { service: 'slack', method: 'GET', path: '/' }).allowed).toBe(
          true,
        );
        expect(
          evaluatePolicy(policy, { service: 'github', method: 'GET', path: '/' }).allowed,
        ).toBe(true);
      });
    });

    // ─── Method Restrictions ─────────────────────────────────────

    describe('method restrictions', () => {
      it('allows a permitted method', () => {
        const policy = makePolicy('bot', [{ service: 'github', methods: ['GET', 'POST'] }]);
        if (!policy) throw new Error('Policy setup failed');

        expect(
          evaluatePolicy(policy, { service: 'github', method: 'GET', path: '/' }).allowed,
        ).toBe(true);
        expect(
          evaluatePolicy(policy, { service: 'github', method: 'POST', path: '/' }).allowed,
        ).toBe(true);
      });

      it('denies a non-permitted method', () => {
        const policy = makePolicy('bot', [{ service: 'github', methods: ['GET'] }]);
        if (!policy) throw new Error('Policy setup failed');

        const result = evaluatePolicy(policy, {
          service: 'github',
          method: 'DELETE',
          path: '/repos/org/repo',
        });
        expect(result.allowed).toBe(false);
        expect(result.violation).toBe('method');
        expect(result.reason).toContain('DELETE');
        expect(result.reason).toContain('GET');
      });

      it('method matching is case-insensitive', () => {
        const policy = makePolicy('bot', [{ service: 'api', methods: ['GET', 'POST'] }]);
        if (!policy) throw new Error('Policy setup failed');

        expect(evaluatePolicy(policy, { service: 'api', method: 'get', path: '/' }).allowed).toBe(
          true,
        );
        expect(evaluatePolicy(policy, { service: 'api', method: 'Post', path: '/' }).allowed).toBe(
          true,
        );
      });

      it('allows any method when methods is not specified', () => {
        const policy = makePolicy('bot', [{ service: 'api' }]);
        if (!policy) throw new Error('Policy setup failed');

        for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']) {
          expect(evaluatePolicy(policy, { service: 'api', method, path: '/' }).allowed).toBe(true);
        }
      });
    });

    // ─── Path Restrictions ───────────────────────────────────────

    describe('path restrictions', () => {
      it('allows a path matching a pattern', () => {
        const policy = makePolicy('bot', [
          { service: 'github', paths: ['^/repos/.*', '^/issues/.*'] },
        ]);
        if (!policy) throw new Error('Policy setup failed');

        expect(
          evaluatePolicy(policy, { service: 'github', method: 'GET', path: '/repos/org/repo' })
            .allowed,
        ).toBe(true);
        expect(
          evaluatePolicy(policy, { service: 'github', method: 'GET', path: '/issues/1' }).allowed,
        ).toBe(true);
      });

      it('denies a path not matching any pattern', () => {
        const policy = makePolicy('bot', [{ service: 'github', paths: ['^/repos/.*'] }]);
        if (!policy) throw new Error('Policy setup failed');

        const result = evaluatePolicy(policy, {
          service: 'github',
          method: 'GET',
          path: '/admin/settings',
        });
        expect(result.allowed).toBe(false);
        expect(result.violation).toBe('path');
        expect(result.reason).toContain('/admin/settings');
      });

      it('allows any path when paths is not specified', () => {
        const policy = makePolicy('bot', [{ service: 'api' }]);
        if (!policy) throw new Error('Policy setup failed');

        expect(
          evaluatePolicy(policy, { service: 'api', method: 'GET', path: '/any/path/here' }).allowed,
        ).toBe(true);
        expect(evaluatePolicy(policy, { service: 'api', method: 'GET', path: '/' }).allowed).toBe(
          true,
        );
      });

      it('uses regex matching for paths', () => {
        // Build policy directly to avoid YAML escaping issues with backslashes
        const policy = {
          agent: 'bot',
          rules: [{ service: 'api', paths: ['^/v[12]/users/\\d+$'] }],
        };

        expect(
          evaluatePolicy(policy, { service: 'api', method: 'GET', path: '/v1/users/123' }).allowed,
        ).toBe(true);
        expect(
          evaluatePolicy(policy, { service: 'api', method: 'GET', path: '/v2/users/456' }).allowed,
        ).toBe(true);
        expect(
          evaluatePolicy(policy, { service: 'api', method: 'GET', path: '/v3/users/789' }).allowed,
        ).toBe(false);
        expect(
          evaluatePolicy(policy, { service: 'api', method: 'GET', path: '/v1/users/abc' }).allowed,
        ).toBe(false);
      });
    });

    // ─── Time Window Restrictions ─────────────────────────────────

    describe('time window restrictions', () => {
      it('allows request within time window', () => {
        const policy = makePolicy('bot', [
          {
            service: 'api',
            time_window: { start: '09:00', end: '18:00', timezone: 'UTC' },
          },
        ]);
        if (!policy) throw new Error('Policy setup failed');

        // Set 'now' to noon UTC
        const noon = new Date('2025-06-15T12:00:00Z');
        const result = evaluatePolicy(policy, {
          service: 'api',
          method: 'GET',
          path: '/data',
          now: noon,
        });
        expect(result.allowed).toBe(true);
      });

      it('denies request outside time window', () => {
        const policy = makePolicy('bot', [
          {
            service: 'api',
            time_window: { start: '09:00', end: '18:00', timezone: 'UTC' },
          },
        ]);
        if (!policy) throw new Error('Policy setup failed');

        // Set 'now' to 11pm UTC
        const lateNight = new Date('2025-06-15T23:00:00Z');
        const result = evaluatePolicy(policy, {
          service: 'api',
          method: 'GET',
          path: '/data',
          now: lateNight,
        });
        expect(result.allowed).toBe(false);
        expect(result.violation).toBe('time_window');
        expect(result.reason).toContain('09:00');
        expect(result.reason).toContain('18:00');
      });

      it('handles midnight-spanning windows', () => {
        const policy = makePolicy('bot', [
          {
            service: 'api',
            time_window: { start: '22:00', end: '06:00', timezone: 'UTC' },
          },
        ]);
        if (!policy) throw new Error('Policy setup failed');

        // 23:00 UTC should be allowed (after 22:00)
        expect(
          evaluatePolicy(policy, {
            service: 'api',
            method: 'GET',
            path: '/',
            now: new Date('2025-06-15T23:00:00Z'),
          }).allowed,
        ).toBe(true);

        // 03:00 UTC should be allowed (before 06:00)
        expect(
          evaluatePolicy(policy, {
            service: 'api',
            method: 'GET',
            path: '/',
            now: new Date('2025-06-15T03:00:00Z'),
          }).allowed,
        ).toBe(true);

        // 12:00 UTC should be denied (between 06:00 and 22:00)
        expect(
          evaluatePolicy(policy, {
            service: 'api',
            method: 'GET',
            path: '/',
            now: new Date('2025-06-15T12:00:00Z'),
          }).allowed,
        ).toBe(false);
      });

      it('allows any time when time_window is not specified', () => {
        const policy = makePolicy('bot', [{ service: 'api' }]);
        if (!policy) throw new Error('Policy setup failed');

        // Middle of the night should still work
        expect(
          evaluatePolicy(policy, {
            service: 'api',
            method: 'GET',
            path: '/',
            now: new Date('2025-06-15T03:00:00Z'),
          }).allowed,
        ).toBe(true);
      });
    });

    // ─── Combined Restrictions ────────────────────────────────────

    describe('combined restrictions', () => {
      it('enforces method + path together', () => {
        const policy = makePolicy('bot', [
          {
            service: 'github',
            methods: ['GET'],
            paths: ['^/repos/.*'],
          },
        ]);
        if (!policy) throw new Error('Policy setup failed');

        // Correct method + correct path = allowed
        expect(
          evaluatePolicy(policy, { service: 'github', method: 'GET', path: '/repos/org/repo' })
            .allowed,
        ).toBe(true);

        // Wrong method + correct path = denied
        const r1 = evaluatePolicy(policy, {
          service: 'github',
          method: 'DELETE',
          path: '/repos/org/repo',
        });
        expect(r1.allowed).toBe(false);
        expect(r1.violation).toBe('method');

        // Correct method + wrong path = denied
        const r2 = evaluatePolicy(policy, { service: 'github', method: 'GET', path: '/admin' });
        expect(r2.allowed).toBe(false);
        expect(r2.violation).toBe('path');
      });

      it('enforces method + path + time together', () => {
        const policy = makePolicy('bot', [
          {
            service: 'api',
            methods: ['POST'],
            paths: ['^/deploy/.*'],
            time_window: { start: '09:00', end: '17:00', timezone: 'UTC' },
          },
        ]);
        if (!policy) throw new Error('Policy setup failed');

        const businessHours = new Date('2025-06-15T14:00:00Z');
        const afterHours = new Date('2025-06-15T22:00:00Z');

        // All constraints met
        expect(
          evaluatePolicy(policy, {
            service: 'api',
            method: 'POST',
            path: '/deploy/prod',
            now: businessHours,
          }).allowed,
        ).toBe(true);

        // Wrong time
        expect(
          evaluatePolicy(policy, {
            service: 'api',
            method: 'POST',
            path: '/deploy/prod',
            now: afterHours,
          }).allowed,
        ).toBe(false);
      });

      it('allows request if ANY matching rule permits it', () => {
        // Two rules for same service — one read-only, one for a specific path
        const yaml = `
agent: hybrid-bot
rules:
  - service: github
    methods: [GET]
  - service: github
    methods: [POST]
    paths:
      - "^/repos/.*/issues$"
`;
        const result = parsePolicy(yaml);
        if (!result.policy) throw new Error('Policy setup failed');

        // GET anything — allowed by first rule
        expect(
          evaluatePolicy(result.policy, {
            service: 'github',
            method: 'GET',
            path: '/repos/org/repo/pulls',
          }).allowed,
        ).toBe(true);

        // POST to /repos/x/issues — allowed by second rule
        expect(
          evaluatePolicy(result.policy, {
            service: 'github',
            method: 'POST',
            path: '/repos/org/repo/issues',
          }).allowed,
        ).toBe(true);

        // POST to /admin — not allowed by either rule
        expect(
          evaluatePolicy(result.policy, {
            service: 'github',
            method: 'POST',
            path: '/admin',
          }).allowed,
        ).toBe(false);
      });
    });

    // ─── Edge Cases ──────────────────────────────────────────────

    describe('edge cases', () => {
      it('returns the matched rule when allowed', () => {
        const policy = makePolicy('bot', [{ service: 'slack', methods: ['POST'] }]);
        if (!policy) throw new Error('Policy setup failed');

        const result = evaluatePolicy(policy, {
          service: 'slack',
          method: 'POST',
          path: '/api/chat.postMessage',
        });
        expect(result.allowed).toBe(true);
        expect(result.matchedRule).toBeDefined();
        expect(result.matchedRule?.service).toBe('slack');
      });

      it('returns the violated rule and reason when denied', () => {
        const policy = makePolicy('bot', [{ service: 'slack', methods: ['GET'] }]);
        if (!policy) throw new Error('Policy setup failed');

        const result = evaluatePolicy(policy, {
          service: 'slack',
          method: 'DELETE',
          path: '/api/chat.delete',
        });
        expect(result.allowed).toBe(false);
        expect(result.matchedRule).toBeDefined();
        expect(result.reason).toBeDefined();
        expect(result.violation).toBeDefined();
      });

      it('handles empty path', () => {
        const policy = makePolicy('bot', [{ service: 'api', paths: ['^/$'] }]);
        if (!policy) throw new Error('Policy setup failed');

        expect(evaluatePolicy(policy, { service: 'api', method: 'GET', path: '/' }).allowed).toBe(
          true,
        );
        expect(
          evaluatePolicy(policy, { service: 'api', method: 'GET', path: '/other' }).allowed,
        ).toBe(false);
      });
    });
  });
});
