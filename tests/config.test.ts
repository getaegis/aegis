import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  type AegisConfigFile,
  findConfigFile,
  parseConfigFile,
  validateConfigFile,
} from '../src/config.js';

// ─── findConfigFile ─────────────────────────────────────────────

describe('findConfigFile', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-config-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns null when no config file exists', () => {
    expect(findConfigFile(tmpDir)).toBeNull();
  });

  it('finds aegis.config.yaml', () => {
    fs.writeFileSync(path.join(tmpDir, 'aegis.config.yaml'), 'gate:\n  port: 3100\n');
    const result = findConfigFile(tmpDir);
    expect(result).toBe(path.join(tmpDir, 'aegis.config.yaml'));
  });

  it('finds aegis.config.yml', () => {
    fs.writeFileSync(path.join(tmpDir, 'aegis.config.yml'), 'gate:\n  port: 3100\n');
    const result = findConfigFile(tmpDir);
    expect(result).toBe(path.join(tmpDir, 'aegis.config.yml'));
  });

  it('prefers .yaml over .yml', () => {
    fs.writeFileSync(path.join(tmpDir, 'aegis.config.yaml'), 'gate:\n  port: 3100\n');
    fs.writeFileSync(path.join(tmpDir, 'aegis.config.yml'), 'gate:\n  port: 4100\n');
    const result = findConfigFile(tmpDir);
    expect(result).toBe(path.join(tmpDir, 'aegis.config.yaml'));
  });
});

// ─── parseConfigFile ────────────────────────────────────────────

describe('parseConfigFile', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-config-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('parses a minimal config file', () => {
    const file = path.join(tmpDir, 'aegis.config.yaml');
    fs.writeFileSync(file, 'gate:\n  port: 3100\n');
    const result = parseConfigFile(file);
    expect(result.gate?.port).toBe(3100);
  });

  it('returns empty object for empty file', () => {
    const file = path.join(tmpDir, 'aegis.config.yaml');
    fs.writeFileSync(file, '');
    const result = parseConfigFile(file);
    expect(result).toEqual({});
  });

  it('parses a complete config file', () => {
    const file = path.join(tmpDir, 'aegis.config.yaml');
    fs.writeFileSync(
      file,
      `gate:
  port: 4100
  tls:
    cert: ./certs/cert.pem
    key: ./certs/key.pem
  require_agent_auth: true
  policy_mode: dry-run
  policies_dir: ./policies

vault:
  name: production
  data_dir: ./.aegis

observability:
  log_level: debug
  log_format: json
  metrics: true
  dashboard:
    enabled: true
    port: 8080

mcp:
  transport: streamable-http
  port: 3300

webhooks:
  - url: https://hooks.example.com/aegis
    secret: webhook-secret
    events:
      - blocked_request
      - credential_expiry
`,
    );

    const result = parseConfigFile(file);

    expect(result.gate?.port).toBe(4100);
    expect(result.gate?.tls?.cert).toBe('./certs/cert.pem');
    expect(result.gate?.tls?.key).toBe('./certs/key.pem');
    expect(result.gate?.require_agent_auth).toBe(true);
    expect(result.gate?.policy_mode).toBe('dry-run');
    expect(result.gate?.policies_dir).toBe('./policies');

    expect(result.vault?.name).toBe('production');
    expect(result.vault?.data_dir).toBe('./.aegis');

    expect(result.observability?.log_level).toBe('debug');
    expect(result.observability?.log_format).toBe('json');
    expect(result.observability?.metrics).toBe(true);
    expect(result.observability?.dashboard?.enabled).toBe(true);
    expect(result.observability?.dashboard?.port).toBe(8080);

    expect(result.mcp?.transport).toBe('streamable-http');
    expect(result.mcp?.port).toBe(3300);

    expect(result.webhooks).toHaveLength(1);
    expect(result.webhooks?.[0].url).toBe('https://hooks.example.com/aegis');
    expect(result.webhooks?.[0].secret).toBe('webhook-secret');
    expect(result.webhooks?.[0].events).toEqual(['blocked_request', 'credential_expiry']);
  });

  it('throws on invalid YAML', () => {
    const file = path.join(tmpDir, 'aegis.config.yaml');
    fs.writeFileSync(file, '{ not: valid: yaml: [');
    expect(() => parseConfigFile(file)).toThrow();
  });

  it('throws when file is not a mapping', () => {
    const file = path.join(tmpDir, 'aegis.config.yaml');
    fs.writeFileSync(file, '- item1\n- item2\n');
    expect(() => parseConfigFile(file)).toThrow('must be a YAML mapping');
  });
});

// ─── validateConfigFile ─────────────────────────────────────────

describe('validateConfigFile', () => {
  it('returns no errors for empty config', () => {
    const errors = validateConfigFile({});
    expect(errors).toHaveLength(0);
  });

  it('returns no errors for valid minimal config', () => {
    const config: AegisConfigFile = {
      gate: { port: 3100 },
    };
    expect(validateConfigFile(config)).toHaveLength(0);
  });

  it('returns no errors for fully valid config', () => {
    const config: AegisConfigFile = {
      gate: {
        port: 3100,
        tls: { cert: './cert.pem', key: './key.pem' },
        require_agent_auth: true,
        policy_mode: 'enforce',
        policies_dir: './policies',
      },
      vault: { name: 'default', data_dir: './.aegis' },
      observability: {
        log_level: 'info',
        log_format: 'pretty',
        metrics: false,
        dashboard: { enabled: true, port: 3200 },
      },
      mcp: { transport: 'stdio', port: 3200 },
      webhooks: [
        {
          url: 'https://hooks.example.com/notify',
          events: ['blocked_request'],
        },
      ],
    };
    expect(validateConfigFile(config)).toHaveLength(0);
  });

  // Gate validation

  describe('gate validation', () => {
    it('rejects invalid port (too low)', () => {
      const errors = validateConfigFile({ gate: { port: 0 } });
      expect(errors).toHaveLength(1);
      expect(errors[0].path).toBe('gate.port');
    });

    it('rejects invalid port (too high)', () => {
      const errors = validateConfigFile({ gate: { port: 70000 } });
      expect(errors).toHaveLength(1);
      expect(errors[0].path).toBe('gate.port');
    });

    it('rejects invalid port (not a number)', () => {
      const errors = validateConfigFile({ gate: { port: 'abc' as unknown as number } });
      expect(errors).toHaveLength(1);
      expect(errors[0].path).toBe('gate.port');
    });

    it('rejects TLS without cert', () => {
      const errors = validateConfigFile({
        gate: { tls: { cert: '', key: './key.pem' } },
      });
      expect(errors.some((e) => e.path === 'gate.tls.cert')).toBe(true);
    });

    it('rejects TLS without key', () => {
      const errors = validateConfigFile({
        gate: { tls: { cert: './cert.pem', key: '' } },
      });
      expect(errors.some((e) => e.path === 'gate.tls.key')).toBe(true);
    });

    it('rejects non-boolean require_agent_auth', () => {
      const errors = validateConfigFile({
        gate: { require_agent_auth: 'yes' as unknown as boolean },
      });
      expect(errors).toHaveLength(1);
      expect(errors[0].path).toBe('gate.require_agent_auth');
    });

    it('rejects invalid policy_mode', () => {
      const errors = validateConfigFile({
        gate: { policy_mode: 'strict' as 'enforce' },
      });
      expect(errors).toHaveLength(1);
      expect(errors[0].path).toBe('gate.policy_mode');
    });

    it('accepts all valid policy modes', () => {
      for (const mode of ['enforce', 'dry-run', 'off'] as const) {
        expect(validateConfigFile({ gate: { policy_mode: mode } })).toHaveLength(0);
      }
    });

    it('rejects non-string policies_dir', () => {
      const errors = validateConfigFile({
        gate: { policies_dir: 123 as unknown as string },
      });
      expect(errors).toHaveLength(1);
      expect(errors[0].path).toBe('gate.policies_dir');
    });
  });

  // Vault validation

  describe('vault validation', () => {
    it('rejects non-string name', () => {
      const errors = validateConfigFile({ vault: { name: 123 as unknown as string } });
      expect(errors).toHaveLength(1);
      expect(errors[0].path).toBe('vault.name');
    });

    it('rejects non-string data_dir', () => {
      const errors = validateConfigFile({ vault: { data_dir: true as unknown as string } });
      expect(errors).toHaveLength(1);
      expect(errors[0].path).toBe('vault.data_dir');
    });
  });

  // Observability validation

  describe('observability validation', () => {
    it('rejects invalid log_level', () => {
      const errors = validateConfigFile({
        observability: { log_level: 'verbose' as 'info' },
      });
      expect(errors).toHaveLength(1);
      expect(errors[0].path).toBe('observability.log_level');
    });

    it('accepts all valid log levels', () => {
      for (const level of ['debug', 'info', 'warn', 'error'] as const) {
        expect(validateConfigFile({ observability: { log_level: level } })).toHaveLength(0);
      }
    });

    it('rejects invalid log_format', () => {
      const errors = validateConfigFile({
        observability: { log_format: 'text' as 'json' },
      });
      expect(errors).toHaveLength(1);
      expect(errors[0].path).toBe('observability.log_format');
    });

    it('rejects non-boolean metrics', () => {
      const errors = validateConfigFile({
        observability: { metrics: 'yes' as unknown as boolean },
      });
      expect(errors).toHaveLength(1);
      expect(errors[0].path).toBe('observability.metrics');
    });

    it('rejects invalid dashboard port', () => {
      const errors = validateConfigFile({
        observability: { dashboard: { enabled: true, port: 99999 } },
      });
      expect(errors.some((e) => e.path === 'observability.dashboard.port')).toBe(true);
    });

    it('rejects non-boolean dashboard enabled', () => {
      const errors = validateConfigFile({
        observability: { dashboard: { enabled: 'yes' as unknown as boolean, port: 3200 } },
      });
      expect(errors.some((e) => e.path === 'observability.dashboard.enabled')).toBe(true);
    });
  });

  // MCP validation

  describe('mcp validation', () => {
    it('rejects invalid transport', () => {
      const errors = validateConfigFile({
        mcp: { transport: 'grpc' as 'stdio' },
      });
      expect(errors).toHaveLength(1);
      expect(errors[0].path).toBe('mcp.transport');
    });

    it('accepts all valid transports', () => {
      for (const transport of ['stdio', 'streamable-http'] as const) {
        expect(validateConfigFile({ mcp: { transport } })).toHaveLength(0);
      }
    });

    it('rejects invalid port', () => {
      const errors = validateConfigFile({
        mcp: { port: -1 },
      });
      expect(errors).toHaveLength(1);
      expect(errors[0].path).toBe('mcp.port');
    });
  });

  // Webhook validation

  describe('webhook validation', () => {
    it('rejects non-array webhooks', () => {
      const errors = validateConfigFile({
        webhooks: 'not-an-array' as unknown as AegisConfigFile['webhooks'],
      });
      expect(errors).toHaveLength(1);
      expect(errors[0].path).toBe('webhooks');
    });

    it('rejects webhook without url', () => {
      const errors = validateConfigFile({
        webhooks: [{ url: '', events: ['blocked_request'] }],
      });
      expect(errors).toHaveLength(1);
      expect(errors[0].path).toBe('webhooks[0].url');
    });

    it('rejects webhook with invalid url', () => {
      const errors = validateConfigFile({
        webhooks: [{ url: 'not-a-url', events: ['blocked_request'] }],
      });
      expect(errors).toHaveLength(1);
      expect(errors[0].path).toBe('webhooks[0].url');
    });

    it('rejects webhook with unknown event', () => {
      const errors = validateConfigFile({
        webhooks: [{ url: 'https://hooks.example.com/notify', events: ['unknown_event'] }],
      });
      expect(errors).toHaveLength(1);
      expect(errors[0].path).toBe('webhooks[0].events');
      expect(errors[0].message).toContain('unknown_event');
    });

    it('accepts valid webhook with all event types', () => {
      const allEvents = [
        'blocked_request',
        'credential_expiry',
        'rate_limit_exceeded',
        'agent_auth_failure',
        'body_inspection',
      ];
      const errors = validateConfigFile({
        webhooks: [{ url: 'https://hooks.example.com/notify', events: allEvents }],
      });
      expect(errors).toHaveLength(0);
    });

    it('rejects non-array events', () => {
      const errors = validateConfigFile({
        webhooks: [
          {
            url: 'https://hooks.example.com/notify',
            events: 'blocked_request' as unknown as string[],
          },
        ],
      });
      expect(errors).toHaveLength(1);
      expect(errors[0].path).toBe('webhooks[0].events');
    });

    it('validates multiple webhooks independently', () => {
      const errors = validateConfigFile({
        webhooks: [
          { url: 'https://valid.example.com/hook', events: ['blocked_request'] },
          { url: '', events: ['blocked_request'] },
        ],
      });
      expect(errors).toHaveLength(1);
      expect(errors[0].path).toBe('webhooks[1].url');
    });
  });

  // Multiple errors

  describe('multiple errors', () => {
    it('reports all validation errors at once', () => {
      const errors = validateConfigFile({
        gate: { port: 0, policy_mode: 'invalid' as 'enforce' },
        observability: { log_level: 'verbose' as 'info' },
        mcp: { transport: 'grpc' as 'stdio' },
      });
      expect(errors.length).toBeGreaterThanOrEqual(4);
    });
  });
});
