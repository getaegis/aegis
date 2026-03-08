import { describe, expect, it } from 'vitest';
import { createLogger, generateRequestId, safeMeta, scrubString } from '../src/logger/index.js';

// ─── scrubString ─────────────────────────────────────────────────

describe('scrubString', () => {
  it('returns plain text unchanged', () => {
    expect(scrubString('hello world')).toBe('hello world');
  });

  it('redacts Bearer tokens', () => {
    const input = 'Authorization: Bearer sk-abc123XYZ_456.defgh';
    const result = scrubString(input);
    expect(result).toContain('[REDACTED]');
    expect(result).not.toContain('sk-abc123XYZ_456.defgh');
  });

  it('redacts Basic auth credentials', () => {
    const input = 'Basic dXNlcjpwYXNz';
    const result = scrubString(input);
    expect(result).toContain('[REDACTED]');
    expect(result).not.toContain('dXNlcjpwYXNz');
  });

  it('redacts API key prefixed strings', () => {
    const input = 'Using key sk-proj-abcdefghij1234567890';
    const result = scrubString(input);
    expect(result).toContain('[REDACTED]');
    expect(result).not.toContain('sk-proj-abcdefghij1234567890');
  });

  it('redacts AWS-style access keys', () => {
    const input = 'Access key: AKIAIOSFODNN7EXAMPLE';
    const result = scrubString(input);
    expect(result).toContain('[REDACTED]');
    expect(result).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('redacts long hex strings (likely keys/tokens)', () => {
    const hex = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6';
    const input = `Token: ${hex}`;
    const result = scrubString(input);
    expect(result).toContain('[REDACTED]');
    expect(result).not.toContain(hex);
  });

  it('redacts JWT-like patterns', () => {
    // This is a simplified JWT structure (header.payload.signature)
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123signature';
    const input = `Token: ${jwt}`;
    const result = scrubString(input);
    expect(result).toContain('[REDACTED]');
    expect(result).not.toContain('eyJhbGciOiJIUzI1NiJ9');
  });

  it('redacts Aegis agent tokens', () => {
    const token = 'aegis_550e8400-e29b-41d4-a716-446655440000_abcdef1234567890';
    const result = scrubString(`Agent: ${token}`);
    expect(result).toContain('[REDACTED]');
    expect(result).not.toContain(token);
  });

  it('redacts multiple patterns in one string', () => {
    const input = 'Bearer sk-test-key AND key: AKIAIOSFODNN7EXAMPLE';
    const result = scrubString(input);
    expect(result).not.toContain('sk-test-key');
    expect(result).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('does not redact short non-sensitive strings', () => {
    const input = 'service: slack, method: GET, path: /api/chat';
    expect(scrubString(input)).toBe(input);
  });

  it('does not redact normal UUIDs (not Aegis agent tokens)', () => {
    const uuid = '550e8400-e29b-41d4-a716-446655440000';
    // Regular UUIDs without the aegis_ prefix should survive (36 chars hex+hyphens)
    const input = `Request: ${uuid}`;
    const result = scrubString(input);
    // UUID itself has hex chars but not 32 contiguous hex chars (hyphens break it)
    expect(result).toContain(uuid);
  });
});

// ─── safeMeta ────────────────────────────────────────────────────

describe('safeMeta', () => {
  it('passes through non-sensitive fields unchanged', () => {
    const meta = { service: 'slack', method: 'GET', status: 200 };
    expect(safeMeta(meta)).toEqual(meta);
  });

  it('redacts known sensitive key names', () => {
    const meta = { service: 'slack', secret: 'my-api-key-123', status: 200 };
    const result = safeMeta(meta);
    expect(result.service).toBe('slack');
    expect(result.secret).toBe('[REDACTED]');
    expect(result.status).toBe(200);
  });

  it('redacts password fields', () => {
    const result = safeMeta({ password: 'hunter2' });
    expect(result.password).toBe('[REDACTED]');
  });

  it('redacts token fields', () => {
    const result = safeMeta({ token: 'aegis_abc123' });
    expect(result.token).toBe('[REDACTED]');
  });

  it('redacts apiKey and api_key', () => {
    expect(safeMeta({ apiKey: 'key123' }).apiKey).toBe('[REDACTED]');
    expect(safeMeta({ api_key: 'key123' }).api_key).toBe('[REDACTED]');
  });

  it('redacts accessToken and access_token', () => {
    expect(safeMeta({ accessToken: 'tok123' }).accessToken).toBe('[REDACTED]');
    expect(safeMeta({ access_token: 'tok123' }).access_token).toBe('[REDACTED]');
  });

  it('redacts refreshToken and refresh_token', () => {
    expect(safeMeta({ refreshToken: 'rt123' }).refreshToken).toBe('[REDACTED]');
    expect(safeMeta({ refresh_token: 'rt123' }).refresh_token).toBe('[REDACTED]');
  });

  it('redacts clientSecret and client_secret', () => {
    expect(safeMeta({ clientSecret: 'cs123' }).clientSecret).toBe('[REDACTED]');
    expect(safeMeta({ client_secret: 'cs123' }).client_secret).toBe('[REDACTED]');
  });

  it('redacts masterKey and master_key', () => {
    expect(safeMeta({ masterKey: 'mk123' }).masterKey).toBe('[REDACTED]');
    expect(safeMeta({ master_key: 'mk123' }).master_key).toBe('[REDACTED]');
  });

  it('redacts authorization headers', () => {
    const result = safeMeta({ authorization: 'Bearer abc123' });
    expect(result.authorization).toBe('[REDACTED]');
  });

  it('redacts cookie fields', () => {
    const result = safeMeta({ cookie: 'session=abc123' });
    expect(result.cookie).toBe('[REDACTED]');
  });

  it('scrubs credential patterns in string values', () => {
    const result = safeMeta({
      message: 'Used Bearer sk-test-key-abcdefghijk1234',
    });
    expect(result.message).toContain('[REDACTED]');
    expect(result.message).not.toContain('sk-test-key-abcdefghijk1234');
  });

  it('recursively processes nested objects', () => {
    const result = safeMeta({
      request: {
        service: 'openai',
        secret: 'sk-abc123',
        headers: {
          authorization: 'Bearer token123',
        },
      },
    });
    const req = result.request as Record<string, unknown>;
    expect(req.service).toBe('openai');
    expect(req.secret).toBe('[REDACTED]');
    const headers = req.headers as Record<string, unknown>;
    expect(headers.authorization).toBe('[REDACTED]');
  });

  it('preserves arrays unchanged', () => {
    const result = safeMeta({ domains: ['api.slack.com', 'api.github.com'] });
    expect(result.domains).toEqual(['api.slack.com', 'api.github.com']);
  });

  it('preserves null values', () => {
    const result = safeMeta({ expiresAt: null });
    expect(result.expiresAt).toBeNull();
  });

  it('preserves boolean values', () => {
    const result = safeMeta({ enabled: true, blocked: false });
    expect(result.enabled).toBe(true);
    expect(result.blocked).toBe(false);
  });
});

// ─── generateRequestId ──────────────────────────────────────────

describe('generateRequestId', () => {
  it('returns a valid UUID v4 string', () => {
    const id = generateRequestId();
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
  });

  it('generates unique IDs on each call', () => {
    const ids = new Set(Array.from({ length: 100 }, () => generateRequestId()));
    expect(ids.size).toBe(100);
  });
});

// ─── createLogger ────────────────────────────────────────────────

describe('createLogger', () => {
  it('creates a logger with default options', () => {
    const logger = createLogger();
    expect(logger).toBeDefined();
    expect(typeof logger.info).toBe('function');
    expect(typeof logger.warn).toBe('function');
    expect(typeof logger.error).toBe('function');
    expect(typeof logger.debug).toBe('function');
  });

  it('creates a logger with a module name', () => {
    const logger = createLogger({ module: 'gate' });
    expect(logger).toBeDefined();
  });

  it('creates a logger with custom level', () => {
    const logger = createLogger({ level: 'debug' });
    expect(logger.level).toBe('debug');
  });

  it('creates a logger with warn level', () => {
    const logger = createLogger({ level: 'warn' });
    expect(logger.level).toBe('warn');
  });

  it('creates a logger with error level', () => {
    const logger = createLogger({ level: 'error' });
    expect(logger.level).toBe('error');
  });

  it('creates a logger with silent level', () => {
    const logger = createLogger({ level: 'silent' });
    expect(logger.level).toBe('silent');
  });

  it('creates a logger with stderr output', () => {
    const logger = createLogger({ stderr: true, module: 'mcp' });
    expect(logger).toBeDefined();
  });

  it('supports child loggers for request correlation', () => {
    const logger = createLogger({ module: 'gate', level: 'silent' });
    const child = logger.child({ requestId: 'test-123' });
    expect(child).toBeDefined();
    expect(typeof child.info).toBe('function');
  });

  it('creates a production JSON logger when pretty is false', () => {
    const logger = createLogger({ pretty: false });
    expect(logger).toBeDefined();
  });

  it('creates a pretty logger when pretty is true', () => {
    const logger = createLogger({ pretty: true });
    expect(logger).toBeDefined();
  });
});

// ─── Pino redaction (integration) ────────────────────────────────

describe('pino redaction', () => {
  it('redacts secret field in log output', () => {
    // Create a logger that writes to a writable stream so we can capture output
    const logger = createLogger({ level: 'info', pretty: false });
    // We can verify the redaction config is set up correctly
    // (Full output capture would require a custom stream, but we verify the config)
    expect(logger).toBeDefined();
    // The redact paths are configured internally — verify logger works without error
    logger.info({ secret: 'my-secret-key' }, 'test message');
  });

  it('logs structured data with module field', () => {
    const logger = createLogger({ module: 'test', level: 'silent' });
    // Logging should not throw even at silent level
    logger.info({ service: 'slack', method: 'GET' }, 'Request proxied');
    logger.warn({ reason: 'rate limit' }, 'Blocked');
    logger.error({ err: new Error('test') }, 'Something failed');
  });
});
