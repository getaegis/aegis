/**
 * Aegis Logger — structured logging with pino.
 *
 * Central logger factory for all Aegis modules. Provides:
 * - Structured JSON output in production, pretty-print in development
 * - Declarative field-level redaction (secrets, tokens, passwords)
 * - Pattern-based scrubbing for credential-like strings in log values
 * - Request correlation IDs via child loggers
 * - stderr output support (required for MCP stdio transport)
 *
 * SECURITY: This is a security product — secrets must NEVER appear in logs.
 * The logger enforces this through three layers:
 *   1. Pino's `redact` option censors known sensitive field paths
 *   2. Custom serializers scrub credential-like patterns from string values
 *   3. The `safeMeta()` helper strips sensitive fields from ad-hoc objects
 */

import { randomUUID } from 'node:crypto';
import pino from 'pino';

// ─── Types ───────────────────────────────────────────────────────

export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'fatal' | 'silent';

export interface LoggerOptions {
  /** Minimum log level (default: 'info') */
  level?: LogLevel;
  /** Module name — appears as `module` field in every log entry (e.g. 'gate', 'mcp', 'vault') */
  module?: string;
  /** Use pretty-print instead of JSON (default: auto-detect from NODE_ENV) */
  pretty?: boolean;
  /** Write to stderr instead of stdout (required for MCP stdio transport) */
  stderr?: boolean;
}

// ─── Redaction ───────────────────────────────────────────────────

/**
 * Field paths that are always redacted from log output.
 * Uses pino's path syntax — supports wildcards and nested paths.
 */
const REDACT_PATHS: string[] = [
  // Direct secret fields
  'secret',
  'password',
  'masterKey',
  'master_key',
  'token',
  'apiKey',
  'api_key',
  'accessToken',
  'access_token',
  'refreshToken',
  'refresh_token',
  'clientSecret',
  'client_secret',

  // Nested in objects
  '*.secret',
  '*.password',
  '*.masterKey',
  '*.master_key',
  '*.token',
  '*.apiKey',
  '*.api_key',
  '*.accessToken',
  '*.access_token',

  // HTTP headers that carry credentials
  'headers.authorization',
  'headers.Authorization',
  'headers.x-api-key',
  'headers.X-API-Key',
  'headers.x-aegis-agent',
  'headers.X-Aegis-Agent',
  'headers.cookie',
  'headers.Cookie',
  'headers.set-cookie',
  'headers.Set-Cookie',
  'headers.proxy-authorization',
  'headers.Proxy-Authorization',

  // Credential object fields
  'credential.secret',
  'credential.password',
  'credential.token',
];

// ─── Pattern Scrubbing ──────────────────────────────────────────

/**
 * Patterns that look like credentials in arbitrary string values.
 * These catch secrets that end up in unexpected places (error messages, URLs, etc.).
 */
const CREDENTIAL_PATTERNS: RegExp[] = [
  // Bearer tokens
  /Bearer\s+[A-Za-z0-9\-._~+/]+=*/g,
  // Basic auth
  /Basic\s+[A-Za-z0-9+/]+=*/g,
  // Common API key formats (sk-, pk-, key-, etc.)
  /\b(sk|pk|key|api|token|secret|password)[-_][A-Za-z0-9\-._]{16,}\b/gi,
  // AWS-style keys
  /\b(AKIA|ASIA)[A-Z0-9]{16}\b/g,
  // Long hex strings (32+ chars — likely keys/tokens)
  /\b[0-9a-f]{32,}\b/gi,
  // JWT-like patterns (three dot-separated base64 segments)
  /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
  // Aegis agent tokens
  /\baegis_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_[0-9a-f]+\b/g,
];

/**
 * Scrub credential-like patterns from a string value.
 * Replaces matches with [REDACTED] to prevent accidental exposure.
 */
export function scrubString(value: string): string {
  let result = value;
  for (const pattern of CREDENTIAL_PATTERNS) {
    // Reset lastIndex for global regexes
    pattern.lastIndex = 0;
    result = result.replace(pattern, '[REDACTED]');
  }
  return result;
}

/**
 * Strip sensitive fields from an arbitrary object before logging.
 * Use this for ad-hoc metadata objects that aren't covered by pino's redact paths.
 */
export function safeMeta(obj: Record<string, unknown>): Record<string, unknown> {
  const sensitiveKeys = new Set([
    'secret',
    'password',
    'masterkey',
    'master_key',
    'token',
    'apikey',
    'api_key',
    'accesstoken',
    'access_token',
    'refreshtoken',
    'refresh_token',
    'clientsecret',
    'client_secret',
    'authorization',
    'cookie',
  ]);

  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (sensitiveKeys.has(key.toLowerCase())) {
      result[key] = '[REDACTED]';
    } else if (typeof value === 'string') {
      result[key] = scrubString(value);
    } else if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      result[key] = safeMeta(value as Record<string, unknown>);
    } else {
      result[key] = value;
    }
  }
  return result;
}

// ─── Logger Factory ─────────────────────────────────────────────

/**
 * Create a pino logger instance for an Aegis module.
 *
 * @example
 * ```ts
 * const logger = createLogger({ module: 'gate', level: 'debug' });
 * logger.info({ service: 'slack', method: 'GET' }, 'Request proxied');
 *
 * // Child logger with request correlation ID
 * const reqLogger = logger.child({ requestId: generateRequestId() });
 * reqLogger.info({ status: 200 }, 'Response sent');
 * ```
 */
export function createLogger(options: LoggerOptions = {}): pino.Logger {
  const { level = 'info', module: moduleName, pretty, stderr = false } = options;

  // Auto-detect pretty mode from NODE_ENV unless explicitly set
  const usePretty = pretty ?? process.env.NODE_ENV !== 'production';

  const pinoOptions: pino.LoggerOptions = {
    level,
    redact: {
      paths: REDACT_PATHS,
      censor: '[REDACTED]',
    },
    // Add the module name as a base field on every log entry
    ...(moduleName ? { base: { module: moduleName } } : { base: {} }),
    // Use ISO timestamps for consistency
    timestamp: pino.stdTimeFunctions.isoTime,
    formatters: {
      level(label: string) {
        return { level: label };
      },
    },
  };

  // Destination: stderr (fd 2) or stdout (fd 1)
  const fd = stderr ? 2 : 1;

  if (usePretty) {
    // Pretty-print for development — human-readable output
    pinoOptions.transport = {
      target: 'pino-pretty',
      options: {
        colorize: true,
        translateTime: 'HH:MM:ss.l',
        ignore: 'pid,hostname',
        destination: fd,
      },
    };
    return pino(pinoOptions);
  }

  // Production: JSON to stdout/stderr
  const destination = pino.destination({ fd, sync: false });
  return pino(pinoOptions, destination);
}

// ─── Correlation IDs ────────────────────────────────────────────

/**
 * Generate a unique request correlation ID.
 * Included in all log entries for a given request, and stored in Ledger records.
 */
export function generateRequestId(): string {
  return randomUUID();
}
