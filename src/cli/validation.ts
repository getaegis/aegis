/**
 * CLI input validation helpers.
 *
 * Pure functions that validate user-provided CLI flags and exit with a
 * descriptive error when the input is invalid.  Extracted from cli.ts so
 * they can be unit-tested independently.
 */

// ─── Constants ───────────────────────────────────────────────────

export const IDENTIFIER_RE = /^[a-zA-Z0-9_-]+$/;

export const VALID_AUTH_TYPES = ['bearer', 'header', 'basic', 'query'] as const;
export const VALID_BODY_INSPECTION_MODES = ['off', 'warn', 'block'] as const;
export const VALID_POLICY_MODES = ['enforce', 'dry-run', 'off'] as const;
export const VALID_LOG_LEVELS = ['debug', 'info', 'warn', 'error'] as const;
export const VALID_MCP_TRANSPORTS = ['stdio', 'streamable-http'] as const;

// ─── Validators ──────────────────────────────────────────────────

/** Validate an identifier (name, service, etc.) used as a DB key or URL path segment. */
export function validateIdentifier(value: string, fieldName: string): void {
  if (!value || !IDENTIFIER_RE.test(value)) {
    console.error(
      `\n✗ Invalid ${fieldName}: "${value}"\n  Must contain only letters, numbers, hyphens, and underscores.\n`,
    );
    process.exit(1);
  }
}

/** Validate a value is one of the allowed enum values. */
export function validateEnum<T extends string>(
  value: string,
  allowed: readonly T[],
  fieldName: string,
): T {
  if (!allowed.includes(value as T)) {
    console.error(
      `\n✗ Invalid ${fieldName}: "${value}"\n  Must be one of: ${allowed.join(', ')}\n`,
    );
    process.exit(1);
  }
  return value as T;
}

/** Validate a port number (1–65535). */
export function validatePort(value: number, fieldName: string): void {
  if (Number.isNaN(value) || !Number.isFinite(value) || value < 1 || value > 65535) {
    console.error(`\n✗ Invalid ${fieldName}: must be a number between 1 and 65535.\n`);
    process.exit(1);
  }
}

/** Validate a positive integer. */
export function validatePositiveInt(value: number, fieldName: string): void {
  if (Number.isNaN(value) || !Number.isFinite(value) || value < 1 || !Number.isInteger(value)) {
    console.error(`\n✗ Invalid ${fieldName}: must be a positive integer.\n`);
    process.exit(1);
  }
}

/** Validate a non-negative float. */
export function validateNonNegativeFloat(value: number, fieldName: string): void {
  if (Number.isNaN(value) || !Number.isFinite(value) || value < 0) {
    console.error(`\n✗ Invalid ${fieldName}: must be a non-negative number.\n`);
    process.exit(1);
  }
}

/** Validate a rate limit string (e.g. 100/min) early, before storing. */
export function validateRateLimit(value: string): void {
  // Re-uses the same regex from rate-limiter.ts
  const match = value.match(/^(\d+)\/(sec(?:ond)?|min(?:ute)?|hr|hour|day)$/i);
  if (!match) {
    console.error(
      `\n✗ Invalid rate limit: "${value}"\n  Expected format: <number>/<unit> (e.g. 100/min, 1000/hour, 10/sec)\n`,
    );
    process.exit(1);
  }
  const count = parseInt(match[1], 10);
  if (count <= 0) {
    console.error(`\n✗ Invalid rate limit: count must be positive.\n`);
    process.exit(1);
  }
}

/** Validate a comma-separated domain list. */
export function validateDomains(raw: string): string[] {
  const domains = raw
    .split(',')
    .map((d) => d.trim())
    .filter((d) => d.length > 0);
  if (domains.length === 0) {
    console.error(`\n✗ At least one valid domain is required.\n`);
    process.exit(1);
  }
  for (const domain of domains) {
    // Allow wildcards like *.slack.com — basic sanity check
    if (!/^[a-zA-Z0-9.*_-]+(\.[a-zA-Z0-9.*_-]+)*$/.test(domain)) {
      console.error(
        `\n✗ Invalid domain: "${domain}"\n  Domains must be valid hostnames (e.g. api.slack.com, *.example.com)\n`,
      );
      process.exit(1);
    }
  }
  return domains;
}

/** Validate an ISO date string. */
export function validateIsoDate(value: string, fieldName: string): void {
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) {
    console.error(
      `\n✗ Invalid ${fieldName}: "${value}"\n  Expected ISO 8601 format (e.g. 2026-01-01, 2026-01-01T00:00:00Z)\n`,
    );
    process.exit(1);
  }
}

// ─── Formatting ──────────────────────────────────────────────────

/**
 * Convert a UTC timestamp from SQLite (e.g. "2026-03-09 00:31:38") to
 * the user's local time string.  SQLite's datetime('now') stores UTC but
 * omits the 'Z' suffix, so we append it before parsing so JavaScript's
 * Date constructor treats it as UTC rather than local.
 */
export function localTime(utcTimestamp: string): string {
  const ts = utcTimestamp.endsWith('Z') ? utcTimestamp : `${utcTimestamp}Z`;
  return new Date(ts).toLocaleString();
}
