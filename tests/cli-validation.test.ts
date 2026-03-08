import type { MockInstance } from 'vitest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  IDENTIFIER_RE,
  VALID_AUTH_TYPES,
  VALID_BODY_INSPECTION_MODES,
  VALID_LOG_LEVELS,
  VALID_MCP_TRANSPORTS,
  VALID_POLICY_MODES,
  validateDomains,
  validateEnum,
  validateIdentifier,
  validateIsoDate,
  validateNonNegativeFloat,
  validatePort,
  validatePositiveInt,
  validateRateLimit,
} from '../src/cli/validation.js';

// All validators call process.exit(1) on invalid input — mock it to throw
// so tests can assert the failure path without terminating the process.
class ExitError extends Error {
  constructor(public code: number) {
    super(`process.exit(${code})`);
  }
}

describe('cli-validation', () => {
  let exitMock: MockInstance;
  let stderrMock: MockInstance;

  beforeEach(() => {
    exitMock = vi.spyOn(process, 'exit').mockImplementation((code) => {
      throw new ExitError(code as number);
    });
    stderrMock = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    exitMock.mockRestore();
    stderrMock.mockRestore();
  });

  // ─── Constants ─────────────────────────────────────────────────

  describe('constants', () => {
    it('IDENTIFIER_RE matches valid identifiers', () => {
      expect(IDENTIFIER_RE.test('my-service')).toBe(true);
      expect(IDENTIFIER_RE.test('my_service')).toBe(true);
      expect(IDENTIFIER_RE.test('MyService123')).toBe(true);
    });

    it('IDENTIFIER_RE rejects invalid identifiers', () => {
      expect(IDENTIFIER_RE.test('has space')).toBe(false);
      expect(IDENTIFIER_RE.test('has.dot')).toBe(false);
      expect(IDENTIFIER_RE.test('')).toBe(false);
    });

    it('VALID_AUTH_TYPES contains expected values', () => {
      expect(VALID_AUTH_TYPES).toEqual(['bearer', 'header', 'basic', 'query']);
    });

    it('VALID_BODY_INSPECTION_MODES contains expected values', () => {
      expect(VALID_BODY_INSPECTION_MODES).toEqual(['off', 'warn', 'block']);
    });

    it('VALID_POLICY_MODES contains expected values', () => {
      expect(VALID_POLICY_MODES).toEqual(['enforce', 'dry-run', 'off']);
    });

    it('VALID_LOG_LEVELS contains expected values', () => {
      expect(VALID_LOG_LEVELS).toEqual(['debug', 'info', 'warn', 'error']);
    });

    it('VALID_MCP_TRANSPORTS contains expected values', () => {
      expect(VALID_MCP_TRANSPORTS).toEqual(['stdio', 'streamable-http']);
    });
  });

  // ─── validateIdentifier ───────────────────────────────────────

  describe('validateIdentifier', () => {
    it('accepts simple names', () => {
      expect(() => validateIdentifier('my-service', 'name')).not.toThrow();
    });

    it('accepts names with underscores and numbers', () => {
      expect(() => validateIdentifier('api_key_2', 'name')).not.toThrow();
    });

    it('rejects empty string', () => {
      expect(() => validateIdentifier('', 'name')).toThrow(ExitError);
      expect(exitMock).toHaveBeenCalledWith(1);
    });

    it('rejects names with spaces', () => {
      expect(() => validateIdentifier('my service', 'name')).toThrow(ExitError);
    });

    it('rejects names with special characters', () => {
      expect(() => validateIdentifier('my@service', 'name')).toThrow(ExitError);
    });

    it('includes the field name in error output', () => {
      try {
        validateIdentifier('bad name!', 'service name');
      } catch {
        // expected
      }
      expect(stderrMock).toHaveBeenCalledWith(expect.stringContaining('service name'));
    });
  });

  // ─── validateEnum ─────────────────────────────────────────────

  describe('validateEnum', () => {
    it('accepts a valid enum value and returns it typed', () => {
      const result = validateEnum('bearer', VALID_AUTH_TYPES, 'auth type');
      expect(result).toBe('bearer');
    });

    it('accepts all valid values', () => {
      for (const v of VALID_AUTH_TYPES) {
        expect(validateEnum(v, VALID_AUTH_TYPES, 'auth type')).toBe(v);
      }
    });

    it('rejects unknown values', () => {
      expect(() => validateEnum('digest', VALID_AUTH_TYPES, 'auth type')).toThrow(ExitError);
    });

    it('includes allowed values in error output', () => {
      try {
        validateEnum('nope', VALID_POLICY_MODES, 'policy mode');
      } catch {
        // expected
      }
      expect(stderrMock).toHaveBeenCalledWith(expect.stringContaining('enforce, dry-run, off'));
    });
  });

  // ─── validatePort ─────────────────────────────────────────────

  describe('validatePort', () => {
    it('accepts valid ports', () => {
      expect(() => validatePort(1, 'port')).not.toThrow();
      expect(() => validatePort(80, 'port')).not.toThrow();
      expect(() => validatePort(3100, 'port')).not.toThrow();
      expect(() => validatePort(65535, 'port')).not.toThrow();
    });

    it('rejects port 0', () => {
      expect(() => validatePort(0, 'port')).toThrow(ExitError);
    });

    it('rejects negative ports', () => {
      expect(() => validatePort(-1, 'port')).toThrow(ExitError);
    });

    it('rejects ports > 65535', () => {
      expect(() => validatePort(65536, 'port')).toThrow(ExitError);
    });

    it('rejects NaN', () => {
      expect(() => validatePort(Number.NaN, 'port')).toThrow(ExitError);
    });

    it('rejects Infinity', () => {
      expect(() => validatePort(Number.POSITIVE_INFINITY, 'port')).toThrow(ExitError);
    });
  });

  // ─── validatePositiveInt ──────────────────────────────────────

  describe('validatePositiveInt', () => {
    it('accepts positive integers', () => {
      expect(() => validatePositiveInt(1, 'count')).not.toThrow();
      expect(() => validatePositiveInt(100, 'count')).not.toThrow();
      expect(() => validatePositiveInt(999999, 'count')).not.toThrow();
    });

    it('rejects zero', () => {
      expect(() => validatePositiveInt(0, 'count')).toThrow(ExitError);
    });

    it('rejects negative numbers', () => {
      expect(() => validatePositiveInt(-5, 'count')).toThrow(ExitError);
    });

    it('rejects floats', () => {
      expect(() => validatePositiveInt(1.5, 'count')).toThrow(ExitError);
    });

    it('rejects NaN', () => {
      expect(() => validatePositiveInt(Number.NaN, 'count')).toThrow(ExitError);
    });
  });

  // ─── validateNonNegativeFloat ─────────────────────────────────

  describe('validateNonNegativeFloat', () => {
    it('accepts zero', () => {
      expect(() => validateNonNegativeFloat(0, 'timeout')).not.toThrow();
    });

    it('accepts positive floats', () => {
      expect(() => validateNonNegativeFloat(0.5, 'timeout')).not.toThrow();
      expect(() => validateNonNegativeFloat(99.99, 'timeout')).not.toThrow();
    });

    it('accepts positive integers', () => {
      expect(() => validateNonNegativeFloat(10, 'timeout')).not.toThrow();
    });

    it('rejects negative numbers', () => {
      expect(() => validateNonNegativeFloat(-0.1, 'timeout')).toThrow(ExitError);
    });

    it('rejects NaN', () => {
      expect(() => validateNonNegativeFloat(Number.NaN, 'timeout')).toThrow(ExitError);
    });

    it('rejects Infinity', () => {
      expect(() => validateNonNegativeFloat(Number.POSITIVE_INFINITY, 'timeout')).toThrow(
        ExitError,
      );
    });
  });

  // ─── validateRateLimit ────────────────────────────────────────

  describe('validateRateLimit', () => {
    it('accepts valid rate limits', () => {
      expect(() => validateRateLimit('100/min')).not.toThrow();
      expect(() => validateRateLimit('10/sec')).not.toThrow();
      expect(() => validateRateLimit('5/second')).not.toThrow();
      expect(() => validateRateLimit('1000/hour')).not.toThrow();
      expect(() => validateRateLimit('500/hr')).not.toThrow();
      expect(() => validateRateLimit('10000/day')).not.toThrow();
      expect(() => validateRateLimit('200/minute')).not.toThrow();
    });

    it('rejects empty string', () => {
      expect(() => validateRateLimit('')).toThrow(ExitError);
    });

    it('rejects missing number', () => {
      expect(() => validateRateLimit('/min')).toThrow(ExitError);
    });

    it('rejects missing unit', () => {
      expect(() => validateRateLimit('100/')).toThrow(ExitError);
    });

    it('rejects unknown unit', () => {
      expect(() => validateRateLimit('100/week')).toThrow(ExitError);
    });

    it('rejects plain number without slash', () => {
      expect(() => validateRateLimit('100')).toThrow(ExitError);
    });

    it('rejects zero count', () => {
      expect(() => validateRateLimit('0/min')).toThrow(ExitError);
    });
  });

  // ─── validateDomains ──────────────────────────────────────────

  describe('validateDomains', () => {
    it('parses a single domain', () => {
      expect(validateDomains('api.slack.com')).toEqual(['api.slack.com']);
    });

    it('parses comma-separated domains', () => {
      expect(validateDomains('api.slack.com,hooks.slack.com')).toEqual([
        'api.slack.com',
        'hooks.slack.com',
      ]);
    });

    it('trims whitespace around domains', () => {
      expect(validateDomains('  api.slack.com , hooks.slack.com  ')).toEqual([
        'api.slack.com',
        'hooks.slack.com',
      ]);
    });

    it('accepts wildcard domains', () => {
      expect(validateDomains('*.slack.com')).toEqual(['*.slack.com']);
    });

    it('rejects empty input', () => {
      expect(() => validateDomains('')).toThrow(ExitError);
    });

    it('rejects only commas', () => {
      expect(() => validateDomains(',')).toThrow(ExitError);
    });

    it('rejects domains with invalid characters', () => {
      expect(() => validateDomains('api slack.com')).toThrow(ExitError);
    });

    it('rejects domains with paths', () => {
      expect(() => validateDomains('api.slack.com/path')).toThrow(ExitError);
    });
  });

  // ─── validateIsoDate ──────────────────────────────────────────

  describe('validateIsoDate', () => {
    it('accepts ISO date strings', () => {
      expect(() => validateIsoDate('2026-01-01', 'expiry')).not.toThrow();
    });

    it('accepts ISO datetime strings', () => {
      expect(() => validateIsoDate('2026-01-01T00:00:00Z', 'expiry')).not.toThrow();
    });

    it('accepts ISO datetime with timezone offset', () => {
      expect(() => validateIsoDate('2026-06-15T12:30:00+05:30', 'expiry')).not.toThrow();
    });

    it('rejects nonsense strings', () => {
      expect(() => validateIsoDate('not-a-date', 'expiry')).toThrow(ExitError);
    });

    it('rejects empty string', () => {
      expect(() => validateIsoDate('', 'expiry')).toThrow(ExitError);
    });

    it('includes field name in error output', () => {
      try {
        validateIsoDate('bad', 'expiry date');
      } catch {
        // expected
      }
      expect(stderrMock).toHaveBeenCalledWith(expect.stringContaining('expiry date'));
    });
  });
});
