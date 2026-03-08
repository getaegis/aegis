import { describe, expect, it } from 'vitest';
import { formatRateLimit, parseRateLimit, RateLimiter } from '../src/gate/rate-limiter.js';

describe('rate-limiter', () => {
  // ─── parseRateLimit ───────────────────────────────────────────────

  describe('parseRateLimit', () => {
    it('parses requests per second', () => {
      const limit = parseRateLimit('10/sec');
      expect(limit.maxRequests).toBe(10);
      expect(limit.windowMs).toBe(1_000);
    });

    it('parses requests per second (full word)', () => {
      const limit = parseRateLimit('5/second');
      expect(limit.maxRequests).toBe(5);
      expect(limit.windowMs).toBe(1_000);
    });

    it('parses requests per minute', () => {
      const limit = parseRateLimit('100/min');
      expect(limit.maxRequests).toBe(100);
      expect(limit.windowMs).toBe(60_000);
    });

    it('parses requests per minute (full word)', () => {
      const limit = parseRateLimit('200/minute');
      expect(limit.maxRequests).toBe(200);
      expect(limit.windowMs).toBe(60_000);
    });

    it('parses requests per hour', () => {
      const limit = parseRateLimit('1000/hour');
      expect(limit.maxRequests).toBe(1000);
      expect(limit.windowMs).toBe(3_600_000);
    });

    it('parses requests per hour (short form)', () => {
      const limit = parseRateLimit('500/hr');
      expect(limit.maxRequests).toBe(500);
      expect(limit.windowMs).toBe(3_600_000);
    });

    it('parses requests per day', () => {
      const limit = parseRateLimit('5000/day');
      expect(limit.maxRequests).toBe(5000);
      expect(limit.windowMs).toBe(86_400_000);
    });

    it('throws on invalid format', () => {
      expect(() => parseRateLimit('abc')).toThrow('Invalid rate limit format');
      expect(() => parseRateLimit('100/week')).toThrow('Invalid rate limit format');
      expect(() => parseRateLimit('100')).toThrow('Invalid rate limit format');
      expect(() => parseRateLimit('/min')).toThrow('Invalid rate limit format');
    });
  });

  // ─── formatRateLimit ──────────────────────────────────────────────

  describe('formatRateLimit', () => {
    it('formats common time units', () => {
      expect(formatRateLimit({ maxRequests: 10, windowMs: 1_000 })).toBe('10/sec');
      expect(formatRateLimit({ maxRequests: 100, windowMs: 60_000 })).toBe('100/min');
      expect(formatRateLimit({ maxRequests: 1000, windowMs: 3_600_000 })).toBe('1000/hour');
      expect(formatRateLimit({ maxRequests: 5000, windowMs: 86_400_000 })).toBe('5000/day');
    });

    it('formats unknown window sizes with ms suffix', () => {
      expect(formatRateLimit({ maxRequests: 50, windowMs: 30_000 })).toBe('50/30000ms');
    });
  });

  // ─── RateLimiter (sliding window) ─────────────────────────────────

  describe('RateLimiter', () => {
    it('allows requests within the limit', () => {
      const limiter = new RateLimiter();
      const limit = { maxRequests: 3, windowMs: 60_000 };

      const r1 = limiter.check('cred-1', limit);
      expect(r1.allowed).toBe(true);
      expect(r1.remaining).toBe(2);
      expect(r1.limit).toBe(3);

      const r2 = limiter.check('cred-1', limit);
      expect(r2.allowed).toBe(true);
      expect(r2.remaining).toBe(1);

      const r3 = limiter.check('cred-1', limit);
      expect(r3.allowed).toBe(true);
      expect(r3.remaining).toBe(0);
    });

    it('blocks requests that exceed the limit', () => {
      const limiter = new RateLimiter();
      const limit = { maxRequests: 2, windowMs: 60_000 };

      limiter.check('cred-1', limit);
      limiter.check('cred-1', limit);

      const r3 = limiter.check('cred-1', limit);
      expect(r3.allowed).toBe(false);
      expect(r3.remaining).toBe(0);
      expect(r3.retryAfterSeconds).toBeGreaterThan(0);
    });

    it('tracks credentials independently', () => {
      const limiter = new RateLimiter();
      const limit = { maxRequests: 1, windowMs: 60_000 };

      limiter.check('cred-1', limit);
      // cred-1 is now maxed out
      const r1 = limiter.check('cred-1', limit);
      expect(r1.allowed).toBe(false);

      // cred-2 should still be allowed
      const r2 = limiter.check('cred-2', limit);
      expect(r2.allowed).toBe(true);
    });

    it("resets a specific credential's window", () => {
      const limiter = new RateLimiter();
      const limit = { maxRequests: 1, windowMs: 60_000 };

      limiter.check('cred-1', limit);
      expect(limiter.check('cred-1', limit).allowed).toBe(false);

      limiter.reset('cred-1');
      expect(limiter.check('cred-1', limit).allowed).toBe(true);
    });

    it('clears all windows', () => {
      const limiter = new RateLimiter();
      const limit = { maxRequests: 1, windowMs: 60_000 };

      limiter.check('cred-1', limit);
      limiter.check('cred-2', limit);

      limiter.clear();

      expect(limiter.check('cred-1', limit).allowed).toBe(true);
      expect(limiter.check('cred-2', limit).allowed).toBe(true);
    });

    it('allows requests after the window expires', async () => {
      const limiter = new RateLimiter();
      // Use a very short window (50ms) so we can test expiry
      const limit = { maxRequests: 1, windowMs: 50 };

      limiter.check('cred-1', limit);
      expect(limiter.check('cred-1', limit).allowed).toBe(false);

      // Wait for the window to expire
      await new Promise((resolve) => setTimeout(resolve, 60));

      expect(limiter.check('cred-1', limit).allowed).toBe(true);
    });

    it('provides a positive retryAfterSeconds when blocked', () => {
      const limiter = new RateLimiter();
      const limit = { maxRequests: 1, windowMs: 10_000 };

      limiter.check('cred-1', limit);
      const result = limiter.check('cred-1', limit);

      expect(result.allowed).toBe(false);
      expect(result.retryAfterSeconds).toBeGreaterThanOrEqual(1);
      expect(result.retryAfterSeconds).toBeLessThanOrEqual(10);
    });
  });
});
