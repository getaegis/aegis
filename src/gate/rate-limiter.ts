/**
 * Sliding window rate limiter — in-memory, resets on Gate restart.
 *
 * Tracks request timestamps per credential and enforces configurable
 * rate limits like "100/min", "1000/hour", "10/sec".
 *
 * This is intentionally simple for v0.2. A persistent rate limiter
 * backed by Redis or SQLite is planned for later phases.
 */

export interface RateLimit {
  /** Maximum number of requests in the window */
  maxRequests: number;
  /** Window size in milliseconds */
  windowMs: number;
}

export interface RateLimitResult {
  allowed: boolean;
  /** Seconds until the client should retry (only set when blocked) */
  retryAfterSeconds?: number;
  /** How many requests remain in the current window */
  remaining: number;
  /** Total limit for the window */
  limit: number;
}

/**
 * Parse a rate limit string like "100/min" into a structured RateLimit.
 *
 * Supported formats:
 *   - "100/min" or "100/minute"
 *   - "1000/hour" or "1000/hr"
 *   - "10/sec" or "10/second"
 *   - "5000/day"
 */
export function parseRateLimit(input: string): RateLimit {
  const match = input.match(/^(\d+)\/(sec(?:ond)?|min(?:ute)?|hr|hour|day)$/i);
  if (!match) {
    throw new Error(
      `Invalid rate limit format: "${input}". Expected format: <number>/<unit> (e.g. 100/min, 1000/hour, 10/sec, 5000/day)`,
    );
  }

  const maxRequests = parseInt(match[1], 10);
  if (maxRequests <= 0) {
    throw new Error('Rate limit must be a positive number');
  }

  const unit = match[2].toLowerCase();
  let windowMs: number;

  switch (unit) {
    case 'sec':
    case 'second':
      windowMs = 1_000;
      break;
    case 'min':
    case 'minute':
      windowMs = 60_000;
      break;
    case 'hr':
    case 'hour':
      windowMs = 3_600_000;
      break;
    case 'day':
      windowMs = 86_400_000;
      break;
    default:
      throw new Error(`Unknown time unit: "${unit}"`);
  }

  return { maxRequests, windowMs };
}

/**
 * Format a RateLimit back to a human-readable string.
 */
export function formatRateLimit(limit: RateLimit): string {
  if (limit.windowMs === 1_000) return `${limit.maxRequests}/sec`;
  if (limit.windowMs === 60_000) return `${limit.maxRequests}/min`;
  if (limit.windowMs === 3_600_000) return `${limit.maxRequests}/hour`;
  if (limit.windowMs === 86_400_000) return `${limit.maxRequests}/day`;
  return `${limit.maxRequests}/${limit.windowMs}ms`;
}

export class RateLimiter {
  /**
   * Map from credential ID → array of request timestamps (epoch ms).
   * Timestamps outside the window are pruned on each check.
   */
  private windows: Map<string, number[]> = new Map();

  /**
   * Check if a request for the given credential is allowed under its rate limit.
   * Records the request timestamp if allowed.
   */
  check(credentialId: string, limit: RateLimit): RateLimitResult {
    const now = Date.now();
    const windowStart = now - limit.windowMs;

    // Get or create the timestamp array for this credential
    let timestamps = this.windows.get(credentialId);
    if (!timestamps) {
      timestamps = [];
      this.windows.set(credentialId, timestamps);
    }

    // Prune expired timestamps (outside the sliding window)
    const pruned = timestamps.filter((t) => t > windowStart);
    this.windows.set(credentialId, pruned);

    if (pruned.length >= limit.maxRequests) {
      // Rate limit exceeded — calculate when the oldest request in the window expires
      const oldestInWindow = pruned[0];
      const retryAfterMs = oldestInWindow + limit.windowMs - now;
      const retryAfterSeconds = Math.ceil(retryAfterMs / 1000);

      return {
        allowed: false,
        retryAfterSeconds: Math.max(1, retryAfterSeconds),
        remaining: 0,
        limit: limit.maxRequests,
      };
    }

    // Allowed — record this request
    pruned.push(now);

    return {
      allowed: true,
      remaining: limit.maxRequests - pruned.length,
      limit: limit.maxRequests,
    };
  }

  /**
   * Reset rate limit state for a specific credential (e.g. after rotation).
   */
  reset(credentialId: string): void {
    this.windows.delete(credentialId);
  }

  /**
   * Clear all rate limit state.
   */
  clear(): void {
    this.windows.clear();
  }
}
