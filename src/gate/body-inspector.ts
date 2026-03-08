/**
 * Request Body Inspector — scans outbound request bodies for credential-like
 * patterns that may indicate an agent is trying to exfiltrate secrets.
 *
 * This is a defence-in-depth measure. Even though the agent never sees
 * decrypted credentials directly, an agent could attempt to send previously
 * obtained secrets (e.g. from environment variables, config files) through
 * Gate to an attacker-controlled domain. The body inspector catches this.
 *
 * Sensitivity modes:
 *   - "off"   — no scanning (fastest, least secure)
 *   - "warn"  — scan and log matches but allow the request through
 *   - "block" — scan and block requests containing credential patterns (default)
 */

export type BodyInspectionMode = 'off' | 'warn' | 'block';

export interface InspectionResult {
  /** Whether any credential-like patterns were found */
  suspicious: boolean;
  /** Human-readable descriptions of what was found */
  matches: string[];
}

/**
 * Patterns that indicate a string might be a credential.
 *
 * Each pattern has a name (for logging), a regex, and an optional
 * minimum match length to reduce false positives.
 */
interface CredentialPattern {
  name: string;
  pattern: RegExp;
  minLength?: number;
}

const CREDENTIAL_PATTERNS: CredentialPattern[] = [
  // Bearer tokens embedded in body text
  {
    name: 'Bearer token',
    pattern: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
    minLength: 20,
  },

  // ── Vendor-specific prefixes ───────────────────────────────────

  // OpenAI / Anthropic
  {
    name: 'API key (sk-* prefix)',
    pattern: /\bsk-[A-Za-z0-9]{20,}\b/g,
  },
  {
    name: 'API key (pk-* prefix)',
    pattern: /\bpk-[A-Za-z0-9]{20,}\b/g,
  },
  // Slack tokens
  {
    name: 'Slack token (xoxb/xoxp/xoxa/xoxr)',
    pattern: /\bxox[bpar]-[A-Za-z0-9-]{10,}\b/g,
  },
  // GitHub tokens
  {
    name: 'GitHub token (ghp/gho/ghu/ghs/ghr)',
    pattern: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g,
  },
  // AWS access keys
  {
    name: 'AWS access key',
    pattern: /\bAKIA[A-Z0-9]{16}\b/g,
  },
  // AWS secret keys (40-char base64-like after common JSON/YAML key names)
  {
    name: 'AWS secret key pattern',
    pattern: /(?:aws_secret_access_key|secret_key|secretAccessKey)["':\s]*[A-Za-z0-9/+=]{40}/gi,
  },
  // Google Cloud / Firebase API keys
  {
    name: 'Google API key (AIza* prefix)',
    pattern: /\bAIza[A-Za-z0-9_-]{35}\b/g,
  },
  // Google OAuth tokens
  {
    name: 'Google OAuth token (ya29.*)',
    pattern: /\bya29\.[A-Za-z0-9_-]{20,}\b/g,
  },
  // Stripe keys
  {
    name: 'Stripe key (sk_live/pk_live/rk_live)',
    pattern: /\b[spr]k_live_[A-Za-z0-9]{20,}\b/g,
  },
  // Stripe test keys (still credentials — should not be in body)
  {
    name: 'Stripe test key (sk_test/pk_test/rk_test)',
    pattern: /\b[spr]k_test_[A-Za-z0-9]{20,}\b/g,
  },
  // Twilio API keys
  {
    name: 'Twilio API key',
    pattern: /\bSK[0-9a-f]{32}\b/g,
  },
  // SendGrid API keys
  {
    name: 'SendGrid API key',
    pattern: /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g,
  },
  // npm tokens
  {
    name: 'npm token',
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/g,
  },
  // Discord bot tokens (base64.base64.base64 format)
  {
    name: 'Discord bot token',
    pattern: /\b[A-Za-z0-9]{24,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b/g,
  },
  // Azure connection strings
  {
    name: 'Azure connection string',
    pattern: /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+/gi,
  },
  // Mailgun API keys
  {
    name: 'Mailgun API key',
    pattern: /\bkey-[A-Za-z0-9]{32}\b/g,
  },
  // Heroku API keys
  {
    name: 'Heroku API key',
    pattern: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g,
  },

  // ── Database connection strings ────────────────────────────────

  // PostgreSQL / MySQL / MongoDB / Redis connection URIs with credentials
  {
    name: 'Database connection string',
    pattern:
      /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss):\/\/[^\s"']+:[^\s"']+@[^\s"']+\b/gi,
  },

  // ── Crypto wallet keys ─────────────────────────────────────────

  // Ethereum / EVM private keys (0x + 64 hex chars)
  {
    name: 'Ethereum private key (0x + 64 hex)',
    pattern: /\b0x[0-9a-fA-F]{64}\b/g,
  },

  // ── Generic heuristics ─────────────────────────────────────────

  // Generic long hex strings (likely keys/tokens — 40+ hex chars)
  {
    name: 'Long hex string (possible key)',
    pattern: /\b[0-9a-f]{40,}\b/gi,
  },
  // Base64-encoded strings that are suspiciously long (likely encoded credentials)
  {
    name: 'Long base64 string (possible encoded credential)',
    pattern: /\b[A-Za-z0-9+/]{50,}={0,2}\b/g,
  },
  // JWT tokens (eyJ prefix = base64-encoded JSON header)
  {
    name: 'JWT token',
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  },
  // Basic auth in body (username:password in base64)
  {
    name: 'Basic auth credential',
    pattern: /Basic\s+[A-Za-z0-9+/]+=*/gi,
    minLength: 15,
  },
  // Authorization header value embedded in body
  {
    name: 'Authorization value in body',
    pattern: /["']?authorization["']?\s*[:=]\s*["'][^"']{10,}["']/gi,
  },
  // Generic "api_key", "api-key", "apikey" with a value
  {
    name: 'API key assignment',
    pattern:
      /["']?(?:api[-_]?key|api[-_]?secret|access[-_]?token|secret[-_]?key|client[-_]?secret|auth[-_]?token)["']?\s*[:=]\s*["'][^"']{8,}["']/gi,
  },
  // Private key blocks (RSA, EC, DSA, ENCRYPTED, generic)
  {
    name: 'Private key block',
    pattern: /-----BEGIN\s(?:RSA\s|EC\s|DSA\s|ENCRYPTED\s|OPENSSH\s)?PRIVATE\sKEY-----/g,
  },
  // Password-like assignments in JSON/YAML/config
  {
    name: 'Password assignment',
    pattern: /["']?(?:password|passwd|pwd|secret)["']?\s*[:=]\s*["'][^"']{8,}["']/gi,
  },
];

export class BodyInspector {
  /**
   * Scan a request body string for credential-like patterns.
   *
   * @param body The raw request body as a string
   * @returns An InspectionResult indicating whether suspicious patterns were found
   */
  inspect(body: string): InspectionResult {
    if (!body || body.length === 0) {
      return { suspicious: false, matches: [] };
    }

    const matches: string[] = [];

    for (const { name, pattern, minLength } of CREDENTIAL_PATTERNS) {
      // Reset lastIndex for global regexes
      pattern.lastIndex = 0;

      const found = body.match(pattern);
      if (found) {
        for (const match of found) {
          if (minLength && match.length < minLength) continue;
          // Don't include the actual matched value in the log — it might be a credential!
          matches.push(`${name} detected (${match.length} chars)`);
        }
      }
    }

    return {
      suspicious: matches.length > 0,
      matches,
    };
  }
}
