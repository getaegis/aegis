import { describe, expect, it } from 'vitest';
import { BodyInspector } from '../src/gate/body-inspector.js';

describe('body-inspector', () => {
  const inspector = new BodyInspector();

  // ─── Clean bodies (no matches) ────────────────────────────────

  describe('clean bodies', () => {
    it('returns no matches for empty body', () => {
      const result = inspector.inspect('');
      expect(result.suspicious).toBe(false);
      expect(result.matches).toHaveLength(0);
    });

    it('returns no matches for normal JSON', () => {
      const result = inspector.inspect(JSON.stringify({ message: 'hello world', count: 42 }));
      expect(result.suspicious).toBe(false);
    });

    it('returns no matches for normal text', () => {
      const result = inspector.inspect('This is a normal request body with no secrets');
      expect(result.suspicious).toBe(false);
    });

    it('returns no matches for short strings that might look like keys', () => {
      const result = inspector.inspect(JSON.stringify({ id: 'abc123', type: 'query' }));
      expect(result.suspicious).toBe(false);
    });
  });

  // ─── Bearer tokens ───────────────────────────────────────────

  describe('bearer tokens', () => {
    it('detects Bearer token in body', () => {
      const body = JSON.stringify({
        auth: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
      });
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('Bearer token'))).toBe(true);
    });
  });

  // ─── API key prefixes ────────────────────────────────────────

  describe('API key patterns', () => {
    it('detects sk-* prefixed keys (OpenAI style)', () => {
      const body = JSON.stringify({
        data: 'here is my key sk-1234567890abcdefghijklmnopqrstuv',
      });
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('sk-'))).toBe(true);
    });

    it('detects Slack tokens', () => {
      const body = `sending token xoxb-123456789012-abcdefghij`;
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('Slack'))).toBe(true);
    });

    it('detects GitHub tokens', () => {
      const body = JSON.stringify({
        token: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh',
      });
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('GitHub'))).toBe(true);
    });

    it('detects AWS access keys', () => {
      const body = `access_key_id: AKIAIOSFODNN7EXAMPLE`;
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('AWS access key'))).toBe(true);
    });

    it('detects Google API keys (AIza prefix)', () => {
      const body = JSON.stringify({
        key: 'AIzaSyA1234567890abcdefghijklmnopqrstuv',
      });
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('Google API key'))).toBe(true);
    });

    it('detects Google OAuth tokens (ya29 prefix)', () => {
      const body = `token: ya29.a0ARrdaM_abcdefghij1234`;
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('Google OAuth'))).toBe(true);
    });

    it('detects Stripe live keys', () => {
      const body = JSON.stringify({
        stripe_key: 'sk_live_51H3bFJDe4abcdefghijklmno',
      });
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('Stripe'))).toBe(true);
    });

    it('detects Stripe test keys', () => {
      const body = `pk_test_51H3bFJDe4abcdefghijklmno`;
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('Stripe test key'))).toBe(true);
    });

    it('detects Twilio API keys', () => {
      const body = JSON.stringify({
        sid: 'SK00000000000000000000000000000000',
      });
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('Twilio'))).toBe(true);
    });

    it('detects SendGrid API keys', () => {
      const body = `apikey: SG.abcdefghij1234567890.ABCDEFGHIJ1234567890abcdefghij`;
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('SendGrid'))).toBe(true);
    });

    it('detects npm tokens', () => {
      const body = JSON.stringify({
        token: 'npm_abcdefghijklmnopqrstuvwxyz1234567890',
      });
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('npm token'))).toBe(true);
    });

    it('detects Mailgun API keys', () => {
      const body = `key-0123456789abcdef0123456789abcdef`;
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('Mailgun'))).toBe(true);
    });
  });

  // ─── Generic patterns ────────────────────────────────────────

  describe('generic credential patterns', () => {
    it('detects long hex strings (possible keys)', () => {
      const body = JSON.stringify({
        data: `key is ${'a'.repeat(40)}`,
      });
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('hex'))).toBe(true);
    });

    it('detects api_key assignments', () => {
      const body = `{"api_key": "my-super-secret-api-key-value-here"}`;
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('API key assignment'))).toBe(true);
    });

    it('detects authorization header values in body', () => {
      const body = `{"authorization": "Bearer some-long-token-value"}`;
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
    });

    it('detects private key blocks', () => {
      const body = `Here is my key:\n-----BEGIN RSA PRIVATE KEY-----\nblahblah`;
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('Private key'))).toBe(true);
    });

    it('detects Basic auth credentials', () => {
      const body = `auth: Basic dXNlcm5hbWU6cGFzc3dvcmQ=`;
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('Basic auth'))).toBe(true);
    });

    it('detects JWT tokens (eyJ prefix)', () => {
      const body = JSON.stringify({
        token:
          'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A',
      });
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('JWT token'))).toBe(true);
    });

    it('detects database connection strings', () => {
      const body = JSON.stringify({
        dsn: 'postgres://admin:s3cret@db.example.com:5432/mydb',
      });
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('Database connection'))).toBe(true);
    });

    it('detects MongoDB connection strings', () => {
      const body = `mongodb+srv://user:password@cluster0.abc.mongodb.net/test`;
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('Database connection'))).toBe(true);
    });

    it('detects Ethereum private keys (0x + 64 hex)', () => {
      const body = JSON.stringify({
        privateKey: `0x${'ab'.repeat(32)}`,
      });
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('Ethereum'))).toBe(true);
    });

    it('detects Azure connection strings', () => {
      const body = `DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc123def456+/==`;
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('Azure'))).toBe(true);
    });

    it('detects password assignments in JSON', () => {
      const body = `{"password": "my-super-secret-password-value"}`;
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('Password assignment'))).toBe(true);
    });

    it('detects EC private key blocks', () => {
      const body = `-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...`;
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      expect(result.matches.some((m) => m.includes('Private key'))).toBe(true);
    });
  });

  // ─── Does NOT leak matched values ─────────────────────────────

  describe('security', () => {
    it('does not include the actual credential value in match descriptions', () => {
      const secret = 'sk-1234567890abcdefghijklmnopqrstuv';
      const body = JSON.stringify({ key: secret });
      const result = inspector.inspect(body);
      expect(result.suspicious).toBe(true);
      // The match description should NOT contain the actual secret
      for (const match of result.matches) {
        expect(match).not.toContain(secret);
      }
    });
  });
});
