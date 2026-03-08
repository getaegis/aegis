# Security Policy

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

If you discover a security vulnerability in Aegis, please report it through GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/getaegis/aegis/security) of this repository
2. Click **"Report a vulnerability"**
3. Fill out the form with details about the vulnerability

You will receive a response within 48 hours. We will work with you to understand the issue and coordinate a fix before any public disclosure.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |

## Security Model

Aegis is a security product — credential isolation is its core purpose. The security model includes:

- **AES-256-GCM** encryption at rest with PBKDF2 key derivation
- **Domain guard** enforcement on every outbound request (no bypass)
- **Hash-only token storage** (agent tokens and user tokens are never stored in recoverable form)
- **Audit logging** of every request (allowed and blocked)
- **Request body inspection** for credential exfiltration patterns
- **Header stripping** of agent-supplied auth headers before credential injection

For the full security architecture, see [SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md).

## Scope

The following are in scope for security reports:

- Credential exposure (plaintext secrets in logs, responses, error messages)
- Domain guard bypass (sending credentials to unauthorized domains)
- Authentication bypass (accessing resources without valid tokens)
- Encryption weaknesses (IV reuse, weak key derivation, algorithm issues)
- Audit trail gaps (requests that bypass logging)
- Injection attacks (SQL injection via service names, path traversal)
- Request smuggling through the Gate proxy

## Out of Scope

- Denial of service against the local proxy (Aegis runs on localhost)
- Social engineering
- Issues in dependencies (report these to the dependency maintainer)
