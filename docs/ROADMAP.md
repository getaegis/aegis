# Aegis Roadmap

**The credential isolation layer for AI agents.**

---

## v1.0 — What Shipped

Aegis v1.0 is a complete credential isolation layer for AI agents:

- **Encrypted credential storage** — AES-256-GCM with PBKDF2 key derivation, full-database encryption (ChaCha20-Poly1305)
- **HTTP proxy (Gate)** — credential injection (bearer, header, basic, query), domain allowlist guard, header scrubbing, TLS support, graceful shutdown
- **Agent identity & auth** — token-based authentication, per-agent credential grants, per-agent rate limits
- **Policy engine** — declarative YAML policies, method/path/time-of-day restrictions, dry-run mode, hot reload
- **MCP integration** — stdio and streamable-http transports, full security pipeline, published to MCP Registry
- **Observability** — structured logging with secret scrubbing, Prometheus metrics, webhook alerts, web dashboard
- **Multi-vault isolation** — per-vault encryption keys, RBAC (admin/operator/viewer), Shamir's Secret Sharing
- **Production hardening** — circuit breakers, retry logic, connection pooling, body size limits, request timeouts, per-agent connection limits, concurrent isolation tests
- **Cross-platform key storage** — macOS Keychain, Windows Credential Manager, Linux Secret Service, file fallback
- **Distribution** — npm (`@getaegis/cli`), Docker, Homebrew, CI/CD pipeline

---

## Future

- Response scanning and secret redaction
- Mutual TLS and IP allowlisting for Gate connections
- Signed policy files (HMAC/GPG verification)
- Append-only audit logs and remote syslog/SIEM forwarding
- Persistent rate limiting (Redis-backed)
- Plugin system (custom auth injection, audit destinations, policy evaluators)
- OAuth2 token management (automatic refresh)
- Credential import (Doppler, HashiCorp Vault, AWS Secrets Manager)
- Framework integrations (LangChain, CrewAI, AutoGen, OpenAI Agents SDK, Vercel AI SDK)

---

*Last updated: 17 March 2026*
