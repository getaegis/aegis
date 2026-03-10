# Aegis Roadmap

**From local dev tool to the standard credential isolation layer for AI agents.**

Each phase builds on the last. Checked items are shipped.

---

## v0.1 — Foundation

- [x] AES-256-GCM encrypted credential storage (PBKDF2, random salt)
- [x] HTTP proxy (Gate) with credential injection (bearer, header, basic, query)
- [x] Domain allowlist guard with wildcard matching
- [x] SQLite audit ledger with query, stats, CSV export
- [x] CLI for all operations

---

## v0.2 — Hardening

- [x] Gate integration tests (30 tests)
- [x] Credential rotation with optional grace period
- [x] Credential TTL (auto-expire)
- [x] Per-credential rate limiting (sliding window, 429 + `Retry-After`)
- [x] Request body inspection (credential exfiltration detection)
- [x] Credential scope enforcement — `read` (GET/HEAD/OPTIONS), `write` (POST/PUT/PATCH/DELETE), `*` (all)
- [x] `aegis doctor` health check diagnostics
- [x] TLS support on Gate (`--tls --cert --key`)
- [x] Graceful shutdown (SIGINT/SIGTERM drain)

---

## v0.3 — Agent Identity

- [x] Agent registration with unique tokens (`aegis agent add`)
- [x] Agent authentication via `X-Aegis-Agent` header
- [x] Per-agent credential scoping (grant/revoke)
- [x] Per-agent rate limits
- [x] Agent identity in audit trail

---

## v0.4 — Policy Engine

- [x] Declarative YAML policy files
- [x] Method-level restrictions (read-only agents)
- [x] Regex path-level restrictions
- [x] Time-of-day policies
- [x] Policy dry-run mode
- [x] Hot reload on file changes
- [x] `aegis policy validate|test|list` CLI

---

## v0.5 — MCP Integration

- [x] MCP server with `aegis_proxy_request`, `aegis_list_services`, `aegis_health` tools
- [x] stdio and streamable-http transports
- [x] Agent authentication and credential injection through MCP
- [x] Auto-generate config for Claude, Cursor, VS Code (`aegis mcp config`)
- [ ] Publish to MCP registries (registry.modelcontextprotocol.io, Smithery)

---

## v0.6 — Observability

- [x] Structured logging (pino) with field-level redaction and credential scrubbing
- [x] Prometheus metrics endpoint (`/_aegis/metrics`)
- [x] Webhook alerts (blocked requests, credential expiry, rate limits, auth failures)
- [x] Web dashboard — real-time request feed, credential health, agent activity, blocked log
- [x] JSON/JSONL export for audit ledger

---

## v0.7 — Teams

- [x] Multiple vaults with isolated encryption keys
- [x] RBAC — admin, operator, viewer roles (16 permissions)
- [x] Shamir's Secret Sharing (M-of-N key splitting)
- [x] Configuration file (`aegis.config.yaml`) with layered overrides

---

## v0.8 — Distribution

- [x] Create GitHub org and repository
- [x] Public-facing README, LICENSE (Apache 2.0), CONTRIBUTING, SECURITY
- [x] npm package (`@getaegis/cli`)
- [x] Docker image (multi-stage, Debian bookworm-slim)
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Homebrew formula

---

## v0.9 — Production Hardening

- [ ] Comprehensive E2E test suite
- [ ] Security audit (STRIDE threat model, dependency audit, pen test checklist)
- [ ] Database hardening (backup/restore, encryption at rest)
- [ ] Error handling & circuit breakers
- [ ] Performance benchmarks (p50/p95/p99 latency)
- [ ] Cross-platform key storage (macOS Keychain, Windows Credential Manager, Linux libsecret)

---

## v1.0 — Production Ready

- [ ] 90%+ test coverage
- [ ] Security audit cleared
- [ ] Documentation site
- [ ] Published on npm, Docker Hub, GHCR, Homebrew

---

## Future

- Plugin system (custom auth injection, audit destinations, policy evaluators)
- OAuth2 token management (automatic refresh)
- Credential import (Doppler, HashiCorp Vault, AWS Secrets Manager)
- Framework integrations (LangChain, CrewAI, AutoGen, OpenAI Agents SDK, Vercel AI SDK)
- Response scanning and secret redaction

---

*Last updated: 10 March 2026*
