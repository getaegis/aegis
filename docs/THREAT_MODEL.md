# Aegis STRIDE Threat Model

A systematic analysis of security threats to Aegis using the STRIDE framework (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege). Each threat is assessed for likelihood, impact, and current mitigation status.

**Last updated:** 11 March 2026
**Version:** 0.9.5

---

## Table of Contents

1. [System Scope](#1-system-scope)
2. [Trust Boundaries](#2-trust-boundaries)
3. [Spoofing](#3-spoofing)
4. [Tampering](#4-tampering)
5. [Repudiation](#5-repudiation)
6. [Information Disclosure](#6-information-disclosure)
7. [Denial of Service](#7-denial-of-service)
8. [Elevation of Privilege](#8-elevation-of-privilege)
9. [Risk Summary Matrix](#9-risk-summary-matrix)
10. [Residual Risks](#10-residual-risks)

---

## 1. System Scope

Aegis is a credential isolation proxy for AI agents. It runs on the operator's machine (localhost) and sits between an untrusted AI agent and external APIs. The agent makes HTTP requests through Gate; Aegis injects the real credentials at the network boundary.

### Components Under Analysis

| Component | Description | Entry Points |
|-----------|-------------|--------------|
| **Gate** | HTTP/HTTPS proxy on `localhost:3100` | Agent HTTP requests, `/_aegis/*` internal endpoints |
| **Vault** | Encrypted credential storage (SQLite + AES-256-GCM) | CLI commands (`vault add/remove/rotate/update`) |
| **Ledger** | Audit log (SQLite) | Gate writes, CLI reads (`ledger show/export`) |
| **Agent Registry** | Agent identity and credential grants | CLI commands (`agent add/grant/revoke`) |
| **User Registry** | RBAC user management | CLI commands (`user add/remove/role`) |
| **Policy Engine** | YAML policy evaluation | Policy files on disk, hot-reload via `fs.watch` |
| **MCP Server** | Model Context Protocol server | stdio transport, streamable-http transport |
| **Dashboard** | Web UI on `localhost:3200` | HTTP REST API, WebSocket |
| **Webhook Manager** | Outbound HTTP alerts | Admin-configured URLs |

### Trust Assumptions

- The machine running Aegis is trusted (not compromised at the OS level)
- The operator who ran `aegis init` is trusted
- Node.js `crypto` module (wrapping OpenSSL) is trusted
- SQLite via `better-sqlite3-multiple-ciphers` is trusted (no network surface, ChaCha20-Poly1305 encryption at rest)
- External APIs are reached over HTTPS (TLS 1.2+)
- **The AI agent is NOT trusted** — this is the core threat actor

---

## 2. Trust Boundaries

```
┌──────────────────────────────────────────────────────────────┐
│  TRUST BOUNDARY 1: Operator's Machine                        │
│                                                              │
│  ┌──────────────────────────────────────────────┐            │
│  │  TRUST BOUNDARY 2: Aegis Process             │            │
│  │                                              │            │
│  │  ┌──────────┐  ┌───────┐  ┌──────────────┐  │            │
│  │  │  Vault   │  │ Gate  │  │   Ledger     │  │            │
│  │  │ (crypto) │  │(proxy)│  │  (audit)     │  │            │
│  │  └──────────┘  └───┬───┘  └──────────────┘  │            │
│  │                    │                         │            │
│  └────────────────────┼─────────────────────────┘            │
│                       │                                      │
│  ┌────────────────────┼─────────────────────────┐            │
│  │  UNTRUSTED ZONE    │                         │            │
│  │                    │ HTTP (localhost)         │            │
│  │  ┌─────────────┐  │                          │            │
│  │  │  AI Agent   │──┘                          │            │
│  │  └─────────────┘                             │            │
│  └──────────────────────────────────────────────┘            │
│                                                              │
└──────────────────────────────────────────────────────────────┘
                        │
                        │ HTTPS (TLS 1.2+)
                        ▼
               ┌─────────────────┐
               │  External APIs  │
               │  (internet)     │
               └─────────────────┘
```

Data crosses three trust boundaries:
1. **Agent → Gate** (untrusted → trusted): HTTP on localhost. The agent can send anything.
2. **Gate → External API** (trusted → external): HTTPS. Credentials are injected here.
3. **Operator → Aegis** (trusted → trusted): CLI commands, config files, policy files.

---

## 3. Spoofing

Spoofing threats involve an attacker pretending to be someone or something they are not.

### S-1: Agent Impersonation (Agent → Gate)

| | |
|---|---|
| **Threat** | A malicious process on localhost pretends to be a legitimate agent by guessing or stealing an agent token. |
| **Likelihood** | Medium — tokens are on localhost, but any process running as the same user can observe network traffic or read environment variables. |
| **Impact** | High — the attacker gains access to all credentials granted to the impersonated agent. |
| **Mitigations** | |
| ✅ Implemented | Agent tokens use UUID+HMAC format (`aegis_{uuid}_{hmac_16hex}`) — not guessable. HMAC proves the token was generated by Aegis. |
| ✅ Implemented | Tokens are SHA-256 hashed for storage — database compromise doesn't reveal tokens. |
| ✅ Implemented | Token prefixes (first 12 chars) used in logs for safe identification without exposure. |
| ✅ Implemented | `regenerateToken()` invalidates old tokens immediately (no grace period for stolen tokens). |
| ✅ Implemented | Agent auth is **on by default**. Requests without a token receive a 401 with a helpful error message and instructions to create an agent (`aegis agent add --name my-agent`). Operators can disable via `--no-agent-auth` if needed. |
| ⬜ Future | Mutual TLS between agent and Gate would bind identity to a certificate. |
| ⬜ Future | IP allowlisting would restrict which local processes can connect. |
| **Residual Risk** | Low — token format is cryptographically strong. The main risk is a co-resident process reading the token from the agent's environment or memory. Accepted because the localhost trust model means any compromised process already has broad access. |

### S-2: Service Name Spoofing (Agent → Gate)

| | |
|---|---|
| **Threat** | An agent crafts a request to `localhost:3100/wrong-service/path` to use a different service's credential. |
| **Likelihood** | High — trivial to attempt. |
| **Impact** | Medium — the agent accesses a credential for a different service, but it's still domain-guarded. |
| **Mitigations** | |
| ✅ Implemented | Per-agent credential grants — agent can only use services explicitly granted to it. Ungranted services return 403. |
| ✅ Implemented | Domain guard — even if the agent accesses a credential, it can only be used against that credential's allowed domains. |
| ✅ Implemented | Policy engine — per-agent policies restrict which services, methods, and paths are permitted. |
| **Residual Risk** | Low — defense in depth (grants + domain guard + policy) makes exploitation require multiple bypasses. |

### S-3: User Token Spoofing (Attacker → CLI)

| | |
|---|---|
| **Threat** | An attacker guesses or steals a user token to execute privileged CLI commands (e.g., add credentials, grant agent access). |
| **Likelihood** | Low — user tokens use the same UUID+HMAC format as agent tokens and are hash-only stored. |
| **Impact** | Critical — admin tokens grant full vault access. |
| **Mitigations** | |
| ✅ Implemented | Same hash-only token storage as agents — database compromise doesn't reveal tokens. |
| ✅ Implemented | RBAC with 3 roles and 16 permissions — viewer tokens can't modify anything. |
| ✅ Implemented | Bootstrap mode only when zero users exist — can't bypass auth by deleting the user table (other data remains). |
| **Residual Risk** | Low — follows industry standard (GitHub, Stripe) token patterns. |

### S-4: X-Target-Host Spoofing (Agent → Gate)

| | |
|---|---|
| **Threat** | An agent sets `X-Target-Host: evil.com` to redirect a credential to an attacker-controlled server. |
| **Likelihood** | High — trivial to attempt. |
| **Impact** | Critical if unmitigated — credential would be sent to the attacker. |
| **Mitigations** | |
| ✅ Implemented | **Domain guard is enforced, not advisory.** The `X-Target-Host` value is checked against the credential's domain allowlist. If `evil.com` is not in the allowlist, the request is blocked (403) and logged. |
| ✅ Implemented | Wildcard matching (`*.slack.com`) is single-level only — `*.slack.com` does not match `deep.nested.slack.com`. |
| ✅ Implemented | Every blocked domain guard violation is recorded in the Ledger with full context. |
| **Residual Risk** | None — this threat is fully mitigated by design. The domain guard cannot be bypassed. |

---

## 4. Tampering

Tampering threats involve modifying data or code to change system behaviour.

### T-1: Path Traversal via URL Encoding (Agent → Gate)

| | |
|---|---|
| **Threat** | An agent uses percent-encoded path segments (`%2e%2e`, `..%2f`) to escape the service routing prefix and access internal endpoints or other services' paths. |
| **Likelihood** | High — well-known attack vector, documented in OWASP and WHATWG URL Standard §4.1. |
| **Impact** | High — could bypass service routing to access `/_aegis/health` or other services' credential scopes. |
| **Mitigations** | |
| ✅ Implemented | **Raw URL parsing** — Gate splits `req.url` as a raw string (not via `new URL()`) to prevent WHATWG normalisation of `%2e%2e` → `..`. |
| ✅ Implemented | **Explicit traversal guard** — every path segment is decoded via `decodeURIComponent()` and rejected (400) if the decoded value is `..` or `.`. |
| ✅ Implemented | 11 smuggling resistance tests cover: `%2e%2e`, `..%2f`, null bytes, double Content-Length, CL/TE desync, header stripping, oversized headers. |
| **Residual Risk** | None — two-layer defense (raw parsing + explicit rejection) with full test coverage. |

### T-2: Header Injection (Agent → Gate)

| | |
|---|---|
| **Threat** | An agent sends `Authorization`, `X-Api-Key`, or `Proxy-Authorization` headers to override Aegis's credential injection. |
| **Likelihood** | High — agents commonly send auth headers. |
| **Impact** | Medium — the agent's credential would be forwarded instead of the vault credential, bypassing Aegis's purpose. |
| **Mitigations** | |
| ✅ Implemented | Gate strips `authorization`, `x-api-key`, `proxy-authorization`, `host`, `x-target-host`, and `x-aegis-agent` from all outbound requests before injecting the vault credential. |
| ✅ Implemented | Smuggling tests verify header stripping works for all 5 sensitive headers. |
| **Residual Risk** | None — agent-supplied auth headers are unconditionally removed. |

### T-3: Request Body Credential Exfiltration (Agent → Gate → External API)

| | |
|---|---|
| **Threat** | An agent embeds stolen credentials in the request body (e.g., as a POST parameter or JSON field) to send them to an external API. |
| **Likelihood** | Medium — requires the agent to have obtained the credential from a previous response or side channel. |
| **Impact** | High — credential exfiltration past the header-level protections. |
| **Mitigations** | |
| ✅ Implemented | **Body inspector** scans outbound request bodies for 7 credential pattern categories: API key formats, Bearer tokens, Basic auth, JWT tokens, AWS keys, hex/base64 secrets, connection strings. |
| ✅ Implemented | Three modes: `off` (no scanning), `warn` (log but allow), `block` (reject with 403). Default is `block`. |
| ✅ Implemented | Blocked body exfiltration attempts are logged to Ledger and emitted as webhook events. |
| **Residual Risk** | Low — pattern-based detection can be evaded by encoding (e.g., reversing the string, splitting across fields). This is a fundamental limitation of regex-based scanning. Future work could add entropy analysis. |

### T-4: Ciphertext Tampering (Attacker → Database)

| | |
|---|---|
| **Threat** | An attacker with database access modifies encrypted credential blobs to alter the decrypted value. |
| **Likelihood** | Low — requires filesystem access to the SQLite database. |
| **Impact** | Low — AES-256-GCM's authentication tag detects any modification. |
| **Mitigations** | |
| ✅ Implemented | GCM mode provides authenticated encryption — tampered ciphertext fails the auth tag check and throws an error. Aegis does not silently use corrupted data. |
| ✅ Implemented | IV is stored alongside ciphertext — unique per encryption, never reused. |
| **Residual Risk** | None — GCM integrity verification is cryptographically sound. The attacker could delete the row (DoS), but cannot modify it undetected. |

### T-5: Policy File Tampering (Attacker → Filesystem)

| | |
|---|---|
| **Threat** | An attacker modifies YAML policy files on disk to grant an agent broader access. |
| **Likelihood** | Low — requires filesystem write access. |
| **Impact** | High — could remove method/path/time-of-day restrictions for any agent. |
| **Mitigations** | |
| ✅ Implemented | Policy hot-reload logs every policy load event — changes are visible in logs. |
| ✅ Implemented | Policy validation rejects malformed YAML — the attacker must produce valid policy syntax. |
| ⬜ Future | Signed policy files (HMAC or GPG) would prevent modification without the signing key. |
| ⬜ Future | Version-controlled policies (`git diff`) provide a separate tamper-detection layer. |
| **Residual Risk** | Medium — policy files on disk are trusted. Filesystem compromise allows policy weakening. This is accepted because filesystem compromise already implies machine compromise (Trust Boundary 1). |

### T-6: Request Smuggling (Agent → Gate)

| | |
|---|---|
| **Threat** | An agent exploits HTTP parsing ambiguities (CL/TE desync, double Content-Length) to smuggle a second request that bypasses security checks. |
| **Likelihood** | Low — Node.js HTTP parser is strict. CL/TE desync typically targets reverse proxy → backend chains, not single-server setups. |
| **Impact** | High — could bypass domain guard, policy evaluation, or agent auth. |
| **Mitigations** | |
| ✅ Implemented | Node.js HTTP parser rejects ambiguous framing (duplicate Content-Length headers return 400). |
| ✅ Implemented | `Transfer-Encoding` is stripped from forwarded requests — Aegis reads the full body, preventing chunked encoding attacks. |
| ✅ Implemented | 11 dedicated smuggling resistance tests. |
| **Residual Risk** | None for current architecture — Gate is a single-server proxy (not a reverse proxy → backend chain), eliminating the classic CL/TE attack surface. |

---

## 5. Repudiation

Repudiation threats involve a user denying they performed an action when there is insufficient evidence to prove otherwise.

### R-1: Unlogged Agent Actions

| | |
|---|---|
| **Threat** | An agent performs API calls that are not recorded, making it impossible to audit what happened. |
| **Likelihood** | None — by design, every code path through Gate writes to the Ledger. |
| **Impact** | High if unmitigated — defeats the purpose of an audit trail. |
| **Mitigations** | |
| ✅ Implemented | **Every** Gate request (allowed AND blocked) is recorded in the Ledger before the response is sent. |
| ✅ Implemented | Ledger entries include: timestamp, service, domain, method, path, status (allowed/blocked), block reason, agent identity, credential ID, response code, request correlation ID. |
| ✅ Implemented | MCP server replicates the same audit trail — MCP proxied requests are also logged. |
| ✅ Implemented | Ledger supports JSON and CSV export for SIEM integration. |
| **Residual Risk** | Low — the only gap is if the Aegis process crashes mid-request before the Ledger write completes. SQLite WAL mode reduces this window. |

### R-2: Audit Log Deletion

| | |
|---|---|
| **Threat** | An attacker with filesystem access deletes or truncates the Ledger database. |
| **Likelihood** | Low — requires filesystem access. |
| **Impact** | High — destroys the audit trail. |
| **Mitigations** | |
| ✅ Implemented | Webhook alerts fire in real-time for security events — even if the Ledger is deleted, external systems have received the events. |
| ⬜ Future | Database backup command (`aegis backup`) for point-in-time copies. |
| ⬜ Future | Append-only log mode or write-once storage integration. |
| ⬜ Future | Remote syslog/SIEM forwarding for tamper-resistant audit storage. |
| **Residual Risk** | Medium — local SQLite file can be deleted. Webhook alerts provide partial mitigation but only for configured event types, not the full audit trail. |

### R-3: Agent Identity Gaps

| | |
|---|---|
| **Threat** | When agent auth is disabled (`--no-agent-auth`), requests are logged without agent identity, making it impossible to attribute actions to a specific agent. |
| **Likelihood** | Low — agent auth is on by default. Operators must explicitly disable it. |
| **Impact** | Medium — audit logs exist but lack attribution. |
| **Mitigations** | |
| ✅ Implemented | When agent auth is enabled, every Ledger entry includes agent name and token prefix. |
| ✅ Implemented | `aegis doctor` could be extended to warn when agent auth is disabled. |
| **Residual Risk** | Low — this is a deliberate operator choice. The data exists; attribution is optional. |

---

## 6. Information Disclosure

Information disclosure threats involve exposing sensitive data to unauthorised parties.

### I-1: Credential Leakage via Logs

| | |
|---|---|
| **Threat** | Decrypted credential values appear in log output, error messages, or stack traces. |
| **Likelihood** | Medium — credential values pass through memory during injection. A careless log statement could expose them. |
| **Impact** | Critical — credential compromise. |
| **Mitigations** | |
| ✅ Implemented | **pino-based logger with 30+ redact paths** — fields like `secret`, `password`, `token`, `authorization`, `masterKey`, `derivedKey`, and all credential-bearing headers are redacted at the logger level. |
| ✅ Implemented | **7 credential pattern scrubbers** in `scrubString()` — catches API keys, Bearer tokens, Basic auth, JWTs, AWS keys, hex/base64 secrets, and connection strings in free-text log fields. |
| ✅ Implemented | `safeMeta()` helper recursively scrubs arbitrary metadata objects before logging. |
| ✅ Implemented | Error messages never include credential values — they reference credential names/IDs only. |
| ✅ Implemented | MCP stdio transport uses stderr for logging so credential data never mixes with MCP protocol messages on stdout. |
| **Residual Risk** | Low — defence in depth (field redaction + pattern scrubbing + code discipline). A novel credential format not matching any of the 7 patterns could theoretically leak, but this is unlikely for common API key formats. |

### I-2: Credential Leakage via API Response

| | |
|---|---|
| **Threat** | An external API includes credentials in its response body (e.g., echoing back the Authorization header), which is then forwarded to the agent. |
| **Likelihood** | Low — rare for well-designed APIs, but possible (e.g., debug/echo endpoints). |
| **Impact** | High — the agent receives the credential in the response. |
| **Mitigations** | |
| ✅ Implemented | `Set-Cookie` headers are stripped from responses — prevents session hijacking. |
| ⬜ Future | Response body scanning (mirror of body inspector) to detect and redact credentials before forwarding to the agent. This is planned post-v1.0. |
| **Residual Risk** | Medium — Aegis does not currently inspect response bodies. If an API echoes back the injected credential, the agent receives it. This is documented in SECURITY_ARCHITECTURE.md §22 as a known limitation. |

### I-3: Master Key Exposure on Disk

| | |
|---|---|
| **Threat** | The master key stored on disk is readable by any process running as the same OS user. |
| **Likelihood** | Medium — AI agents (the entities Aegis protects against) often have filesystem access, but the OS keychain is access-controlled. |
| **Impact** | Critical — master key + database = all credentials decrypted. |
| **Mitigations** | |
| ✅ Implemented | `aegis init` defaults to printing the master key to stdout (user stores it securely). `--write-secrets` must be explicitly chosen. |
| ✅ Implemented | When written to `.env`, file permissions are set to `0600` (owner read/write only). |
| ✅ Implemented | Shamir's Secret Sharing — master key can be split into K-of-N shares, requiring multiple parties to unseal. |
| ✅ Implemented | **Cross-platform key storage (v0.8.4)** — `aegis init` stores the master key in the OS keychain by default: macOS Keychain (`security` CLI), Windows Credential Manager (`cmdkey` + PowerShell), Linux Secret Service (`secret-tool`). File fallback (`.aegis/.master-key`, mode 0600) when no keychain is available. `--env-file` flag for CI/headless environments. |
| ✅ Implemented | `aegis key where` diagnostics command shows where the master key is stored and which backend is active. |
| ✅ Implemented | `aegis doctor` checks key storage backend type and reports whether a key is present. |
| **Residual Risk** | Low — OS keychains are encrypted and access-controlled, significantly reducing the attack surface compared to plaintext `.env`. The file fallback (`.aegis/.master-key`) is restricted to mode 0600 and warns if permissions are too open. The in-memory derived key at runtime remains accessible via process memory dump (see I-5), but this requires debugger attachment or core dump access. |

### I-4: Credential Leakage via Dashboard

| | |
|---|---|
| **Threat** | The web dashboard exposes credential values or sensitive data through its REST API or WebSocket feed. |
| **Likelihood** | Low — dashboard endpoints return metadata only (names, services, domains), never secret values. |
| **Impact** | Low if only metadata; Critical if secrets leak. |
| **Mitigations** | |
| ✅ Implemented | Dashboard API never returns `secret`, `encrypted`, `iv`, or `auth_tag` fields. |
| ✅ Implemented | Dashboard is localhost-only by default. |
| ⬜ Future | Dashboard access token for authentication (currently open on localhost). |
| **Residual Risk** | Low — metadata exposure (credential names, service names, agent names) is acceptable for an operator-facing dashboard on localhost. |

### I-5: Credential Leakage in Memory

| | |
|---|---|
| **Threat** | Decrypted credentials and the derived encryption key persist in V8 heap memory longer than necessary, accessible via process memory dumps. |
| **Likelihood** | Low — requires a process memory dump (core dump, `/proc/pid/mem`, debugger attachment). |
| **Impact** | Critical — all in-memory credentials exposed. |
| **Mitigations** | |
| ✅ Implemented | Decrypted secrets are used only for the duration of a single request — they become eligible for garbage collection immediately after. |
| ✅ Implemented | The derived key is cached (once per process) but never logged or returned via any API. |
| ⬜ Future | Native addon to explicitly zero Buffer contents after use (V8 does not guarantee immediate garbage collection). |
| **Residual Risk** | Medium — V8's GC is non-deterministic. Secrets can persist in heap memory. This is a fundamental limitation of managed-memory runtimes (JavaScript, Python, Java, Go). Documented in SECURITY_ARCHITECTURE.md §24. |

### I-6: Sensitive Header Forwarding

| | |
|---|---|
| **Threat** | Internal Aegis headers (`X-Aegis-Agent`, `X-Target-Host`) are forwarded to external APIs, revealing internal routing or agent identity. |
| **Likelihood** | High — these headers are on every request. |
| **Impact** | Low — reveals Aegis is in use and which agent made the call. |
| **Mitigations** | |
| ✅ Implemented | Both `x-aegis-agent` and `x-target-host` are stripped from outbound requests before forwarding. |
| ✅ Implemented | Smuggling tests verify these headers are removed. |
| **Residual Risk** | None — internal headers are unconditionally stripped. |

---

## 7. Denial of Service

Denial of service threats involve making the system unavailable or degraded.

### D-1: Agent Request Flooding (Agent → Gate)

| | |
|---|---|
| **Threat** | An agent sends a massive volume of requests to overwhelm Gate, consuming CPU, memory, and network resources. |
| **Likelihood** | Medium — AI agents can generate requests very quickly, especially in loops. |
| **Impact** | Medium — Gate becomes unresponsive, blocking all agents (not just the attacker). Upstream APIs may also rate-limit or ban the credential. |
| **Mitigations** | |
| ✅ Implemented | **Per-credential rate limiting** — configurable at `vault add` time (e.g., `--rate-limit 100/min`). Returns 429 with `Retry-After`. |
| ✅ Implemented | **Per-agent rate limiting** — more restrictive limit (agent vs credential) wins. |
| ✅ Implemented | **Policy-level rate limits** — YAML policies can set per-service rate limits per agent. |
| ✅ Implemented | Rate limit violations are logged to Ledger and emitted as webhook events. |
| ✅ Implemented | **Per-agent connection limits** — configurable concurrent connection cap (default 50). Returns 429 when exceeded. |
| ⬜ Future | Persistent rate limiting (Redis-backed) to survive Gate restarts. |
| **Residual Risk** | Low — four layers of protection (credential rate limit + agent rate limit + policy rate limit + connection cap). The main gap is that rate limits reset on Gate restart (in-memory sliding window). |

### D-2: Oversized Request Bodies

| | |
|---|---|
| **Threat** | An agent sends extremely large request bodies to consume memory (body inspector buffers the entire body for scanning). |
| **Likelihood** | Medium — agents might legitimately send large payloads (file uploads), or maliciously to exhaust memory. |
| **Impact** | Medium — Node.js process memory exhaustion could crash Gate. |
| **Mitigations** | |
| ✅ Implemented | Body inspector has a configurable size limit — bodies exceeding the threshold skip detailed scanning. |
| ✅ Implemented | Node.js HTTP server has default header size limits (16KB). Smuggling tests verify oversized headers are rejected. |
| ✅ Implemented | **Configurable maximum request body size** at the Gate level (default 1 MB). Oversized bodies are rejected with 413 before full buffering. Configurable via `gate.max_body_size` in `aegis.config.yaml`. |
| **Residual Risk** | None — hard body size limit enforced at the Gate level with configurable threshold. |

### D-3: Slowloris / Slow-Read Attacks

| | |
|---|---|
| **Threat** | An agent opens connections and sends data very slowly, tying up Gate's connection pool. |
| **Likelihood** | Low — typically used against public-facing servers, less relevant for localhost. |
| **Impact** | Medium — could exhaust Node.js connection limits. |
| **Mitigations** | |
| ✅ Implemented | Node.js HTTP server has default timeouts for headers and keep-alive. |
| ✅ Implemented | Graceful shutdown drains in-flight requests with a configurable timeout (default 10s). |
| ✅ Implemented | **Explicit request timeout configuration** — server-level idle timeout defends against slowloris; per-outbound-request timeout (default 30s) returns 504 when upstream is unresponsive. Configurable via `gate.request_timeout` in `aegis.config.yaml`. |
| **Residual Risk** | None — explicit timeouts configured at both inbound (idle) and outbound (proxy) layers. |

### D-4: Database Lock Contention

| | |
|---|---|
| **Threat** | High-concurrency writes to SQLite (audit log entries) cause lock contention, degrading Gate performance. |
| **Likelihood** | Low — SQLite WAL mode supports concurrent reads with serialised writes. |
| **Impact** | Low — writes may queue, adding latency to Gate responses. |
| **Mitigations** | |
| ✅ Implemented | SQLite runs in WAL (Write-Ahead Logging) mode — concurrent reads are never blocked. |
| ✅ Implemented | Concurrent isolation tests verify correct behaviour under 5/20/50/100 parallel requests. |
| **Residual Risk** | Low — WAL mode handles typical loads well. Extremely high throughput (>1000 req/s sustained) could hit SQLite's write serialisation limit, but this is beyond the expected use case for a localhost proxy. |

---

## 8. Elevation of Privilege

Elevation of privilege threats involve gaining capabilities beyond what was intended.

### E-1: Service Routing Escape (Agent → Gate)

| | |
|---|---|
| **Threat** | An agent escapes the service routing prefix to access internal Aegis endpoints (`/_aegis/health`, `/_aegis/stats`) or other services' credential scopes. |
| **Likelihood** | Medium — path traversal is the primary vector (see T-1). |
| **Impact** | High — could access health/stats data or use another service's credential. |
| **Mitigations** | |
| ✅ Implemented | Raw URL parsing prevents WHATWG normalisation attacks. |
| ✅ Implemented | Explicit traversal guard rejects `..` and `.` segments (both raw and percent-encoded). |
| ✅ Implemented | Internal `/_aegis/*` endpoints are handled before service routing — they never trigger credential lookup. |
| ✅ Implemented | Domain guard as a safety net — even if routing is escaped, the credential's domain allowlist prevents misuse. |
| **Residual Risk** | None — two-layer path defence + domain guard makes routing escape impossible without also bypassing the domain guard. |

### E-2: Domain Guard Bypass (Agent → Gate)

| | |
|---|---|
| **Threat** | An agent finds a way to bypass the domain guard and send a credential to an unauthorised domain. |
| **Likelihood** | Low — the domain guard is enforced on every code path. |
| **Impact** | Critical — credential exfiltration to an attacker-controlled server. |
| **Mitigations** | |
| ✅ Implemented | **Domain guard is enforced, not advisory.** There is no bypass, no override, no admin mode that skips this check. This is Architecture Decision #1. |
| ✅ Implemented | Both Gate and MCP server enforce the domain guard independently. |
| ✅ Implemented | Wildcard matching is single-level only (`*.slack.com` matches `api.slack.com` but not `deep.api.slack.com`). |
| ✅ Implemented | Domain matching is exact or wildcard — no regex, no substring matching, no normalisation tricks. |
| **Residual Risk** | None — the domain guard is the most hardened component in Aegis. It's tested extensively in Gate integration tests and enforced on every code path. |

### E-3: Credential Scope Bypass (Agent → Gate)

| | |
|---|---|
| **Threat** | An agent with `read` scope on a credential makes a `POST` request (write operation), bypassing scope restrictions. |
| **Likelihood** | Medium — agents routinely attempt all HTTP methods. |
| **Impact** | Medium — the agent performs write operations that were not intended. |
| **Mitigations** | |
| ✅ Implemented | Scope enforcement maps: `read` → GET/HEAD/OPTIONS, `write` → POST/PUT/PATCH/DELETE, `*` → all. |
| ✅ Implemented | Scope checks run before credential injection — blocked requests never reach the external API. |
| ✅ Implemented | Both Gate and MCP server enforce scopes. 13 dedicated scope enforcement tests. |
| **Residual Risk** | None — scope enforcement is applied uniformly across both Gate and MCP. |

### E-4: MCP-to-Gate Security Mismatch (MCP → Gate Pipeline)

| | |
|---|---|
| **Threat** | The MCP server's security pipeline diverges from Gate's, allowing an agent to bypass controls by using MCP instead of HTTP. |
| **Likelihood** | Low — the MCP server was explicitly designed to replicate Gate's full security pipeline. |
| **Impact** | High — all Gate protections bypassed for MCP clients. |
| **Mitigations** | |
| ✅ Implemented | MCP server replicates all Gate checks: agent auth, credential grants, domain guard, scope enforcement, policy evaluation, rate limiting, body inspection, audit logging. |
| ✅ Implemented | 30 MCP-specific tests verify security parity with Gate. |
| **Residual Risk** | Low — any new Gate security feature must be replicated in MCP. This is a maintenance risk that increases as new security controls are added. Code review must verify feature parity. |

### E-5: RBAC Role Escalation (Operator → Admin)

| | |
|---|---|
| **Threat** | A user with `operator` or `viewer` role escalates to `admin` privileges. |
| **Likelihood** | Low — role changes require admin privileges, and the permission check runs before the operation. |
| **Impact** | Critical — admin can manage all credentials, users, and configuration. |
| **Mitigations** | |
| ✅ Implemented | 16 permissions mapped to 3 roles — every CLI command checks `user.checkPermission()` before executing. |
| ✅ Implemented | `updateRole()` requires `manage_users` permission (admin only). |
| ✅ Implemented | Token regeneration requires `manage_users` permission. |
| ✅ Implemented | Bootstrap mode (no auth required) only activates when zero users exist. |
| **Residual Risk** | None — permission checks are mandatory on all state-changing operations. |

---

## 9. Risk Summary Matrix

| ID | Threat | Category | Likelihood | Impact | Residual Risk | Status |
|----|--------|----------|------------|--------|---------------|--------|
| S-1 | Agent impersonation | Spoofing | Medium | High | Low | ✅ Mitigated |
| S-2 | Service name spoofing | Spoofing | High | Medium | Low | ✅ Mitigated |
| S-3 | User token spoofing | Spoofing | Low | Critical | Low | ✅ Mitigated |
| S-4 | X-Target-Host spoofing | Spoofing | High | Critical | None | ✅ Fully mitigated |
| T-1 | Path traversal (URL encoding) | Tampering | High | High | None | ✅ Fully mitigated |
| T-2 | Header injection | Tampering | High | Medium | None | ✅ Fully mitigated |
| T-3 | Body credential exfiltration | Tampering | Medium | High | Low | ✅ Mitigated |
| T-4 | Ciphertext tampering | Tampering | Low | Low | None | ✅ Fully mitigated |
| T-5 | Policy file tampering | Tampering | Low | High | Medium | ⚠️ Accepted |
| T-6 | Request smuggling | Tampering | Low | High | None | ✅ Fully mitigated |
| R-1 | Unlogged agent actions | Repudiation | None | High | Low | ✅ Mitigated |
| R-2 | Audit log deletion | Repudiation | Low | High | Medium | ⚠️ Partially mitigated |
| R-3 | Agent identity gaps | Repudiation | Low | Medium | Low | ✅ Mitigated |
| I-1 | Credential leakage (logs) | Info Disclosure | Medium | Critical | Low | ✅ Mitigated |
| I-2 | Credential leakage (response) | Info Disclosure | Low | High | Medium | ⚠️ Partially mitigated |
| I-3 | Master key on disk | Info Disclosure | Medium | Critical | Low | ✅ Mitigated |
| I-4 | Credential leakage (dashboard) | Info Disclosure | Low | Low | Low | ✅ Mitigated |
| I-5 | Credential leakage (memory) | Info Disclosure | Low | Critical | Medium | ⚠️ Fundamental limitation |
| I-6 | Sensitive header forwarding | Info Disclosure | High | Low | None | ✅ Fully mitigated |
| D-1 | Agent request flooding | Denial of Service | Medium | Medium | Low | ✅ Mitigated |
| D-2 | Oversized request bodies | Denial of Service | Medium | Medium | None | ✅ Fully mitigated |
| D-3 | Slowloris / slow-read | Denial of Service | Low | Medium | None | ✅ Fully mitigated |
| D-4 | Database lock contention | Denial of Service | Low | Low | Low | ✅ Mitigated |
| E-1 | Service routing escape | Elevation | Medium | High | None | ✅ Fully mitigated |
| E-2 | Domain guard bypass | Elevation | Low | Critical | None | ✅ Fully mitigated |
| E-3 | Credential scope bypass | Elevation | Medium | Medium | None | ✅ Fully mitigated |
| E-4 | MCP-to-Gate mismatch | Elevation | Low | High | Low | ✅ Mitigated |
| E-5 | RBAC role escalation | Elevation | Low | Critical | None | ✅ Fully mitigated |

### Summary

- **Fully mitigated (None residual):** 14 threats
- **Mitigated (Low residual):** 10 threats
- **Partially mitigated / Accepted:** 4 threats (T-5, R-2, I-2, I-5)
- **Known weakness:** 0
- **Critical/High unmitigated findings:** 0

---

## 10. Residual Risks

The following residual risks are accepted with documented rationale and planned mitigations.

### Medium Residual Risk

| Risk | Rationale | Planned Mitigation |
|------|-----------|-------------------|
| **T-5: Policy file tampering** | Policy files on disk are trusted. Filesystem compromise already implies machine compromise (Trust Boundary 1 violation). | Future: Signed policy files (HMAC or GPG signature verification). |
| **R-2: Audit log deletion** | SQLite file can be deleted. Webhook alerts provide partial real-time mitigation. | Future: Database backup command, remote syslog forwarding, append-only mode. |
| **I-3: Master key on disk** | OS keychain is the default storage (v0.8.4). File fallback uses mode 0600. Residual risk is co-resident process attaching a debugger or reading the fallback file. | Resolved via cross-platform key storage. Further hardening: native keychain bindings (avoiding CLI process args). |
| **I-2: Credential leakage via response** | External APIs could echo back injected credentials. No response body scanning exists yet. | Post-v1.0: Response body scanning and redaction (competitive with Infisical Agent Sentinel's PII filtering). |
| **I-5: Credential leakage in memory** | V8's non-deterministic garbage collection means secrets persist in heap. Fundamental limitation of managed-memory runtimes. | Future: Native addon for explicit buffer zeroing. This is an industry-wide limitation (applies to Python, Java, Go equally). |

### Accepted Risks (By Design)

| Risk | Why Accepted |
|------|-------------|
| **Localhost network sniffing** | Any process on the same machine can observe localhost traffic (e.g., via `tcpdump`). Mitigated by optional TLS (`--tls`), but the fundamental localhost trust model accepts this. |
| **Agent auth can be disabled** | Agent auth is on by default, but operators can disable it via `--no-agent-auth`. When disabled, any localhost process can use any credential. This is a deliberate operator choice. |
| **Single-user OS account** | Aegis assumes a single-user context. If multiple OS users share a machine, file permissions isolate the vault, but cross-user attacks are not in scope. |
| **V8 heap inspection** | A debugger attached to the Node.js process can dump all in-memory secrets. This is accepted because debugger attachment requires the same OS user (or root), which is already Trust Boundary 1. |

---

*This document should be reviewed and updated whenever security-relevant changes are made to Aegis. Cross-reference with [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md) for implementation details.*
