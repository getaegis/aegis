# Aegis Security Architecture

A complete technical reference explaining how Aegis protects credentials, where data flows, what decisions were made, and why. Written so that you can audit every trust boundary yourself.

**Last updated:** 11 March 2026
**Version:** 0.9.3

---

## Table of Contents

1. [The Problem Aegis Solves](#1-the-problem-aegis-solves)
2. [Threat Model](#2-threat-model)
3. [System Architecture Overview](#3-system-architecture-overview)
4. [Data Flow — Step by Step](#4-data-flow--step-by-step)
5. [Cryptographic Design](#5-cryptographic-design)
6. [Trust Boundaries](#6-trust-boundaries)
7. [The Domain Guard](#7-the-domain-guard)
8. [Audit Trail (Ledger)](#8-audit-trail-ledger)
9. [Request Lifecycle — Complete Walkthrough](#9-request-lifecycle--complete-walkthrough)
10. [Storage Security](#10-storage-security)
11. [Agent Authentication](#11-agent-authentication)
12. [Rate Limiting](#12-rate-limiting)
13. [Body Inspection](#13-body-inspection)
14. [Policy Engine](#14-policy-engine)
15. [Webhook Alerts](#15-webhook-alerts)
16. [User RBAC](#16-user-rbac)
17. [Shamir's Secret Sharing & Seal/Unseal](#17-shamirs-secret-sharing--sealunseal)
18. [Multi-Vault Isolation](#18-multi-vault-isolation)
19. [MCP Server Security](#19-mcp-server-security)
20. [Credential Validation](#20-credential-validation)
21. [Logging & Secret Scrubbing](#21-logging--secret-scrubbing)
22. [What Aegis Does NOT Protect Against](#22-what-aegis-does-not-protect-against)
23. [Design Decisions and Rationale](#23-design-decisions-and-rationale)
24. [Known Limitations and Future Work](#24-known-limitations-and-future-work)
25. [Learning Resources](#25-learning-resources)

---

## 1. The Problem Aegis Solves

When you give an AI agent an API key, you're trusting it with:
- **Confidentiality** — the agent knows your secret and could leak it (in logs, in responses, to other APIs)
- **Scope** — the agent could use your credential against any endpoint, not just the one you intended
- **Auditability** — you have no record of what the agent actually did with your key

Aegis eliminates all three risks:

```
WITHOUT AEGIS:
  Agent has API key → Agent sends it wherever it wants → You hope for the best

WITH AEGIS:
  Agent has NO key → Agent asks Aegis to call API → Aegis injects key at network boundary
                                                  → Aegis checks domain allowlist
                                                  → Aegis logs everything
                                                  → Agent sees response, never the key
```

**The fundamental principle:** The agent never possesses the credential. It only possesses the ability to *request* that a credentialed call be made, and Aegis decides whether to allow it.

---

## 2. Threat Model

### What we're defending against

| Threat | Description | Aegis Mitigation |
|--------|-------------|------------------|
| **Credential exfiltration** | Agent sends your API key to an attacker-controlled server | Agent never has the key. Domain guard prevents forwarding to unapproved domains. |
| **Credential leakage in logs** | Agent includes key in its output/reasoning | Key never enters agent memory. It's injected after the agent's request leaves. |
| **Scope creep** | Agent uses a Slack key to call GitHub | Each credential is bound to specific service names and domains. |
| **Unaudited actions** | Agent makes API calls you can't trace | Every request (allowed AND blocked) is recorded in the Ledger. |
| **Replay attacks** | Someone re-sends a previously captured request | Not directly mitigated by Aegis — relies on upstream API's own protections. |
| **Body flooding (STRIDE D-2)** | Agent sends enormous request body to exhaust memory | Configurable max body size (default 1 MB), rejects with 413 before full buffering. |
| **Slowloris / slow read (STRIDE D-3)** | Attacker holds connections open with slow data | Server-level idle timeout + outbound request timeout (default 30s), returns 504. |
| **Socket exhaustion (STRIDE D-1)** | Agent opens too many concurrent connections | Per-agent connection limit (default 50), returns 429 when exceeded. |
| **Cascading upstream failure** | Failing API drags Gate down | Circuit breaker: 5 consecutive 5xx → 30s cooldown → 503 with Retry-After. |

### What we assume is trusted

| Trust Assumption | Why |
|------------------|-----|
| **The machine running Aegis** | Aegis runs on localhost. If the machine is compromised, all bets are off. |
| **The person who ran `aegis init`** | They generated the master key. If they're malicious, they already have access. |
| **Node.js `crypto` module** | We use Node's built-in crypto which wraps OpenSSL. It's extensively audited. |
| **SQLite via better-sqlite3-multiple-ciphers** | Embedded database, no network surface. WAL mode for concurrent reads. ChaCha20-Poly1305 encryption at rest. |
| **The upstream API** | We forward requests over HTTPS. The API itself could be compromised, but that's outside Aegis's scope. |

### What we explicitly do NOT trust

| Untrusted Entity | Why |
|------------------|-----|
| **The AI agent** | This is the whole point. The agent is treated as a potentially hostile client. |
| **Agent-supplied headers** | The agent could try to inject `Authorization` or `X-API-Key` headers — Aegis strips them. |
| **Agent-supplied target domains** | The agent can request an `X-Target-Host`, but Aegis validates it against the allowlist. |

---

## 3. System Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                         YOUR MACHINE                                 │
│                                                                      │
│  ┌───────────┐     HTTP (localhost)     ┌─────────────────────────┐  │
│  │           │ ──────────────────────── │       AEGIS GATE        │  │
│  │  AI Agent │   Agent never has keys   │    (localhost:3100)     │  │
│  │           │ ◄─────────────────────── │                         │  │
│  └───────────┘     API responses only   │  ┌──────────────────┐  │  │
│                                         │  │  HEADER SCRUBBER │  │  │
│                                         │  │  Strips auth     │  │  │
│                                         │  │  headers from    │  │  │
│                                         │  │  agent request   │  │  │
│                                         │  └────────┬─────────┘  │  │
│                                         │           │            │  │
│                                         │  ┌────────▼─────────┐  │  │
│                                         │  │  DOMAIN GUARD    │  │  │
│                                         │  │  Is this domain  │  │  │
│                                         │  │  in the allow-   │  │  │
│                                         │  │  list?           │  │  │
│                                         │  └────────┬─────────┘  │  │
│                                         │      PASS │ FAIL→403   │  │
│                                         │  ┌────────▼─────────┐  │  │
│                                         │  │  CRED INJECTOR   │  │  │
│                                         │  │  Adds real auth  │  │  │
│                                         │  │  header to       │  │  │
│                                         │  │  outbound req    │  │  │
│  ┌───────────┐                          │  └────────┬─────────┘  │  │
│  │   VAULT   │◄── decrypt on demand ───────────────┤            │  │
│  │  (SQLite) │                          │           │            │  │
│  │  AES-256  │                          │  ┌────────▼─────────┐  │  │
│  │  -GCM     │                          │  │  LEDGER LOGGER   │  │  │
│  └───────────┘                          │  │  Records every   │  │
│                                         │  │  request         │  │  │
│  ┌───────────┐                          │  └────────┬─────────┘  │  │
│  │  LEDGER   │◄── insert ──────────────────────────┤            │  │
│  │  (SQLite) │                          │           │            │  │
│  └───────────┘                          └───────────┼────────────┘  │
│                                                     │               │
└─────────────────────────────────────────────────────┼───────────────┘
                                                      │ HTTPS (TLS 1.2+)
                                                      ▼
                                            ┌──────────────────┐
                                            │  EXTERNAL API    │
                                            │  (api.slack.com, │
                                            │   api.openai.com │
                                            │   etc.)          │
                                            └──────────────────┘
```

> **Interactive diagram:** [docs/diagrams/trust-boundaries.mmd](diagrams/trust-boundaries.mmd)

```mermaid
graph LR
    subgraph TRUSTED["TRUSTED ZONE (your machine)"]
        direction TB
        ENV["Environment Variables<br/>AEGIS_MASTER_KEY<br/>AEGIS_SALT"]
        VAULT["Vault<br/>(encrypted secrets<br/>in SQLite)"]
        GATE["Aegis Gate<br/>(localhost:3100)"]
        LEDGER["Ledger<br/>(audit log)"]

        ENV -->|"loaded at startup"| GATE
        VAULT -->|"decrypt on demand"| GATE
        GATE -->|"log every request"| LEDGER
    end

    subgraph UNTRUSTED["UNTRUSTED ZONE"]
        AGENT["AI Agent<br/>(any language/framework)"]
    end

    subgraph EXTERNAL["EXTERNAL (internet)"]
        API["Target API<br/>(api.slack.com etc.)"]
    end

    AGENT -->|"① HTTP request<br/>(no credentials)"| GATE
    GATE -->|"③ HTTPS request<br/>(with credentials,<br/>TLS encrypted)"| API
    API -->|"④ HTTPS response"| GATE
    GATE -->|"⑤ HTTP response<br/>(no credentials)"| AGENT
    GATE -->|"② Domain Guard<br/>check"| GATE

    style AGENT fill:#ffcccc,stroke:#cc0000,color:#000
    style ENV fill:#ff9999,stroke:#cc0000,color:#000
    style VAULT fill:#99ccff,stroke:#0066cc,color:#000
    style GATE fill:#99ff99,stroke:#009900,color:#000
    style LEDGER fill:#ffff99,stroke:#cccc00,color:#000
    style API fill:#cccccc,stroke:#666666,color:#000
```

---

## 4. Data Flow — Step by Step

### 4.1 Initialization (`aegis init`)

```
User runs `aegis init`
    │
    ├─► crypto.randomBytes(32) generates 256-bit master key
    ├─► generateSalt() generates 256-bit random salt (also crypto.randomBytes(32))
    │
    ├─► Default mode: master key stored in OS keychain (macOS Keychain,
    │   Windows Credential Manager, Linux Secret Service via secret-tool)
    │   .env gets only: AEGIS_PORT, AEGIS_DATA_DIR, AEGIS_LOG_LEVEL
    │
    ├─► --env-file mode: master key written to .env with file mode 0600
    │   (for CI/headless environments without an OS keychain)
    │
    ├─► --write-secrets mode: everything written to aegis.config.yaml
    │
    └─► Fallback (no OS keychain detected): key stored in .aegis/.master-key
        with file mode 0600 and a warning printed to the user
```

**Why OS keychain by default?** The master key in plaintext on disk (`.env`) was the biggest gap in Aegis's threat model — any process running as your user (including the AI agents Aegis protects against) could read it. OS keychains are encrypted, access-controlled, and scoped to the user's login session. On macOS, the Keychain is backed by the Secure Enclave. On Windows, DPAPI ties the key to the user's login credentials. The `--env-file` flag keeps CI workflows working.

### 4.2 Storing a Credential (`aegis vault add`)

```
User runs: aegis vault add --name slack --service slack --secret xoxb-... --domains api.slack.com

    ┌─────────────────────────────────────────────────────────────┐
    │                    ENCRYPTION PIPELINE                       │
    │                                                             │
    │  1. Load AEGIS_MASTER_KEY and AEGIS_SALT from env/.env      │
    │                                                             │
    │  2. Derive encryption key (PBKDF2):                         │
    │     masterKey ──┐                                           │
    │     salt ───────┤                                           │
    │                 ▼                                           │
    │     PBKDF2-SHA512 (210,000 iterations)                      │
    │                 │                                           │
    │                 ▼                                           │
    │     derivedKey (32 bytes / 256 bits)                        │
    │     ⚠ Cached in Vault instance — NOT called per-operation   │
    │                                                             │
    │  3. Generate random IV:                                     │
    │     crypto.randomBytes(16) → iv (16 bytes / 128 bits)       │
    │     (Unique per encryption — NEVER reused)                  │
    │                                                             │
    │  4. Encrypt:                                                │
    │     plaintext ("xoxb-...") ──┐                              │
    │     derivedKey ──────────────┤                               │
    │     iv ──────────────────────┤                               │
    │                              ▼                              │
    │                    AES-256-GCM encrypt                      │
    │                         │    │                              │
    │                         ▼    ▼                              │
    │                 ciphertext  authTag (16 bytes)              │
    │                                                             │
    │  5. Store in SQLite:                                        │
    │     ┌──────────────────────────────────────────────┐        │
    │     │ credentials table                            │        │
    │     │   id:        random UUID                     │        │
    │     │   name:      "slack" (plaintext)             │        │
    │     │   service:   "slack" (plaintext)             │        │
    │     │   encrypted: [ciphertext bytes]   ◄── BLOB   │        │
    │     │   iv:        [iv bytes]           ◄── BLOB   │        │
    │     │   auth_tag:  [authTag bytes]      ◄── BLOB   │        │
    │     │   auth_type: "bearer" (plaintext)            │        │
    │     │   domains:   '["api.slack.com"]' (JSON text) │        │
    │     │   scopes:    '["*"]' (JSON text)             │        │
    │     └──────────────────────────────────────────────┘        │
    │                                                             │
    │  ⚠ The plaintext secret ("xoxb-...") is NEVER stored.      │
    │    It exists in memory only during this encrypt operation.  │
    └─────────────────────────────────────────────────────────────┘
```

**Key insight:** The credential name, service, domains, and auth type are stored in plaintext. This is intentional — Aegis needs to look up credentials by service name without decrypting. Only the actual secret value is encrypted. The metadata is not sensitive (knowing that you *have* a Slack credential doesn't compromise it).

### 4.3 Proxying a Request (`aegis gate` running)

This is the critical path. See [Section 9](#9-request-lifecycle--complete-walkthrough) for the line-by-line code walkthrough.

```
Agent sends: POST http://localhost:3100/slack/api/chat.postMessage
             Headers: Content-Type: application/json
                      X-Target-Host: api.slack.com     ← optional
                      Authorization: Bearer fake-key   ← agent might try this

    ┌──────────────────────────────────────────────────────────────────┐
    │                      GATE REQUEST PIPELINE                       │
    │                                                                  │
    │  STEP 1: Parse URL                                               │
    │    new URL("/slack/api/chat.postMessage", "http://localhost:3100")│
    │    pathParts = ["slack", "api", "chat.postMessage"]              │
    │    serviceName = "slack"                                         │
    │    remainingPath = "/api/chat.postMessage"                       │
    │                                                                  │
    │  STEP 2: Credential Lookup                                       │
    │    vault.getByService("slack")                                   │
    │      → SQL: SELECT * FROM credentials WHERE service = 'slack'    │
    │      → Decrypts secret using cached derivedKey                   │
    │      → Returns: { secret: "xoxb-real-key", domains: [...], ... } │
    │    ⚠ Decrypted secret is now in Node.js heap memory              │
    │    ⚠ It will be garbage collected after this request completes   │
    │                                                                  │
    │  STEP 3: Determine Target Domain                                 │
    │    Read X-Target-Host header → "api.slack.com" (or null)         │
    │    targetDomain = header value ?? credential.domains[0]          │
    │                                                                  │
    │  STEP 4: Domain Guard ★ SECURITY CRITICAL ★                     │
    │    vault.domainMatches("api.slack.com", ["api.slack.com"])        │
    │      → Is "api.slack.com" in the allowlist? YES → proceed        │
    │      → If NO → 403 Forbidden, log to Ledger, stop here          │
    │                                                                  │
    │  STEP 5: Header Scrubbing                                        │
    │    For each header the agent sent:                                │
    │      ✗ "authorization"  → STRIPPED (agent can't inject auth)     │
    │      ✗ "x-api-key"      → STRIPPED                               │
    │      ✗ "host"           → STRIPPED (replaced with target domain) │
    │      ✗ "x-target-host"  → STRIPPED (internal routing header)     │
    │      ✓ "content-type"   → KEPT                                   │
    │      ✓ "accept"         → KEPT                                   │
    │      ✓ other headers    → KEPT                                   │
    │                                                                  │
    │  STEP 6: Credential Injection                                    │
    │    Based on auth_type:                                           │
    │      "bearer" → Authorization: Bearer xoxb-real-key              │
    │      "header" → {headerName}: xoxb-real-key                      │
    │      "basic"  → Authorization: Basic base64(xoxb-real-key)       │
    │      "query"  → append ?{paramName}=secret to URL               │
    │    Also sets: Host: api.slack.com                                 │
    │                                                                  │
    │  STEP 7: Forward via HTTPS                                       │
    │    https.request({                                                │
    │      hostname: "api.slack.com",     ← validated domain           │
    │      port: 443,                     ← always TLS                 │
    │      path: "/api/chat.postMessage", ← from agent's URL          │
    │      method: "POST",                                             │
    │      headers: { ...scrubbed, ...injectedAuth }                   │
    │    })                                                            │
    │    ⚠ Connection is HTTPS — credential is encrypted in transit    │
    │    ⚠ Agent's request body is piped through unchanged             │
    │                                                                  │
    │  STEP 8: Response Handling                                       │
    │    Response comes back from api.slack.com                        │
    │      → Strip set-cookie headers (prevent session hijack)         │
    │      → Log to Ledger (credential_id, service, domain, status)   │
    │      → Pipe response body back to agent                          │
    │    ⚠ The response NEVER contains the credential                 │
    │    ⚠ The agent gets the API response, not the key               │
    │                                                                  │
    └──────────────────────────────────────────────────────────────────┘
```

---

## 5. Cryptographic Design

> **Interactive diagram:** [docs/diagrams/crypto-pipeline.mmd](diagrams/crypto-pipeline.mmd)

```mermaid
graph TD
    subgraph INIT["aegis init"]
        MK["crypto.randomBytes(32)<br/>→ Master Key<br/>(256 bits, hex encoded)"]
        SALT["crypto.randomBytes(32)<br/>→ Salt<br/>(256 bits, hex encoded)"]
    end

    subgraph KDF["Key Derivation (once per process)"]
        MK --> PBKDF2["PBKDF2-SHA512<br/>210,000 iterations"]
        SALT --> PBKDF2
        PBKDF2 --> DK["Derived Key<br/>(32 bytes / 256 bits)<br/>Cached in Vault.derivedKey"]
    end

    subgraph ENC["Encryption (per credential stored)"]
        RIV["crypto.randomBytes(16)<br/>→ Random IV<br/>(unique per encrypt)"]
        PT["Plaintext Secret<br/>(e.g., 'xoxb-real-key')"]
        DK --> AESGCM["AES-256-GCM<br/>Encrypt"]
        RIV --> AESGCM
        PT --> AESGCM
        AESGCM --> CT["Ciphertext<br/>(BLOB)"]
        AESGCM --> AT["Auth Tag<br/>(16 bytes)"]
    end

    subgraph DB["SQLite Storage"]
        CT --> ROW["credentials row:<br/>encrypted = BLOB<br/>iv = BLOB<br/>auth_tag = BLOB"]
        AT --> ROW
        RIV --> ROW
    end

    subgraph DEC["Decryption (per request)"]
        ROW --> |"Read BLOB columns"| AESD["AES-256-GCM<br/>Decrypt"]
        DK --> AESD
        AESD --> |"Verify auth tag"| PTOUT["Plaintext Secret<br/>(in memory only,<br/>used for one request)"]
    end

    style MK fill:#ff9999,stroke:#cc0000,color:#000
    style SALT fill:#ff9999,stroke:#cc0000,color:#000
    style DK fill:#ffcc99,stroke:#cc6600,color:#000
    style PT fill:#ff9999,stroke:#cc0000,color:#000
    style PTOUT fill:#ff9999,stroke:#cc0000,color:#000
    style CT fill:#99ff99,stroke:#009900,color:#000
    style AT fill:#99ff99,stroke:#009900,color:#000
    style ROW fill:#99ccff,stroke:#0066cc,color:#000
```

### 5.1 Algorithm Choice: AES-256-GCM

| Property | Value | Why |
|----------|-------|-----|
| **Algorithm** | AES-256-GCM | Industry standard authenticated encryption. Used by TLS 1.3, AWS KMS, Google Cloud KMS. |
| **Key size** | 256 bits (32 bytes) | Maximum AES key size. 128-bit would be sufficient for most uses, but 256-bit provides extra margin. |
| **IV size** | 128 bits (16 bytes) | Standard for GCM mode. Generated fresh for every encryption via `crypto.randomBytes()`. |
| **Auth tag** | 128 bits (16 bytes) | Default GCM tag size. Provides integrity — if anyone tampers with the ciphertext, decryption fails. |

**Why GCM instead of CBC?**
- GCM provides **authenticated encryption** — it guarantees both confidentiality AND integrity in a single operation.
- CBC only provides confidentiality. You'd need to add HMAC separately (encrypt-then-MAC) to get integrity. This is error-prone — many real-world vulnerabilities came from getting the MAC wrong (padding oracle attacks, etc.).
- GCM is the cipher suite used by TLS 1.3. If it's good enough for every HTTPS connection on the internet, it's good enough for us.

**Source:** [src/vault/crypto.ts](../src/vault/crypto.ts) lines 1-4

### 5.2 Key Derivation: PBKDF2

```
MASTER KEY (64 hex chars = 256 bits of entropy)
     │
     │  Resolution chain (highest priority wins):
     │    1. AEGIS_MASTER_KEY env var
     │    2. .env file (AEGIS_MASTER_KEY)
     │    3. aegis.config.yaml (vault.master_key)
     │    4. OS keychain (macOS/Windows/Linux)
     │    5. File fallback (.aegis/.master-key)
     │
     │  Example: a3f8c1d9e0b7...64 hex characters
     │
     ▼
 ┌──────────────────────────────┐
 │         PBKDF2               │
 │                              │
 │  Algorithm:    SHA-512       │
 │  Iterations:   210,000       │
 │  Salt:         random        │
 │                (32 bytes,    │
 │                 generated    │
 │                 at init)     │
 │  Output:       32 bytes      │
 │                (256-bit key) │
 └──────────┬───────────────────┘
            │
            ▼
     DERIVED KEY (32 bytes)
     Used directly by AES-256-GCM
     Cached in Vault instance (one derivation per process lifetime)
```

**Why PBKDF2 instead of using the master key directly?**
- PBKDF2 is a **key derivation function** — it stretches a password/key through many iterations to make brute-force attacks computationally expensive.
- Even though our master key is already high-entropy (256 random bits), PBKDF2 adds defense-in-depth. If someone chose a weaker master key, the 210,000 iterations slow down brute-force attempts.
- The **salt** ensures that identical master keys on different deployments produce different derived keys. Without salt, two Aegis instances with the same master key would produce identical ciphertext for the same plaintext, which is an information leak.

**Why 210,000 iterations?**
- OWASP recommends a minimum of 600,000 for PBKDF2-SHA256 and 210,000 for PBKDF2-SHA512 (as of 2023). We use SHA-512, which produces roughly 2.8× more work per iteration than SHA-256, so 210,000 SHA-512 iterations meets the OWASP minimum.
- The key is derived once at startup and cached, so the ~150-250ms cost is a one-time hit, not per-request.
- This is a reasonable trade-off for a local tool. If Aegis becomes a server handling many concurrent inits, we should switch to Argon2id.

**Why not Argon2 or scrypt?**
- PBKDF2 is built into Node.js `crypto` — no native addon dependency.
- Argon2 is memory-hard (better against GPU attacks) but requires a native module.
- For Aegis's threat model (local machine, high-entropy master key), PBKDF2 is sufficient.
- Future consideration: if Aegis is deployed as a shared service, Argon2id would be the better choice.

**Source:** [src/vault/crypto.ts](../src/vault/crypto.ts) lines 18-28

### 5.3 IV (Initialization Vector) Management

Every call to `encrypt()` generates a fresh 16-byte random IV using `crypto.randomBytes()`.

**Why this matters:**
- AES-GCM is catastrophically broken if you ever reuse an IV with the same key. An attacker can XOR two ciphertexts together to cancel out the key stream and recover plaintext.
- By generating the IV randomly from a cryptographic RNG for every encryption, the probability of collision is negligible (birthday problem on 128-bit space = need ~2^64 encryptions before a 50% chance of collision).
- The IV is stored alongside the ciphertext in the `credentials` table. It's not a secret — its purpose is to ensure uniqueness, not confidentiality.

**Source:** [src/vault/crypto.ts](../src/vault/crypto.ts) lines 38-47

### 5.4 Authentication Tag

GCM produces a 16-byte authentication tag during encryption, which is verified during decryption.

**What it protects against:**
- If anyone modifies the ciphertext (even a single bit), `decipher.setAuthTag()` + `decipher.final()` will throw an error instead of returning corrupted plaintext.
- This prevents a class of attacks where an attacker modifies encrypted data without knowing the key, hoping the tampered result does something useful (e.g., changing `admin=false` to `admin=true` in an encrypted cookie).

**Source:** [src/vault/crypto.ts](../src/vault/crypto.ts) lines 53-60

### 5.5 Key Caching

The PBKDF2 derivation (210,000 iterations of SHA-512) takes ~150-250ms depending on hardware. This is intentional for security (slows brute force) but would be a performance problem if done per-request.

**Solution:** The `Vault` class derives the key once in its constructor and caches it in `this.derivedKey`. This means:
- `aegis vault add` — one derivation for the session
- `aegis gate` — one derivation at startup, then zero for all requests

The derived key lives in Node.js heap memory for the process lifetime. When the process exits, the memory is released. JavaScript's garbage collector will eventually overwrite the memory, but there's no explicit zeroing of the key material. This is a known limitation (see [Section 13](#13-known-limitations-and-future-work)).

**Source:** [src/vault/vault.ts](../src/vault/vault.ts) lines 43-58

---

## 6. Trust Boundaries

A trust boundary is a line where data crosses from a higher-trust zone to a lower-trust zone (or vice versa). Aegis has four.

> **Interactive diagram:** [docs/diagrams/request-lifecycle.mmd](diagrams/request-lifecycle.mmd) — shows an allowed request crossing all boundaries.

```mermaid
sequenceDiagram
    participant Agent as AI Agent
    participant Gate as Aegis Gate<br/>(localhost:3100)
    participant Vault as Vault<br/>(SQLite + AES-256-GCM)
    participant Ledger as Ledger<br/>(SQLite audit_log)
    participant API as External API<br/>(HTTPS)

    Note over Agent,API: Agent NEVER has the real credential

    Agent->>Gate: POST /slack/api/chat.postMessage<br/>Headers: Content-Type, X-Target-Host

    Gate->>Gate: Parse URL<br/>service = "slack"<br/>path = "/api/chat.postMessage"

    Gate->>Vault: getByService("slack")
    Vault->>Vault: SELECT encrypted, iv, auth_tag<br/>FROM credentials<br/>WHERE service = 'slack'
    Vault->>Vault: AES-256-GCM decrypt<br/>using cached derivedKey
    Vault-->>Gate: { secret: "xoxb-real-key",<br/>domains: ["api.slack.com"],<br/>authType: "bearer" }

    Gate->>Gate: Domain Guard Check<br/>Is "api.slack.com" in<br/>["api.slack.com"]?<br/>✓ ALLOWED

    Gate->>Gate: Strip agent auth headers<br/>(Authorization, X-API-Key,<br/>Host, X-Target-Host)

    Gate->>Gate: Inject credential<br/>Authorization: Bearer xoxb-real-key<br/>Host: api.slack.com

    Gate->>API: HTTPS POST api.slack.com/api/chat.postMessage<br/>Authorization: Bearer xoxb-real-key<br/>(TLS encrypted in transit)
    API-->>Gate: 200 OK { "ok": true }

    Gate->>Gate: Strip Set-Cookie<br/>from response

    Gate->>Ledger: logAllowed({ service: "slack",<br/>domain: "api.slack.com",<br/>method: "POST", status: 200 })

    Gate-->>Agent: 200 OK { "ok": true }<br/>(NO credential in response)
```

The four boundaries in detail:

```
 ┌─────────────────────────────────────────────────────────────────┐
 │                                                                 │
 │  BOUNDARY 1: Agent ←→ Gate           (localhost HTTP)           │
 │  ═════════════════════════════════════                           │
 │  The agent is UNTRUSTED. Everything it sends is suspect.        │
 │  Gate strips auth headers, validates domains, controls routing. │
 │                                                                 │
 │  BOUNDARY 2: Gate ←→ Vault           (in-process function call) │
 │  ════════════════════════════════════                            │
 │  Gate asks Vault for a credential. Vault returns decrypted      │
 │  secret. This happens in the same Node.js process — no network. │
 │  The secret exists in heap memory briefly.                      │
 │                                                                 │
 │  BOUNDARY 3: Gate ←→ External API    (HTTPS over internet)      │
 │  ══════════════════════════════════════                          │
 │  The credential travels over TLS to the real API.               │
 │  Aegis trusts the TLS certificate chain (Node.js default CA).   │
 │  The credential is in the HTTP header, encrypted by TLS.        │
 │                                                                 │
 │  BOUNDARY 4: User ←→ Aegis Config    (filesystem / env vars)    │
 │  ════════════════════════════════════                            │
 │  The master key must get from the user into Aegis somehow.      │
 │  Options: env var (ephemeral) or .env file (persisted).         │
 │  .env files use mode 0600 (owner-only read).                    │
 │                                                                 │
 └─────────────────────────────────────────────────────────────────┘
```

### Boundary 1 in detail: What does Gate strip from agent requests?

| Header | Action | Why |
|--------|--------|-----|
| `Authorization` | **Stripped** | Agent could try to send its own auth header — we replace it with the real one |
| `X-API-Key` | **Stripped** | Same reason — common alternative auth header |
| `Host` | **Stripped** | Replaced with the validated target domain |
| `X-Target-Host` | **Stripped** | Internal routing header — should not be forwarded to upstream |
| `Set-Cookie` (response) | **Stripped** | Prevents upstream API from setting cookies that the agent could replay |
| Everything else | **Passed through** | Content-Type, Accept, etc. are safe to forward |

---

## 7. The Domain Guard

The domain guard is the most critical security mechanism in Aegis. It answers one question: **"Is the agent allowed to send this credential to this domain?"**

### How it works

```
Agent requests: POST http://localhost:3100/slack/api/chat.postMessage
                X-Target-Host: evil.com    ← agent tries to exfiltrate

Gate resolves:
  service = "slack"
  credential = vault.getByService("slack")
  credential.domains = ["api.slack.com", "*.slack.com"]
  targetDomain = "evil.com" (from X-Target-Host)

Domain Guard check:
  vault.domainMatches("evil.com", ["api.slack.com", "*.slack.com"])

  Check 1: "evil.com" === "api.slack.com"?       → NO
  Check 2: "evil.com" matches "*.slack.com"?
           Does "evil.com" end with ".slack.com"? → NO

  RESULT: ✗ BLOCKED
  → 403 Forbidden returned to agent
  → Logged to Ledger with reason: 'Domain "evil.com" not in allowlist'
```

### Wildcard matching rules

| Pattern | Matches | Doesn't Match | Why |
|---------|---------|---------------|-----|
| `api.slack.com` | `api.slack.com` | `hooks.slack.com` | Exact match only |
| `*.slack.com` | `api.slack.com`, `hooks.slack.com` | `slack.com`, `deep.api.slack.com` | Single-level wildcard only |

**Why single-level only?** A pattern like `*.slack.com` could be dangerous if it matched `evil.attacker.slack.com` — but subdomain takeover could make deep subdomains controllable by an attacker. Limiting to single-level (`api`, `hooks`, etc.) reduces this risk.

**Source:** [src/vault/vault.ts](../src/vault/vault.ts) lines 194-210

### Blocked exfiltration — visual

> **Interactive diagram:** [docs/diagrams/blocked-exfiltration.mmd](diagrams/blocked-exfiltration.mmd)

```mermaid
sequenceDiagram
    participant Agent as AI Agent<br/>(Malicious)
    participant Gate as Aegis Gate
    participant Vault as Vault
    participant Ledger as Ledger

    Note over Agent,Ledger: Exfiltration attempt — agent tries to<br/>send Slack credential to evil.com

    Agent->>Gate: POST /slack/steal<br/>X-Target-Host: evil.com

    Gate->>Gate: Parse URL<br/>service = "slack"

    Gate->>Vault: getByService("slack")
    Vault-->>Gate: { domains: ["api.slack.com"],<br/>secret: "xoxb-..." }

    Gate->>Gate: Domain Guard Check<br/>Is "evil.com" in<br/>["api.slack.com"]?

    rect rgb(255, 200, 200)
        Gate->>Gate: ✗ BLOCKED<br/>evil.com NOT in allowlist
    end

    Gate->>Ledger: logBlocked({<br/>domain: "evil.com",<br/>reason: "not in allowlist" })

    Gate-->>Agent: 403 Forbidden<br/>{ error: "Domain not in<br/>credential allowlist" }

    Note over Agent,Ledger: Credential NEVER left the process.<br/>Attack fully logged in Ledger.
```

### What if X-Target-Host is not provided?

If the agent doesn't send `X-Target-Host`, Aegis uses `credential.domains[0]` — the first domain in the allowlist. This is always safe because it was put there by the user when they created the credential.

**Source:** [src/gate/gate.ts](../src/gate/gate.ts) lines 122-127

---

## 8. Audit Trail (Ledger)

Every request through Gate is recorded — both allowed and blocked. This is non-negotiable.

### What gets logged

**Allowed requests:**
```
┌──────────────────────────────────────────────────────────┐
│  audit_log                                               │
│                                                          │
│  id:              1                                      │
│  timestamp:       2026-03-07T12:34:56.000Z               │
│  credential_id:   "a1b2c3d4-..."      ← which key       │
│  credential_name: "slack-bot"          ← human-readable  │
│  service:         "slack"              ← service name    │
│  target_domain:   "api.slack.com"      ← where it went   │
│  method:          "POST"               ← HTTP method     │
│  path:            "/api/chat.postMessage" ← API endpoint │
│  status:          "allowed"                              │
│  response_code:   200                  ← upstream reply   │
│  blocked_reason:  NULL                                   │
└──────────────────────────────────────────────────────────┘
```

**Blocked requests:**
```
┌──────────────────────────────────────────────────────────┐
│  audit_log                                               │
│                                                          │
│  id:              2                                      │
│  timestamp:       2026-03-07T12:35:01.000Z               │
│  credential_id:   NULL                 ← no cred used    │
│  credential_name: NULL                                   │
│  service:         "slack"                                │
│  target_domain:   "evil.com"                             │
│  method:          "POST"                                 │
│  path:            "/api/chat.postMessage"                │
│  status:          "blocked"                              │
│  response_code:   NULL                 ← never forwarded │
│  blocked_reason:  "Domain \"evil.com\" not in allowlist" │
└──────────────────────────────────────────────────────────┘
```

### What is NOT logged

- **The credential value itself** — never, under any circumstances
- **Request/response bodies** — these could contain sensitive data and would balloon storage
- **Query parameters** — could contain tokens or PII

### Querying and exporting

```bash
aegis ledger show                       # Last 20 entries
aegis ledger show --blocked             # Only blocked requests
aegis ledger show --service slack       # Filter by service
aegis ledger stats                      # Summary statistics
aegis ledger export -o audit.csv        # CSV export for analysis
```

**Source:** [src/ledger/ledger.ts](../src/ledger/ledger.ts)

---

## 9. Request Lifecycle — Complete Walkthrough

Here's what happens for every single request, mapped to the actual source code:

### Phase 1: Request Arrives

```typescript
// gate.ts — handleRequest()

// Agent sends: POST http://localhost:3100/slack/api/chat.postMessage
// Parse from raw URL to prevent WHATWG URL normalization attacks
const rawUrl = req.url ?? '/';
const qIdx = rawUrl.indexOf('?');
const rawPath = qIdx >= 0 ? rawUrl.slice(0, qIdx) : rawUrl;
const pathParts = rawPath.split('/').filter(Boolean);
// pathParts = ["slack", "api", "chat.postMessage"]
```

**Decision point:** We parse `req.url` as a raw string instead of using `new URL()`. The WHATWG URL standard (`new URL()`) normalises percent-encoded dot segments — `%2e%2e` → `..` — and resolves path traversal. This means an agent could send `/service/%2e%2e/_aegis/health` and `new URL()` would normalise it to `/_aegis/health`, bypassing service routing and reaching internal endpoints. Raw string splitting preserves percent-encoding as-is, preventing this attack. An additional explicit guard rejects any path segment that decodes to `..` or `.`, returning 400 before routing occurs.

### Phase 2: Service Resolution

```typescript
const serviceName = pathParts[0]; // "slack"
const credential = this.vault.getByService(serviceName);
```

The service name is the first path segment. Everything after it is the actual API path. This means the agent's URL naturally describes what it's trying to do:
- `localhost:3100/slack/api/chat.postMessage` → call Slack's chat API
- `localhost:3100/openai/v1/chat/completions` → call OpenAI's completion API

If no credential exists for this service → **404, logged as blocked**.

### Phase 3: Credential Decryption

```typescript
// vault.ts — getByService()
const secret = decrypt(
  { encrypted: row.encrypted, iv: row.iv, authTag: row.auth_tag },
  this.derivedKey,  // ← cached PBKDF2 result, NOT recomputed
);
```

At this point, the plaintext secret (`"xoxb-real-key"`) is in Node.js heap memory. It will be used briefly in Phase 6 and then become eligible for garbage collection.

### Phase 4: Domain Guard

```typescript
const agentRequestedHost = (req.headers["x-target-host"] as string | undefined) ?? undefined;
const targetDomain = agentRequestedHost ?? credential.domains[0];

if (!this.vault.domainMatches(targetDomain, credential.domains)) {
  // → 403 Forbidden, logged as blocked
}
```

This is where credential exfiltration is prevented. The domain guard is the **primary security boundary** of the system.

### Phase 5: Header Scrubbing

```typescript
for (const [key, value] of Object.entries(req.headers)) {
  const lower = key.toLowerCase();
  if (lower === "authorization" || lower === "x-api-key") continue;  // strip
  if (lower === "host" || lower === "x-target-host") continue;       // strip
  outboundHeaders[key] = value;  // keep everything else
}
```

### Phase 6: Credential Injection

```typescript
switch (credential.authType) {
  case "bearer":
    headers.authorization = `Bearer ${credential.secret}`;
    break;
  case "header":
    headers[credential.headerName ?? "x-api-key"] = credential.secret;
    break;
  case "basic":
    headers.authorization = `Basic ${Buffer.from(credential.secret).toString("base64")}`;
    break;
}
outboundHeaders.host = targetDomain;
```

The real credential is now in the outbound headers. This is the only moment it leaves the process boundary — over a TLS connection to the validated domain.

### Phase 7: Forward & Log

```typescript
const proxyReq = https.request({
  hostname: targetDomain,     // validated domain
  port: 443,                   // always TLS
  path: `${remainingPath}${query}`,
  method: req.method,
  headers: outboundHeaders,   // includes injected credential
});

// On response:
delete safeHeaders["set-cookie"];  // strip session cookies
this.ledger.logAllowed({ ... });   // always log
res.writeHead(proxyRes.statusCode ?? 500, safeHeaders);
proxyRes.pipe(res);                // pipe response to agent
```

---

## 10. Storage Security

### Database: SQLite with WAL mode and encryption at rest

```
.aegis/
└── vaults/
    └── default.db    ← encrypted SQLite database file (ChaCha20-Poly1305)
```

| Setting | Value | Why |
|---------|-------|-----|
| **WAL mode** | `journal_mode = WAL` | Write-Ahead Logging allows concurrent reads while writing. More crash-resistant than default journal mode. |
| **Location** | `./.aegis/vaults/<name>.db` or `AEGIS_DATA_DIR` | Local filesystem, no network database. |
| **Full-database encryption** | ChaCha20-Poly1305 (sqleet cipher via SQLite3MultipleCiphers) | Entire database file is encrypted at rest — all tables, indexes, WAL/journal files. Key derived from master key via PBKDF2-SHA512 with a separate salt context (`salt-db`) to isolate from credential encryption keys. |
| **Field-level encryption** | AES-256-GCM for credential secrets | Defense in depth — credential values are additionally encrypted at the application level. |
| **Schema versioning** | `schema_version` table with ordered migrations | Enables safe schema evolution across upgrades. Each migration runs exactly once. |

### What's in the database (encrypted at rest, plaintext when decrypted)

With full-database encryption, all data below is encrypted on disk. When the database is open (decrypted in memory), this data is accessible:

| Data | Where | Why not additionally field-encrypted |
|------|-------|--------------------------------------|
| Credential names | `credentials.name` | Needed for lookup (`WHERE name = ?`) |
| Service names | `credentials.service` | Needed for lookup (`WHERE service = ?`) |
| Allowed domains | `credentials.domains` | Needed for domain guard validation |
| Auth type | `credentials.auth_type` | Needed to know how to inject |
| Audit log entries | `audit_log.*` | Entire audit trail — no secrets in here |

### What's encrypted in the database

| Data | Column | Format |
|------|--------|--------|
| API key/token value | `credentials.encrypted` | AES-256-GCM ciphertext (BLOB) |
| Encryption IV | `credentials.iv` | Random 16 bytes (BLOB) |
| Auth tag | `credentials.auth_tag` | GCM authentication tag (BLOB) |

### Agent token storage (hash-only)

Agent tokens (`aegis_{uuid}_{hmac}`) are **never stored in recoverable form**. The database contains:

| Data | Column | Purpose |
|------|--------|---------|
| SHA-256 hash of token | `agents.token_hash` | Fast O(1) lookup during authentication |
| First 12 chars | `agents.token_prefix` | Safe display in logs and audit entries |

This is a deliberate security hardening. The original design stored tokens encrypted (AES-256-GCM) for admin recovery, but this was removed because a master key compromise would have exposed all agent tokens. Hash-only storage means even with full database + master key access, tokens cannot be extracted.

If a token is lost, use `regenerateToken()` (or `aegis agent regenerate`) to issue a new one. The old token is immediately invalidated. This follows the same pattern as GitHub personal access tokens and Stripe API key rotation.

### What's NOT in the database

| Data | Where it is |
|------|-------------|
| Master key | Environment variable or .env file |
| PBKDF2 salt | Environment variable or .env file |
| Derived encryption key | Process memory only (never persisted) |
| Agent tokens (plaintext) | Shown once at creation/regeneration, then discarded |

---

## 11. Agent Authentication

Agent authentication adds identity and access control to the security model. Agent auth is **on by default** — every request through Gate must carry a valid `X-Aegis-Agent` token. Requests without a token receive a 401 with a helpful error message including instructions to create an agent. Use `--no-agent-auth` to disable (not recommended).

### Token Design

```
Format: aegis_{uuid}_{hmac_prefix_16hex}

Example: aegis_a1b2c3d4-e5f6-7890-abcd-ef1234567890_8f3c2a1b9d4e7f60
         ├─────────────────────────────────────────┤ ├──────────────────┤
                        UUID v4                         HMAC prefix
```

| Property | Implementation | Why |
|----------|---------------|-----|
| **UUID component** | `crypto.randomUUID()` | 122 bits of entropy, globally unique |
| **HMAC component** | `HMAC-SHA256(uuid, masterDerivedKey)` truncated to 16 hex chars | Proves the token was generated by Aegis, not guessable |
| **Storage** | SHA-256 hash of full token | O(1) lookup, no recovery — even with DB + master key access |
| **Display** | First 12 characters (`token_prefix`) | Safe for logs and audit display |

### Security Properties

- **Hash-only storage:** Tokens are never stored in recoverable form. A database dump reveals only SHA-256 hashes, which cannot be reversed.
- **Non-guessable:** The HMAC suffix is derived from the master key. Even knowing the UUID format, an attacker cannot generate a valid token without the key.
- **Regeneration model:** Lost tokens cannot be recovered. `aegis agent regenerate <name>` issues a new token and invalidates the old one. Same pattern as GitHub PATs and Stripe API keys.
- **Credential grants:** Agents can be scoped to specific credentials via `aegis agent grant/revoke`. Without a grant, the agent gets a 403 even with a valid token.
- **Per-agent rate limits:** Each agent can have its own rate limit (e.g., `"100/min"`). The more restrictive limit — agent or credential — wins.

### Authentication Flow

```
Agent sends: POST /slack/api/chat.postMessage
             X-Aegis-Agent: aegis_a1b2c3d4-..._8f3c2a1b9d4e7f60

Gate:
  1. Hash the token → SHA-256(token)
  2. Look up hash in agents table → found? → Agent identified
  3. Check credential grants → agent has grant for "slack"? → proceed
  4. Check agent rate limit → under limit? → proceed
  5. Continue with Domain Guard, cred injection, etc.
```

**Source:** [src/agent/agent.ts](../src/agent/agent.ts), [src/gate/gate.ts](../src/gate/gate.ts)

---

## 12. Rate Limiting

Aegis includes a sliding window rate limiter that prevents API cost abuse and throttles probing attacks.

### Design

- **Algorithm:** Sliding window — tracks individual request timestamps, not fixed counters
- **Storage:** In-memory (resets on Gate restart — intentionally simple for a local tool)
- **Key format:** `{service}` for per-credential limits, `agent:{id}` for per-agent limits
- **Conflict resolution:** When both a credential and an agent have rate limits, the **more restrictive** limit wins

### Supported Formats

```
"100/min"     → 100 requests per 60 seconds
"1000/hour"   → 1000 requests per 3600 seconds
"10/sec"      → 10 requests per 1 second
"5000/day"    → 5000 requests per 86400 seconds
```

### What Happens When Blocked

- Gate returns `429 Too Many Requests` with a `Retry-After` header
- The block is logged to the Ledger with reason `rate_limit_exceeded`
- If webhooks are configured, a `rate_limit_exceeded` event is emitted
- Response headers include `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`

**Source:** [src/gate/rate-limiter.ts](../src/gate/rate-limiter.ts)

---

## 13. Body Inspection

The body inspector is a defence-in-depth measure that scans outbound request bodies for credential-like patterns. Even though agents never see decrypted credentials through Aegis, they might try to exfiltrate secrets obtained from other sources (environment variables, config files, etc.).

### Sensitivity Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| `off` | No scanning | Maximum performance, least security |
| `warn` | Scan and log matches, allow request | Monitoring without blocking |
| `block` | Scan and block requests with matches (default) | Maximum security |

### Patterns Detected

| Pattern | Examples | Min Length |
|---------|----------|-----------|
| Bearer tokens | `Bearer sk-abc123...` | 20 chars |
| API key prefixes | `sk-*`, `xoxb-*`, `ghp_*`, `ghu_*`, `glpat-*`, `AKIA*` | 20+ chars |
| Generic long hex/base64 strings | `a3f8c1d9e0b7...` | 32+ chars |
| Basic auth credentials | `Basic dXNlcjpwYXNz...` | 20 chars |
| Private key markers | `-----BEGIN PRIVATE KEY-----` | — |
| Connection strings | `postgresql://user:pass@host` | — |
| AWS-style keys | `AKIA...` (20 uppercase chars) | 20 chars |

### Security Properties

- Body inspection happens **before** the request is forwarded to the external API
- Blocked requests are logged to the Ledger with reason `body_inspection`
- The body inspector also runs in the MCP server's `aegis_proxy_request` tool
- Credential patterns are checked against actual credential values stored in the vault for exact-match detection

**Source:** [src/gate/body-inspector.ts](../src/gate/body-inspector.ts)

---

## 14. Policy Engine

The policy engine provides declarative, version-controlled access control via YAML files. Policies define what each agent can do, with which services, and when.

### Policy File Format

```yaml
# policies/ci-bot.yaml
agent: ci-bot
rules:
  - service: github
    methods: [GET, POST]
    paths:
      - /repos/*/pulls
      - /repos/*/issues
    rate_limit: "100/min"
    time_window:
      start: "09:00"
      end: "17:00"
      timezone: "America/New_York"
  - service: slack
    methods: [POST]
    paths:
      - /api/chat.postMessage
```

### Enforcement

| Check | Blocked Response | Ledger Reason |
|-------|-----------------|---------------|
| Service not in policy | 403 Forbidden | `policy_violation` |
| HTTP method not allowed | 403 Forbidden | `policy_violation` |
| Path doesn't match any pattern | 403 Forbidden | `policy_violation` |
| Rate limit exceeded | 429 Too Many Requests | `rate_limit_exceeded` |
| Outside time window | 403 Forbidden | `policy_violation` |

### Modes

- **`enforce`** (default) — policy violations block the request
- **`dry-run`** — policy violations are logged but the request proceeds (useful for testing new policies)

### Security Properties

- Policies are loaded from disk at Gate startup — they cannot be modified at runtime through the API
- Policy files are validated against a strict schema — invalid files produce clear error messages
- Hot-reload is supported (Gate watches the policy directory for changes)
- Policies compose with agent authentication — a request must satisfy both the agent's credential grants AND the policy rules

**Source:** [src/policy/policy.ts](../src/policy/policy.ts)

---

## 15. Webhook Alerts

Webhooks provide real-time HTTP notifications for security events. Every webhook payload is HMAC-signed for authenticity verification.

### Event Types

| Event | Trigger | Example Payload |
|-------|---------|-----------------|
| `blocked_request` | Domain guard, policy, or auth failure blocks a request | Service, domain, block reason, agent (if known) |
| `credential_expiry` | A credential's expiration date is approaching or past | Credential name, expiry date, days remaining |
| `rate_limit_exceeded` | An agent or credential exceeds its rate limit | Service, agent, limit, current count |
| `agent_auth_failure` | Invalid or missing `X-Aegis-Agent` token | Attempted token prefix (safe), client IP |
| `body_inspection` | Body inspector detects credential-like patterns | Service, matched patterns, mode (warn/block) |

### Delivery Security

- **HMAC-SHA256 signatures:** Every payload is signed with a per-webhook secret. Recipients verify `X-Aegis-Signature` header.
- **Retry with exponential backoff:** Up to 3 retries on delivery failure
- **Fire-and-forget:** Webhook delivery never blocks the request pipeline
- **Auto-generated secrets:** Each webhook gets a unique HMAC secret at creation time

### Signature Verification (Recipient Side)

```javascript
const crypto = require('crypto');
const expected = crypto.createHmac('sha256', webhookSecret)
  .update(rawBody)
  .digest('hex');
const valid = crypto.timingSafeEqual(
  Buffer.from(signature),
  Buffer.from(expected)
);
```

**Source:** [src/webhook/webhook.ts](../src/webhook/webhook.ts)

---

## 16. User RBAC

Aegis includes a role-based access control system for multi-user environments.

### Roles

| Role | Access Level | Permissions |
|------|-------------|-------------|
| **admin** | Full access | All 16 permissions — manage vaults, agents, policies, users, webhooks |
| **operator** | Operational access | Start/stop Gate, view Ledger, manage agents (no vault management) |
| **viewer** | Read-only | View Ledger, stats, credential metadata (no secrets) |

### Security Properties

- **Token authentication:** User tokens follow the same hash-only pattern as agent tokens (SHA-256, no recovery)
- **Bootstrap mode:** The first user created is automatically granted the `admin` role
- **Permission inheritance:** More privileged roles include all permissions from less privileged ones
- **16 granular permissions:** `vault:read`, `vault:write`, `vault:manage`, `agent:read`, `agent:write`, `ledger:read`, `ledger:export`, `gate:start`, `policy:read`, `policy:write`, `webhook:read`, `webhook:write`, `user:read`, `user:write`, `dashboard:view`, `doctor:run`

**Source:** [src/user/user.ts](../src/user/user.ts)

---

## 17. Shamir's Secret Sharing & Seal/Unseal

Aegis supports splitting the master key into N shares where any K (threshold) shares can reconstruct it. This eliminates the single-point-of-failure of one person knowing the master key.

### How It Works

```
Master Key (32 bytes)
       │
       ▼
  Shamir Split (K-of-N)
       │
       ├── Share 1 → Person A
       ├── Share 2 → Person B
       ├── Share 3 → Person C
       ├── Share 4 → Person D
       └── Share 5 → Person E
       
  Any 3 shares → reconstruct Master Key (for example K=3, N=5)
  Any 2 shares → reveal NOTHING about the key (information-theoretic security)
```

### Cryptographic Details

| Property | Value |
|----------|-------|
| **Field** | GF(2^8) with AES irreducible polynomial (x^8 + x^4 + x^3 + x + 1) |
| **Share format** | `aegis_share_{index}_{hex_encoded_share_bytes}` |
| **Verification** | SHA-256 hash of master key stored in `.aegis/.seal-config.json` |
| **Random coefficients** | `crypto.randomBytes()` for polynomial coefficients |

### Seal/Unseal Lifecycle

1. **`aegis vault seal`** — Splits the master key into shares, removes the key from `.env`/environment
2. **Vault is sealed** — Aegis cannot decrypt credentials without the reconstructed key
3. **`aegis vault unseal --key-share ... --key-share ...`** — Provide K shares to reconstruct the key
4. **Vault is unsealed** — Reconstructed key is written to a restricted file (mode 0600) for the session

### Security Properties

- **Information-theoretic security:** K-1 shares reveal zero information about the secret. This is mathematically proven, not just computationally hard.
- **No share storage:** Shares are shown once at split time and never stored by Aegis
- **Key hash verification:** The reconstructed key is verified against the stored SHA-256 hash before use
- **Independent shares:** Each share is generated with fresh random polynomial coefficients

**Source:** [src/vault/shamir.ts](../src/vault/shamir.ts), [src/vault/seal.ts](../src/vault/seal.ts)

---

## 18. Multi-Vault Isolation

Aegis supports multiple named vaults, each with its own database and encryption key. This enables environment separation (production vs staging) and team isolation.

### Architecture

```
.aegis/
├── vaults/
│   ├── default.db      ← default vault (created by aegis init)
│   ├── production.db   ← separate vault with its own key + salt
│   └── staging.db      ← separate vault with its own key + salt
└── vaults.json         ← vault registry (names + salts, NEVER keys)
```

### Security Properties

- **Key isolation:** Each vault has its own PBKDF2 salt and requires its own master key. Compromising one vault's key does not affect others.
- **Database isolation:** Each vault is a separate SQLite file. No cross-vault queries.
- **Registry stores no secrets:** `vaults.json` tracks names, paths, and salts — never master keys.

**Source:** [src/vault/vault-manager.ts](../src/vault/vault-manager.ts)

---

## 19. MCP Server Security

The MCP (Model Context Protocol) server replicates Gate's full security pipeline, making Aegis accessible to any MCP-compatible AI agent (Claude Desktop, Cursor, VS Code Copilot).

### Security Pipeline Replication

The MCP server's `aegis_proxy_request` tool applies the same security checks as Gate:

1. **Agent authentication** — MCP session token validates against agent registry
2. **Credential lookup** — Service-based credential resolution via Vault
3. **Credential scope enforcement** — HTTP method checked against credential scopes (read/write/*)
4. **Domain guard** — Target domain validated against credential allowlist
5. **Policy evaluation** — Per-agent rules checked (methods, paths, rate limits, time windows)
6. **Rate limiting** — Per-agent and per-credential sliding window limits
7. **Body inspection** — Request body scanned for credential patterns
8. **Header scrubbing** — Auth headers stripped from agent's request
9. **Credential injection** — Real secret injected into outbound headers
10. **Audit logging** — Every request (allowed and blocked) logged to Ledger
11. **Webhook alerts** — Security events emitted to configured endpoints

### Transport Security

| Transport | Use Case | Security |
|-----------|----------|----------|
| **stdio** | Local process (Claude Desktop, Cursor) | Process isolation — no network exposure |
| **streamable-http** | Remote access | HTTP server on configurable port |

### Tools Exposed

| Tool | What It Does | Security Relevant |
|------|-------------|-------------------|
| `aegis_proxy_request` | Make authenticated API call | Full security pipeline |
| `aegis_list_services` | List available services | Names only — never secrets |
| `aegis_health` | Check Aegis status | No sensitive data |

**Source:** [src/mcp/mcp-server.ts](../src/mcp/mcp-server.ts)

---

## 20. Credential Validation

Aegis enforces limits on credential names and values to prevent abuse and ensure system stability.

### Limits

| Property | Limit | Why |
|----------|-------|-----|
| **Credential name** | Max 128 characters, alphanumeric + hyphens + underscores only | Prevents injection via names, avoids filesystem issues |
| **Secret value** | Max 512 KB (524,288 bytes) | Prevents memory exhaustion and Node.js argument size limits |

### Master Key Verification

The Vault constructor now calls `verifyKey()` on startup. This test-decrypts the first stored credential to verify the master key is correct. If decryption fails (AES-256-GCM auth tag mismatch), Aegis throws immediately rather than silently returning empty results.

```
Vault constructor:
  1. Derive key (PBKDF2)
  2. Query first credential row
  3. Attempt AES-256-GCM decrypt
  4. Auth tag mismatch? → throw "Invalid master key"
  5. Empty vault? → skip (nothing to verify against)
```

**Source:** [src/vault/vault.ts](../src/vault/vault.ts)

---

## 21. Logging & Secret Scrubbing

Aegis uses structured logging (pino) with aggressive secret protection to prevent credentials from leaking into log output.

### Redaction

Over 30 field paths are redacted from log output:

```
'secret', 'password', 'token', 'apiKey', 'api_key',
'authorization', 'masterKey', 'derivedKey', 'encrypted',
'req.headers.authorization', 'req.headers["x-api-key"]',
...
```

### Pattern Scrubbing

7 credential-like patterns are scrubbed from any string that passes through `safeMeta()`:

| Pattern | Replacement |
|---------|-------------|
| `sk-` prefixed tokens | `[REDACTED:api-key]` |
| `xoxb-`/`xoxp-` Slack tokens | `[REDACTED:slack-token]` |
| `ghp_`/`ghu_` GitHub tokens | `[REDACTED:github-token]` |
| `Bearer` tokens | `[REDACTED:bearer]` |
| AWS access keys (`AKIA...`) | `[REDACTED:aws-key]` |
| Long hex strings (64+ chars) | `[REDACTED:hex-string]` |
| Base64-encoded credentials | `[REDACTED:base64]` |

### MCP stdio Safety

When running as an MCP stdio server, all log output goes to stderr (not stdout) to prevent log messages from corrupting the JSON-RPC protocol stream.

**Source:** [src/logger/logger.ts](../src/logger/logger.ts)

---

## 22. What Aegis Does NOT Protect Against

Being honest about limitations is as important as describing protections.

| Scenario | Why Aegis Can't Help | Mitigation |
|----------|---------------------|------------|
| **Compromised host machine** | If an attacker has root on the machine running Aegis, they can read process memory, the database, the .env file — everything | Use OS-level security (full disk encryption, strong passwords, SSH keys) |
| **Malicious user who set up Aegis** | They already know the master key | Segregation of duties — the person who provisions keys should be authorized; Shamir sharing distributes trust |
| **Response body containing secrets** | If an API returns secrets in its response (e.g., creating an API key), the agent sees it | Some APIs support "show once" patterns; otherwise, use scoped permissions |
| **DNS rebinding attacks** | An attacker could make `evil.com` resolve to `api.slack.com`'s IP, but the domain guard checks the hostname string, not the resolved IP | Would need certificate pinning or resolved-IP validation to fully mitigate |
| **HTTPS interception** | A corporate proxy doing TLS interception could see the credential | Deploy Aegis in environments where you control the network, or use certificate pinning |
| **Side-channel attacks** | Timing attacks on PBKDF2 or GCM, memory inspection of the running process | These require local access, which circles back to "compromised host" |
| **Secrets remaining in memory** | Node.js/V8 doesn't guarantee timely overwriting of deallocated memory | Would require native addon to explicitly zero buffers after use |

---

## 23. Design Decisions and Rationale

### D1: Why a local HTTP proxy instead of a library/SDK?

**Decision:** Aegis runs as a standalone process that the agent connects to via HTTP.

**Alternatives considered:**
- **Library integration** — import Aegis into the agent's process
- **OS-level proxy** — use iptables/pfctl to intercept all outbound traffic

**Why we chose local proxy:**
- **Language agnostic** — any agent that can make HTTP calls can use Aegis, regardless of language
- **Process isolation** — the agent's process never has the credential in its memory space
- **Simple mental model** — the agent just changes its base URL from `https://api.slack.com` to `http://localhost:3100/slack`
- **No OS-level permissions needed** — no need for root/admin to set up routing rules

### D2: Why SQLite instead of PostgreSQL/Redis?

**Decision:** Embedded SQLite with better-sqlite3.

**Why:**
- **Zero deployment overhead** — no database server to install, configure, or maintain
- **Single-file database** — entire state is in one file, easy to back up or delete
- **Synchronous API** — better-sqlite3 is synchronous (no async/await needed for DB calls), which makes the code simpler and avoids race conditions
- **WAL mode** — allows concurrent reads while writing, sufficient for a local tool
- **No network surface** — the database is never exposed to the network

**Trade-off:** SQLite doesn't support concurrent writes from multiple processes. This means you can't run two instances of `aegis gate` against the same database. For a single-user local tool, this is fine.

### D3: Why AES-256-GCM instead of libsodium/NaCl?

**Decision:** Use Node.js built-in `crypto` module with AES-256-GCM.

**Why:**
- **No native dependencies** — `crypto` is built into Node.js (wraps OpenSSL)
- **Authenticated encryption** — GCM provides both confidentiality and integrity
- **Industry standard** — same algorithm used by TLS 1.3, AWS KMS, etc.

**Alternative (libsodium/NaCl):**
- Would use XChaCha20-Poly1305 instead of AES-256-GCM
- Slightly better resistance to timing attacks (ChaCha20 is constant-time in software; AES relies on hardware AES-NI instructions)
- Would add two native dependencies (`sodium-native` or `tweetnacl`)
- For a local tool where timing attacks require machine access, AES-GCM is sufficient

### D4: Why PBKDF2 instead of Argon2?

See discussion in [Section 5.2](#52-key-derivation-pbkdf2).

### D8: Why hash-only token storage?

**Decision:** Agent and user tokens are stored as SHA-256 hashes. Lost tokens cannot be recovered — only regenerated.

**Alternative considered:** Store tokens encrypted with AES-256-GCM (using the master key) for admin recovery.

**Why we chose hash-only:**
- A master key compromise would expose all agent tokens if they were merely encrypted
- Hash-only storage means even with full database + master key access, tokens cannot be extracted
- Matches industry standard: GitHub PATs, Stripe API keys, and MCP OAuth 2.1 all use hash-only storage
- Regeneration is a simple, well-understood recovery mechanism

### D9: Why in-memory rate limiting?

**Decision:** Rate limiter stores timestamps in process memory, not in a database.

**Why:** Aegis is a single-process local tool. Persistent rate limiting (Redis, SQLite) adds complexity with zero benefit when the limiter resets on restart anyway. If Aegis becomes a multi-process service, Redis-backed rate limiting is the logical upgrade.

### D5: Why not encrypt the entire SQLite database?

**Decision:** Encrypt credential values at the application level, leave SQLite metadata in plaintext.

**Alternative:** Use SQLCipher (encrypted SQLite) to encrypt everything.

**Why we chose application-level:**
- **SQLCipher adds a native dependency** — complicates builds and cross-platform support
- **We need to query metadata** — service lookups, domain matching, and audit log queries all need to read plaintext metadata
- **The metadata isn't secret** — knowing that you have a credential named "slack" for `api.slack.com` doesn't help an attacker. The *value* of the credential is what matters, and that's encrypted.

**Trade-off:** If the database file is stolen, an attacker learns which services you use and which domains are configured. In most threat models, this is acceptable.

### D6: Why default to NOT writing secrets to .env?

**Decision:** `aegis init` prints the master key and salt to stdout by default. The `--write-secrets` flag writes them to `.env`.

**Why:**
- A `.env` file is readable by any process running as your user
- Environment variables (set in a shell profile) are slightly more contained — they're part of the process environment, not a file on disk
- The most secure option is a secrets manager (1Password CLI, AWS SSM, HashiCorp Vault), which environment variables can be populated from
- Printing to stdout once lets the user decide how to store the secrets

### D7: Why always HTTPS for outbound requests?

**Decision:** Gate always uses `https.request()` on port 443.

**Why:** The credential is in the HTTP headers of the outbound request. If we used HTTP (plaintext), anyone between Aegis and the API could read the credential. TLS is non-negotiable for transporting secrets.

**Limitation:** This means Aegis can't proxy to HTTP-only APIs. For v0.1, this is an acceptable limitation — any API worth protecting with Aegis should be using HTTPS anyway.

---

## 24. Known Limitations and Future Work

### Current Limitations

| Limitation | Impact | Potential Fix |
|------------|--------|---------------|
| **No memory zeroing** | Derived key and decrypted secrets stay in V8 heap until GC | Native addon to explicitly zero Buffer contents after use |
| **Secret visible in process args** | macOS `security` CLI and Windows `cmdkey` receive the master key as a command-line argument, which is briefly visible in `ps` output. Linux `secret-tool` reads from stdin (not affected). | Use stdin-based APIs or native bindings instead of CLI wrappers. Low-risk in practice: the window is milliseconds, on localhost, and only visible to same-user processes. |
| **HTTPS only** | Can't proxy to HTTP APIs (rare but possible) | Add optional HTTP support with a scary warning |
| **No mutual TLS** | Gate trusts any localhost client | Add optional mTLS for Gate-to-agent connection |
| **Single-level wildcards only** | `*.slack.com` doesn't match `deep.api.slack.com` | Could add `**` glob support if needed |
| **Query auth type incomplete** | `authType: "query"` is defined but not implemented | Append key to URL query string |
| **Master key in .env** | Plaintext key on disk readable by any user-level process | ~~OS keychain integration planned~~ → **Resolved in v0.8.4** via cross-platform key storage (macOS Keychain, Windows Credential Manager, Linux libsecret). `.env` and file fallback still available for CI. |
| **In-memory rate limiter** | Rate limits reset on Gate restart | Redis or SQLite-backed limiter for persistence |
| **PBKDF2 iteration count** | 210,000 iterations (meets OWASP minimum for SHA-512) | Switching to Argon2id is planned for further hardening |

### Resolved Limitations (since v0.2)

| Previously a Limitation | Resolution | Version |
|-------------------------|------------|---------|
| Master key in .env | Cross-platform key storage: macOS Keychain, Windows Credential Manager, Linux Secret Service, with file fallback. `aegis init` stores in OS keychain by default | v0.8.4 |
| No rate limiting | Sliding window rate limiter (per-credential and per-agent) | v0.2 |
| No request body inspection | Body inspector with 7 credential patterns, 3 modes | v0.3 |
| No credential rotation | `aegis vault rotate` command | v0.2 |
| No agent identity | Agent registry with hash-only tokens and credential grants | v0.2 |
| No multi-user support | RBAC user system with 3 roles and 16 permissions | v0.5 |
| No scopes enforcement | Credential scope enforcement: read (GET/HEAD/OPTIONS), write (POST/PUT/PATCH/DELETE), * (all). Enforced in Gate and MCP | v0.7 |
| No master key splitting | Shamir's Secret Sharing (K-of-N) with seal/unseal | v0.5 |
| No multi-vault isolation | VaultManager with per-vault databases and encryption keys | v0.5 |
| No declarative access control | YAML policy engine with per-agent rules | v0.3 |
| No body size limits (STRIDE D-2) | Configurable max body size with 413 rejection | v0.8.2 |
| No request timeouts / slowloris defense (STRIDE D-3) | Server-level idle timeout + per-request outbound timeout with 504 | v0.8.2 |
| No per-agent connection limits (STRIDE D-1) | Configurable concurrent connection cap per agent with 429 | v0.8.2 |
| No circuit breaker for upstream failures | Circuit breaker: 5 consecutive 5xx → 30s cooldown → 503 with Retry-After | v0.8.2 |
| No retry logic for transient failures | Automatic retry (max 2, exponential backoff) for idempotent methods on 502/503/504 | v0.8.2 |

### Future Security Enhancements

1. **IP allowlisting** — restrict which local IPs can connect to Gate
2. **Request signing** — HMAC sign outgoing requests for additional accountability
3. **Mutual TLS** — optional mTLS between agent and Gate
4. **Argon2id key derivation** — memory-hard KDF for better GPU attack resistance
5. **Persistent rate limiting** — Redis or SQLite-backed for cross-restart persistence

---

## 25. Learning Resources

Curated resources to deepen your understanding of the security concepts used in Aegis. Organized from practical to theoretical.

### Cryptography Fundamentals

| Resource | Type | What You'll Learn | Link |
|----------|------|-------------------|------|
| **Practical Cryptography for Developers** | Free online book | AES, GCM, PBKDF2, key derivation — all explained with code examples | [cryptobook.nakov.com](https://cryptobook.nakov.com/) |
| **Crypto 101** | Free PDF book | Zero-to-solid-understanding of crypto primitives. Covers why you never roll your own crypto. | [crypto101.io](https://www.crypto101.io/) |
| **Computerphile: AES Explained** | YouTube (10 min) | Visual explanation of how AES works internally | [youtube.com/watch?v=O4xNJsjtN6E](https://www.youtube.com/watch?v=O4xNJsjtN6E) |
| **Computerphile: Galois Counter Mode** | YouTube (13 min) | Why GCM provides authentication, and how the tag is computed | [youtube.com/watch?v=g_eY7JXOc8U](https://www.youtube.com/watch?v=g_eY7JXOc8U) |
| **How PBKDF2 Works** (by F5 DevCentral) | Blog post | Visual walkthrough of key derivation with iteration count rationale | Search "PBKDF2 explained devcentral" |

### Application Security

| Resource | Type | What You'll Learn | Link |
|----------|------|-------------------|------|
| **OWASP Cheat Sheet Series** | Reference docs | Industry-standard guidance on key management, auth, secrets handling | [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/) |
| **OWASP: Key Management** | Cheat sheet | Specifically covers key derivation, storage, rotation — directly relevant to Aegis | [Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html) |
| **OWASP: Cryptographic Storage** | Cheat sheet | When to use which algorithm, how to store encrypted data | [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) |
| **The Twelve-Factor App: Config** | Methodology | Why secrets should be in env vars, not config files | [12factor.net/config](https://12factor.net/config) |

### Node.js Security

| Resource | Type | What You'll Learn | Link |
|----------|------|-------------------|------|
| **Node.js Crypto Documentation** | Official docs | API reference for everything Aegis uses: createCipheriv, pbkdf2Sync, randomBytes | [nodejs.org/api/crypto.html](https://nodejs.org/api/crypto.html) |
| **Node.js Threat Model** | Official doc | What Node.js considers in-scope and out-of-scope for security | [github.com/nodejs/node/blob/main/SECURITY.md](https://github.com/nodejs/node/blob/main/SECURITY.md) |
| **Snyk: Node.js Security Best Practices** | Guide | Practical checklist for Node.js app security | [snyk.io/blog/nodejs-security-best-practices](https://snyk.io/blog/10-best-practices-to-containerize-nodejs-web-applications-with-docker/) |

### Proxy & Network Security

| Resource | Type | What You'll Learn | Link |
|----------|------|-------------------|------|
| **How HTTPS Works** | Comic/visual guide | TLS handshake, certificate verification, why HTTPS matters | [howhttps.works](https://howhttps.works/) |
| **mitmproxy Documentation** | Tool docs | Understanding how HTTP proxies intercept and modify requests (what Aegis does, legitimately) | [docs.mitmproxy.org](https://docs.mitmproxy.org/stable/) |
| **Cloudflare: What is a reverse proxy?** | Blog post | Conceptual overview of reverse proxying (similar to what Gate does) | [cloudflare.com/learning/cdn/glossary/reverse-proxy](https://www.cloudflare.com/learning/cdn/glossary/reverse-proxy/) |

### Threat Modeling

| Resource | Type | What You'll Learn | Link |
|----------|------|-------------------|------|
| **STRIDE Threat Model** | Framework | Systematic way to think about security threats (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) | Search "Microsoft STRIDE threat model" |
| **Threat Modeling: Designing for Security** by Adam Shostack | Book | The definitive book on how to think about threats to a system | ISBN: 978-1118809990 |
| **OWASP Threat Modeling** | Guide | Practical threat modeling for web applications | [owasp.org/www-community/Threat_Modeling](https://owasp.org/www-community/Threat_Modeling) |

### AI Agent Security (Directly Relevant to Aegis's Purpose)

| Resource | Type | What You'll Learn | Link |
|----------|------|-------------------|------|
| **OWASP Top 10 for LLM Applications** | Reference | Top security risks when deploying LLMs, including prompt injection and excessive agency | [owasp.org/www-project-top-10-for-large-language-model-applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) |
| **Simon Willison: Prompt Injection** | Blog series | Why AI agents with tool access are inherently risky — the exact problem Aegis addresses | [simonwillison.net/series/prompt-injection](https://simonwillison.net/series/prompt-injection/) |
| **Anthropic: Building Safe AI Agents** | Research paper | How to build AI agents that are safe to give tools to | Search "Anthropic tool use safety" |

### Hands-On Practice

| Resource | Type | What You'll Learn | Link |
|----------|------|-------------------|------|
| **CryptoHack** | Interactive challenges | Practice breaking (and understanding) crypto — from basic XOR to RSA and AES | [cryptohack.org](https://cryptohack.org/) |
| **PortSwigger Web Security Academy** | Free interactive labs | Hands-on web security labs including auth, access control, and injection | [portswigger.net/web-security](https://portswigger.net/web-security) |
| **Hack The Box** | CTF platform | Practical security challenges from beginner to advanced | [hackthebox.com](https://www.hackthebox.com/) |

### Recommended Reading Order

If you're starting from scratch, work through these in order:

1. **Crypto 101** (free PDF) — understand the primitives
2. **How HTTPS Works** (visual comic) — understand transport security
3. **Computerphile AES + GCM videos** (20 min total) — see how Aegis's encryption works
4. **OWASP Key Management Cheat Sheet** — understand why keys are managed the way they are
5. **OWASP Top 10 for LLM Applications** — understand the threat landscape Aegis operates in
6. **Simon Willison's prompt injection series** — understand why credential isolation matters
7. **CryptoHack** (ongoing) — build intuition by breaking things

---

## Appendix A: File-to-Security-Function Mapping

Quick reference for which file implements which security function:

| File | Security Function |
|------|-------------------|
| `src/vault/crypto.ts` | AES-256-GCM encryption, PBKDF2 key derivation, salt generation |
| `src/vault/vault.ts` | Key caching, credential CRUD, domain matching, master key verification, credential size limits |
| `src/vault/vault-manager.ts` | Multi-vault registry, per-vault database and key isolation |
| `src/vault/shamir.ts` | Shamir's Secret Sharing over GF(256), key splitting and reconstruction |
| `src/vault/seal.ts` | Seal/unseal lifecycle, key hash verification, restricted file persistence |
| `src/gate/gate.ts` | Domain guard, header scrubbing, credential injection, TLS forwarding, agent auth, policy enforcement, body inspection |
| `src/gate/rate-limiter.ts` | Sliding window rate limiter, per-credential and per-agent limits |
| `src/gate/body-inspector.ts` | Request body credential pattern scanner, 7 pattern categories, 3 modes |
| `src/agent/agent.ts` | Agent registry, UUID+HMAC token generation, hash-only storage, credential grants |
| `src/user/user.ts` | RBAC user management, 3 roles, 16 permissions, token authentication |
| `src/policy/policy.ts` | YAML policy parsing, validation, per-agent rules, method/path/rate-limit/time-window constraints |
| `src/mcp/mcp-server.ts` | MCP server with full security pipeline replication (auth, scope enforcement, domain guard, policy, rate limiting, body inspection) |
| `src/webhook/webhook.ts` | HMAC-SHA256 signed webhook delivery, retry with exponential backoff |
| `src/logger/logger.ts` | Structured logging with 30+ redact paths, 7 credential pattern scrubbers, MCP stdio safety |
| `src/metrics/metrics.ts` | Prometheus metrics (request counts, block reasons, durations) |
| `src/ledger/ledger.ts` | Audit logging (allowed + blocked), agent identity tracking, JSON export |
| `src/config.ts` | Configuration loading (YAML file + env vars), master key + salt resolution, key format validation |
| `src/key-storage/key-storage.ts` | KeyStorage interface, getKeyStorage() platform-aware factory, commandExists() helper |
| `src/key-storage/keychain-macos.ts` | macOS Keychain backend via `security` CLI |
| `src/key-storage/credential-manager-windows.ts` | Windows Credential Manager backend via `cmdkey` + PowerShell |
| `src/key-storage/secret-service-linux.ts` | Linux Secret Service backend via `secret-tool` CLI |
| `src/key-storage/file-fallback.ts` | File-based fallback key storage (`.aegis/.master-key`, mode 0600), permission validation |
| `src/db.ts` | Schema definition, WAL mode, ChaCha20-Poly1305 encryption at rest, migration |
| `src/doctor.ts` | Health diagnostics, master key verification, environment validation |

## Appendix B: Encryption at a Glance

```
ENCRYPT:
  plaintext + derivedKey + randomIV → AES-256-GCM → ciphertext + authTag
  Store: [ciphertext, IV, authTag] in SQLite

DECRYPT:
  ciphertext + derivedKey + storedIV + storedAuthTag → AES-256-GCM → plaintext
  If authTag doesn't verify → throw Error (tampered data)

KEY DERIVATION:
  masterKey + salt → PBKDF2(SHA-512, 210,000 iterations) → derivedKey
  Done once per process, cached in Vault.derivedKey
```
