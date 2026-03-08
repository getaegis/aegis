# Aegis

**Credential isolation for AI agents.**

Aegis sits between your AI agent and the APIs it calls. The agent never sees, stores, or transmits real credentials — Aegis injects them at the network boundary.

```
┌──────────┐       ┌────────────────────────────┐       ┌──────────────┐
│ AI Agent │──────▶│         Aegis Gate         │──────▶│  Slack API   │
│          │       │  localhost:3100/slack/...  │       │              │
│ (no keys)│◀──────│  inject creds + audit log  │◀──────│ api.slack.com│
└──────────┘       └────────────────────────────┘       └──────────────┘
                          │            │
                   ┌──────┘            └──────┐
              ┌────▼────┐           ┌─────────▼──┐
              │  Vault  │           │   Ledger   │
              │ AES-256 │           │  Audit Log │
              │ encrypt │           │   SQLite   │
              └─────────┘           └────────────┘
```

## Why?

AI agents (Claude, GPT, Cursor, custom bots) increasingly need to call APIs — Slack, GitHub, databases, internal tools. The current pattern is dangerous:

1. **Agents see raw API keys** — one prompt injection exfiltrates them
2. **No domain guard** — a compromised agent can send your Slack token to `evil.com`
3. **No audit trail** — you can't see what an agent did with your credentials
4. **No access control** — every agent can use every credential

Aegis solves all four. Your agent makes HTTP calls through a local proxy. Aegis handles authentication, enforces domain restrictions, and logs everything.

## Prerequisites

- **Node.js ≥ 20** — check with `node -v`

## Quick Start

```bash
# Install globally
npm install -g @getaegis/cli

# Initialize — generates master key, config file, and encrypted vault
aegis init --write-secrets
```

`aegis init` prints a master key. Without `--write-secrets`, you must export it yourself:

```bash
export AEGIS_MASTER_KEY=<key from init>
```

With `--write-secrets`, the key is saved to `aegis.config.yaml` automatically (convenient for local dev, not recommended for production).

```bash
# Add a credential
aegis vault add \
  --name slack-bot \
  --service slack \
  --secret "xoxb-your-token-here" \
  --domains api.slack.com

# Start the proxy
aegis gate
```

Your agent now calls `http://localhost:3100/slack/api/chat.postMessage` — Aegis injects the Bearer token and forwards to `https://api.slack.com`. The agent never sees the token. The request is logged.

```bash
# Verify it works
curl http://localhost:3100/slack/api/auth.test \
  -H "X-Target-Host: api.slack.com"
```

## Features

| Feature | Description |
|---------|-------------|
| **Encrypted Vault** | AES-256-GCM encrypted credential storage with PBKDF2 key derivation |
| **HTTP Proxy (Gate)** | Transparent credential injection — agent hits `localhost:3100/{service}/path` |
| **Domain Guard** | Every outbound request checked against credential allowlists. No bypass. |
| **Audit Ledger** | Every request (allowed and blocked) logged to SQLite with full context |
| **Agent Identity** | Per-agent tokens, credential scoping, and rate limits |
| **Policy Engine** | Declarative YAML policies — method, path, rate-limit, time-of-day restrictions |
| **Body Inspector** | Outbound request bodies scanned for credential-like patterns |
| **MCP Server** | Native Model Context Protocol integration for Claude, Cursor, VS Code |
| **Web Dashboard** | Real-time monitoring UI with WebSocket live feed |
| **Prometheus Metrics** | `/_aegis/metrics` endpoint for Grafana dashboards |
| **Webhook Alerts** | HMAC-signed notifications for blocked requests, expiring credentials |
| **RBAC** | Admin, operator, viewer roles with 16 granular permissions |
| **Multi-Vault** | Separate vaults for dev/staging/prod with isolated encryption keys |
| **Shamir's Secret Sharing** | M-of-N key splitting for team master key management |
| **TLS Support** | Optional HTTPS on Gate with cert/key configuration |
| **Configuration File** | `aegis.config.yaml` with env var overrides and CLI flag overrides |

## MCP Integration

Aegis is a first-class [MCP](https://modelcontextprotocol.io) server. Any MCP-compatible AI agent (Claude Desktop, Cursor, VS Code Copilot) can use Aegis natively — no HTTP calls needed.

```bash
# Generate config for your AI host
aegis mcp config claude   # Claude Desktop
aegis mcp config cursor   # Cursor
aegis mcp config vscode   # VS Code
```

Copy the printed JSON into your AI host's MCP config file. The MCP server exposes three tools:

| Tool | Description |
|------|-------------|
| `aegis_proxy_request` | Make an authenticated API call (provide service + path, Aegis injects credentials) |
| `aegis_list_services` | List available services (names only, never secrets) |
| `aegis_health` | Check Aegis status |

The MCP server replicates the full Gate security pipeline: domain guard, agent auth, body inspection, rate limiting, audit logging.

## Agent Identity & Scoping

Without agent auth, any process on localhost can use any credential. Enable agent auth to restrict access:

```bash
# Register an agent — token is printed once, save it
aegis agent add --name "research-bot"

# Grant access to specific credentials only
aegis agent grant --agent "research-bot" --credential "slack-bot"

# Set per-agent rate limits
aegis agent set-rate-limit --agent "research-bot" --limit 50/min

# Start Gate with agent auth required
aegis gate --require-agent-auth

# Agent must include its token in every request
curl http://localhost:3100/slack/api/auth.test \
  -H "X-Target-Host: api.slack.com" \
  -H "X-Aegis-Agent: aegis_a1b2c3d4..."
```

Tokens are SHA-256 hashed for storage — they cannot be recovered, only regenerated:

```bash
aegis agent regenerate --name "research-bot"
# Old token stops working immediately. New token printed once.
```

## Policy Engine

Declarative YAML policies control what each agent can do:

```yaml
# policies/research-bot.yaml
agent: research-bot
rules:
  - service: slack
    methods: [GET]
    paths:
      - /api/conversations.*
      - /api/users.*
    rate_limit: 100/hour
    time_window:
      start: "09:00"
      end: "18:00"
      timezone: "UTC"
  - service: github
    methods: [GET, POST]
    paths:
      - /repos/myorg/.*
    rate_limit: 200/hour
```

```bash
# Validate policies without starting Gate
aegis policy validate --policies-dir ./policies

# Dry-run: see what would be allowed/blocked without enforcing
aegis gate --policies-dir ./policies --policy-mode dry-run

# Enforce policies
aegis gate --policies-dir ./policies --policy-mode enforce
```

## Credential Options

When adding a credential, you can configure TTL, scopes, rate limits, and body inspection:

```bash
aegis vault add \
  --name github-bot \
  --service github \
  --secret "ghp_xxxxxxxxxxxxxxxxxxxx" \
  --domains api.github.com \
  --auth-type bearer \
  --scopes read,write \
  --ttl 90 \
  --rate-limit 100/min \
  --body-inspection block
```

| Flag | Default | Description |
|------|---------|-------------|
| `--auth-type` | `bearer` | How Aegis injects the credential (see Auth Types below) |
| `--scopes` | `*` | Comma-separated: `read` (GET/HEAD/OPTIONS), `write` (POST/PUT/PATCH/DELETE), `*` (all) |
| `--ttl <days>` | *(none)* | Credential expires after this many days |
| `--rate-limit` | *(none)* | Rate limit: `100/min`, `1000/hour`, `10/sec` |
| `--body-inspection` | `block` | Scan outbound bodies for credential patterns: `off`, `warn`, `block` |
| `--header-name` | — | Custom header name (only for `--auth-type header`) |

Update any field later:

```bash
aegis vault update --name github-bot --rate-limit 200/min --body-inspection warn
```

## Auth Types

Aegis supports four credential injection methods:

| Type | Flag | What Aegis Injects |
|------|------|--------------------|
| `bearer` | `--auth-type bearer` (default) | `Authorization: Bearer <secret>` |
| `header` | `--auth-type header --header-name X-API-Key` | `X-API-Key: <secret>` |
| `basic` | `--auth-type basic` | `Authorization: Basic <base64(secret)>` |
| `query` | `--auth-type query` | Appends `?key=<secret>` to the URL |

## Configuration

Aegis uses a layered configuration model: **CLI flags** > **environment variables** > **config file** > **built-in defaults**.

```yaml
# aegis.config.yaml
gate:
  port: 3100
  tls:
    cert: ./certs/aegis.crt
    key: ./certs/aegis.key
  require_agent_auth: true
  policy_mode: enforce
  policies_dir: ./policies

vault:
  name: default
  data_dir: ./.aegis

observability:
  log_level: info
  log_format: json
  metrics: true
  dashboard:
    enabled: true
    port: 3200

mcp:
  transport: stdio
  port: 3300

webhooks:
  - url: https://your-webhook-endpoint.com/aegis
    events: [blocked_request, credential_expiry]
    secret: your-hmac-secret
```

```bash
# Validate your config file
aegis config validate

# Show resolved config (with all overrides applied)
aegis config show
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `AEGIS_MASTER_KEY` | Master encryption key (from `aegis init`) |
| `AEGIS_SALT` | Vault encryption salt (auto-generated, stored in `.aegis/vaults.json`) |
| `AEGIS_VAULT` | Active vault name (default: `default`) |
| `AEGIS_USER_TOKEN` | RBAC user token for CLI authentication |

## Webhooks

Get real-time notifications when security events occur:

```bash
# Add a webhook for blocked requests and expiring credentials
aegis webhook add \
  --url https://your-endpoint.com/aegis \
  --events blocked_request,credential_expiry \
  --secret your-hmac-signing-secret

# Test delivery
aegis webhook test --id <webhook-id>

# Check for credentials expiring within 7 days
aegis webhook check-expiry

# Manage
aegis webhook list
aegis webhook remove --id <webhook-id>
```

Webhook payloads are signed with HMAC-SHA256. Verify the `X-Aegis-Signature` header to authenticate delivery. Five event types: `blocked_request`, `credential_expiry`, `rate_limit_exceeded`, `agent_auth_failure`, `body_inspection`.

## Web Dashboard

```bash
# Start the dashboard (launches Gate automatically)
aegis dashboard
# → Dashboard: http://localhost:3200
# → Gate:      http://localhost:3100
```

Six views: **Overview** (health + stats), **Request Feed** (WebSocket live updates), **Credentials**, **Agents**, **Users** (RBAC), **Blocked Requests**. Dark theme.

## RBAC (Role-Based Access Control)

Aegis has a built-in user registry with three roles and 16 granular permissions. Once the first user is created, **every CLI command requires authentication** via `AEGIS_USER_TOKEN`.

### Bootstrap Mode

Before any users exist, all commands are unrestricted — this lets you run `aegis init` and `aegis user add` to create the first admin. Once at least one user exists, RBAC locks in.

```bash
# Create the first admin user (no auth required — bootstrap mode)
aegis user add --name admin --role admin

# ✓ User added to Aegis
#   Name:   admin
#   Role:   admin
#   API Key (shown ONCE — save it now):
#   aegis_user_xxxxxxxx-xxxx_xxxxxxxxxxxxxxxx
#
#   Use AEGIS_USER_TOKEN=<key> to authenticate CLI commands.
```

> **Save the token immediately.** Tokens are SHA-256 hashed for storage and **cannot be recovered**. If lost, an admin must regenerate it.

### Authenticating

Set `AEGIS_USER_TOKEN` in your environment:

```bash
export AEGIS_USER_TOKEN=aegis_user_xxxxxxxx-xxxx_xxxxxxxxxxxxxxxx

# Now all commands authenticate against this token
aegis vault list
aegis agent list
aegis ledger show
```

### Roles & Permissions

| Permission | Admin | Operator | Viewer |
|------------|:-----:|:--------:|:------:|
| `vault:read` — list credentials | ✓ | ✓ | ✓ |
| `vault:write` — add/remove/rotate credentials | ✓ | | |
| `vault:manage` — create/destroy vaults | ✓ | | |
| `agent:read` — list agents | ✓ | ✓ | |
| `agent:write` — add/remove/grant agents | ✓ | ✓ | |
| `ledger:read` — view audit logs | ✓ | ✓ | ✓ |
| `ledger:export` — export audit logs | ✓ | ✓ | |
| `gate:start` — start the proxy | ✓ | ✓ | |
| `policy:read` — view policies | ✓ | ✓ | |
| `policy:write` — manage policies | ✓ | | |
| `webhook:read` — list webhooks | ✓ | ✓ | |
| `webhook:write` — add/remove webhooks | ✓ | | |
| `user:read` — list users | ✓ | | |
| `user:write` — add/remove users | ✓ | | |
| `dashboard:view` — access the dashboard | ✓ | ✓ | ✓ |
| `doctor:run` — run health checks | ✓ | ✓ | ✓ |

### Managing Users

```bash
# Add more users (requires admin role)
aegis user add --name alice --role operator
aegis user add --name bob --role viewer

# Change a user's role
aegis user role --name alice --role admin

# Regenerate a lost token (invalidates the old one immediately)
aegis user regenerate-token --name alice

# Remove a user
aegis user remove --name bob --confirm

# List all users
aegis user list
```

## Multi-Vault

Isolate credentials across environments:

```bash
aegis vault create --name staging
aegis vault create --name production

# Add credentials to a specific vault
AEGIS_VAULT=staging aegis vault add --name slack --service slack ...

# List vaults
aegis vault vaults

# Destroy a vault and all its credentials
aegis vault destroy --name staging
```

Each vault has its own database and encryption salt. Credentials encrypted in one vault cannot be decrypted by another.

## Shamir's Secret Sharing

Split the master key across team members so no single person can unlock the vault alone:

```bash
# Split into 5 shares, requiring any 3 to reconstruct
aegis vault split --shares 5 --threshold 3

# Seal the vault (removes the reconstructed key)
aegis vault seal

# Unseal with 3 shares
aegis vault unseal \
  --key-share <share-1> \
  --key-share <share-2> \
  --key-share <share-3>
```

## Audit Ledger

Every request through Gate is logged — allowed and blocked.

```bash
# View recent entries (default: last 20)
aegis ledger show

# Filter by service, agent, or status
aegis ledger show --service slack --limit 50
aegis ledger show --agent research-bot
aegis ledger show --blocked
aegis ledger show --system          # Startup/shutdown events
aegis ledger show --since 2026-03-01

# Request statistics
aegis ledger stats
aegis ledger stats --agent research-bot
aegis ledger stats --since 2026-03-01

# Export (CSV, JSON, or JSON Lines)
aegis ledger export -f csv
aegis ledger export -f json -o audit.json
aegis ledger export -f jsonl --service slack --since 2026-03-01
```

## Health Checks

```bash
aegis doctor
```

Runs diagnostics on your Aegis installation:
- Config file validation
- Database accessibility and schema
- Master key correctness (test decrypt)
- Expired or expiring-soon credentials

Returns pass/warn/fail for each check.

## Security Model

- **Encryption at rest** — AES-256-GCM with PBKDF2 key derivation (100k iterations, SHA-512, random per-deployment salt)
- **Domain guard** — enforced on every outbound request. No bypass, no override. Wildcards supported (`*.slack.com`)
- **Credential scopes** — `read` (GET/HEAD/OPTIONS), `write` (POST/PUT/PATCH/DELETE), `*` (all). Enforced at the Gate before any request is forwarded
- **Header stripping** — agent-supplied `Authorization`, `X-API-Key`, `Proxy-Authorization` headers are removed before injection
- **Body inspection** — outbound request bodies scanned for credential-like patterns (configurable per credential: `off`, `warn`, `block`)
- **Hash-only token storage** — agent tokens stored as SHA-256 hashes. Lost tokens are regenerated, never recovered
- **Audit logging** — every request (allowed and blocked) recorded with full context. Export with `aegis ledger export -f csv`
- **TLS support** — optional HTTPS on Gate (`aegis gate --tls --cert <path> --key <path>`)
- **Graceful shutdown** — drains in-flight requests on SIGINT/SIGTERM

See [SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md) for the full security design, threat model, and trust boundaries.

## CLI Reference

```
aegis init [--write-secrets]              Initialize Aegis (master key + config)
aegis gate [--port] [--tls] [--require-agent-auth] [--policies-dir] [--policy-mode]
                                          Start the HTTP proxy
aegis dashboard [--port] [--gate-port]    Start the web dashboard + Gate

aegis vault add [--name] [--service] [--secret] [--domains] [--auth-type]
               [--header-name] [--scopes] [--ttl] [--rate-limit] [--body-inspection]
                                          Add a credential
aegis vault list                          List credentials (secrets never shown)
aegis vault remove --name <name>          Remove a credential
aegis vault rotate --name <name> --secret <new>
                                          Rotate a credential's secret
aegis vault update --name <name> [--domains] [--auth-type] [--header-name]
               [--scopes] [--rate-limit] [--body-inspection]
                                          Update credential metadata
aegis vault create --name <name>          Create a new named vault
aegis vault vaults                        List all vaults
aegis vault destroy --name <name>         Delete a vault and its credentials
aegis vault split [--shares] [--threshold]
                                          Split master key (Shamir)
aegis vault seal                          Seal the vault
aegis vault unseal --key-share <share>... Unseal (provide threshold shares)

aegis agent add --name <name>             Register agent, print token (one-time)
aegis agent list                          List agents (no tokens shown)
aegis agent remove --name <name>          Remove agent + cascade-delete grants
aegis agent regenerate --name <name>      Regenerate token (old one invalidated)
aegis agent grant --agent <a> --credential <c>
                                          Grant credential access
aegis agent revoke --agent <a> --credential <c>
                                          Revoke credential access
aegis agent set-rate-limit --agent <a> --limit <rate>
                                          Set per-agent rate limit

aegis policy validate [--policies-dir]    Validate policy files
aegis policy test --agent <a> --service <s> --method <m> --path <p>
                                          Test a request against policies
aegis policy list [--policies-dir]        List loaded policies

aegis ledger show [--service] [--agent] [--blocked] [--system] [--since] [--limit]
                                          View audit logs
aegis ledger stats [--agent] [--since]    Request statistics
aegis ledger export -f <csv|json|jsonl> [-o file] [--service] [--since]
                                          Export audit log

aegis webhook add --url <url> --events <types>
                                          Add a webhook endpoint
aegis webhook list                        List webhooks
aegis webhook remove --id <id>            Remove a webhook
aegis webhook test --id <id>              Send a test payload
aegis webhook check-expiry                Check for expiring credentials

aegis user add --name <name> --role <role>
                                          Add RBAC user (admin/operator/viewer)
aegis user list                           List users
aegis user remove --name <name>           Remove user
aegis user role --name <name> --role <role>
                                          Change user role
aegis user regenerate-token --name <name> Regenerate user token

aegis mcp serve [--transport] [--port]    Start the MCP server
aegis mcp config <claude|cursor|vscode>   Generate MCP host config

aegis config validate                     Validate config file
aegis config show                         Show resolved configuration
aegis doctor                              Health check diagnostics
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `AEGIS_MASTER_KEY is not set` | No master key in config or env | `export AEGIS_MASTER_KEY=<key>` or use `aegis init --write-secrets` |
| `Invalid master key` | Wrong key for this vault | Check `AEGIS_MASTER_KEY` matches the key from `aegis init` |
| `Port 3100 is already in use` | Another process on that port | Use `aegis gate --port 3200` or stop the other process |
| `Database file is corrupted` | SQLite file damaged | Back up `.aegis/` and re-run `aegis init` |
| `Domain guard: blocked` | Target domain not in credential allowlist | Update domains: `aegis vault update --name <n> --domains <d>` |
| `Body inspection: blocked` | Request body contains credential-like patterns | Remove sensitive patterns from the body, or set `--body-inspection warn` on the credential |
| `Authentication required` | RBAC is active (users exist) but no token set | `export AEGIS_USER_TOKEN=<key>` — get a key from your admin or `aegis user regenerate-token` |
| `Permission denied` | Your RBAC role lacks the required permission | Ask an admin to upgrade your role with `aegis user role` |

## Development

```bash
git clone https://github.com/getaegis/aegis.git
cd aegis
yarn install
yarn build
yarn test        
yarn lint        # Biome linter
yarn verify      # Biome check + TypeScript typecheck
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for code style, PR process, and architecture overview.

### Tech Stack

| Layer | Technology |
|-------|------------|
| Language | TypeScript (ES2022, native ESM) |
| Runtime | Node.js ≥ 20 |
| Database | SQLite via better-sqlite3 (WAL mode) |
| Encryption | AES-256-GCM, PBKDF2 |
| Logging | pino (structured JSON, field-level redaction) |
| Metrics | prom-client (Prometheus) |
| CLI | Commander.js |
| MCP | @modelcontextprotocol/sdk |
| Dashboard | Vite + React 19 + Tailwind CSS v4 |
| Testing | Vitest |
| Linting | Biome |

## Roadmap

See [ROADMAP.md](docs/ROADMAP.md) for the full plan from v0.1 to v1.0.

## License

[Apache 2.0](LICENSE)
