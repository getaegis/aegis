# Aegis

[![CI](https://github.com/getaegis/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/getaegis/aegis/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@getaegis/cli)](https://www.npmjs.com/package/@getaegis/cli)
[![Docker](https://img.shields.io/badge/ghcr.io-getaegis%2Faegis-blue?logo=docker)](https://ghcr.io/getaegis/aegis)
[![License](https://img.shields.io/github/license/getaegis/aegis)](LICENSE)

**Stop putting API keys where AI agents can read them.**

Aegis is a local-first credential isolation proxy for AI agents. It sits between your agent and the APIs it calls — injecting secrets at the network boundary so the agent never sees, stores, or transmits real credentials.

<p align="center">
  <img src="docs/assets/demo.gif" alt="Aegis demo" width="720" />
</p>

## How It Works

```mermaid
graph LR
    Agent["🤖 AI Agent<br/><i>No credentials</i>"]
    Gate["🛡️ Aegis Gate<br/><i>localhost:3100</i>"]
    Check{"② Domain<br/>allowed?"}
    API["🌐 Target API<br/><i>slack.com, github.com</i>"]
    Ledger["📋 Ledger"]

    Agent -->|"① HTTP request<br/>(no auth headers)"| Gate
    Gate --> Check
    Check -->|"Yes"| Inject
    Inject["③ Inject credential"] -->|"Forward over HTTPS"| API
    API -->|"④ Response"| Gate
    Gate -->|"⑤ Return response<br/>(credential stripped)"| Agent
    Check -->|"No"| Block["🚫 Blocked"]
    Gate -.->|"Log every request"| Ledger

    style Agent fill:#1a1f26,stroke:#C8973E,color:#e8ecef
    style Gate fill:#1a1f26,stroke:#C8973E,color:#C8973E,stroke-width:2px
    style Check fill:#1a1f26,stroke:#C8973E,color:#e8ecef
    style Inject fill:#1a1f26,stroke:#C8973E,color:#e8ecef
    style API fill:#1a1f26,stroke:#666,color:#e8ecef
    style Block fill:#1a1f26,stroke:#e74c3c,color:#e74c3c
    style Ledger fill:#1a1f26,stroke:#C8973E,color:#e8ecef
```

## Why?

AI agents (Claude, GPT, Cursor, custom bots) increasingly call real APIs — Slack, GitHub, Stripe, databases. The current pattern is dangerous:

1. **Agents see raw API keys** — one prompt injection exfiltrates them
2. **No domain guard** — a compromised agent can send your Slack token to `evil.com`
3. **No audit trail** — you can't see what an agent did with your credentials
4. **No access control** — every agent can use every credential

Aegis solves all four. Your agent makes HTTP calls through a local proxy. Aegis handles authentication, enforces domain restrictions, and logs everything.

## Quick Start

```bash
# Install
npm install -g @getaegis/cli

# Initialize (stores master key in OS keychain by default)
aegis init

# Add a credential
aegis vault add \
  --name slack-bot \
  --service slack \
  --secret "xoxb-your-token-here" \
  --domains api.slack.com

# Start the proxy
aegis gate --no-agent-auth

# Test it — Aegis injects the token, forwards to Slack, logs the request
# X-Target-Host tells Gate which upstream server to forward to (optional if credential has one domain)
curl http://localhost:3100/slack/api/auth.test \
  -H "X-Target-Host: api.slack.com"
```

### Production Setup (with agent auth)

```bash
# Create an agent identity
aegis agent add --name "my-agent"
# Save the printed token — it's shown once only

# Grant it access to specific credentials
aegis agent grant --agent "my-agent" --credential "slack-bot"

# Start Gate (agent auth is on by default)
aegis gate

# Agent must include its token
curl http://localhost:3100/slack/api/auth.test \
  -H "X-Target-Host: api.slack.com" \
  -H "X-Aegis-Agent: aegis_a1b2c3d4..."
```

## MCP Integration

Aegis is a first-class [MCP](https://modelcontextprotocol.io) server. Any MCP-compatible AI agent can use it natively — no HTTP calls needed.

**Before (plaintext key in config):**
```json
{
  "mcpServers": {
    "slack": {
      "command": "node",
      "args": ["slack-mcp-server"],
      "env": { "SLACK_TOKEN": "xoxb-1234-real-token-here" }
    }
  }
}
```

**After (Aegis — no key visible):**
```json
{
  "mcpServers": {
    "aegis": {
      "command": "npx",
      "args": ["-y", "@getaegis/cli", "mcp", "serve"]
    }
  }
}
```

Generate the config for your AI host:

```bash
aegis mcp config claude   # Claude Desktop
aegis mcp config cursor   # Cursor
aegis mcp config vscode   # VS Code
```

The MCP server exposes three tools:

| Tool | Description |
|------|-------------|
| `aegis_proxy_request` | Make an authenticated API call (provide service + path, Aegis injects credentials) |
| `aegis_list_services` | List available services (names only, never secrets) |
| `aegis_health` | Check Aegis status |

The MCP server replicates the full Gate security pipeline: domain guard, agent auth, body inspection, rate limiting, audit logging.

### Setup Guides

- [Claude Desktop](docs/guides/claude-desktop.md)
- [Cursor](docs/guides/cursor.md)
- [VS Code](docs/guides/vscode.md)
- [Windsurf](docs/guides/windsurf.md)
- [Cline](docs/guides/cline.md)

## Features

| Feature | Description |
|---------|-------------|
| **Encrypted Vault** | AES-256-GCM encrypted credential storage with PBKDF2 key derivation |
| **HTTP Proxy (Gate)** | Transparent credential injection — agent hits `localhost:3100/{service}/path` |
| **Domain Guard** | Every outbound request checked against credential allowlists. No bypass |
| **Audit Ledger** | Every request (allowed and blocked) logged with full context |
| **Agent Identity** | Per-agent tokens, credential scoping, and rate limits |
| **Policy Engine** | Declarative YAML policies — method, path, rate-limit, time-of-day restrictions |
| **Body Inspector** | Outbound request bodies scanned for credential-like patterns |
| **MCP Server** | Native Model Context Protocol for Claude, Cursor, VS Code, Windsurf, Cline |
| **Web Dashboard** | Real-time monitoring UI with WebSocket live feed |
| **Prometheus Metrics** | `/_aegis/metrics` endpoint for Grafana dashboards |
| **Webhook Alerts** | HMAC-signed notifications for blocked requests, expiring credentials |
| **RBAC** | Admin, operator, viewer roles with 16 granular permissions |
| **Multi-Vault** | Separate vaults for dev/staging/prod with isolated encryption keys |
| **Shamir's Secret Sharing** | M-of-N key splitting for team master key management |
| **Cross-Platform Key Storage** | OS keychain by default (macOS, Windows, Linux) with file fallback |
| **TLS Support** | Optional HTTPS on Gate with cert/key configuration |
| **Configuration File** | `aegis.config.yaml` with env var overrides and CLI flag overrides |

## Example Integrations

Step-by-step guides with config files and policies included:

- [**Slack Bot**](examples/slack-bot/) — Protect your Slack bot token with domain-restricted proxy access
- [**GitHub Integration**](examples/github-integration/) — Secure GitHub PAT with per-agent grants and read-only policies
- [**Stripe Backend**](examples/stripe-backend/) — Isolate Stripe API keys with body inspection and rate limiting

## Security

- Published [STRIDE threat model](docs/THREAT_MODEL.md) — 28 threats analysed, 0 critical/high unmitigated findings
- Full [security architecture](docs/SECURITY_ARCHITECTURE.md) documentation (trust boundaries, crypto pipeline, data flow)
- AES-256-GCM + ChaCha20-Poly1305 encryption at rest
- Domain guard enforced on every request — no bypass
- Agent tokens stored as SHA-256 hashes — cannot be recovered, only regenerated
- Request body inspection for credential pattern detection
- Open source (Apache 2.0) — read the code

## How Aegis Compares

| | `.env` files | Vault/Doppler | Infisical | **Aegis** |
|---|---|---|---|---|
| Agent sees raw key | Yes | Yes (after fetch) | Yes (after fetch) | **No — never** |
| Domain restrictions | No | No | No | **Yes** |
| MCP-native | No | No | Adding | **Yes** |
| Local-first | Yes | No | No | **Yes** |
| Setup | 10 sec | 30+ min | 15+ min | **~2 min** |

See [full comparison](docs/COMPARISON.md) for detailed breakdowns against each approach.

## Documentation

| Document | Description |
|----------|-------------|
| [Usage Guide](docs/USAGE.md) | Full reference: CLI commands, configuration, RBAC, policies, webhooks, troubleshooting |
| [Security Architecture](docs/SECURITY_ARCHITECTURE.md) | Trust boundaries, crypto pipeline, data flow diagrams |
| [Threat Model](docs/THREAT_MODEL.md) | STRIDE analysis — 28 threats, mitigations, residual risks |
| [Comparison](docs/COMPARISON.md) | Detailed comparison with .env, Vault, Doppler, Infisical |
| [FAQ](docs/FAQ.md) | Common questions and objections |
| [Roadmap](docs/ROADMAP.md) | Feature roadmap from v0.1 to v1.0 |
| [Contributing](CONTRIBUTING.md) | Code style, PR process, architecture overview |

## Install

```bash
# npm
npm install -g @getaegis/cli

# Homebrew
brew tap getaegis/aegis && brew install aegis

# Docker
docker run ghcr.io/getaegis/aegis --help
```

**Requires Node.js ≥ 20** — check with `node -v`

## Development

```bash
git clone https://github.com/getaegis/aegis.git
cd aegis
yarn install
yarn build
yarn test
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for code style, PR process, and architecture overview.

## License

[Apache 2.0](LICENSE)
