# Aegis — Comparison Guide

How Aegis compares to common approaches for managing credentials with AI agents.

---

## The Core Difference

Most secret management tools answer: **"Where do I store my secrets?"**

Aegis answers a different question: **"How do I use secrets without my AI agent ever seeing them?"**

This isn't a better vault — it's a different layer. You can use Aegis *alongside* Vault, Doppler, or Infisical. They store the secret; Aegis ensures the agent never touches it.

---

## Feature Comparison

| Feature | `.env` / env vars | HashiCorp Vault | Doppler | Infisical | **Aegis** |
|---------|-------------------|-----------------|---------|-----------|-----------|
| **Encryption at rest** | No | Yes | Yes | Yes | Yes (AES-256-GCM + ChaCha20-Poly1305 full-DB) |
| **Agent can read raw key** | Yes | Yes (after fetch) | Yes (after fetch) | Yes (after fetch) | **No — never** |
| **Domain restrictions** | No | No | No | No | **Yes (per-credential allowlist)** |
| **Audit trail** | No | Yes | Partial | Yes | **Yes (every request, allowed + blocked)** |
| **Local-first** | Yes | No (server) | No (cloud) | No (cloud) | **Yes** |
| **MCP-native** | No | No | No | Adding | **Yes (ships as MCP server)** |
| **Agent authentication** | No | No | No | No | **Yes (token-based, per-agent grants)** |
| **Body inspection** | No | No | No | No | **Yes (detects credential patterns in request bodies)** |
| **Policy engine** | No | Yes (ACL) | No | Yes (RBAC) | **Yes (declarative YAML, per-agent rules)** |
| **Setup time** | 10 seconds | 30+ minutes | 15+ minutes | 15+ minutes | **~2 minutes** |
| **Infrastructure required** | None | Server cluster | Cloud account | Cloud account | **None (single binary)** |
| **Cost** | Free | Open-source / paid | Paid | Free tier / paid | **Free (Apache 2.0)** |
| **Designed for AI agents** | No | No | No | Adding | **Yes (built for this)** |

---

## Detailed Comparisons

### `.env` Files / Environment Variables vs Aegis

**The status quo.** Most developers put API keys in `.env` files or environment variables that AI agents read directly.

| | `.env` / env vars | Aegis |
|---|---|---|
| **How the agent gets the key** | Reads it from the environment or file — knows the raw value | Never gets the key. Makes HTTP requests through Aegis, which injects the key at the network boundary |
| **What stops the agent sending the key to the wrong server?** | Nothing | Domain guard: each credential has an allowlist of approved domains |
| **What stops prompt injection from exfiltrating the key?** | Nothing — the key is in the agent's memory | The key was never in the agent's memory |
| **Audit trail** | None | Every request logged (service, domain, agent, status, timestamp) |
| **Encryption** | Plaintext on disk | AES-256-GCM per-credential + ChaCha20-Poly1305 full-database encryption |
| **Rotation** | Edit the file, restart the process | `aegis vault rotate` — zero-downtime, no agent restart needed |
| **MCP integration** | Paste key directly into `claude_desktop_config.json` | `aegis mcp config claude` generates config with no keys visible |

**Before (`.env`):**
```json
// claude_desktop_config.json — key visible in plaintext
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

**After (Aegis):**
```json
// claude_desktop_config.json — no keys anywhere
{
  "mcpServers": {
    "aegis": {
      "command": "npx",
      "args": ["-y", "@getaegis/cli", "mcp", "serve"]
    }
  }
}
```

The Slack token lives in Aegis's encrypted vault. Claude never sees it.

---

### HashiCorp Vault / Doppler vs Aegis

**Different problems.** Vault and Doppler solve *secret storage and distribution*. Aegis solves *secret isolation from agents*.

| | Vault / Doppler | Aegis |
|---|---|---|
| **Primary purpose** | Centralised secret management for teams and infrastructure | Credential isolation — prevent AI agents from possessing raw keys |
| **How the app gets the secret** | Fetches it via API or SDK — the app holds the raw value | Never fetches it — Aegis injects it into outbound requests |
| **Architecture** | Server (Vault) or cloud service (Doppler) | Local proxy on localhost |
| **AI agent awareness** | None — treats AI agents same as any other client | Built for AI agents — agent auth, grants, body inspection, MCP server |
| **Domain restrictions** | ACL-based access to secrets, not outbound network | Per-credential domain allowlist on outbound API calls |
| **Setup** | Deploy cluster or create cloud account, configure auth backends | `aegis init` — one command, local SQLite |
| **Can they work together?** | **Yes.** Store secrets in Vault/Doppler, route agent API calls through Aegis. They solve different layers of the problem | |

---

### Infisical vs Aegis

**Closest competitor, different position.** Infisical ($38M funded, 12k+ orgs) is a cloud secrets platform actively adding MCP and agent security features.

| | Infisical | Aegis |
|---|---|---|
| **Trust model** | Secrets flow through Infisical's control plane (cloud or self-hosted server) | Secrets never leave your machine — local-only |
| **Architecture** | Platform with web dashboard, API, SDKs, SSO, RBAC, rotation | Single CLI binary, transparent proxy, no cloud |
| **AI agent integration** | Adding MCP server features to existing platform | MCP-native from day one — built specifically for agents |
| **Integration method** | SDK / framework coupling | No SDK — any process that makes HTTP calls works |
| **Credential isolation** | Agent fetches secret via the platform — still holds the raw value | Agent never holds the raw value — Aegis injects at network boundary |
| **Target user** | Enterprise platform teams needing full secrets lifecycle management | Solo developers and small teams using AI coding tools |
| **Pricing** | Free tier, paid plans for teams | Free forever (Apache 2.0, open source) |
| **Maturity** | Production-hardened, $38M funding, 12k orgs | v1.0 — new project, battle-testing in progress |

**When to use Infisical:** Your team already uses it, you need enterprise features (SSO, rotation schedules, compliance workflows), or you want a managed cloud solution.

**When to use Aegis:** You want local-first credential isolation, you don't want to send secrets through a cloud control plane, you want MCP-native integration, or you want a zero-dependency single binary.

**They're not mutually exclusive.** You could store secrets in Infisical and route AI agent API calls through Aegis for the isolation layer.

---

## Summary

| Approach | Best for | Limitation with AI agents |
|----------|----------|---------------------------|
| **`.env` files** | Quick prototyping | Agent sees the raw key — one prompt injection away from exfiltration |
| **HashiCorp Vault** | Enterprise secret management at scale | Agent still fetches and holds the raw secret |
| **Doppler** | Team secret sync across environments | Agent still fetches and holds the raw secret |
| **Infisical** | Cloud-first secrets platform with growing agent features | Agent fetches the secret — holds it in memory |
| **Aegis** | Credential isolation — agent never sees the key | New project, local-only (no cloud sync yet) |

The right choice depends on your threat model. If your concern is **where secrets are stored**, use Vault/Doppler/Infisical. If your concern is **whether the AI agent should ever possess the raw secret**, use Aegis.
