# Using Aegis with OpenClaw

> Route your OpenClaw agent's API calls through the Aegis credential proxy so raw API keys never enter OpenClaw's process or context window.

## Why Use Aegis with OpenClaw?

OpenClaw skills inject API keys into `process.env` per agent run. This means the LLM can access them — intentionally (via tools) but also accidentally (e.g. `echo $GITHUB_TOKEN` in a shell command, or through a malicious skill's tool description).

Aegis eliminates this attack surface entirely:

| Without Aegis | With Aegis |
|---------------|------------|
| API keys in `openclaw.json` as plaintext | API keys stored in Aegis encrypted vault (AES-256-GCM) |
| Keys injected into `process.env` per run | Keys never enter OpenClaw's process |
| Any skill or shell command can read keys | Agent only has an Aegis token (can't access real keys) |
| No domain restrictions on API calls | Domain allowlists prevent exfiltration |
| No audit trail of which API calls were made | Every request logged to the Aegis ledger |

## Prerequisites

- [OpenClaw](https://openclaw.ai) installed and running (`openclaw gateway status`)
- [Aegis](https://github.com/getaegis/aegis) installed and initialised (`aegis init`)
- At least one credential stored in Aegis
- An Aegis agent token created for OpenClaw

## Setup

### Step 1: Store Your API Keys in Aegis (Not OpenClaw)

Instead of putting API keys directly in `openclaw.json` skill entries, store them in Aegis:

```bash
# Store a GitHub token
aegis vault add \
  --name github \
  --service github \
  --secret "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  --domains api.github.com \
  --auth-type bearer

# Store a Slack token
aegis vault add \
  --name slack \
  --service slack \
  --secret "xoxb-xxxxxxxxxxxx-xxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxx" \
  --domains slack.com,api.slack.com \
  --auth-type bearer

# Store a Stripe key
aegis vault add \
  --name stripe \
  --service stripe \
  --secret "YOUR_STRIPE_SECRET_KEY" \
  --domains api.stripe.com \
  --auth-type bearer
```

### Step 2: Create an Aegis Agent for OpenClaw

```bash
# Create an agent identity
aegis agent add --name openclaw

# Grant it access to the credentials it needs
aegis agent grant --agent openclaw --credential github
aegis agent grant --agent openclaw --credential slack
aegis agent grant --agent openclaw --credential stripe
```

Save the agent token — you'll need it in Step 4.

### Step 3: Start Aegis Gate

```bash
aegis gate
```

Gate will be listening on `http://localhost:3100`. Verify it's running:

```bash
curl http://localhost:3100/_aegis/health
```

> **Tip:** Run Gate as a background service (launchd on macOS, systemd on Linux) so it starts automatically. OpenClaw's Gateway is already a daemon — Aegis Gate should be too.

### Step 4: Install the Aegis Skill

Copy the Aegis skill into your OpenClaw skills directory:

```bash
# Create the skill directory
mkdir -p ~/.openclaw/skills/aegis

# Create the skill file
cat > ~/.openclaw/skills/aegis/SKILL.md << 'EOF'
---
name: aegis
description: Route API calls through the Aegis credential proxy — keeps raw API keys out of the agent context
metadata: { "openclaw": { "always": true, "emoji": "🛡️", "requires": { "bins": ["aegis"] } } }
---

## Aegis Credential Proxy

You have access to external APIs through the Aegis credential proxy running at `http://localhost:3100`. Aegis stores and injects real API credentials at the network boundary — you never see or handle raw API keys.

### How to make API calls

**Instead of calling APIs directly, route through Aegis:**

- Replace `https://api.github.com/...` with `http://localhost:3100/github/...`
- Replace `https://api.slack.com/...` with `http://localhost:3100/slack/...`
- Replace `https://api.stripe.com/...` with `http://localhost:3100/stripe/...`

**Always include these headers:**

- `X-Aegis-Agent`: Your agent token (available as `$AEGIS_AGENT_TOKEN`)
- `X-Target-Host`: The real API domain (e.g. `api.github.com`)

### Examples

**GitHub — list repositories:**
```bash
curl http://localhost:3100/github/user/repos \
  -H "X-Aegis-Agent: $AEGIS_AGENT_TOKEN" \
  -H "X-Target-Host: api.github.com"
```

**Slack — send a message:**
```bash
curl -X POST http://localhost:3100/slack/api/chat.postMessage \
  -H "X-Aegis-Agent: $AEGIS_AGENT_TOKEN" \
  -H "X-Target-Host: api.slack.com" \
  -H "Content-Type: application/json" \
  -d '{"channel": "C01234567", "text": "Hello from OpenClaw via Aegis!"}'
```

**Stripe — list customers:**
```bash
curl http://localhost:3100/stripe/v1/customers \
  -H "X-Aegis-Agent: $AEGIS_AGENT_TOKEN" \
  -H "X-Target-Host: api.stripe.com"
```

### Important rules

1. **Never use raw API keys.** You do not have direct access to API keys. All credentials are managed by Aegis.
2. **Always use the proxy URL.** Route through `http://localhost:3100/{service}/...`, not directly to the API.
3. **Always include both headers.** `X-Aegis-Agent` authenticates you, `X-Target-Host` tells Aegis where to forward.
4. **Domain restrictions are enforced.** If you try to call a domain not in the credential's allowlist, Aegis will block it.
5. **Everything is audited.** Every API call through Aegis is logged — both allowed and blocked.

### Available services

The services you have access to depend on what credentials have been granted to your agent. Common patterns:
- `github` → `api.github.com`
- `slack` → `api.slack.com`
- `stripe` → `api.stripe.com`

To check if Aegis is running: `curl http://localhost:3100/_aegis/health`
EOF
```

Or if you've cloned the Aegis repo, copy from the example:

```bash
cp -r /path/to/aegis/examples/openclaw-skill/aegis ~/.openclaw/skills/
```

### Step 5: Configure the Agent Token

Add the Aegis agent token to your OpenClaw config:

```bash
# Edit ~/.openclaw/openclaw.json
```

Add this to the `skills.entries` section:

```json
{
  "skills": {
    "entries": {
      "aegis": {
        "enabled": true,
        "env": {
          "AEGIS_AGENT_TOKEN": "aegis_your-token-from-step-2"
        }
      }
    }
  }
}
```

### Step 6: Remove Raw API Keys from Other Skills

For any skill that previously had API keys configured directly:

**Before (insecure):**
```json
{
  "skills": {
    "entries": {
      "github": {
        "enabled": true,
        "apiKey": { "source": "env", "provider": "default", "id": "GITHUB_TOKEN" },
        "env": { "GITHUB_TOKEN": "ghp_xxxxxxxxxxxxx" }
      }
    }
  }
}
```

**After (with Aegis):**
```json
{
  "skills": {
    "entries": {
      "github": {
        "enabled": true
      },
      "aegis": {
        "enabled": true,
        "env": { "AEGIS_AGENT_TOKEN": "aegis_your-token-here" }
      }
    }
  }
}
```

The GitHub skill still works — but instead of calling `api.github.com` directly with a raw token, the Aegis skill teaches the agent to route through the proxy.

### Step 7: Verify It Works

Restart OpenClaw's gateway to pick up the new skill:

```bash
openclaw gateway restart
```

Then chat with your agent:

> "List my GitHub repositories"

The agent should make the request via `http://localhost:3100/github/...` instead of directly to `api.github.com`. You can verify in the Aegis ledger:

```bash
aegis ledger show --last 5
```

## How It Works

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│              │     │              │     │              │     │              │
│   OpenClaw   │────▶│  Aegis Gate  │────▶│   Real API   │────▶│   Response   │
│   (agent)    │     │  :3100       │     │  github.com  │     │   (back)     │
│              │     │              │     │              │     │              │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                           │
                     ┌─────┴─────┐
                     │ • Verify  │
                     │   agent   │
                     │ • Inject  │
                     │   creds   │
                     │ • Check   │
                     │   domain  │
                     │ • Log to  │
                     │   ledger  │
                     └───────────┘
```

1. OpenClaw's agent makes an HTTP request to `localhost:3100/{service}/...`
2. Aegis Gate receives the request, verifies the agent token
3. Gate looks up the credential for the service, checks the domain allowlist
4. Gate injects the real API key (e.g. `Authorization: Bearer ghp_xxx`) into the outbound request
5. Gate forwards to the real API
6. Response flows back through Gate to OpenClaw
7. The entire request/response is logged in the Aegis ledger

The agent never sees `ghp_xxx` — only the Aegis agent token.

## MCP Alternative

If you prefer the MCP approach over the HTTP proxy, OpenClaw supports MCP servers too. See the [Claude Desktop guide](./claude-desktop.md) for MCP setup — the same `aegis mcp serve` command works with any MCP-compatible client.

The HTTP proxy approach (described above) is generally simpler for OpenClaw because skills already use `curl` and HTTP calls. MCP is better for tools that explicitly use MCP tool calls.

## Security Benefits

| Threat | Without Aegis | With Aegis |
|--------|--------------|------------|
| **Prompt injection reads env vars** | Attacker extracts real API keys | Attacker only gets Aegis token (scoped, revocable) |
| **Malicious skill exfiltrates keys** | Skill reads `process.env` and phones home | No keys in `process.env` to steal |
| **Cross-tool hijacking** | Poisoned tool description uses real keys | Keys don't exist in agent context |
| **Key rotation** | Update every `openclaw.json` entry | Update once in Aegis vault |
| **Audit** | No record of which API calls were made | Full ledger with timestamps, agent ID, status |
| **Blast radius** | Compromised key = full access | Domain allowlists + credential scoping limit damage |

## Troubleshooting

### "Connection refused" on localhost:3100

Aegis Gate isn't running. Start it:

```bash
aegis gate
```

### "Agent auth required" (401)

The `X-Aegis-Agent` header is missing or the token is invalid. Check:

```bash
aegis agent list
```

Make sure the token in `openclaw.json` matches an active agent.

### "Domain not in allowlist" (403)

The service is trying to call a domain that wasn't included when the credential was created. Update the credential's domain list:

```bash
aegis vault add --name github --service github --secret "..." --domains api.github.com,github.com
```

### Agent doesn't use the proxy

If the agent calls APIs directly instead of through Aegis, the skill may not be loaded. Check:

1. Verify the skill exists: `ls ~/.openclaw/skills/aegis/SKILL.md`
2. Verify `aegis` is in PATH: `which aegis`
3. Restart the gateway: `openclaw gateway restart`
4. Check skill loading in OpenClaw logs

## Further Reading

- [Aegis Documentation](https://github.com/getaegis/aegis)
- [OpenClaw Skills Reference](https://docs.openclaw.ai/tools/skills)
- [Aegis Security Architecture](../SECURITY_ARCHITECTURE.md)
- [ClawHub](https://clawhub.com) — Browse and publish OpenClaw skills
