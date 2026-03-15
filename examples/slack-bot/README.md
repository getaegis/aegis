# Aegis Quick Start — Slack Bot

Protect your Slack bot token with Aegis. Your AI agent calls the Slack API through Aegis's local proxy, so it never sees the `xoxb-` token.

## What This Example Does

- Stores your Slack bot token in Aegis's encrypted vault (AES-256-GCM)
- Restricts API calls to `slack.com` only (domain guard)
- Limits the agent to read-only Slack methods (GET only via policy)
- Logs every API call to the audit ledger

## Prerequisites

- [Aegis installed](https://github.com/getaegis/aegis#quick-start) (`npm install -g @getaegis/cli`)
- A Slack bot token (`xoxb-...`) — create one at [api.slack.com/apps](https://api.slack.com/apps)
- Aegis initialized (`aegis init`)

## Setup

### 1. Add your Slack bot token to Aegis

```bash
aegis vault add \
  --name slack-bot \
  --service slack \
  --secret "xoxb-your-bot-token-here" \
  --domains slack.com \
  --auth-type bearer \
  --scopes read \
  --rate-limit 100/min \
  --body-inspection block
```

**What each flag does:**
- `--service slack` — requests to `localhost:3100/slack/...` will use this credential
- `--domains slack.com` — Aegis will only forward requests to this domain (domain guard)
- `--auth-type bearer` — injects `Authorization: Bearer xoxb-...` on outbound requests
- `--scopes read` — only allows GET/HEAD/OPTIONS methods (no posting or deleting)
- `--rate-limit 100/min` — prevents runaway request loops
- `--body-inspection block` — blocks outbound requests that contain credential-like strings

### 2. (Optional) Create an agent with scoped access

```bash
# Create an agent identity
aegis agent add --name "slack-reader"

# Grant it access to the slack credential only
aegis agent grant --agent "slack-reader" --credential "slack-bot"
```

Save the agent token that's printed — your agent will need it.

> **Service naming note:** the `slack` service name must match everywhere — the credential (`--service slack`), any policy rules (`service: slack`), and the URL path (`/slack/...`).

### 3. Copy the config and policy files

```bash
# Copy the example config (or merge into your existing aegis.config.yaml)
cp aegis.config.yaml /path/to/your/project/aegis.config.yaml

# Copy the policy file
mkdir -p /path/to/your/project/policies
cp policies/slack-bot.yaml /path/to/your/project/policies/
```

### 4. Start the Gate proxy

```bash
aegis gate --policies-dir ./policies --policy-mode enforce
```

### 5. Make API calls through Aegis

Your agent now makes requests to `localhost:3100/slack/...` instead of calling Slack directly:

```bash
# List channels (through Aegis)
curl http://localhost:3100/slack/api/conversations.list \
  -H "X-Target-Host: slack.com" \
  -H "X-Aegis-Agent: aegis_your-agent-token-here"

# Get user info
curl http://localhost:3100/slack/api/users.info?user=U12345678 \
  -H "X-Target-Host: slack.com" \
  -H "X-Aegis-Agent: aegis_your-agent-token-here"

# Check auth
curl http://localhost:3100/slack/api/auth.test \
  -H "X-Target-Host: slack.com" \
  -H "X-Aegis-Agent: aegis_your-agent-token-here"
```

Aegis injects the `Authorization: Bearer xoxb-...` header automatically. The agent never sees the token.

### 6. Confirm a successful test

Your first request is working if:

- the HTTP response is `200 OK`
- the JSON body from `/api/auth.test` contains `"ok": true`
- `aegis ledger show -n 1` shows an `allowed` entry for `slack`

### 7. Verify the audit trail

```bash
# See all requests
aegis ledger show

# See only blocked requests
aegis ledger show --blocked

# Export for analysis
aegis ledger export -f json
```

## What Gets Blocked

With this configuration, Aegis will block:

| Scenario | Result | Reason |
|----------|--------|--------|
| POST to `slack.com/api/chat.postMessage` | **403 Blocked** | Policy restricts to GET only (`--scopes read`) |
| Request to `evil.com` | **403 Blocked** | Domain guard — only `slack.com` is allowed |
| Request body containing `xoxb-...` | **403 Blocked** | Body inspection detects credential exfiltration |
| More than 100 requests/minute | **429 Rate Limited** | Per-credential rate limit exceeded |
| Request without `X-Aegis-Agent` header | **401 Unauthorized** | Agent auth is required by default |

## Slack API Reference

- **Base URL:** `https://slack.com/api/`
- **Auth:** Bearer token (`xoxb-` prefix for bot tokens, `xoxp-` prefix for user tokens)
- **Common read endpoints:**
  - `conversations.list` — list channels
  - `conversations.history` — get messages from a channel
  - `users.list` — list workspace members
  - `users.info` — get a single user's info
  - `auth.test` — test authentication
- **Docs:** [docs.slack.dev](https://docs.slack.dev/)
