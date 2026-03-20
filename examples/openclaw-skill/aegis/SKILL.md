---
name: aegis
description: Route API calls through the Aegis credential proxy — keeps raw API keys out of the agent context
version: 1.0.0
homepage: https://github.com/getaegis/aegis
user-invocable: false
metadata: { "openclaw": { "always": true, "emoji": "🛡️", "homepage": "https://github.com/getaegis/aegis", "requires": { "bins": ["aegis"], "env": ["AEGIS_AGENT_TOKEN"] }, "primaryEnv": "AEGIS_AGENT_TOKEN" } }
---

## Aegis Credential Proxy

You have access to external APIs through the Aegis credential proxy running at `http://localhost:3100`. Aegis stores and injects real API credentials at the network boundary — you never see or handle raw API keys.

### How to make API calls

**Instead of calling APIs directly, route all requests through Aegis Gate:**

| Real API | Aegis proxy URL |
|----------|-----------------|
| `https://api.github.com/...` | `http://localhost:3100/github/...` |
| `https://api.slack.com/...` | `http://localhost:3100/slack/...` |
| `https://api.stripe.com/...` | `http://localhost:3100/stripe/...` |
| `https://api.openai.com/...` | `http://localhost:3100/openai/...` |

The pattern is always: `http://localhost:3100/{service-name}/{api-path}`

**Required headers on every request:**

```
X-Aegis-Agent: $AEGIS_AGENT_TOKEN
X-Target-Host: <real-api-domain>
```

- `X-Aegis-Agent` authenticates you with Aegis using your agent token
- `X-Target-Host` tells Aegis which real API domain to forward to

### Examples

**GitHub — list repositories:**
```bash
curl http://localhost:3100/github/user/repos \
  -H "X-Aegis-Agent: $AEGIS_AGENT_TOKEN" \
  -H "X-Target-Host: api.github.com"
```

**GitHub — create an issue:**
```bash
curl -X POST http://localhost:3100/github/repos/owner/repo/issues \
  -H "X-Aegis-Agent: $AEGIS_AGENT_TOKEN" \
  -H "X-Target-Host: api.github.com" \
  -H "Content-Type: application/json" \
  -d '{"title": "Bug report", "body": "Description here"}'
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

**Generic — any service registered in Aegis:**
```bash
curl http://localhost:3100/{service}/{path} \
  -H "X-Aegis-Agent: $AEGIS_AGENT_TOKEN" \
  -H "X-Target-Host: {real-domain}"
```

### Rules

1. **Never use raw API keys.** All credentials are managed by Aegis. Do not attempt to read API keys from environment variables or config files.
2. **Always route through the proxy.** Use `http://localhost:3100/{service}/...` for every external API call.
3. **Always include both headers.** `X-Aegis-Agent` for auth, `X-Target-Host` for routing.
4. **Domain restrictions are enforced.** Aegis will block requests to domains not in the credential's allowlist (HTTP 403).
5. **Everything is audited.** Every API call through Aegis is logged with timestamp, agent identity, and status.

### Health check

To verify Aegis is running:
```bash
curl http://localhost:3100/_aegis/health
```

### If Aegis is not running

If `localhost:3100` is unreachable, tell the user to start Aegis Gate:
```bash
aegis gate
```

Do not fall back to direct API calls with raw keys. If Aegis is down, report the error and ask the user to start it.
