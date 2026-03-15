# Aegis Quick Start — GitHub Integration

Protect your GitHub personal access token with Aegis. Your AI agent talks to the GitHub REST API through Aegis's local proxy, so it never touches the `ghp_` or `github_pat_` token.

## What This Example Does

- Stores your GitHub token in Aegis's encrypted vault (AES-256-GCM)
- Restricts API calls to `api.github.com` only (domain guard)
- Limits the agent to specific repo operations via policy
- Logs every API call to the audit ledger

## Prerequisites

- [Aegis installed](https://github.com/getaegis/aegis#quick-start) (`npm install -g @getaegis/cli`)
- A GitHub personal access token — create one at [github.com/settings/tokens](https://github.com/settings/tokens)
  - **Fine-grained tokens** (recommended): start with `github_pat_`
  - **Classic tokens**: start with `ghp_`
- Aegis initialized (`aegis init`)

## Setup

### 1. Add your GitHub token to Aegis

```bash
aegis vault add \
  --name github-bot \
  --service github \
  --secret "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  --domains api.github.com \
  --auth-type bearer \
  --rate-limit 200/min \
  --body-inspection block
```

**What each flag does:**
- `--service github` — requests to `localhost:3100/github/...` will use this credential
- `--domains api.github.com` — Aegis will only forward requests to this domain
- `--auth-type bearer` — injects `Authorization: Bearer ghp_...` on outbound requests
- `--rate-limit 200/min` — stay well within GitHub's 5,000 requests/hour limit
- `--body-inspection block` — prevents credential patterns from leaking in request bodies

### 2. (Optional) Create an agent with scoped access

```bash
# Create an agent identity
aegis agent add --name "github-assistant"

# Grant it access to the github credential only
aegis agent grant --agent "github-assistant" --credential "github-bot"
```

Save the agent token — your agent needs it for every request.

> **Service naming note:** the `github` service name must match everywhere — the credential (`--service github`), any policy rules (`service: github`), and the URL path (`/github/...`).

### 3. Copy the config and policy files

```bash
cp aegis.config.yaml /path/to/your/project/aegis.config.yaml

mkdir -p /path/to/your/project/policies
cp policies/github-bot.yaml /path/to/your/project/policies/
```

### 4. Start the Gate proxy

```bash
aegis gate --policies-dir ./policies --policy-mode enforce
```

### 5. Make API calls through Aegis

Your agent calls `localhost:3100/github/...` instead of `api.github.com` directly. The `X-Target-Host` header tells Gate which upstream server to forward to (it's checked against the credential's domain allowlist). Since this credential has only one domain, the header is optional — but shown here for clarity:

```bash
# List your repos
curl http://localhost:3100/github/user/repos \
  -H "X-Target-Host: api.github.com" \
  -H "X-Aegis-Agent: aegis_your-agent-token-here"

# Get a specific repo
curl http://localhost:3100/github/repos/your-org/your-repo \
  -H "X-Target-Host: api.github.com" \
  -H "X-Aegis-Agent: aegis_your-agent-token-here"

# List issues
curl http://localhost:3100/github/repos/your-org/your-repo/issues \
  -H "X-Target-Host: api.github.com" \
  -H "X-Aegis-Agent: aegis_your-agent-token-here"

# Create an issue (if policy allows POST)
curl -X POST http://localhost:3100/github/repos/your-org/your-repo/issues \
  -H "X-Target-Host: api.github.com" \
  -H "X-Aegis-Agent: aegis_your-agent-token-here" \
  -H "Content-Type: application/json" \
  -d '{"title": "Bug found by agent", "body": "Details here"}'
```

Aegis injects `Authorization: Bearer ghp_...` automatically. The agent never sees the token.

### 6. Confirm a successful test

Your first request is working if:

- the HTTP response is `200 OK`
- the JSON body contains repository data (for example, an array from `/user/repos`)
- `aegis ledger show -n 1` shows an `allowed` entry for `github`

### 7. Verify the audit trail

```bash
aegis ledger show
aegis ledger show --agent "github-assistant"
aegis ledger export -f json
```

## What Gets Blocked

| Scenario | Result | Reason |
|----------|--------|--------|
| Request to `evil.com` with your GitHub token | **403 Blocked** | Domain guard — only `api.github.com` allowed |
| DELETE to `/repos/org/repo` | **403 Blocked** | Policy restricts to GET and POST only |
| Request body containing `ghp_...` | **403 Blocked** | Body inspection detects credential exfiltration |
| Request to `/admin/...` endpoint | **403 Blocked** | Policy path restriction |
| Request without agent token | **401 Unauthorized** | Agent auth required |

## GitHub API Reference

- **Base URL:** `https://api.github.com`
- **Auth:** `Authorization: Bearer <token>` (supports both `Bearer` and `token` prefix)
- **API Version Header:** `X-GitHub-Api-Version: 2026-03-10` (optional but recommended)
- **Rate Limit:** 5,000 requests/hour for authenticated requests
- **Common endpoints:**
  - `GET /user/repos` — list authenticated user's repos
  - `GET /repos/{owner}/{repo}` — get a repo
  - `GET /repos/{owner}/{repo}/issues` — list issues
  - `POST /repos/{owner}/{repo}/issues` — create an issue
  - `GET /repos/{owner}/{repo}/pulls` — list pull requests
  - `GET /search/repositories?q={query}` — search repos
- **Docs:** [docs.github.com/en/rest](https://docs.github.com/en/rest)
