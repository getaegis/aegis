# Aegis Quick Start — Stripe Backend

Protect your Stripe secret key with Aegis. Your AI agent queries the Stripe API through Aegis's local proxy, so it never touches the `sk_live_` or `sk_test_` key.

## What This Example Does

- Stores your Stripe secret key in Aegis's encrypted vault (AES-256-GCM)
- Restricts API calls to `api.stripe.com` only (domain guard)
- Limits the agent to read-only Stripe operations via policy (GET only)
- Logs every API call to the audit ledger

## Prerequisites

- [Aegis installed](https://github.com/getaegis/aegis#quick-start) (`npm install -g @getaegis/cli`)
- A Stripe API key — find yours at [dashboard.stripe.com/apikeys](https://dashboard.stripe.com/apikeys)
  - **Test mode keys** start with `sk_test_`
  - **Live mode keys** start with `sk_live_`
- Aegis initialized (`aegis init`)

## Important: Stripe Uses Basic Auth

Stripe authenticates via HTTP Basic Auth with the API key as the username and an empty password. Aegis handles this automatically when you use `--auth-type basic`.

## Setup

### 1. Add your Stripe key to Aegis

```bash
aegis vault add \
  --name stripe-key \
  --service stripe \
  --secret "sk_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  --domains api.stripe.com \
  --auth-type basic \
  --scopes read \
  --rate-limit 80/min \
  --body-inspection block
```

**What each flag does:**
- `--service stripe` — requests to `localhost:3100/stripe/...` will use this credential
- `--domains api.stripe.com` — only forward requests to Stripe's API
- `--auth-type basic` — injects `Authorization: Basic <base64(sk_test_...:)>` (how Stripe expects it)
- `--scopes read` — read-only (GET/HEAD/OPTIONS), prevents creating charges or modifying data
- `--rate-limit 80/min` — conservative limit to stay within Stripe's rate limits
- `--body-inspection block` — prevents credential exfiltration in request bodies

### 2. (Optional) Create an agent with scoped access

```bash
aegis agent add --name "stripe-reader"
aegis agent grant --agent "stripe-reader" --credential "stripe-key"
```

> **Service naming note:** the `stripe` service name must match everywhere — the credential (`--service stripe`), any policy rules (`service: stripe`), and the URL path (`/stripe/...`).

### 3. Copy the config and policy files

```bash
cp aegis.config.yaml /path/to/your/project/aegis.config.yaml

mkdir -p /path/to/your/project/policies
cp policies/stripe-bot.yaml /path/to/your/project/policies/
```

### 4. Start the Gate proxy

```bash
aegis gate --policies-dir ./policies --policy-mode enforce
```

### 5. Make API calls through Aegis

The `X-Target-Host` header tells Gate which upstream server to forward to (it's checked against the credential's domain allowlist). Since this credential has only one domain, the header is optional — but shown here for clarity:

```bash
# List recent charges
curl http://localhost:3100/stripe/v1/charges?limit=5 \
  -H "X-Target-Host: api.stripe.com" \
  -H "X-Aegis-Agent: aegis_your-agent-token-here"

# Get account balance
curl http://localhost:3100/stripe/v1/balance \
  -H "X-Target-Host: api.stripe.com" \
  -H "X-Aegis-Agent: aegis_your-agent-token-here"

# List customers
curl http://localhost:3100/stripe/v1/customers?limit=10 \
  -H "X-Target-Host: api.stripe.com" \
  -H "X-Aegis-Agent: aegis_your-agent-token-here"

# Get a specific invoice
curl http://localhost:3100/stripe/v1/invoices/in_1234567890 \
  -H "X-Target-Host: api.stripe.com" \
  -H "X-Aegis-Agent: aegis_your-agent-token-here"
```

Aegis injects `Authorization: Basic <base64(sk_test_...:)>` automatically.

### 6. Confirm a successful test

Your first request is working if:

- the HTTP response is `200 OK`
- the JSON body from `/v1/balance` or `/v1/charges` contains Stripe data
- `aegis ledger show -n 1` shows an `allowed` entry for `stripe`

### 7. Verify the audit trail

```bash
aegis ledger show
aegis ledger show --agent "stripe-reader"
```

## What Gets Blocked

| Scenario | Result | Reason |
|----------|--------|--------|
| POST to `/v1/charges` (create a charge) | **403 Blocked** | Policy restricts to GET only |
| Request to `evil.com` | **403 Blocked** | Domain guard — only `api.stripe.com` allowed |
| Request body containing `sk_test_...` | **403 Blocked** | Body inspection detects credential |
| DELETE to `/v1/customers/cus_123` | **403 Blocked** | Policy restricts to GET only |
| Request without agent token | **401 Unauthorized** | Agent auth required |

## Stripe API Reference

- **Base URL:** `https://api.stripe.com`
- **Auth:** Basic auth with API key as username, empty password (`-u sk_test_...:`)
  - Equivalent to `Authorization: Basic <base64("sk_test_...:") >`
  - Also supports `Authorization: Bearer sk_test_...`
- **Current API version:** `2026-02-25.clover`
- **Rate limits:** Not publicly documented, but Stripe recommends treating 429 responses with exponential backoff
- **Common read endpoints:**
  - `GET /v1/charges` — list charges
  - `GET /v1/customers` — list customers
  - `GET /v1/invoices` — list invoices
  - `GET /v1/balance` — get account balance
  - `GET /v1/products` — list products
  - `GET /v1/subscriptions` — list subscriptions
  - `GET /v1/payment_intents` — list payment intents
- **Docs:** [docs.stripe.com/api](https://docs.stripe.com/api)
