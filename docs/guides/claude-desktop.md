# Using Aegis with Claude Desktop

> Connect Aegis as an MCP server so Claude Desktop can make authenticated API calls while keeping raw credentials out of the agent context.

## Prerequisites

- [Claude Desktop](https://claude.ai/download) installed (macOS or Windows)
- Aegis installed and initialised (`aegis init`)
- At least one credential stored (`aegis vault add`)
- An agent token created (`aegis agent add --name claude-desktop`)
- The agent granted access to at least one credential (`aegis agent grant --agent claude-desktop --credential <name>`)

## Quick Setup (Recommended)

Use `aegis mcp config` to generate the correct configuration. This is the **strongly recommended** path — it includes environment variables (`HOME`, `PATH`, `AEGIS_DATA_DIR`) that MCP hosts need but don't inherit from your shell:

```bash
# Generate Claude Desktop config (stdio transport — recommended)
aegis mcp config claude

# With an agent token for authenticated sessions
aegis mcp config claude --agent-token aegis_abc123...

# Using HTTP transport instead of stdio
aegis mcp config claude --transport streamable-http --port 3200
```

Copy the generated JSON into your Claude Desktop config file.

> **Important:** Do not write the config JSON by hand. MCP hosts like Claude Desktop spawn Aegis as a child process without your shell environment. Without the `env` block that `aegis mcp config` generates, Aegis won't find your vault and will fail with path errors.

Before you do that, make sure the Claude agent can actually use a credential:

```bash
# Example: create and grant a GitHub credential
aegis vault add \
  --name github-bot \
  --service github \
  --secret "ghp_xxxxxxxxxxxxxxxxxxxx" \
  --domains api.github.com

aegis agent add --name claude-desktop
aegis agent grant --agent claude-desktop --credential github-bot
```

> **Service naming note:** the service name you store (`--service github`) must match what the MCP tool uses later (`service: "github"`).

## Manual Setup

> **Warning:** If you write the config JSON by hand, you **must** include an `env` block with `HOME`, `PATH`, and `AEGIS_DATA_DIR`. Without these, the MCP server will fail because Claude Desktop doesn't inherit your shell environment. Use `aegis mcp config claude` instead to avoid this.

### Step 1: Locate Your Config File

| OS | Path |
|----|------|
| **macOS** | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| **Windows** | `%APPDATA%\Claude\claude_desktop_config.json` |

Open it via Claude Desktop:
1. Click the **Claude** menu in your system menu bar
2. Select **Settings…**
3. Navigate to **Developer** tab
4. Click **Edit Config**

### Step 2: Add Aegis as an MCP Server

#### Option A: stdio transport (recommended)

The server runs as a child process managed by Claude Desktop. No port needed.

```json
{
  "mcpServers": {
    "aegis": {
      "command": "/path/to/node",
      "args": [
        "/path/to/aegis/dist/cli.js",
        "mcp",
        "serve",
        "--transport",
        "stdio"
      ],
      "env": {
        "HOME": "/Users/yourname",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "AEGIS_DATA_DIR": "/path/to/your/project/.aegis"
      }
    }
  }
}
```

**Finding the right paths:**

```bash
# Get your node path
which node
# Example: /usr/local/bin/node

# Get your Aegis CLI path (if installed globally via npm)
which aegis
# Or use the dist/cli.js from your Aegis installation directory

# Get your AEGIS_DATA_DIR (wherever you ran aegis init)
ls ~/.aegis  # or /path/to/your/project/.aegis
```

> **Easier alternative:** Run `aegis mcp config claude` from the directory where you ran `aegis init`. It fills in all the paths automatically.
```

#### Option B: Streamable HTTP transport

Run Aegis as a standalone HTTP server, then point Claude Desktop to it.

**Start the server first:**
```bash
aegis mcp serve --transport streamable-http --port 3200
```

**Config:**
```json
{
  "mcpServers": {
    "aegis": {
      "url": "http://127.0.0.1:3200/mcp"
    }
  }
}
```

### Step 3: Add Agent Authentication (Recommended)

For authenticated sessions, include an agent token. The easiest way:

```bash
aegis agent add --name claude-desktop
# Copy the token, then:
aegis mcp config claude --agent-token aegis_your-token-here
```

If configuring manually, add `--agent-token` to the args (the `env` block is still required).

Generate a token:
```bash
aegis agent add --name claude-desktop
# Save the token — it's shown only once
```

Then grant that agent access to the credential you want Claude to use:

```bash
aegis agent grant --agent claude-desktop --credential github-bot
```

### Step 4: Restart Claude Desktop

Completely quit and relaunch Claude Desktop. Look for the MCP server indicator (hammer icon) in the bottom-right of the chat input box.

## Available Tools

Once connected, Claude Desktop can use these Aegis tools:

| Tool | Description |
|------|-------------|
| `aegis_proxy_request` | Make authenticated API calls through Aegis (credentials injected automatically) |
| `aegis_list_services` | List all available services/credentials in the vault |
| `aegis_health` | Check Aegis server health status |

## Example Conversation

```
You: "Can you check my GitHub notifications using Aegis?"

Claude: I'll use the Aegis proxy to check your GitHub notifications.
        [Uses aegis_proxy_request with service "github" and path "/notifications"]

        You have 3 unread notifications:
        1. PR review requested on repo/project (#42)
        2. Issue comment on repo/bug-fix (#15)
        3. CI failure on repo/main
```

## Troubleshooting

### Server not appearing (no hammer icon)

1. Verify the config file is valid JSON — use `cat` or a JSON validator
2. Check the `command` path exists: `ls -la /path/to/node`
3. Ensure Aegis is built: `cd /path/to/aegis && yarn build`
4. Check Claude Desktop logs: **Help** → **Troubleshooting** → **Open Logs**

### "Agent auth required" error

The MCP server has agent authentication enabled (default). Either:
- Add `--agent-token` to the args (recommended)
- Or start the server with `--no-agent-auth` (not recommended for security)

### Tools not showing up

1. Click the hammer icon to see available tools
2. If empty, the server may have failed to start — check logs
3. Ensure Aegis has at least one credential stored: `aegis vault list`

### Tools appear, but requests fail

Check these in order:

1. The agent has a grant: `aegis agent grant --agent claude-desktop --credential <name>`
2. The MCP request `service` matches the credential's `--service` name exactly
3. The target host is in the credential allowlist
4. The request was not blocked by policy or body inspection — inspect `aegis ledger show -n 5`

## Security Notes

- Claude Desktop runs the MCP server as a local child process — credentials never leave your machine
- The agent token scopes what credentials Claude can access (based on grants)
- All requests are logged in the Aegis audit ledger: `aegis ledger show`
- Claude never sees the actual credential values — Aegis injects them at the network boundary
