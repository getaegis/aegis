# Using Aegis with Cline

> Connect Aegis as an MCP server so Cline can make authenticated API calls while keeping raw credentials out of the agent context.

> **Verification note:** This guide reflects Cline MCP behavior and UI labels verified against public documentation in March 2026. Re-check the current extension docs if the UI has moved.

## Prerequisites

- [Cline](https://marketplace.visualstudio.com/items?itemName=saoudrizwan.claude-dev) VS Code extension installed
- Aegis installed and initialised (`aegis init`)
- At least one credential stored (`aegis vault add`)
- An agent token created (`aegis agent add --name cline-agent`)
- The agent granted access to at least one credential (`aegis agent grant --agent cline-agent --credential <name>`)

Before wiring up MCP, create a credential and grant it to the Cline agent:

```bash
# Example: GitHub PAT
aegis vault add \
  --name github-bot \
  --service github \
  --secret "ghp_xxxxxxxxxxxxxxxxxxxx" \
  --domains api.github.com

aegis agent add --name cline-agent
aegis agent grant --agent cline-agent --credential github-bot
```

> **Service naming note:** the service name you store (`--service github`) must match what Cline later sends in `aegis_proxy_request`.

## Quick Setup (Recommended)

Use `aegis mcp config` to generate the correct configuration. This is the **strongly recommended** path — it includes environment variables (`HOME`, `PATH`, `AEGIS_DATA_DIR`) that MCP hosts need but don't inherit from your shell:

```bash
# Generate Cline config (stdio transport — recommended)
aegis mcp config cline

# With an agent token
aegis mcp config cline --agent-token aegis_abc123...

# Using HTTP transport
aegis mcp config cline --transport streamable-http --port 3200
```

Copy the generated JSON into your Cline MCP settings file.

> **Important:** Do not write the config JSON by hand. Cline spawns Aegis as a child process without your shell environment. Without the `env` block that `aegis mcp config` generates, Aegis won't find your vault and will fail with path errors.

## Setup

### Step 1: Open the MCP Configuration

Cline stores MCP settings in `cline_mcp_settings.json`, managed through the Cline UI:

1. Open the Cline sidebar panel in VS Code
2. Click the **MCP Servers** icon in the top navigation
3. Select the **Configure** tab
4. Click **Configure MCP Servers**

This opens the settings file for editing.

### Step 2: Paste the Generated Config

Paste the output of `aegis mcp config cline` into this file. If you need to write it manually:

> **Warning:** You **must** include an `env` block with `HOME`, `PATH`, and `AEGIS_DATA_DIR`. Without these, the MCP server will fail.

#### Option A: stdio transport (recommended)

```json
{
  "mcpServers": {
    "aegis": {
      "command": "aegis",
      "args": [
        "mcp",
        "serve",
        "--transport",
        "stdio",
        "--agent-token",
        "aegis_your-agent-token-here"
      ],
      "env": {
        "HOME": "/Users/yourname",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "AEGIS_DATA_DIR": "/path/to/your/project/.aegis"
      },
      "disabled": false
    }
  }
}
```

> **Easier alternative:** Run `aegis mcp config cline --agent-token <token>` to generate this with the correct paths.
```

#### Option B: Streamable HTTP transport (SSE)

Start Aegis as a standalone server first:

```bash
aegis mcp serve --transport streamable-http --port 3200
```

Then configure Cline:

```json
{
  "mcpServers": {
    "aegis": {
      "url": "http://127.0.0.1:3200/mcp",
      "disabled": false
    }
  }
}
```

#### Auto-approving Aegis Tools (Optional)

If you trust Aegis tools and want to skip approval prompts for specific tools:

```json
{
  "mcpServers": {
    "aegis": {
      "command": "aegis",
      "args": [
        "mcp",
        "serve",
        "--transport",
        "stdio",
        "--agent-token",
        "aegis_your-agent-token-here"
      ],
      "alwaysAllow": [
        "aegis_health",
        "aegis_list_services"
      ],
      "disabled": false
    }
  }
}
```

> **Tip:** Start by auto-approving only read-only tools (`aegis_health`, `aegis_list_services`). Keep `aegis_proxy_request` on manual approval until you're comfortable, since it makes outbound API calls.

### Step 3: Verify the Connection

1. Open the Cline sidebar
2. Click the **MCP Servers** icon
3. You should see **aegis** listed with a green status indicator
4. Click on it to see the available tools

### Step 4: Use Aegis in Conversation

Just ask Cline to interact with your APIs:

```
You: "Check my GitHub repos using Aegis"

Cline: I'll use the Aegis proxy to list your GitHub repositories.
       [Requesting approval to use aegis_proxy_request]
       
       Service: github
       Method: GET
       Path: /user/repos

       [You click Approve]

       Here are your repositories:
       1. my-app (private, 45 stars)
       2. my-library (public, 120 stars)
       ...
```

## Available Tools

| Tool | Description |
|------|-------------|
| `aegis_proxy_request` | Make authenticated API calls through Aegis |
| `aegis_list_services` | List all services/credentials in the vault |
| `aegis_health` | Check Aegis server health |

## Let Cline Set It Up For You

One of Cline's killer features is that you can ask it to install MCP servers for you:

```
You: "Add the Aegis MCP server from https://github.com/getaegis/aegis — 
      I have it installed globally via npm as @getaegis/cli"

Cline: I'll configure the Aegis MCP server for you...
       [Creates the configuration automatically]
```

Cline will handle cloning, building, and configuring the server.

## Managing the Server

| Action | How |
|--------|-----|
| **Enable/Disable** | Toggle the switch next to "aegis" in MCP Servers |
| **Restart** | Click "Restart Server" if it becomes unresponsive |
| **Delete** | Click the trash icon (no confirmation dialog) |
| **Timeout** | Adjust network timeout (default: 1 minute, max: 1 hour) |

## Troubleshooting

### Server not responding

1. Click **MCP Servers** icon → check if aegis shows a green status
2. Try clicking **Restart Server**
3. Verify the command path: `which aegis`
4. Check if Aegis is properly initialised: `aegis doctor`

### "Agent auth required" error

Add `--agent-token` to the args:
```bash
aegis agent add --name cline-agent
# Copy the token into your cline_mcp_settings.json args
```

### Tools appear, but the request is denied

Check these in order:

1. The agent has a credential grant: `aegis agent grant --agent cline-agent --credential <name>`
2. The tool call `service` matches the credential's `--service` value exactly
3. The credential allowlist includes the outbound host
4. A policy or body-inspection rule did not block the request — inspect `aegis ledger show -n 5`

### Tool not available

1. Confirm the server is enabled (not disabled)
2. Check that the tool isn't in the `disabledTools` array
3. Restart the server

### Slow responses

1. Increase the network timeout for the aegis server
2. Check if the upstream API is slow: `curl -I https://api.github.com`
3. Check Aegis rate limits: `aegis agent list`

## Security Notes

- Cline runs the MCP server as a local process — credentials stay on your machine
- Every tool invocation requires your explicit approval (unless auto-approved)
- Agent tokens scope what credentials Cline can access
- All API calls are logged: `aegis ledger show`
- Cline never sees raw credential values — Aegis injects them at the network boundary
- The human-in-the-loop approval model pairs perfectly with Aegis's credential isolation
