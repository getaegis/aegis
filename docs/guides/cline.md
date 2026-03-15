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

## Setup

### Step 1: Open the MCP Configuration

Cline stores MCP settings in `cline_mcp_settings.json`, managed through the Cline UI:

1. Open the Cline sidebar panel in VS Code
2. Click the **MCP Servers** icon in the top navigation
3. Select the **Configure** tab
4. Click **Configure MCP Servers**

This opens the settings file for editing.

### Step 2: Add Aegis as an MCP Server

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
      "disabled": false
    }
  }
}
```

If `aegis` is not on your PATH, use full paths:

```json
{
  "mcpServers": {
    "aegis": {
      "command": "/usr/local/bin/node",
      "args": [
        "/path/to/aegis/dist/cli.js",
        "mcp",
        "serve",
        "--transport",
        "stdio"
      ],
      "disabled": false
    }
  }
}
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
