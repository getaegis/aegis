# Using Aegis with Windsurf

> Connect Aegis as an MCP server so Windsurf's Cascade agent can make authenticated API calls while keeping raw credentials out of the agent context.

> **Verification note:** This guide reflects Windsurf MCP behavior and UI labels verified against public documentation in March 2026. Re-check the current MCP docs if the UI has moved.

## Prerequisites

- [Windsurf](https://windsurf.com) IDE installed
- Aegis installed and initialised (`aegis init`)
- At least one credential stored (`aegis vault add`)
- An agent token created (`aegis agent add --name windsurf-cascade`)
- The agent granted access to at least one credential (`aegis agent grant --agent windsurf-cascade --credential <name>`)

Before wiring up MCP, create a credential and grant it to the Windsurf agent:

```bash
# Example: Slack bot token
aegis vault add \
  --name slack-bot \
  --service slack \
  --secret "xoxb-your-bot-token-here" \
  --domains slack.com

aegis agent add --name windsurf-cascade
aegis agent grant --agent windsurf-cascade --credential slack-bot
```

> **Service naming note:** the service name you store (`--service slack`) must match what Cascade later sends in `aegis_proxy_request`.

## Quick Setup (Recommended)

Use `aegis mcp config` to generate the correct configuration. This is the **strongly recommended** path — it includes environment variables (`HOME`, `PATH`, `AEGIS_DATA_DIR`) that MCP hosts need but don't inherit from your shell:

```bash
# Generate Windsurf config (stdio transport — recommended)
aegis mcp config windsurf

# With an agent token
aegis mcp config windsurf --agent-token aegis_abc123...

# Using HTTP transport
aegis mcp config windsurf --transport streamable-http --port 3200
```

Copy the generated JSON into your Windsurf MCP config file.

> **Important:** Do not write the config JSON by hand. Windsurf spawns Aegis as a child process without your shell environment. Without the `env` block that `aegis mcp config` generates, Aegis won't find your vault and will fail with path errors.

## Manual Setup

### Step 1: Open the MCP Config File

Windsurf stores MCP configuration in:

```
~/.codeium/windsurf/mcp_config.json
```

You can access it through the Windsurf UI:
1. Click the **MCPs** icon in the top-right of the Cascade panel
2. Or go to **Windsurf Settings** → **Cascade** → **MCP Servers**
3. Edit the raw `mcp_config.json` file

### Step 2: Paste the Generated Config

Paste the output of `aegis mcp config windsurf` into this file. If you need to write it manually:

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
      }
    }
  }
}
```

> **Easier alternative:** Run `aegis mcp config windsurf --agent-token <token>` to generate this with the correct paths.
```

#### Option B: Streamable HTTP transport

Start Aegis as a standalone server first:

```bash
aegis mcp serve --transport streamable-http --port 3200
```

Then configure Windsurf:

```json
{
  "mcpServers": {
    "aegis": {
      "serverUrl": "http://127.0.0.1:3200/mcp"
    }
  }
}
```

> **Note:** Windsurf uses `serverUrl` (not `url`) for HTTP-based MCP servers.

#### Using Environment Variables

Windsurf supports `${env:VAR}` interpolation in `command`, `args`, `env`, `serverUrl`, `url`, and `headers` fields:

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
        "${env:AEGIS_AGENT_TOKEN}"
      ]
    }
  }
}
```

### Step 3: Enable the Server

1. Click the **MCPs** icon in the Cascade panel
2. Find **aegis** in the server list
3. Toggle it on
4. Cascade will now have access to Aegis tools

### Step 4: Configure Tool Access (Optional)

Windsurf has a limit of 100 total tools across all MCP servers. You can toggle individual tools:

1. Click **MCPs** icon → click on **aegis**
2. Toggle specific tools on/off as needed

## Available Tools

| Tool | Description |
|------|-------------|
| `aegis_proxy_request` | Make authenticated API calls through Aegis |
| `aegis_list_services` | List all services/credentials in the vault |
| `aegis_health` | Check Aegis server health |

## Example Usage

```
You: "Use Aegis to post a message to the #general Slack channel saying 'Deploy complete'"

Cascade: I'll use Aegis to send the Slack message.
         [Uses aegis_proxy_request: service="slack", method="POST",
          path="/api/chat.postMessage",
          body={"channel": "general", "text": "Deploy complete"}]

         ✓ Message posted to #general: "Deploy complete"
```

## Troubleshooting

### Server not appearing

1. Verify `~/.codeium/windsurf/mcp_config.json` is valid JSON
2. Check the command path: `which aegis` or `which node`
3. Restart Windsurf after editing the config
4. Look for errors in the MCP server status indicator

### "Agent auth required" error

Add `--agent-token` to the args:
```bash
aegis agent add --name windsurf-cascade
# Copy the token into your mcp_config.json args
```

### Tools appear, but the request is denied

Check these in order:

1. The agent has a credential grant: `aegis agent grant --agent windsurf-cascade --credential <name>`
2. The tool call `service` matches the credential's `--service` value exactly
3. The credential allowlist includes the outbound host
4. A policy or body-inspection rule did not block the request — inspect `aegis ledger show -n 5`

### Server becomes unresponsive

1. Click **MCPs** icon
2. Find **aegis** and click **Restart Server**

### Tool calls failing

1. Ensure Aegis has credentials stored: `aegis vault list`
2. Check agent grants: `aegis agent list`
3. Verify the upstream API is reachable
4. Check the Aegis audit log: `aegis ledger show`

## Teams & Enterprise

If your team admin has enabled MCP whitelisting:
- The server ID (`aegis`) must match the whitelist entry exactly (case-sensitive)
- Environment variables (`env` section) are not regex-matched and can be configured freely
- Ask your admin to whitelist the `aegis` server with appropriate command patterns

## Security Notes

- Windsurf runs the stdio MCP server as a local process — credentials stay on your machine
- Agent tokens scope what credentials Cascade can access
- All API calls are logged: `aegis ledger show`
- Cascade never sees raw credential values — Aegis injects them at the network boundary
- Domain guard prevents credential misuse even if the agent tries unexpected domains
