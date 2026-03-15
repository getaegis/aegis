# Using Aegis with Cursor

> Connect Aegis as an MCP server so Cursor's AI agent can make authenticated API calls while keeping raw credentials out of the agent context.

## Prerequisites

- [Cursor](https://cursor.com) installed
- Aegis installed and initialised (`aegis init`)
- At least one credential stored (`aegis vault add`)
- An agent token created (`aegis agent add --name cursor-agent`)
- The agent granted access to at least one credential (`aegis agent grant --agent cursor-agent --credential <name>`)

## Quick Setup (Recommended)

Aegis can generate the configuration for you. This is the preferred path because it keeps the setup consistent with the actual CLI output:

```bash
# Generate Cursor config (stdio transport — recommended)
aegis mcp config cursor

# With an agent token
aegis mcp config cursor --agent-token aegis_abc123...

# Using HTTP transport
aegis mcp config cursor --transport streamable-http --port 3200
```

Copy the generated JSON into your Cursor MCP config file.

Before you paste it, make sure the Cursor agent can actually access a credential:

```bash
# Example: create and grant a GitHub credential
aegis vault add \
  --name github-bot \
  --service github \
  --secret "ghp_xxxxxxxxxxxxxxxxxxxx" \
  --domains api.github.com

aegis agent add --name cursor-agent
aegis agent grant --agent cursor-agent --credential github-bot
```

> **Service naming note:** the service name you store (`--service github`) must match what Cursor later sends in `aegis_proxy_request`.

## Manual Setup

### Step 1: Locate Your Config File

| Scope | Path |
|-------|------|
| **Project** | `.cursor/mcp.json` in your project root |
| **Global** | `~/.cursor/mcp.json` in your home directory |

**Project config** is recommended for team setups (commit it to source control). **Global config** makes Aegis available across all your projects.

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
      ]
    }
  }
}
```

If `aegis` is not on your PATH (e.g., installed locally), use the full path:

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
      ]
    }
  }
}
```

#### Option B: Streamable HTTP transport

Start Aegis as a standalone server first:

```bash
aegis mcp serve --transport streamable-http --port 3200
```

Then configure Cursor to connect:

```json
{
  "mcpServers": {
    "aegis": {
      "url": "http://127.0.0.1:3200/mcp"
    }
  }
}
```

#### Using Environment Variables

Cursor supports `${env:VAR}` interpolation in config values:

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
      ],
      "env": {
        "AEGIS_MASTER_KEY": "${env:AEGIS_MASTER_KEY}"
      }
    }
  }
}
```

### Step 3: Verify the Connection

1. Open a project in Cursor
2. Open the Cursor Agent (Cmd/Ctrl + I)
3. The agent will automatically detect Aegis tools when relevant
4. Or ask directly: "List my available Aegis services"

## Available Tools

| Tool | Description |
|------|-------------|
| `aegis_proxy_request` | Make authenticated API calls through Aegis |
| `aegis_list_services` | List all services/credentials in the vault |
| `aegis_health` | Check Aegis server health |

## Example Usage

```
You: "Use Aegis to create a new GitHub issue in my repo called 'Fix login bug'"

Cursor: I'll use aegis_proxy_request to create the issue.
        [Calls aegis_proxy_request: service="github", method="POST",
         path="/repos/owner/repo/issues", body={"title": "Fix login bug"}]

        ✓ Issue #47 created: "Fix login bug"
          URL: https://github.com/owner/repo/issues/47
```

## Tool Approval

By default, Cursor asks for approval before using MCP tools. You'll see a confirmation prompt with the tool name and arguments.

To enable auto-run (skip approval prompts):
1. Open Cursor Settings
2. Navigate to **Agent** → **Auto-run**
3. Enable auto-run for MCP tools

> **Note:** Only enable auto-run if you trust all configured MCP servers. Aegis only makes outbound requests to domains in your credential allowlists, so it's safe by design.

## Troubleshooting

### Server not connecting

1. Verify your config file is valid JSON
2. Check the command path: `which aegis` or `which node`
3. Ensure Aegis is built if using the dist path: `yarn build`
4. Check Cursor's MCP logs: **View** → **Output** → select **MCP** from the dropdown

### "Agent auth required" error

Add `--agent-token` to the args with a valid token:
```bash
aegis agent add --name cursor-agent
# Copy the token and add it to your mcp.json
```

### Tools appear, but the request is denied

Check these in order:

1. The agent has a credential grant: `aegis agent grant --agent cursor-agent --credential <name>`
2. The tool call `service` matches the credential's `--service` value exactly
3. The credential allowlist includes the outbound host
4. A policy or body-inspection rule did not block the request — inspect `aegis ledger show -n 5`

### Slow tool responses

If MCP tool calls are timing out:
1. Check if the upstream API is responsive
2. Try increasing Cursor's network timeout in MCP settings
3. Verify Aegis isn't rate-limiting the agent: `aegis agent list`

## Security Notes

- Cursor runs the stdio MCP server as a local process — credentials stay on your machine
- Agent tokens scope what credentials the AI can access
- All API calls are logged: `aegis ledger show`
- The AI agent never sees raw credentials — Aegis injects them at the network boundary
- Domain guard prevents credential use on unauthorized domains
