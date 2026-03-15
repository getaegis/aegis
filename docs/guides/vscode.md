# Using Aegis with VS Code (GitHub Copilot)

> Connect Aegis as an MCP server so GitHub Copilot in VS Code can make authenticated API calls while keeping raw credentials out of the agent context.

## Prerequisites

- [VS Code](https://code.visualstudio.com) with GitHub Copilot enabled
- Aegis installed and initialised (`aegis init`)
- At least one credential stored (`aegis vault add`)
- An agent token created (`aegis agent add --name vscode-copilot`)
- The agent granted access to at least one credential (`aegis agent grant --agent vscode-copilot --credential <name>`)

## Quick Setup (Recommended)

Aegis can generate the configuration for you. This is the preferred path because it keeps the setup consistent with the actual CLI output:

```bash
# Generate VS Code config (stdio transport — recommended)
aegis mcp config vscode

# With an agent token
aegis mcp config vscode --agent-token aegis_abc123...

# Using HTTP transport
aegis mcp config vscode --transport streamable-http --port 3200
```

Copy the generated JSON into your VS Code MCP configuration.

Before you paste it, make sure the VS Code agent can actually access a credential:

```bash
# Example: create and grant a Stripe credential
aegis vault add \
  --name stripe-key \
  --service stripe \
  --secret "sk_test_xxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  --domains api.stripe.com \
  --auth-type basic

aegis agent add --name vscode-copilot
aegis agent grant --agent vscode-copilot --credential stripe-key
```

> **Service naming note:** the service name you store (`--service stripe`) must match what Copilot later sends in `aegis_proxy_request`.

## Manual Setup

### Step 1: Choose Your Config Location

The built-in config generator currently prints VS Code configuration for `settings.json` under the `mcp` section. Use that as the canonical setup path so your generated output and your docs match.

| Scope | Path | Use Case |
|-------|------|----------|
| **Workspace** | `.vscode/settings.json` in your project | Per-project, shareable via source control |
| **User profile** | Run `Preferences: Open User Settings (JSON)` from Command Palette | Available across all workspaces |

> **Note:** VS Code's MCP config uses the `servers` key (not `mcpServers` like Claude/Cursor). If you use `aegis mcp config vscode`, paste the generated JSON into the `mcp` section of your settings file.

### Step 2: Add Aegis as an MCP Server

Open or create `.vscode/settings.json` in your project root, then add an `mcp` section:

#### Option A: stdio transport (recommended)

```json
{
  "mcp": {
    "servers": {
      "aegis": {
        "type": "stdio",
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
}
```

If `aegis` is not on your PATH, use full paths:

```json
{
  "mcp": {
    "servers": {
      "aegis": {
        "type": "stdio",
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
}
```

#### Option B: Streamable HTTP transport

Start Aegis as a standalone server first:

```bash
aegis mcp serve --transport streamable-http --port 3200
```

Then configure VS Code:

```json
{
  "mcp": {
    "servers": {
      "aegis": {
        "type": "http",
        "url": "http://127.0.0.1:3200/mcp"
      }
    }
  }
}
```

### Step 3: Trust and Start the Server

1. Open the Command Palette (⇧⌘P / Ctrl+Shift+P)
2. Run `MCP: List Servers`
3. Select **aegis** and choose **Start Server**
4. When prompted, confirm that you trust the server

VS Code will show a trust dialog the first time. Click **Start** to confirm.

### Step 4: Use Aegis Tools in Chat

1. Open the Chat view (⌃⌘I / Ctrl+Alt+I)
2. Ask Copilot to use Aegis tools naturally
3. You'll see tool invocations in the chat — approve each one

## Available Tools

| Tool | Description |
|------|-------------|
| `aegis_proxy_request` | Make authenticated API calls through Aegis |
| `aegis_list_services` | List all services/credentials in the vault |
| `aegis_health` | Check Aegis server health |

You can toggle specific tools on/off:
1. Click the **Configure Tools** button in the chat input
2. Find the Aegis tools and toggle as needed

## Example Usage

```
You: "Use Aegis to check the status of my Stripe account"

Copilot: I'll use the Aegis proxy to query your Stripe account.
         [Uses aegis_proxy_request: service="stripe", method="GET", path="/v1/account"]

         Your Stripe account is active:
         - Business name: My Company
         - Country: US
         - Default currency: USD
```

## Sandboxing (Optional, macOS/Linux)

VS Code supports sandboxing for MCP servers to restrict file system and network access:

```json
{
  "mcp": {
    "servers": {
      "aegis": {
        "type": "stdio",
        "command": "aegis",
        "args": ["mcp", "serve", "--transport", "stdio"],
        "sandboxEnabled": true,
        "sandbox": {
          "network": {
            "allowedDomains": [
              "api.github.com",
              "api.stripe.com",
              "slack.com"
            ]
          }
        }
      }
    }
  }
}
```

> **Note:** When sandboxing is enabled, tool calls are auto-approved because they run in a controlled environment. This pairs well with Aegis's own domain guard for defense in depth.

## Troubleshooting

### Server not starting

1. Open Command Palette → `MCP: List Servers` → select **aegis** → **Show Output**
2. Check if the command path is correct: `which aegis`
3. Ensure Aegis is built: `cd /path/to/aegis && yarn build`
4. Verify the JSON syntax in `.vscode/settings.json`

### Tools not appearing

1. Ensure the server is running (check the MCP server indicator)
2. Click **Configure Tools** in the chat input to see available tools
3. Restart the server: Command Palette → `MCP: List Servers` → **aegis** → **Restart**

### "Agent auth required" error

Add an `--agent-token` argument:
```bash
aegis agent add --name vscode-copilot
# Add the token to your settings.json mcp args
```

### Tools appear, but the request is denied

Check these in order:

1. The agent has a credential grant: `aegis agent grant --agent vscode-copilot --credential <name>`
2. The tool call `service` matches the credential's `--service` value exactly
3. The credential allowlist includes the outbound host
4. A policy or body-inspection rule did not block the request — inspect `aegis ledger show -n 5`

### Config not loading

- If using workspace config, ensure the file is at `.vscode/settings.json`
- VS Code provides IntelliSense in the config file — look for red underlines
- Run `Preferences: Open Workspace Settings (JSON)` to open the correct file

## Security Notes

- VS Code runs the MCP server as a local child process — credentials never leave your machine
- Agent tokens scope what credentials Copilot can access
- All API calls are logged in the audit ledger: `aegis ledger show`
- Copilot never sees raw credential values — Aegis injects them at the network boundary
- VS Code sandbox + Aegis domain guard = defense in depth
