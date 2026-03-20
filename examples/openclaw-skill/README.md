# Aegis Skill for OpenClaw

An [OpenClaw](https://openclaw.ai) skill that teaches your AI agent to route all API calls through the [Aegis](https://github.com/getaegis/aegis) credential proxy.

## What It Does

When this skill is active, your OpenClaw agent routes external API calls through `http://localhost:3100` instead of calling APIs directly. Aegis injects real credentials at the network boundary — the agent never sees your raw API keys.

## Why

OpenClaw skills inject API keys into `process.env`, which means:
- The LLM can access them via shell commands (`echo $GITHUB_TOKEN`)
- A malicious skill could read and exfiltrate them
- Cross-tool hijacking (tool description poisoning) could leverage them

With Aegis, your real API keys live in an encrypted vault. The agent only gets a scoped agent token that can't be used to extract real credentials.

## Install

### Option 1: Copy directly

```bash
cp -r aegis ~/.openclaw/skills/
```

### Option 2: Into a workspace

```bash
cp -r aegis /path/to/your/workspace/skills/
```

## Configure

Add the Aegis agent token to `~/.openclaw/openclaw.json`:

```json
{
  "skills": {
    "entries": {
      "aegis": {
        "enabled": true,
        "env": {
          "AEGIS_AGENT_TOKEN": "aegis_your-token-here"
        }
      }
    }
  }
}
```

## Prerequisites

1. [Aegis CLI](https://github.com/getaegis/aegis) installed (`npm i -g @getaegis/cli` or `brew install getaegis/aegis/aegis`)
2. Aegis initialised (`aegis init`)
3. Credentials stored (`aegis vault add ...`)
4. Agent created and granted credentials:
   ```bash
   aegis agent add --name openclaw
   aegis agent grant --agent openclaw --credential github
   ```
5. Aegis Gate running (`aegis gate`)

## Full Guide

See [Using Aegis with OpenClaw](https://github.com/getaegis/aegis/blob/master/docs/guides/openclaw.md) for the complete setup walkthrough.

## License

Apache-2.0 — same as Aegis
