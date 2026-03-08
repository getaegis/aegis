/**
 * MCP commands: serve, config.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Command } from 'commander';
import { AgentRegistry } from '../../agent/index.js';
import { getConfig } from '../../config.js';
import { getDb, getVaultSalt, migrate } from '../../db.js';
import { Ledger } from '../../ledger/index.js';
import { AegisMcpServer } from '../../mcp/index.js';
import type { PolicyValidationResult } from '../../policy/index.js';
import { loadPoliciesFromDirectory } from '../../policy/index.js';
import { deriveKey, Vault } from '../../vault/index.js';
import { WebhookManager } from '../../webhook/index.js';
import { requireUserAuth } from '../auth.js';
import {
  VALID_LOG_LEVELS,
  VALID_MCP_TRANSPORTS,
  validateEnum,
  validatePort,
} from '../validation.js';

export function register(program: Command): void {
  const mcpCmd = program.command('mcp').description('Run Aegis as an MCP server');

  mcpCmd
    .command('serve')
    .description('Start the Aegis MCP server')
    .option('--transport <type>', 'Transport type: "stdio" or "streamable-http"')
    .option('--port <port>', 'Port for streamable-http transport')
    .option('--agent-token <token>', 'Agent token to authenticate this MCP session')
    .option('--policies-dir <dir>', 'Directory containing YAML policy files')
    .option('--policy-mode <mode>', 'Policy enforcement mode: "enforce" or "dry-run"')
    .option('--log-level <level>', 'Log level: debug, info, warn, error')
    .action(
      async (opts: {
        transport?: string;
        port?: string;
        agentToken?: string;
        policiesDir?: string;
        policyMode?: string;
        logLevel?: string;
      }) => {
        // ── Validate CLI flags ──
        if (opts.port) {
          const p = Number.parseInt(opts.port, 10);
          validatePort(p, 'MCP port');
        }
        if (opts.transport) {
          validateEnum(opts.transport, VALID_MCP_TRANSPORTS, 'transport');
        }
        if (opts.policyMode) {
          validateEnum(opts.policyMode, ['enforce', 'dry-run'] as const, 'policy mode');
        }
        if (opts.logLevel) {
          validateEnum(opts.logLevel, VALID_LOG_LEVELS, 'log level');
        }
        if (opts.policiesDir && !fs.existsSync(path.resolve(opts.policiesDir))) {
          console.error(
            `\n✗ Policy directory not found: ${path.resolve(opts.policiesDir)}\n  Create it and add YAML policy files, or omit --policies-dir\n`,
          );
          process.exit(1);
        }

        const config = getConfig();
        const db = getDb(config);
        migrate(db);

        const mcpKey = deriveKey(config.masterKey, getVaultSalt(config));
        requireUserAuth(db, mcpKey, 'gate:start');

        const vault = new Vault(db, config.masterKey, getVaultSalt(config));
        const ledger = new Ledger(db);
        const agentRegistry = new AgentRegistry(db, mcpKey);

        // Resolve policies: CLI flags → config file
        const policyDir = opts.policiesDir ?? config.policiesDir;
        let policies: PolicyValidationResult[] = [];
        if (policyDir) {
          policies = loadPoliciesFromDirectory(policyDir);
        }

        // Resolve transport: CLI → config file → default (stdio)
        const transportOpt = opts.transport ?? config.mcp.transport;
        const transport =
          transportOpt === 'streamable-http' ? ('streamable-http' as const) : ('stdio' as const);

        // Resolve port: CLI → config file → default (3200)
        const mcpPort = opts.port ? Number.parseInt(opts.port, 10) : config.mcp.port;

        // Resolve policy mode: CLI → config file → default (enforce)
        const effectivePolicyMode =
          opts.policyMode ?? (config.policyMode === 'off' ? 'enforce' : config.policyMode);

        // Resolve log level: CLI → config file → default (info)
        const effectiveLogLevel = (opts.logLevel ?? config.logLevel) as
          | 'debug'
          | 'info'
          | 'warn'
          | 'error';

        const webhookManager = new WebhookManager({ db, logLevel: config.logLevel });

        const mcpServer = new AegisMcpServer({
          vault,
          ledger,
          agentRegistry,
          agentToken: opts.agentToken,
          transport,
          port: mcpPort,
          policies,
          policyMode: effectivePolicyMode === 'dry-run' ? 'dry-run' : 'enforce',
          logLevel: effectiveLogLevel,
          webhooks: webhookManager,
        });

        await mcpServer.start();

        // Handle graceful shutdown
        const shutdown = async (): Promise<void> => {
          await mcpServer.stop();
          db.close();
          process.exit(0);
        };

        process.on('SIGINT', shutdown);
        process.on('SIGTERM', shutdown);
      },
    );

  mcpCmd
    .command('config')
    .description('Generate MCP client configuration for popular hosts')
    .argument('<host>', 'Target host: "claude", "cursor", or "vscode"')
    .option('--transport <type>', 'Transport type (default: stdio)', 'stdio')
    .option('--port <port>', 'Port for streamable-http transport (default: 3200)', '3200')
    .option('--agent-token <token>', 'Agent token to include in the configuration')
    .action((host: string, opts: { transport: string; port: string; agentToken?: string }) => {
      const transport = opts.transport;
      const port = opts.port;

      // Resolve the aegis CLI path.
      // Prefer the built dist/cli.js with an absolute node path — this is stable
      // across shell sessions (unlike `which aegis` which may resolve to an
      // ephemeral fnm/nvm multishell path that disappears when the terminal closes).
      let aegisCmd: string;
      let aegisBaseArgs: string[];

      const distCli = path.resolve('dist/cli.js');
      if (fs.existsSync(distCli)) {
        // Use node + absolute path to the built CLI (always stable)
        aegisCmd = process.execPath; // absolute path to the current node binary
        aegisBaseArgs = [distCli];
      } else {
        // Development fallback: use tsx
        const cliPath = path.resolve('src/cli.ts');
        aegisCmd = 'npx';
        aegisBaseArgs = ['tsx', cliPath];
      }

      const buildArgs = (): string[] => {
        const args = [...aegisBaseArgs, 'mcp', 'serve', '--transport', transport];
        if (transport === 'streamable-http') {
          args.push('--port', port);
        }
        if (opts.agentToken) {
          args.push('--agent-token', opts.agentToken);
        }
        return args;
      };

      const args = buildArgs();

      switch (host.toLowerCase()) {
        case 'claude': {
          if (transport === 'streamable-http') {
            const config = {
              mcpServers: {
                aegis: {
                  url: `http://127.0.0.1:${port}/mcp`,
                },
              },
            };
            console.log('Add this to your Claude Desktop config (claude_desktop_config.json):');
            console.log();
            console.log(JSON.stringify(config, null, 2));
          } else {
            const config = {
              mcpServers: {
                aegis: {
                  command: aegisCmd,
                  args,
                },
              },
            };
            console.log('Add this to your Claude Desktop config (claude_desktop_config.json):');
            console.log();
            console.log(JSON.stringify(config, null, 2));
          }
          break;
        }
        case 'cursor': {
          if (transport === 'streamable-http') {
            const config = {
              mcpServers: {
                aegis: {
                  url: `http://127.0.0.1:${port}/mcp`,
                },
              },
            };
            console.log('Add this to your Cursor MCP config (.cursor/mcp.json):');
            console.log();
            console.log(JSON.stringify(config, null, 2));
          } else {
            const config = {
              mcpServers: {
                aegis: {
                  command: aegisCmd,
                  args,
                },
              },
            };
            console.log('Add this to your Cursor MCP config (.cursor/mcp.json):');
            console.log();
            console.log(JSON.stringify(config, null, 2));
          }
          break;
        }
        case 'vscode': {
          if (transport === 'streamable-http') {
            const config = {
              servers: {
                aegis: {
                  type: 'http',
                  url: `http://127.0.0.1:${port}/mcp`,
                },
              },
            };
            console.log('Add this to your VS Code settings (settings.json) under "mcp":');
            console.log();
            console.log(JSON.stringify(config, null, 2));
          } else {
            const config = {
              servers: {
                aegis: {
                  type: 'stdio',
                  command: aegisCmd,
                  args,
                },
              },
            };
            console.log('Add this to your VS Code settings (settings.json) under "mcp":');
            console.log();
            console.log(JSON.stringify(config, null, 2));
          }
          break;
        }
        default:
          console.error(`Unknown host: ${host}. Supported hosts: claude, cursor, vscode`);
          process.exit(1);
      }
    });
}
