/**
 * MCP commands: serve, config.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Command } from 'commander';
import { AgentRegistry } from '../../agent/index.js';
import { findConfigFile, getConfig } from '../../config.js';
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
    .argument('<host>', 'Target host: "claude", "cursor", "vscode", "cline", or "windsurf"')
    .option('--transport <type>', 'Transport type (default: stdio)', 'stdio')
    .option('--port <port>', 'Port for streamable-http transport (default: 3200)', '3200')
    .option('--agent-token <token>', 'Agent token to include in the configuration')
    .action((host: string, opts: { transport: string; port: string; agentToken?: string }) => {
      const transport = opts.transport;
      const port = opts.port;

      // Resolve the aegis CLI path relative to this module's own location
      // (not CWD). This module lives at src/cli/commands/mcp.ts and compiles
      // to dist/cli/commands/mcp.js — package root is three levels up.
      const currentFile = fileURLToPath(import.meta.url);
      const packageRoot = path.resolve(path.dirname(currentFile), '..', '..', '..');

      let aegisCmd: string;
      let aegisBaseArgs: string[];

      const distCli = path.join(packageRoot, 'dist', 'cli.js');
      const srcCli = path.join(packageRoot, 'src', 'cli.ts');

      if (fs.existsSync(distCli)) {
        // Use node + absolute path to the built CLI (always stable)
        aegisCmd = process.execPath;
        aegisBaseArgs = [distCli];
      } else if (fs.existsSync(srcCli)) {
        // Development fallback: use tsx
        aegisCmd = 'npx';
        aegisBaseArgs = ['tsx', srcCli];
      } else {
        // Last resort: reuse however we were invoked
        aegisCmd = process.execPath;
        aegisBaseArgs = [path.resolve(process.argv[1])];
      }

      // Build environment block for stdio configs.
      // MCP hosts (Claude Desktop, Cursor) don't inherit the user's shell
      // environment, so we must pass variables the Aegis process needs.
      const stdioEnv: Record<string, string> = {
        HOME: os.homedir(),
        PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin',
      };

      // Capture data directory so the MCP server finds the right vault
      // even when spawned from an unpredictable CWD.
      const cfgFile = findConfigFile();
      const baseDir = cfgFile ? path.dirname(path.resolve(cfgFile)) : process.cwd();
      stdioEnv.AEGIS_DATA_DIR = path.resolve(baseDir, '.aegis');

      // Forward master key if set in the current environment
      if (process.env.AEGIS_MASTER_KEY) {
        stdioEnv.AEGIS_MASTER_KEY = process.env.AEGIS_MASTER_KEY;
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

      // ── Host definitions ──
      // Each host defines its config file hint and how to build the JSON block.
      // VS Code uses "servers" with a "type" field; all others use "mcpServers".
      // Cline adds "disabled: false".
      interface HostDef {
        fileHint: string;
        wrapperKey: 'mcpServers' | 'servers';
        extraFields?: Record<string, unknown>;
        stdioType?: string; // VS Code needs type: "stdio" / "http"
      }

      const hosts: Record<string, HostDef> = {
        claude: {
          fileHint: 'Claude Desktop config (claude_desktop_config.json)',
          wrapperKey: 'mcpServers',
        },
        cursor: {
          fileHint: 'Cursor MCP config (.cursor/mcp.json)',
          wrapperKey: 'mcpServers',
        },
        vscode: {
          fileHint: 'VS Code settings (settings.json) under "mcp"',
          wrapperKey: 'servers',
          stdioType: 'stdio',
        },
        cline: {
          fileHint: 'Cline MCP settings (cline_mcp_settings.json)',
          wrapperKey: 'mcpServers',
          extraFields: { disabled: false },
        },
        windsurf: {
          fileHint: 'Windsurf MCP config (~/.codeium/windsurf/mcp_config.json)',
          wrapperKey: 'mcpServers',
        },
      };

      const hostDef = hosts[host.toLowerCase()];
      if (!hostDef) {
        console.error(`Unknown host: ${host}. Supported hosts: ${Object.keys(hosts).join(', ')}`);
        process.exit(1);
      }

      let serverEntry: Record<string, unknown>;
      if (transport === 'streamable-http') {
        serverEntry = {
          ...(hostDef.stdioType ? { type: 'http' } : {}),
          url: `http://127.0.0.1:${port}/mcp`,
          ...hostDef.extraFields,
        };
      } else {
        serverEntry = {
          ...(hostDef.stdioType ? { type: hostDef.stdioType } : {}),
          command: aegisCmd,
          args,
          env: stdioEnv,
          ...hostDef.extraFields,
        };
      }

      const config = {
        [hostDef.wrapperKey]: {
          aegis: serverEntry,
        },
      };

      console.log(`Add this to your ${hostDef.fileHint}:`);
      console.log();
      console.log(JSON.stringify(config, null, 2));
    });
}
