/**
 * Config commands: validate, show.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Command } from 'commander';
import { findConfigFile, getConfig, parseConfigFile, validateConfigFile } from '../../config.js';

export function register(program: Command): void {
  const configCmd = program.command('config').description('Manage Aegis configuration');

  configCmd
    .command('validate')
    .description('Validate an aegis.config.yaml file')
    .option('--file <path>', 'Path to config file (default: auto-detect aegis.config.yaml)')
    .action((opts: { file?: string }) => {
      // Find config file
      const configFilePath = opts.file ?? findConfigFile();
      if (!configFilePath) {
        console.error(
          '\n  ✗ No aegis.config.yaml found in the current directory.\n  Create one with: aegis init\n',
        );
        process.exit(1);
      }

      const resolvedPath = path.resolve(configFilePath);
      if (!fs.existsSync(resolvedPath)) {
        console.error(`\n  ✗ Config file not found: ${resolvedPath}\n`);
        process.exit(1);
      }

      console.log(`\n  Validating: ${resolvedPath}\n`);

      // Parse the file
      let parsed: ReturnType<typeof parseConfigFile>;
      try {
        parsed = parseConfigFile(resolvedPath);
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`  ✗ Failed to parse YAML: ${message}\n`);
        process.exit(1);
        return; // unreachable but helps TS
      }

      // Validate the parsed config
      const errors = validateConfigFile(parsed);

      if (errors.length === 0) {
        console.log('  ✓ Configuration is valid.\n');

        // Show a summary of resolved values
        const config = getConfig();
        console.log('  Resolved configuration:');
        console.log(`    Gate port:       ${config.port}`);
        console.log(`    Vault name:      ${config.vaultName}`);
        console.log(`    Data directory:  ${config.dataDir}`);
        console.log(`    Log level:       ${config.logLevel}`);
        console.log(`    Log format:      ${config.logFormat}`);
        console.log(`    Metrics:         ${config.metricsEnabled ? 'enabled' : 'disabled'}`);
        console.log(`    Agent auth:      ${config.requireAgentAuth ? 'required' : 'optional'}`);
        console.log(`    TLS:             ${config.tls ? 'enabled' : 'disabled'}`);
        console.log(`    Policy mode:     ${config.policyMode}`);
        if (config.policiesDir) {
          console.log(`    Policies dir:    ${config.policiesDir}`);
        }
        console.log(
          `    Dashboard:       ${config.dashboard.enabled ? `enabled (port ${config.dashboard.port})` : 'disabled'}`,
        );
        console.log(`    MCP transport:   ${config.mcp.transport}`);
        if (config.mcp.transport === 'streamable-http') {
          console.log(`    MCP port:        ${config.mcp.port}`);
        }
        if (config.webhooks.length > 0) {
          console.log(`    Webhooks:        ${config.webhooks.length} configured`);
        }
        console.log();
      } else {
        console.log(`  ✗ ${errors.length} validation error(s) found:\n`);
        for (const error of errors) {
          console.log(`    • ${error.path}: ${error.message}`);
        }
        console.log();
        process.exit(1);
      }
    });

  configCmd
    .command('show')
    .description('Show the resolved configuration (all sources merged)')
    .action(() => {
      const config = getConfig();

      console.log(`\n  Aegis Configuration\n`);
      if (config.configFilePath) {
        console.log(`  Source: ${config.configFilePath}`);
      } else {
        console.log('  Source: defaults + environment variables (no config file found)');
      }
      console.log();
      console.log(`  gate:`);
      console.log(`    port:               ${config.port}`);
      console.log(`    require_agent_auth: ${config.requireAgentAuth}`);
      if (config.tls) {
        console.log(`    tls:`);
        console.log(`      cert: ${config.tls.cert}`);
        console.log(`      key:  ${config.tls.key}`);
      }
      console.log(`  vault:`);
      console.log(`    name:     ${config.vaultName}`);
      console.log(`    data_dir: ${config.dataDir}`);
      console.log(`    master_key: ${config.masterKey ? '********' : '(not set)'}`);
      console.log(`  observability:`);
      console.log(`    log_level:  ${config.logLevel}`);
      console.log(`    log_format: ${config.logFormat}`);
      console.log(`    metrics:    ${config.metricsEnabled}`);
      console.log(`    dashboard:`);
      console.log(`      enabled: ${config.dashboard.enabled}`);
      console.log(`      port:    ${config.dashboard.port}`);
      if (config.policiesDir) {
        console.log(`  policies:`);
        console.log(`    dir:  ${config.policiesDir}`);
        console.log(`    mode: ${config.policyMode}`);
      }
      console.log(`  mcp:`);
      console.log(`    transport: ${config.mcp.transport}`);
      console.log(`    port:      ${config.mcp.port}`);
      if (config.webhooks.length > 0) {
        console.log(`  webhooks:`);
        for (const wh of config.webhooks) {
          console.log(`    - url: ${wh.url}`);
          console.log(`      events: [${wh.events.join(', ')}]`);
        }
      }
      console.log();
    });
}
