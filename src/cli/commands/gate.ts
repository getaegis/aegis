/**
 * Gate command: start the Aegis Gate proxy.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Command } from 'commander';
import { AgentRegistry } from '../../agent/index.js';
import { getConfig } from '../../config.js';
import { getDb, getVaultSalt, migrate } from '../../db.js';
import { Gate } from '../../gate/index.js';
import { Ledger } from '../../ledger/index.js';
import { AegisMetrics } from '../../metrics/index.js';
import { deriveKey, Vault } from '../../vault/index.js';
import { VERSION } from '../../version.js';
import { WebhookManager } from '../../webhook/index.js';
import { requireUserAuth } from '../auth.js';
import { VALID_POLICY_MODES, validateEnum, validatePort } from '../validation.js';

export function register(program: Command): void {
  program
    .command('gate')
    .description('Start the Aegis Gate proxy')
    .option('-p, --port <port>', 'Port to listen on')
    .option('--tls', 'Enable TLS (HTTPS) on Gate')
    .option('--cert <path>', 'Path to TLS certificate file (PEM)')
    .option('--key <path>', 'Path to TLS private key file (PEM)')
    .option(
      '--no-agent-auth',
      'Disable agent authentication (allows any localhost process to use credentials)',
    )
    .option('--policies-dir <path>', 'Directory containing YAML policy files')
    .option('--policy-mode <mode>', 'Policy enforcement mode: enforce, dry-run, or off')
    .action(
      async (opts: {
        port?: string;
        tls?: boolean;
        cert?: string;
        key?: string;
        agentAuth?: boolean;
        policiesDir?: string;
        policyMode?: string;
      }) => {
        // ── Validate CLI flags ──
        if (opts.port) {
          const p = Number.parseInt(opts.port, 10);
          validatePort(p, 'gate port');
        }
        if (opts.policyMode) {
          validateEnum(opts.policyMode, VALID_POLICY_MODES, 'policy mode');
        }

        let config: ReturnType<typeof getConfig>;
        try {
          config = getConfig();
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          console.error(`\n✗ ${msg}\n`);
          process.exit(1);
        }
        const port = opts.port ? Number.parseInt(opts.port, 10) : config.port;

        let db: ReturnType<typeof getDb>;
        try {
          db = getDb(config);
          migrate(db);
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          console.error(`\n✗ Cannot open database: ${msg}\n`);
          process.exit(1);
        }

        if (!config.masterKey) {
          console.error(
            '\n✗ AEGIS_MASTER_KEY is not set.\n  Run `aegis init` to generate a config and master key.\n',
          );
          process.exit(1);
        }

        const key = deriveKey(config.masterKey, getVaultSalt(config));
        requireUserAuth(db, key, 'gate:start');

        const vaultInstance = new Vault(db, config.masterKey, getVaultSalt(config));
        const ledger = new Ledger(db);

        // Resolve TLS: CLI flags → config file
        const useTls = opts.tls ?? !!config.tls;
        let tlsConfig: { certPath: string; keyPath: string } | undefined;
        if (useTls) {
          const certPath =
            opts.cert ?? config.tls?.cert ?? path.join(process.cwd(), 'certs', 'aegis.crt');
          const keyPath =
            opts.key ?? config.tls?.key ?? path.join(process.cwd(), 'certs', 'aegis.key');

          if (!fs.existsSync(certPath)) {
            console.error(
              `\n✗ TLS certificate not found at ${certPath}\n  Generate one with: aegis init --generate-cert\n  Or specify a path: aegis gate --tls --cert /path/to/cert.pem --key /path/to/key.pem\n`,
            );
            process.exit(1);
          }
          if (!fs.existsSync(keyPath)) {
            console.error(
              `\n✗ TLS private key not found at ${keyPath}\n  Generate one with: aegis init --generate-cert\n  Or specify a path: aegis gate --tls --cert /path/to/cert.pem --key /path/to/key.pem\n`,
            );
            process.exit(1);
          }

          tlsConfig = { certPath, keyPath };
        }

        const registry = new AgentRegistry(db, key);

        // Resolve policy: CLI flags → config file
        const effectiveRequireAgentAuth =
          opts.agentAuth !== undefined ? opts.agentAuth : config.requireAgentAuth;
        const effectivePolicyMode =
          (opts.policyMode as 'enforce' | 'dry-run' | undefined) ??
          (config.policyMode === 'off' ? undefined : (config.policyMode as 'enforce' | 'dry-run'));
        const policyDir = opts.policiesDir
          ? path.resolve(opts.policiesDir)
          : config.policiesDir
            ? path.resolve(config.policiesDir)
            : undefined;

        if (policyDir && !fs.existsSync(policyDir)) {
          console.error(
            `\n✗ Policy directory not found at ${policyDir}\n  Create it and add YAML policy files, or omit --policies-dir\n`,
          );
          process.exit(1);
        }

        const webhookManager = new WebhookManager({ db, logLevel: config.logLevel });

        // Metrics: create instance if enabled in config
        const metrics = config.metricsEnabled
          ? new AegisMetrics({ vault: vaultInstance })
          : undefined;

        const gate = new Gate({
          port,
          vault: vaultInstance,
          ledger,
          logLevel: config.logLevel,
          tls: tlsConfig,
          agentRegistry: registry,
          requireAgentAuth: effectiveRequireAgentAuth,
          policyDir,
          policyMode: effectivePolicyMode,
          webhooks: webhookManager,
          metrics,
          maxBodySize: config.maxBodySize,
          requestTimeout: config.requestTimeout,
          maxConnectionsPerAgent: config.maxConnectionsPerAgent,
        });

        const protocol = tlsConfig ? 'https' : 'http';

        console.log(`\n  ╔══════════════════════════════════╗`);
        console.log(`  ║         Aegis Gate ${VERSION.padEnd(13)}║`);
        console.log(`  ╚══════════════════════════════════╝\n`);

        if (tlsConfig) {
          console.log('  🔒 TLS enabled\n');
        } else {
          console.log(
            '  ⚠  Running without TLS — credentials are transmitted in cleartext on localhost\n',
          );
          console.log(
            '     To enable TLS: aegis gate --tls (after running aegis init --generate-cert)\n',
          );
        }

        if (effectiveRequireAgentAuth) {
          console.log('  🔑 Agent authentication required (X-Aegis-Agent header)\n');
        } else {
          console.log(
            '  ⚠  Agent authentication disabled (--no-agent-auth) — any localhost process can use credentials\n',
          );
        }

        if (metrics) {
          console.log('  📊 Metrics enabled (/_aegis/metrics)\n');
        }

        if (policyDir) {
          const modeLabel =
            effectivePolicyMode === 'dry-run' ? 'DRY-RUN (log only)' : 'ENFORCE (block violations)';
          console.log(`  📋 Policies: ${policyDir}`);
          console.log(`     Mode:     ${modeLabel}\n`);
        }

        if (config.configFilePath) {
          console.log(`  📄 Config:   ${config.configFilePath}\n`);
        }

        const creds = vaultInstance.list();
        if (creds.length === 0) {
          console.log('  ⚠ No credentials in vault. Add some first: aegis vault add\n');
        } else {
          console.log(`  ${creds.length} credential(s) loaded:\n`);
          for (const c of creds) {
            console.log(`    ${c.service} → ${c.domains.join(', ')} (${c.authType})`);
          }
          console.log();
        }

        try {
          await gate.start();
        } catch (err: unknown) {
          const message = err instanceof Error ? err.message : String(err);
          console.error(`\n✗ Failed to start Gate: ${message}\n`);
          db.close();
          process.exit(1);
        }

        console.log(`  Agent config: set your agent's base URL to ${protocol}://localhost:${port}`);
        console.log(
          `  Example:      curl ${protocol}://localhost:${port}/slack/api/chat.postMessage\n`,
        );
        console.log(`  Press Ctrl+C to stop.\n`);

        // Graceful shutdown
        let shutdownInProgress = false;
        const shutdown = async () => {
          if (shutdownInProgress) {
            console.log('\n  Force shutdown — terminating immediately.');
            process.exit(1);
          }
          shutdownInProgress = true;
          console.log('\n  Shutting down Aegis Gate...');
          console.log('  (Press Ctrl+C again to force quit)\n');

          const result = await gate.stop();

          if (result.drained) {
            console.log('  All in-flight requests completed.');
          } else {
            console.log(
              `  Shutdown timed out — ${result.activeAtClose} request(s) were still in-flight.`,
            );
          }

          // Log shutdown event to Ledger as a system event
          ledger.logSystem({
            service: '_aegis',
            targetDomain: 'localhost',
            method: 'SHUTDOWN',
            path: '/',
            reason: result.drained
              ? 'Graceful shutdown — all requests drained'
              : `Forced shutdown — ${result.activeAtClose} request(s) still active`,
          });

          db.close();
          console.log('  Aegis Gate stopped.\n');
          process.exit(0);
        };
        process.on('SIGINT', shutdown);
        process.on('SIGTERM', shutdown);
      },
    );
}
