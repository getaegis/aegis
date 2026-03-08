/**
 * Ledger commands: show, stats, export.
 */

import * as fs from 'node:fs';
import type { Command } from 'commander';
import { getConfig } from '../../config.js';
import { getDb, getVaultSalt, migrate } from '../../db.js';
import { Ledger } from '../../ledger/index.js';
import { deriveKey } from '../../vault/index.js';
import { requireUserAuth } from '../auth.js';
import { localTime, validateEnum, validateIsoDate, validatePositiveInt } from '../validation.js';

export function register(program: Command): void {
  const ledgerCmd = program.command('ledger').description('View and export audit logs');

  ledgerCmd
    .command('show')
    .description('Show recent audit log entries')
    .option('-s, --service <service>', 'Filter by service')
    .option('-n, --limit <limit>', 'Number of entries to show', '20')
    .option('--since <date>', 'Show entries since date (ISO format)')
    .option('--blocked', 'Show only blocked requests')
    .option('--system', 'Show only system events (startup, shutdown)')
    .option('--agent <name>', 'Filter by agent name')
    .action(
      (opts: {
        service?: string;
        limit: string;
        since?: string;
        blocked?: boolean;
        system?: boolean;
        agent?: string;
      }) => {
        const config = getConfig();
        // ── Validate CLI flags ──
        const parsedLimit = parseInt(opts.limit, 10);
        validatePositiveInt(parsedLimit, 'limit');
        if (opts.since) {
          validateIsoDate(opts.since, '--since date');
        }

        const db = getDb(config);
        migrate(db);
        const key = deriveKey(config.masterKey, getVaultSalt(config));
        requireUserAuth(db, key, 'ledger:read');
        const ledger = new Ledger(db);

        const entries = ledger.query({
          service: opts.service,
          status: opts.blocked ? 'blocked' : opts.system ? 'system' : undefined,
          since: opts.since,
          limit: parsedLimit,
          agentName: opts.agent,
        });

        if (entries.length === 0) {
          console.log('\n  No audit entries found.\n');
          db.close();
          return;
        }

        console.log(`\n  Aegis Ledger — ${entries.length} entries\n`);
        for (const entry of entries) {
          const icon = entry.status === 'allowed' ? '✓' : entry.status === 'system' ? '●' : '✗';
          const reason = entry.blockedReason ? ` (${entry.blockedReason})` : '';
          const agent = entry.agentName ? ` [${entry.agentName}]` : '';
          const channel = entry.channel !== 'gate' ? ` via ${entry.channel}` : '';
          console.log(
            `  ${icon} ${localTime(entry.timestamp)} | ${entry.method.padEnd(6)} ${entry.service}${entry.path} → ${entry.targetDomain} [${entry.responseCode ?? '-'}]${agent}${channel}${reason}`,
          );
        }
        console.log();
        db.close();
      },
    );

  ledgerCmd
    .command('stats')
    .description('Show audit log statistics')
    .option('--since <date>', 'Stats since date (ISO format)')
    .option('--agent <name>', 'Stats for a specific agent')
    .action((opts: { since?: string; agent?: string }) => {
      // ── Validate CLI flags ──
      if (opts.since) {
        validateIsoDate(opts.since, '--since date');
      }

      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'ledger:read');
      const ledger = new Ledger(db);

      const stats = ledger.stats(opts.since, opts.agent);

      console.log(`\n  Aegis Ledger — Statistics\n`);
      console.log(`  Total requests:   ${stats.total}`);
      console.log(`  Allowed:          ${stats.allowed}`);
      console.log(`  Blocked:          ${stats.blocked}`);
      if (stats.system > 0) {
        console.log(`  System:           ${stats.system}`);
      }
      if (Object.keys(stats.byService).length > 0) {
        console.log(`\n  By service:`);
        for (const [service, count] of Object.entries(stats.byService)) {
          console.log(`    ${service}: ${count}`);
        }
      }
      console.log();
      db.close();
    });

  ledgerCmd
    .command('export')
    .description('Export audit log (CSV, JSON, or JSON Lines)')
    .option('-s, --service <service>', 'Filter by service')
    .option('--since <date>', 'Export entries since date')
    .option('-f, --format <format>', 'Output format: csv, json, or jsonl', 'csv')
    .option('-o, --output <file>', 'Output file path')
    .action((opts: { service?: string; since?: string; format: string; output?: string }) => {
      // ── Validate CLI flags ──
      if (opts.since) {
        validateIsoDate(opts.since, '--since date');
      }
      validateEnum(opts.format, ['csv', 'json', 'jsonl'] as const, 'format');

      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'ledger:export');
      const ledger = new Ledger(db);

      const queryParams = {
        service: opts.service,
        since: opts.since,
      };

      let output: string;
      switch (opts.format) {
        case 'json':
          output = ledger.exportJson(queryParams);
          break;
        case 'jsonl':
          output = ledger.exportJsonLines(queryParams);
          break;
        case 'csv':
          output = ledger.exportCsv(queryParams);
          break;
        default:
          console.error(`\n✗ Unknown format "${opts.format}". Use csv, json, or jsonl.\n`);
          db.close();
          return;
      }

      if (opts.output) {
        fs.writeFileSync(opts.output, output, 'utf-8');
        console.log(`\n✓ Exported ${opts.format.toUpperCase()} to ${opts.output}\n`);
      } else {
        console.log(output);
      }
      db.close();
    });
}
