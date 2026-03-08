/**
 * Webhook commands: add, list, remove, test, check-expiry.
 */

import type { Command } from 'commander';
import { getConfig } from '../../config.js';
import { getDb, getVaultSalt, migrate } from '../../db.js';
import { deriveKey, Vault } from '../../vault/index.js';
import { WEBHOOK_EVENT_TYPES, WebhookManager } from '../../webhook/index.js';
import { requireUserAuth } from '../auth.js';
import { localTime } from '../validation.js';

export function register(program: Command): void {
  const webhookCmd = program.command('webhook').description('Manage webhook alert endpoints');

  webhookCmd
    .command('add')
    .description('Register a webhook endpoint for event notifications')
    .requiredOption('-u, --url <url>', 'Webhook endpoint URL (http or https)')
    .requiredOption(
      '-e, --events <events>',
      'Comma-separated event types: blocked_request, credential_expiry, rate_limit_exceeded, agent_auth_failure, body_inspection',
    )
    .option('-l, --label <label>', 'Human-readable label for this webhook')
    .action((opts: { url: string; events: string; label?: string }) => {
      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'webhook:write');

      const webhookManager = new WebhookManager({ db, logLevel: config.logLevel });

      const events = opts.events.split(',').map((e) => e.trim());
      for (const event of events) {
        if (!WEBHOOK_EVENT_TYPES.includes(event as (typeof WEBHOOK_EVENT_TYPES)[number])) {
          console.error(
            `\n  ✗ Invalid event type: ${event}\n  Valid types: ${WEBHOOK_EVENT_TYPES.join(', ')}\n`,
          );
          process.exit(1);
        }
      }

      try {
        const webhook = webhookManager.add({
          url: opts.url,
          events: events as (typeof WEBHOOK_EVENT_TYPES)[number][],
          label: opts.label,
        });

        console.log(`\n  ✔ Webhook registered`);
        console.log(`    ID:     ${webhook.id}`);
        console.log(`    URL:    ${webhook.url}`);
        console.log(`    Events: ${webhook.events.join(', ')}`);
        if (webhook.label) console.log(`    Label:  ${webhook.label}`);
        console.log(`    Secret: ${webhook.secret}`);
        console.log(
          `\n  Use the secret to verify payload signatures (X-Aegis-Signature header).\n`,
        );
      } catch (err: unknown) {
        console.error(`\n  ✗ ${err instanceof Error ? err.message : String(err)}\n`);
        process.exit(1);
      }

      db.close();
    });

  webhookCmd
    .command('list')
    .description('List all registered webhooks')
    .action(() => {
      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'webhook:read');

      const webhookManager = new WebhookManager({ db, logLevel: config.logLevel });
      const webhooks = webhookManager.list();

      if (webhooks.length === 0) {
        console.log(
          '\n  No webhooks registered. Add one with: aegis webhook add --url https://example.com/hook --events blocked_request\n',
        );
      } else {
        console.log(`\n  Aegis Webhooks — ${webhooks.length} registered\n`);
        for (const w of webhooks) {
          console.log(`    ${w.label ?? w.id}`);
          console.log(`      URL:    ${w.url}`);
          console.log(`      Events: ${w.events.join(', ')}`);
          console.log(`      Added:  ${localTime(w.createdAt)}`);
          console.log();
        }
      }

      db.close();
    });

  webhookCmd
    .command('remove')
    .description('Remove a webhook by ID')
    .requiredOption('--id <id>', 'Webhook ID to remove')
    .action((opts: { id: string }) => {
      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'webhook:write');

      const webhookManager = new WebhookManager({ db, logLevel: config.logLevel });

      if (webhookManager.remove(opts.id)) {
        console.log(`\n  ✔ Webhook removed: ${opts.id}\n`);
      } else {
        console.error(`\n  ✗ Webhook not found: ${opts.id}\n`);
        process.exit(1);
      }

      db.close();
    });

  webhookCmd
    .command('test')
    .description('Send a test event to a webhook')
    .requiredOption('--id <id>', 'Webhook ID to test')
    .action(async (opts: { id: string }) => {
      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'webhook:read');

      const webhookManager = new WebhookManager({ db, logLevel: config.logLevel });

      const webhook = webhookManager.getById(opts.id);
      if (!webhook) {
        console.error(`\n  ✗ Webhook not found: ${opts.id}\n`);
        db.close();
        process.exit(1);
      }

      console.log(`\n  Sending test event to ${webhook.url}...`);
      webhookManager.emit('blocked_request', {
        test: true,
        service: 'test-service',
        reason: 'test_event',
        message: 'This is a test webhook delivery from Aegis',
      });

      // Give it a moment to deliver
      await new Promise((resolve) => setTimeout(resolve, 3000));
      console.log(`  ✔ Test event sent\n`);

      db.close();
    });

  webhookCmd
    .command('check-expiry')
    .description('Check for credentials approaching expiry and emit webhook alerts')
    .option('--threshold <days>', 'Alert threshold in days (default: 7)', '7')
    .action((opts: { threshold: string }) => {
      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'webhook:read');

      const vaultInstance = new Vault(db, config.masterKey, getVaultSalt(config));
      const webhookManager = new WebhookManager({ db, logLevel: config.logLevel });

      const thresholdDays = Number.parseInt(opts.threshold, 10) || 7;
      const alertCount = webhookManager.checkExpiringCredentials(vaultInstance, thresholdDays);

      if (alertCount === 0) {
        console.log(`\n  ✔ No credentials expiring within ${thresholdDays} days\n`);
      } else {
        console.log(
          `\n  ⚠ ${alertCount} credential(s) expiring within ${thresholdDays} days — webhook alerts sent\n`,
        );
      }

      db.close();
    });
}
