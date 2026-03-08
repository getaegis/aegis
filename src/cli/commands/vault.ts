/**
 * Vault CRUD commands: add, list, remove, rotate, update.
 */

import type { Command } from 'commander';
import { getConfig } from '../../config.js';
import { getDb, getVaultSalt, migrate } from '../../db.js';
import type { BodyInspectionMode } from '../../gate/body-inspector.js';
import type { AuthType } from '../../vault/index.js';
import { deriveKey, Vault } from '../../vault/index.js';
import { requireUserAuth } from '../auth.js';
import {
  localTime,
  VALID_AUTH_TYPES,
  VALID_BODY_INSPECTION_MODES,
  validateDomains,
  validateEnum,
  validateIdentifier,
  validateNonNegativeFloat,
  validatePositiveInt,
  validateRateLimit,
} from '../validation.js';

export function register(program: Command): void {
  const vault = program.command('vault').description('Manage stored credentials');

  vault
    .command('add')
    .description('Add a new credential to the vault')
    .requiredOption('-n, --name <name>', 'Unique name for this credential')
    .requiredOption('-s, --service <service>', 'Service identifier (used in proxy URL path)')
    .requiredOption('--secret <secret>', 'The API key or token')
    .requiredOption(
      '-d, --domains <domains>',
      'Comma-separated allowed domains (e.g. api.slack.com,*.slack.com)',
    )
    .option('-a, --auth-type <type>', 'Auth injection type: bearer, header, basic, query', 'bearer')
    .option('--header-name <name>', 'Custom header name (for auth-type: header)')
    .option('--scopes <scopes>', 'Comma-separated scopes: read, write, *', '*')
    .option('--ttl <days>', 'Credential expires after this many days')
    .option('--rate-limit <limit>', 'Rate limit: e.g. 100/min, 1000/hour, 10/sec')
    .option('--body-inspection <mode>', 'Body inspection mode: off, warn, block', 'block')
    .action(
      (opts: {
        name: string;
        service: string;
        secret: string;
        domains: string;
        authType: string;
        headerName?: string;
        scopes: string;
        ttl?: string;
        rateLimit?: string;
        bodyInspection: string;
      }) => {
        // ── Input validation ──
        validateIdentifier(opts.name, 'credential name');
        validateIdentifier(opts.service, 'service');
        const authType = validateEnum(opts.authType, VALID_AUTH_TYPES, 'auth type');
        const bodyInspection = validateEnum(
          opts.bodyInspection,
          VALID_BODY_INSPECTION_MODES,
          'body inspection mode',
        );
        const domains = validateDomains(opts.domains);
        const ttlDays = opts.ttl ? parseInt(opts.ttl, 10) : undefined;
        if (ttlDays !== undefined) validatePositiveInt(ttlDays, 'TTL (days)');
        if (opts.rateLimit) validateRateLimit(opts.rateLimit);

        const config = getConfig();
        const db = getDb(config);
        migrate(db);
        const key = deriveKey(config.masterKey, getVaultSalt(config));
        requireUserAuth(db, key, 'vault:write');
        const vaultInstance = new Vault(db, config.masterKey, getVaultSalt(config));

        try {
          const cred = vaultInstance.add({
            name: opts.name,
            service: opts.service,
            secret: opts.secret,
            authType,
            headerName: opts.headerName,
            domains,
            scopes: opts.scopes.split(',').map((s) => s.trim()),
            ttlDays,
            rateLimit: opts.rateLimit,
            bodyInspection,
          });

          console.log(`\n✓ Credential added to Aegis Vault\n`);
          console.log(`  Name:    ${cred.name}`);
          console.log(`  Service: ${cred.service}`);
          console.log(`  Auth:    ${cred.authType}`);
          console.log(`  Domains: ${cred.domains.join(', ')}`);
          console.log(`  Scopes:  ${cred.scopes.join(', ')}`);
          if (cred.expiresAt) {
            console.log(`  Expires: ${localTime(cred.expiresAt)}`);
          }
          if (cred.rateLimit) {
            console.log(`  Rate:    ${cred.rateLimit}`);
          }
          console.log(`  Body:    ${cred.bodyInspection}`);
          console.log(
            `\n  Your agent can now use: http://localhost:${config.port}/${cred.service}/...\n`,
          );
        } catch (err: unknown) {
          const message = err instanceof Error ? err.message : String(err);
          if (message.includes('UNIQUE')) {
            console.error(
              `\n✗ A credential named "${opts.name}" already exists. Remove it first with: aegis vault remove --name ${opts.name}\n`,
            );
          } else {
            console.error(`\n✗ Error: ${message}\n`);
          }
          process.exit(1);
        } finally {
          db.close();
        }
      },
    );

  vault
    .command('list')
    .description('List all stored credentials (secrets are never shown)')
    .action(() => {
      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'vault:read');
      const vaultInstance = new Vault(db, config.masterKey, getVaultSalt(config));

      const creds = vaultInstance.list();
      if (creds.length === 0) {
        console.log('\n  No credentials stored. Add one with: aegis vault add\n');
        db.close();
        return;
      }

      console.log(`\n  Aegis Vault — ${creds.length} credential(s)\n`);
      for (const cred of creds) {
        console.log(`  ┌ ${cred.name} (${cred.service})`);
        console.log(`  │ Auth:    ${cred.authType}`);
        console.log(`  │ Domains: ${cred.domains.join(', ')}`);
        console.log(`  │ Scopes:  ${cred.scopes.join(', ')}`);
        if (cred.rateLimit) {
          console.log(`  │ Rate:    ${cred.rateLimit}`);
        }
        if (cred.expiresAt) {
          console.log(`  │ Expires: ${localTime(cred.expiresAt)}`);
        }
        console.log(`  │ Added:   ${localTime(cred.createdAt)}`);
        console.log(`  └`);
      }
      console.log();
      db.close();
    });

  vault
    .command('remove')
    .description('Remove a credential from the vault')
    .requiredOption('-n, --name <name>', 'Name of the credential to remove')
    .action((opts: { name: string }) => {
      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'vault:write');
      const vaultInstance = new Vault(db, config.masterKey, getVaultSalt(config));

      const removed = vaultInstance.remove(opts.name);
      if (removed) {
        console.log(`\n✓ Credential "${opts.name}" removed from vault.\n`);
      } else {
        console.error(`\n✗ No credential found with name "${opts.name}".\n`);
        process.exit(1);
      }
      db.close();
    });

  vault
    .command('rotate')
    .description("Rotate a credential's secret (old secret saved to history)")
    .requiredOption('-n, --name <name>', 'Name of the credential to rotate')
    .requiredOption('--secret <secret>', 'The new API key or token')
    .option(
      '--grace-period <hours>',
      'Keep old secret valid for this many hours (for zero-downtime rotation)',
    )
    .action((opts: { name: string; secret: string; gracePeriod?: string }) => {
      const gracePeriodHours = opts.gracePeriod ? parseFloat(opts.gracePeriod) : undefined;
      if (gracePeriodHours !== undefined)
        validateNonNegativeFloat(gracePeriodHours, 'grace period (hours)');

      const config = getConfig();
      const db = getDb(config);
      migrate(db);
      const key = deriveKey(config.masterKey, getVaultSalt(config));
      requireUserAuth(db, key, 'vault:write');
      const vaultInstance = new Vault(db, config.masterKey, getVaultSalt(config));

      try {
        const cred = vaultInstance.rotate({
          name: opts.name,
          newSecret: opts.secret,
          gracePeriodHours,
        });

        console.log(`\n✓ Credential "${cred.name}" rotated successfully\n`);
        console.log(`  Old secret saved to history`);
        if (gracePeriodHours) {
          console.log(`  Grace period: ${gracePeriodHours} hour(s)`);
        }
        console.log();
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(`\n✗ ${message}\n`);
        process.exit(1);
      } finally {
        db.close();
      }
    });

  vault
    .command('update')
    .description("Update a credential's metadata without re-entering the secret")
    .requiredOption('-n, --name <name>', 'Name of the credential to update')
    .option('-d, --domains <domains>', 'New comma-separated allowed domains')
    .option('--scopes <scopes>', 'New comma-separated scopes')
    .option('-a, --auth-type <type>', 'New auth injection type: bearer, header, basic, query')
    .option('--header-name <name>', 'New custom header name (for auth-type: header)')
    .option(
      '--rate-limit <limit>',
      "New rate limit: e.g. 100/min, 1000/hour (use 'none' to remove)",
    )
    .option('--body-inspection <mode>', 'Body inspection mode: off, warn, block')
    .action(
      (opts: {
        name: string;
        domains?: string;
        scopes?: string;
        authType?: string;
        headerName?: string;
        rateLimit?: string;
        bodyInspection?: string;
      }) => {
        // ── Input validation ──
        if (opts.authType) validateEnum(opts.authType, VALID_AUTH_TYPES, 'auth type');
        if (opts.bodyInspection)
          validateEnum(opts.bodyInspection, VALID_BODY_INSPECTION_MODES, 'body inspection mode');
        const domains = opts.domains ? validateDomains(opts.domains) : undefined;
        if (opts.rateLimit && opts.rateLimit.toLowerCase() !== 'none')
          validateRateLimit(opts.rateLimit);

        const config = getConfig();
        const db = getDb(config);
        migrate(db);
        const key = deriveKey(config.masterKey, getVaultSalt(config));
        requireUserAuth(db, key, 'vault:write');
        const vaultInstance = new Vault(db, config.masterKey, getVaultSalt(config));

        try {
          // "none" means remove the rate limit
          const rateLimit =
            opts.rateLimit !== undefined
              ? opts.rateLimit.toLowerCase() === 'none'
                ? null
                : opts.rateLimit
              : undefined;

          const cred = vaultInstance.update({
            name: opts.name,
            domains,
            scopes: opts.scopes?.split(',').map((s) => s.trim()),
            authType: opts.authType as AuthType | undefined,
            headerName: opts.headerName,
            rateLimit,
            bodyInspection: opts.bodyInspection as BodyInspectionMode | undefined,
          });

          console.log(`\n✓ Credential "${cred.name}" updated\n`);
          console.log(`  Domains: ${cred.domains.join(', ')}`);
          console.log(`  Scopes:  ${cred.scopes.join(', ')}`);
          console.log(`  Auth:    ${cred.authType}`);
          if (cred.headerName) {
            console.log(`  Header:  ${cred.headerName}`);
          }
          if (cred.rateLimit) {
            console.log(`  Rate:    ${cred.rateLimit}`);
          }
          console.log(`  Body:    ${cred.bodyInspection}`);
          console.log();
        } catch (err: unknown) {
          const message = err instanceof Error ? err.message : String(err);
          console.error(`\n✗ ${message}\n`);
          process.exit(1);
        } finally {
          db.close();
        }
      },
    );
}
