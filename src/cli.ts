#!/usr/bin/env node

import { Command } from 'commander';
import {
  registerAgent,
  registerConfig,
  registerDashboard,
  registerDoctor,
  registerGate,
  registerInit,
  registerLedger,
  registerMcp,
  registerPolicy,
  registerUser,
  registerVault,
  registerVaultManager,
  registerWebhook,
} from './cli/index.js';
import { VERSION } from './version.js';

const program = new Command();

program
  .name('aegis')
  .description('Credential isolation for AI agents. Store, guard, and record.')
  .version(VERSION);

// Register all command groups
registerVault(program);
registerVaultManager(program);
registerGate(program);
registerAgent(program);
registerPolicy(program);
registerMcp(program);
registerWebhook(program);
registerLedger(program);
registerUser(program);
registerConfig(program);
registerInit(program);
registerDoctor(program);
registerDashboard(program);

// ── Global error handler — catch unhandled errors and print clean messages ──
process.on('uncaughtException', (err: Error & { code?: string }) => {
  console.error(`\n✗ ${err.message}\n`);
  process.exit(1);
});

program.parse();
