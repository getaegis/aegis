/**
 * CLI module barrel — re-exports all command registration functions.
 */

export { register as registerAgent } from './commands/agent.js';
export { register as registerConfig } from './commands/config.js';
export { register as registerDashboard } from './commands/dashboard.js';
export { register as registerDoctor } from './commands/doctor.js';
export { register as registerGate } from './commands/gate.js';
export { register as registerInit } from './commands/init.js';
export { register as registerLedger } from './commands/ledger.js';
export { register as registerMcp } from './commands/mcp.js';
export { register as registerPolicy } from './commands/policy.js';
export { register as registerUser } from './commands/user.js';
export { register as registerVault } from './commands/vault.js';
export { register as registerVaultManager } from './commands/vault-manager.js';
export { register as registerWebhook } from './commands/webhook.js';
