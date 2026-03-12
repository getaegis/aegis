export { AgentRegistry } from './agent/index.js';
export type {
  AegisConfig,
  AegisConfigFile,
  ConfigValidationError,
  GateConfig,
  McpConfig,
  ObservabilityConfig,
  VaultConfig,
  WebhookConfigEntry,
} from './config.js';
export {
  findConfigFile,
  getConfig,
  loadEnv,
  parseConfigFile,
  validateConfigFile,
} from './config.js';
export type { DashboardServerOptions } from './dashboard/index.js';
export { DashboardServer } from './dashboard/index.js';
export { getDb, getVaultSalt, migrate } from './db.js';
export type { CheckResult, DoctorOptions, DoctorReport } from './doctor.js';
export { printDoctorReport, runDoctor } from './doctor.js';
export { Gate } from './gate/index.js';
export type { KeyStorage, KeyStorageBackend } from './key-storage/index.js';
export { commandExists, getKeyStorage } from './key-storage/index.js';
export { Ledger } from './ledger/index.js';
export type { LoggerOptions, LogLevel } from './logger/index.js';
export { createLogger, generateRequestId, safeMeta, scrubString } from './logger/index.js';
export type { AegisMcpServerOptions } from './mcp/index.js';
export { AegisMcpServer } from './mcp/index.js';
export type { BlockReason, MetricsOptions } from './metrics/index.js';
export { AegisMetrics } from './metrics/index.js';
export type {
  HttpMethod,
  Policy,
  PolicyEvaluation,
  PolicyRequest,
  PolicyRule,
  PolicyValidationError,
  PolicyValidationResult,
  TimeWindow,
} from './policy/index.js';
export {
  buildPolicyMap,
  evaluatePolicy,
  loadPoliciesFromDirectory,
  loadPolicyFile,
  parsePolicy,
} from './policy/index.js';
export type { Permission, User, UserRole, UserWithToken } from './user/index.js';
export { getPermissions, hasPermission, UserRegistry, VALID_ROLES } from './user/index.js';
export type { SealConfig, ShamirShare } from './vault/index.js';
export {
  combine,
  decodeShare,
  encodeShare,
  SealManager,
  split,
  Vault,
  VaultManager,
} from './vault/index.js';
export { VERSION } from './version.js';
export type {
  Webhook,
  WebhookEventType,
  WebhookManagerOptions,
  WebhookPayload,
} from './webhook/index.js';
export { WEBHOOK_EVENT_TYPES, WebhookManager } from './webhook/index.js';
