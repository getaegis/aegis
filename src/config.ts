import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { getKeyStorage } from './key-storage/index.js';

// ─── Config File Schema ──────────────────────────────────────────

/** Gate proxy configuration. */
export interface GateConfig {
  port: number;
  tls?: {
    cert: string;
    key: string;
  };
  require_agent_auth: boolean;
  policy_mode: 'enforce' | 'dry-run' | 'off';
  policies_dir?: string;
  /** Maximum request body size in bytes (default: 1048576 = 1 MB). Bodies exceeding this return 413. */
  max_body_size: number;
  /** Request timeout in milliseconds (default: 30000 = 30s). Prevents slowloris attacks. */
  request_timeout: number;
  /** Maximum concurrent in-flight requests per agent (default: 50). Prevents socket exhaustion. */
  max_connections_per_agent: number;
}

/** Vault configuration. */
export interface VaultConfig {
  name: string;
  data_dir: string;
  master_key: string;
}

/** Observability configuration. */
export interface ObservabilityConfig {
  log_level: 'debug' | 'info' | 'warn' | 'error';
  log_format: 'json' | 'pretty';
  metrics: boolean;
  dashboard?: {
    enabled: boolean;
    port: number;
  };
}

/** MCP server configuration. */
export interface McpConfig {
  transport: 'stdio' | 'streamable-http';
  port: number;
}

/** Webhook configuration (inline in config file). */
export interface WebhookConfigEntry {
  url: string;
  secret?: string;
  events: string[];
}

/** Complete aegis.config.yaml schema. */
export interface AegisConfigFile {
  gate?: Partial<GateConfig>;
  vault?: Partial<VaultConfig>;
  observability?: Partial<ObservabilityConfig>;
  mcp?: Partial<McpConfig>;
  webhooks?: WebhookConfigEntry[];
}

/** Resolved Aegis configuration — all fields have values. */
export interface AegisConfig {
  port: number;
  masterKey: string;
  salt: string;
  dataDir: string;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  logFormat: 'json' | 'pretty';
  vaultName: string;
  tls?: { cert: string; key: string };
  requireAgentAuth: boolean;
  policyMode: 'enforce' | 'dry-run' | 'off';
  policiesDir?: string;
  metricsEnabled: boolean;
  dashboard: { enabled: boolean; port: number };
  mcp: { transport: 'stdio' | 'streamable-http'; port: number };
  webhooks: WebhookConfigEntry[];
  /** Maximum request body size in bytes (default: 1 MB). */
  maxBodySize: number;
  /** Request timeout in milliseconds (default: 30s). */
  requestTimeout: number;
  /** Max concurrent in-flight requests per agent (default: 50). */
  maxConnectionsPerAgent: number;
  /** Path to the config file used, if any. */
  configFilePath?: string;
}

// ─── Defaults ─────────────────────────────────────────────────────

const DEFAULTS: AegisConfig = {
  port: 3100,
  masterKey: '',
  salt: 'aegis-vault-v1',
  dataDir: path.join(process.cwd(), '.aegis'),
  logLevel: 'info',
  logFormat: 'json',
  vaultName: 'default',
  requireAgentAuth: true,
  policyMode: 'enforce',
  metricsEnabled: true,
  dashboard: { enabled: false, port: 3200 },
  mcp: { transport: 'stdio', port: 3200 },
  webhooks: [],
  maxBodySize: 1_048_576, // 1 MB
  requestTimeout: 30_000, // 30 seconds
  maxConnectionsPerAgent: 50,
};

// ─── Config File Discovery ────────────────────────────────────────

/** Search order for config file, relative to CWD. */
const CONFIG_FILE_NAMES = ['aegis.config.yaml', 'aegis.config.yml'];

/**
 * Find the config file path, checking CWD first, then the CLI script's directory.
 * The script directory fallback ensures MCP servers spawned by Claude Desktop /
 * Cursor (which set cwd=/) can still find the config file next to the CLI.
 * Returns absolute path or null if not found.
 */
export function findConfigFile(cwd?: string): string | null {
  const searchDir = cwd ?? process.cwd();

  // Search the given (or current) directory
  for (const name of CONFIG_FILE_NAMES) {
    const filePath = path.join(searchDir, name);
    if (fs.existsSync(filePath)) return filePath;
  }

  // Fallback: search relative to the CLI script's directory — but only when
  // no explicit cwd was provided (so tests that pass a temp dir aren't polluted).
  if (cwd === undefined) {
    const scriptDir = path.dirname(fileURLToPath(import.meta.url));
    const projectDir = path.resolve(scriptDir, '..');
    if (projectDir !== searchDir) {
      for (const name of CONFIG_FILE_NAMES) {
        const filePath = path.join(projectDir, name);
        if (fs.existsSync(filePath)) return filePath;
      }
    }

    // Fallback: search $HOME — MCP hosts often spawn processes with CWD=/
    // and the config file lives in the user's home directory or project dir.
    const home = os.homedir();
    if (home && home !== searchDir && home !== projectDir) {
      for (const name of CONFIG_FILE_NAMES) {
        const filePath = path.join(home, name);
        if (fs.existsSync(filePath)) return filePath;
      }
    }
  }

  return null;
}

/**
 * Parse a YAML config file. Returns the parsed object.
 * Throws on invalid YAML or file read errors.
 */
export function parseConfigFile(filePath: string): AegisConfigFile {
  const content = fs.readFileSync(filePath, 'utf-8');
  const parsed = parseYaml(content);
  if (parsed === null || parsed === undefined) return {};
  if (typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`Config file must be a YAML mapping, got ${typeof parsed}.`);
  }
  return parsed as AegisConfigFile;
}

// ─── Validation ───────────────────────────────────────────────────

export interface ConfigValidationError {
  path: string;
  message: string;
}

const VALID_LOG_LEVELS = ['debug', 'info', 'warn', 'error'];
const VALID_LOG_FORMATS = ['json', 'pretty'];
const VALID_POLICY_MODES = ['enforce', 'dry-run', 'off'];
const VALID_MCP_TRANSPORTS = ['stdio', 'streamable-http'];
const VALID_WEBHOOK_EVENTS = [
  'blocked_request',
  'credential_expiry',
  'rate_limit_exceeded',
  'agent_auth_failure',
  'body_inspection',
];

/**
 * Validate a parsed config file. Returns an array of errors (empty = valid).
 */
export function validateConfigFile(config: AegisConfigFile): ConfigValidationError[] {
  const errors: ConfigValidationError[] = [];

  if (config.gate !== undefined) {
    if (config.gate.port !== undefined) {
      if (
        typeof config.gate.port !== 'number' ||
        config.gate.port < 1 ||
        config.gate.port > 65535
      ) {
        errors.push({ path: 'gate.port', message: 'Must be a number between 1 and 65535.' });
      }
    }
    if (config.gate.tls !== undefined) {
      if (typeof config.gate.tls !== 'object' || config.gate.tls === null) {
        errors.push({ path: 'gate.tls', message: 'Must be an object with cert and key paths.' });
      } else {
        if (!config.gate.tls.cert) {
          errors.push({ path: 'gate.tls.cert', message: 'TLS certificate path is required.' });
        }
        if (!config.gate.tls.key) {
          errors.push({ path: 'gate.tls.key', message: 'TLS private key path is required.' });
        }
      }
    }
    if (
      config.gate.require_agent_auth !== undefined &&
      typeof config.gate.require_agent_auth !== 'boolean'
    ) {
      errors.push({ path: 'gate.require_agent_auth', message: 'Must be true or false.' });
    }
    if (
      config.gate.policy_mode !== undefined &&
      !VALID_POLICY_MODES.includes(config.gate.policy_mode)
    ) {
      errors.push({
        path: 'gate.policy_mode',
        message: `Must be one of: ${VALID_POLICY_MODES.join(', ')}.`,
      });
    }
    if (config.gate.policies_dir !== undefined && typeof config.gate.policies_dir !== 'string') {
      errors.push({ path: 'gate.policies_dir', message: 'Must be a string path.' });
    }
    if (config.gate.max_body_size !== undefined) {
      if (typeof config.gate.max_body_size !== 'number' || config.gate.max_body_size < 1) {
        errors.push({ path: 'gate.max_body_size', message: 'Must be a positive number (bytes).' });
      }
    }
    if (config.gate.request_timeout !== undefined) {
      if (typeof config.gate.request_timeout !== 'number' || config.gate.request_timeout < 1000) {
        errors.push({
          path: 'gate.request_timeout',
          message: 'Must be a number >= 1000 (milliseconds).',
        });
      }
    }
    if (config.gate.max_connections_per_agent !== undefined) {
      if (
        typeof config.gate.max_connections_per_agent !== 'number' ||
        config.gate.max_connections_per_agent < 1
      ) {
        errors.push({
          path: 'gate.max_connections_per_agent',
          message: 'Must be a positive number.',
        });
      }
    }
  }

  if (config.vault !== undefined) {
    if (config.vault.name !== undefined && typeof config.vault.name !== 'string') {
      errors.push({ path: 'vault.name', message: 'Must be a string.' });
    }
    if (config.vault.data_dir !== undefined && typeof config.vault.data_dir !== 'string') {
      errors.push({ path: 'vault.data_dir', message: 'Must be a string path.' });
    }
  }

  if (config.observability !== undefined) {
    if (
      config.observability.log_level !== undefined &&
      !VALID_LOG_LEVELS.includes(config.observability.log_level)
    ) {
      errors.push({
        path: 'observability.log_level',
        message: `Must be one of: ${VALID_LOG_LEVELS.join(', ')}.`,
      });
    }
    if (
      config.observability.log_format !== undefined &&
      !VALID_LOG_FORMATS.includes(config.observability.log_format)
    ) {
      errors.push({
        path: 'observability.log_format',
        message: `Must be one of: ${VALID_LOG_FORMATS.join(', ')}.`,
      });
    }
    if (
      config.observability.metrics !== undefined &&
      typeof config.observability.metrics !== 'boolean'
    ) {
      errors.push({ path: 'observability.metrics', message: 'Must be true or false.' });
    }
    if (config.observability.dashboard !== undefined) {
      if (
        typeof config.observability.dashboard !== 'object' ||
        config.observability.dashboard === null
      ) {
        errors.push({
          path: 'observability.dashboard',
          message: 'Must be an object with enabled and port.',
        });
      } else {
        if (
          config.observability.dashboard.enabled !== undefined &&
          typeof config.observability.dashboard.enabled !== 'boolean'
        ) {
          errors.push({
            path: 'observability.dashboard.enabled',
            message: 'Must be true or false.',
          });
        }
        if (config.observability.dashboard.port !== undefined) {
          if (
            typeof config.observability.dashboard.port !== 'number' ||
            config.observability.dashboard.port < 1 ||
            config.observability.dashboard.port > 65535
          ) {
            errors.push({
              path: 'observability.dashboard.port',
              message: 'Must be a number between 1 and 65535.',
            });
          }
        }
      }
    }
  }

  if (config.mcp !== undefined) {
    if (
      config.mcp.transport !== undefined &&
      !VALID_MCP_TRANSPORTS.includes(config.mcp.transport)
    ) {
      errors.push({
        path: 'mcp.transport',
        message: `Must be one of: ${VALID_MCP_TRANSPORTS.join(', ')}.`,
      });
    }
    if (config.mcp.port !== undefined) {
      if (typeof config.mcp.port !== 'number' || config.mcp.port < 1 || config.mcp.port > 65535) {
        errors.push({ path: 'mcp.port', message: 'Must be a number between 1 and 65535.' });
      }
    }
  }

  if (config.webhooks !== undefined) {
    if (!Array.isArray(config.webhooks)) {
      errors.push({ path: 'webhooks', message: 'Must be an array.' });
    } else {
      for (let i = 0; i < config.webhooks.length; i++) {
        const wh = config.webhooks[i];
        if (!wh.url || typeof wh.url !== 'string') {
          errors.push({
            path: `webhooks[${i}].url`,
            message: 'URL is required and must be a string.',
          });
        } else {
          try {
            new URL(wh.url);
          } catch {
            errors.push({ path: `webhooks[${i}].url`, message: 'Must be a valid URL.' });
          }
        }
        if (wh.events !== undefined) {
          if (!Array.isArray(wh.events)) {
            errors.push({
              path: `webhooks[${i}].events`,
              message: 'Must be an array of event types.',
            });
          } else {
            for (const evt of wh.events) {
              if (!VALID_WEBHOOK_EVENTS.includes(evt)) {
                errors.push({
                  path: `webhooks[${i}].events`,
                  message: `Unknown event "${evt}". Valid: ${VALID_WEBHOOK_EVENTS.join(', ')}.`,
                });
              }
            }
          }
        }
      }
    }
  }

  return errors;
}

// ─── Config Resolution ────────────────────────────────────────────

export function loadEnv(filePath: string): Record<string, string> {
  const env: Record<string, string> = {};
  if (!fs.existsSync(filePath)) return env;
  const content = fs.readFileSync(filePath, 'utf-8');
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) continue;
    const key = trimmed.slice(0, eqIndex).trim();
    const value = trimmed.slice(eqIndex + 1).trim();
    env[key] = value;
  }
  return env;
}

/**
 * Load and resolve the full Aegis configuration.
 *
 * Resolution order (highest priority wins):
 *   1. Environment variables (AEGIS_*)
 *   2. Config file (aegis.config.yaml)
 *   3. Built-in defaults
 *
 * The .env file is loaded into the environment variable layer.
 * The master key has special handling: env → unseal key file → empty.
 */
export function getConfig(): AegisConfig {
  // Layer 2: Config file (resolve first so we know baseDir for .env)
  const configFilePath = findConfigFile();

  // Base directory for resolving relative paths:
  // If a config file was found, use its directory (so MCP servers spawned
  // from any cwd still resolve .aegis/ correctly). Otherwise fall back to
  // HOME (handles MCP hosts that spawn from / or unpredictable CWDs),
  // then process.cwd() as a last resort.
  const baseDir = configFilePath
    ? path.dirname(path.resolve(configFilePath))
    : os.homedir() || process.cwd();

  // Layer 1: .env (loaded into env layer, searched relative to baseDir)
  const dotenv = loadEnv(path.join(baseDir, '.env'));
  const getEnv = (key: string): string | undefined => process.env[key] ?? dotenv[key];
  let fileConfig: AegisConfigFile = {};
  if (configFilePath) {
    fileConfig = parseConfigFile(configFilePath);
  }

  // Resolve data directory (env → config file → default)
  const rawDataDir = getEnv('AEGIS_DATA_DIR') ?? fileConfig.vault?.data_dir ?? DEFAULTS.dataDir;
  const dataDir = path.isAbsolute(rawDataDir) ? rawDataDir : path.resolve(baseDir, rawDataDir);

  // Ensure data directory exists
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  // Master key resolution: env var / .env file → config YAML → OS keychain / file fallback → empty
  let masterKey = getEnv('AEGIS_MASTER_KEY') ?? fileConfig.vault?.master_key ?? '';
  if (!masterKey) {
    try {
      const keyStorage = getKeyStorage(dataDir);
      masterKey = keyStorage.getKey() ?? '';
    } catch {
      // Key storage not available — continue without key
    }
  }

  // Validate master key format: must be 64 hex chars (256-bit key)
  if (masterKey && !/^[0-9a-f]{64}$/i.test(masterKey)) {
    // Warn but don't reject — legacy keys or test keys may differ
    if (typeof process !== 'undefined' && process.stderr) {
      process.stderr.write(
        '⚠  Master key format warning: expected 64 hex characters (256-bit key).\n' +
          '   Decryption may fail if the key is invalid.\n',
      );
    }
  }

  // Resolve port: env → config file → default
  const port =
    (getEnv('AEGIS_PORT') ? Number.parseInt(getEnv('AEGIS_PORT') as string, 10) : undefined) ??
    fileConfig.gate?.port ??
    DEFAULTS.port;

  // Resolve log level: env → config file → default
  const logLevel = (getEnv('AEGIS_LOG_LEVEL') ??
    fileConfig.observability?.log_level ??
    DEFAULTS.logLevel) as AegisConfig['logLevel'];

  // Resolve log format: env → config file → default
  const logFormat = (getEnv('AEGIS_LOG_FORMAT') ??
    fileConfig.observability?.log_format ??
    DEFAULTS.logFormat) as AegisConfig['logFormat'];

  // Resolve vault name: env → config file → default
  const vaultName = getEnv('AEGIS_VAULT') ?? fileConfig.vault?.name ?? DEFAULTS.vaultName;

  // Resolve salt (env only — salt is stored in vault registry, not config file)
  const salt = getEnv('AEGIS_SALT') ?? DEFAULTS.salt;

  // Resolve TLS: config file
  const tls = fileConfig.gate?.tls;

  // Resolve agent auth: env → config file → default (on by default since v0.8.2)
  const envAgentAuth = getEnv('AEGIS_REQUIRE_AGENT_AUTH');
  const requireAgentAuth =
    envAgentAuth !== undefined
      ? envAgentAuth === 'true'
      : (fileConfig.gate?.require_agent_auth ?? DEFAULTS.requireAgentAuth);

  // Resolve policy mode: env → config file → default
  const policyMode = (getEnv('AEGIS_POLICY_MODE') ??
    fileConfig.gate?.policy_mode ??
    DEFAULTS.policyMode) as AegisConfig['policyMode'];

  // Resolve policies dir: env → config file
  const policiesDir = getEnv('AEGIS_POLICIES_DIR') ?? fileConfig.gate?.policies_dir;

  // Resolve metrics: env → config file → default
  const metricsEnabled =
    getEnv('AEGIS_METRICS') !== undefined
      ? getEnv('AEGIS_METRICS') === 'true'
      : (fileConfig.observability?.metrics ?? DEFAULTS.metricsEnabled);

  // Resolve dashboard: config file → defaults
  const dashboard = {
    enabled: fileConfig.observability?.dashboard?.enabled ?? DEFAULTS.dashboard.enabled,
    port: fileConfig.observability?.dashboard?.port ?? DEFAULTS.dashboard.port,
  };

  // Resolve MCP: config file → defaults
  const mcp = {
    transport: (fileConfig.mcp?.transport ??
      DEFAULTS.mcp.transport) as AegisConfig['mcp']['transport'],
    port: fileConfig.mcp?.port ?? DEFAULTS.mcp.port,
  };

  // Webhooks from config file
  const webhooks = fileConfig.webhooks ?? DEFAULTS.webhooks;

  // Resolve Gate hardening: config file → defaults
  const maxBodySize = fileConfig.gate?.max_body_size ?? DEFAULTS.maxBodySize;
  const requestTimeout = fileConfig.gate?.request_timeout ?? DEFAULTS.requestTimeout;
  const maxConnectionsPerAgent =
    fileConfig.gate?.max_connections_per_agent ?? DEFAULTS.maxConnectionsPerAgent;

  return {
    port,
    masterKey,
    salt,
    dataDir,
    logLevel,
    logFormat,
    vaultName,
    tls,
    requireAgentAuth,
    policyMode,
    policiesDir,
    metricsEnabled,
    dashboard,
    mcp,
    webhooks,
    maxBodySize,
    requestTimeout,
    maxConnectionsPerAgent,
    configFilePath: configFilePath ?? undefined,
  };
}
