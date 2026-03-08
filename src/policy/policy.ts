import * as fs from 'node:fs';
import * as path from 'node:path';
import { parse as parseYaml } from 'yaml';

// ─── Types ───────────────────────────────────────────────────────

/**
 * Allowed HTTP methods in a policy rule.
 */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';

const VALID_METHODS: ReadonlySet<string> = new Set([
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'HEAD',
  'OPTIONS',
]);

/**
 * A time window restricting when a rule is active.
 */
export interface TimeWindow {
  /** Start time in HH:MM 24-hour format */
  start: string;
  /** End time in HH:MM 24-hour format */
  end: string;
  /** IANA timezone (e.g. "UTC", "America/New_York"). Defaults to "UTC". */
  timezone: string;
}

/**
 * A single policy rule — defines what an agent can do with a specific service.
 */
export interface PolicyRule {
  /** The service name this rule applies to (must match a credential's service) */
  service: string;
  /** Allowed HTTP methods. If omitted, all methods are allowed. */
  methods?: HttpMethod[];
  /** Allowed path patterns (regex strings). If omitted, all paths are allowed. */
  paths?: string[];
  /** Rate limit for this rule (e.g. "100/hour", "50/min"). Overrides credential-level limit. */
  rateLimit?: string;
  /** Optional time window restricting when this rule is active */
  timeWindow?: TimeWindow;
}

/**
 * A complete policy — binds an agent name to a set of rules.
 */
export interface Policy {
  /** The agent name this policy applies to */
  agent: string;
  /** The set of rules defining what this agent can do */
  rules: PolicyRule[];
}

/**
 * A validation error found when parsing or validating a policy file.
 */
export interface PolicyValidationError {
  /** The file path (if loaded from a file) */
  file?: string;
  /** Human-readable description of the error */
  message: string;
  /** The path to the offending field (e.g. "rules[0].methods[2]") */
  path?: string;
}

/**
 * Result of validating a policy (or set of policies).
 */
export interface PolicyValidationResult {
  valid: boolean;
  errors: PolicyValidationError[];
  /** The parsed policy, if valid */
  policy?: Policy;
  /** The source file path, if loaded from a file */
  filePath?: string;
}

// ─── Time format regex ────────────────────────────────────────────

const TIME_PATTERN = /^([01]\d|2[0-3]):([0-5]\d)$/;

// ─── Rate limit format regex ──────────────────────────────────────

const RATE_LIMIT_PATTERN = /^\d+\/(second|sec|min|minute|hour|hr|day)$/;

// ─── Validation ───────────────────────────────────────────────────

/**
 * Validate a single policy rule.
 */
function validateRule(rule: unknown, index: number, errors: PolicyValidationError[]): void {
  const prefix = `rules[${index}]`;

  if (typeof rule !== 'object' || rule === null) {
    errors.push({ message: `${prefix} must be an object`, path: prefix });
    return;
  }

  const r = rule as Record<string, unknown>;

  // service — required string
  if (typeof r.service !== 'string' || r.service.trim().length === 0) {
    errors.push({
      message: `${prefix}.service is required and must be a non-empty string`,
      path: `${prefix}.service`,
    });
  }

  // methods — optional array of valid HTTP methods
  if (r.methods !== undefined) {
    if (!Array.isArray(r.methods)) {
      errors.push({
        message: `${prefix}.methods must be an array of HTTP methods`,
        path: `${prefix}.methods`,
      });
    } else {
      for (let i = 0; i < r.methods.length; i++) {
        const m = r.methods[i];
        if (typeof m !== 'string' || !VALID_METHODS.has(m.toUpperCase())) {
          errors.push({
            message: `${prefix}.methods[${i}] "${String(m)}" is not a valid HTTP method. Allowed: ${[...VALID_METHODS].join(', ')}`,
            path: `${prefix}.methods[${i}]`,
          });
        }
      }
    }
  }

  // paths — optional array of regex strings
  if (r.paths !== undefined) {
    if (!Array.isArray(r.paths)) {
      errors.push({
        message: `${prefix}.paths must be an array of regex pattern strings`,
        path: `${prefix}.paths`,
      });
    } else {
      for (let i = 0; i < r.paths.length; i++) {
        const p = r.paths[i];
        if (typeof p !== 'string') {
          errors.push({
            message: `${prefix}.paths[${i}] must be a string`,
            path: `${prefix}.paths[${i}]`,
          });
        } else {
          try {
            new RegExp(p);
          } catch {
            errors.push({
              message: `${prefix}.paths[${i}] "${p}" is not a valid regular expression`,
              path: `${prefix}.paths[${i}]`,
            });
          }
        }
      }
    }
  }

  // rate_limit / rateLimit — optional string matching pattern
  const rateLimit = r.rate_limit ?? r.rateLimit;
  if (rateLimit !== undefined) {
    if (typeof rateLimit !== 'string' || !RATE_LIMIT_PATTERN.test(rateLimit)) {
      errors.push({
        message: `${prefix}.rate_limit "${String(rateLimit)}" is invalid. Expected format: "<number>/<unit>" (e.g. "100/hour", "50/min")`,
        path: `${prefix}.rate_limit`,
      });
    }
  }

  // time_window / timeWindow — optional object with start, end, timezone
  const timeWindow = r.time_window ?? r.timeWindow;
  if (timeWindow !== undefined) {
    if (typeof timeWindow !== 'object' || timeWindow === null) {
      errors.push({
        message: `${prefix}.time_window must be an object with start, end, and timezone`,
        path: `${prefix}.time_window`,
      });
    } else {
      const tw = timeWindow as Record<string, unknown>;

      if (typeof tw.start !== 'string' || !TIME_PATTERN.test(tw.start)) {
        errors.push({
          message: `${prefix}.time_window.start must be in HH:MM 24-hour format (e.g. "09:00")`,
          path: `${prefix}.time_window.start`,
        });
      }
      if (typeof tw.end !== 'string' || !TIME_PATTERN.test(tw.end)) {
        errors.push({
          message: `${prefix}.time_window.end must be in HH:MM 24-hour format (e.g. "18:00")`,
          path: `${prefix}.time_window.end`,
        });
      }
      if (tw.timezone !== undefined && typeof tw.timezone !== 'string') {
        errors.push({
          message: `${prefix}.time_window.timezone must be a string (IANA timezone)`,
          path: `${prefix}.time_window.timezone`,
        });
      }
      // Validate timezone is a real IANA zone
      if (typeof tw.timezone === 'string') {
        try {
          Intl.DateTimeFormat(undefined, { timeZone: tw.timezone });
        } catch {
          errors.push({
            message: `${prefix}.time_window.timezone "${tw.timezone}" is not a valid IANA timezone`,
            path: `${prefix}.time_window.timezone`,
          });
        }
      }
    }
  }
}

/**
 * Parse and validate a raw YAML string into a Policy.
 * Returns a validation result with errors (if any) and the parsed policy (if valid).
 */
export function parsePolicy(yamlContent: string, filePath?: string): PolicyValidationResult {
  const errors: PolicyValidationError[] = [];

  // Parse YAML
  let raw: unknown;
  try {
    raw = parseYaml(yamlContent);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      valid: false,
      errors: [{ file: filePath, message: `YAML parse error: ${message}` }],
      filePath,
    };
  }

  if (typeof raw !== 'object' || raw === null) {
    return {
      valid: false,
      errors: [{ file: filePath, message: 'Policy must be a YAML object' }],
      filePath,
    };
  }

  const doc = raw as Record<string, unknown>;

  // agent — required string
  if (typeof doc.agent !== 'string' || doc.agent.trim().length === 0) {
    errors.push({
      file: filePath,
      message: '"agent" is required and must be a non-empty string',
      path: 'agent',
    });
  }

  // rules — required non-empty array
  if (!Array.isArray(doc.rules)) {
    errors.push({
      file: filePath,
      message: '"rules" is required and must be an array',
      path: 'rules',
    });
  } else if (doc.rules.length === 0) {
    errors.push({
      file: filePath,
      message: '"rules" must contain at least one rule',
      path: 'rules',
    });
  } else {
    for (let i = 0; i < doc.rules.length; i++) {
      validateRule(doc.rules[i], i, errors);
    }
  }

  if (errors.length > 0) {
    // Attach file to all errors
    for (const err of errors) {
      err.file = err.file ?? filePath;
    }
    return { valid: false, errors, filePath };
  }

  // Build the validated Policy object
  const rules: PolicyRule[] = (doc.rules as Array<Record<string, unknown>>).map((r) => {
    const rule: PolicyRule = {
      service: r.service as string,
    };

    if (r.methods) {
      rule.methods = (r.methods as string[]).map((m) => m.toUpperCase() as HttpMethod);
    }

    if (r.paths) {
      rule.paths = r.paths as string[];
    }

    const rateLimitVal = r.rate_limit ?? r.rateLimit;
    if (rateLimitVal) {
      rule.rateLimit = rateLimitVal as string;
    }

    const timeWindowVal = r.time_window ?? r.timeWindow;
    if (timeWindowVal) {
      const tw = timeWindowVal as Record<string, unknown>;
      rule.timeWindow = {
        start: tw.start as string,
        end: tw.end as string,
        timezone: (tw.timezone as string) ?? 'UTC',
      };
    }

    return rule;
  });

  return {
    valid: true,
    errors: [],
    policy: {
      agent: doc.agent as string,
      rules,
    },
    filePath,
  };
}

/**
 * Load and validate a single policy file from disk.
 */
export function loadPolicyFile(filePath: string): PolicyValidationResult {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      valid: false,
      errors: [{ file: filePath, message: `Failed to read file: ${message}` }],
      filePath,
    };
  }

  return parsePolicy(content, filePath);
}

/**
 * Load all policy files from a directory (*.yaml and *.yml).
 * Returns an array of validation results, one per file.
 */
export function loadPoliciesFromDirectory(dirPath: string): PolicyValidationResult[] {
  if (!fs.existsSync(dirPath)) {
    return [
      {
        valid: false,
        errors: [{ message: `Policy directory does not exist: ${dirPath}` }],
      },
    ];
  }

  const stat = fs.statSync(dirPath);
  if (!stat.isDirectory()) {
    return [
      {
        valid: false,
        errors: [{ message: `Not a directory: ${dirPath}` }],
      },
    ];
  }

  const files = fs
    .readdirSync(dirPath)
    .filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'))
    .sort();

  if (files.length === 0) {
    return [];
  }

  const results: PolicyValidationResult[] = [];

  for (const file of files) {
    const fullPath = path.join(dirPath, file);
    results.push(loadPolicyFile(fullPath));
  }

  // Check for duplicate agent names across files
  const agentNames = new Map<string, string>();
  for (const result of results) {
    if (result.valid && result.policy) {
      const existing = agentNames.get(result.policy.agent);
      if (existing) {
        result.valid = false;
        result.errors.push({
          file: result.errors[0]?.file,
          message: `Duplicate policy for agent "${result.policy.agent}" — already defined in ${existing}`,
          path: 'agent',
        });
      } else {
        agentNames.set(result.policy.agent, result.errors[0]?.file ?? 'unknown');
      }
    }
  }

  return results;
}

/**
 * Build a map of agent name → Policy from a set of validation results.
 * Only includes valid policies.
 */
export function buildPolicyMap(results: PolicyValidationResult[]): Map<string, Policy> {
  const map = new Map<string, Policy>();
  for (const result of results) {
    if (result.valid && result.policy) {
      map.set(result.policy.agent, result.policy);
    }
  }
  return map;
}

// ─── Policy Evaluation ───────────────────────────────────────────

/**
 * The result of evaluating a request against a policy.
 */
export interface PolicyEvaluation {
  /** Whether the request is allowed by the policy */
  allowed: boolean;
  /** The specific rule that matched (if any) */
  matchedRule?: PolicyRule;
  /** If denied, the reason for the denial */
  reason?: string;
  /** The specific constraint that was violated (method, path, time_window, no_matching_rule) */
  violation?: 'method' | 'path' | 'time_window' | 'no_matching_rule';
}

/**
 * A request context to evaluate against a policy.
 */
export interface PolicyRequest {
  /** The service being accessed */
  service: string;
  /** The HTTP method */
  method: string;
  /** The request path (the part after /{service}/) */
  path: string;
  /** The current time — injectable for testing (defaults to new Date()) */
  now?: Date;
}

/**
 * Check if the current time falls within a time window.
 *
 * Handles midnight-spanning windows (e.g. 22:00 → 06:00).
 */
function isWithinTimeWindow(timeWindow: TimeWindow, now: Date): boolean {
  // Get the current time in the specified timezone
  const formatter = new Intl.DateTimeFormat('en-US', {
    timeZone: timeWindow.timezone,
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });

  const parts = formatter.formatToParts(now);
  const hourPart = parts.find((p) => p.type === 'hour');
  const minutePart = parts.find((p) => p.type === 'minute');
  const currentHour = parseInt(hourPart?.value ?? '0', 10);
  const currentMinute = parseInt(minutePart?.value ?? '0', 10);
  const currentMinutes = currentHour * 60 + currentMinute;

  const [startH, startM] = timeWindow.start.split(':').map(Number);
  const [endH, endM] = timeWindow.end.split(':').map(Number);
  const startMinutes = startH * 60 + startM;
  const endMinutes = endH * 60 + endM;

  if (startMinutes <= endMinutes) {
    // Normal window: e.g. 09:00 → 18:00
    return currentMinutes >= startMinutes && currentMinutes < endMinutes;
  }
  // Midnight-spanning window: e.g. 22:00 → 06:00
  return currentMinutes >= startMinutes || currentMinutes < endMinutes;
}

/**
 * Evaluate a request against a policy.
 *
 * Rules are matched by service name. If no rule matches the service,
 * the request is denied. If a rule matches, method and path constraints
 * are checked. If multiple rules match the same service, the request is
 * allowed if ANY rule permits it.
 *
 * Returns an evaluation result indicating whether the request is allowed
 * and, if not, why.
 */
export function evaluatePolicy(policy: Policy, request: PolicyRequest): PolicyEvaluation {
  const now = request.now ?? new Date();
  const method = request.method.toUpperCase();

  // Find all rules matching this service
  const matchingRules = policy.rules.filter((r) => r.service === request.service);

  if (matchingRules.length === 0) {
    return {
      allowed: false,
      reason: `No policy rule for service "${request.service}" — agent "${policy.agent}" is not permitted to access this service`,
      violation: 'no_matching_rule',
    };
  }

  // Try each matching rule — allowed if ANY rule permits the request
  const denials: { rule: PolicyRule; reason: string; violation: PolicyEvaluation['violation'] }[] =
    [];

  for (const rule of matchingRules) {
    // Check method restriction
    if (rule.methods && !rule.methods.includes(method as HttpMethod)) {
      denials.push({
        rule,
        reason: `Method ${method} not allowed — permitted: ${rule.methods.join(', ')}`,
        violation: 'method',
      });
      continue;
    }

    // Check path restriction
    if (rule.paths) {
      const pathMatch = rule.paths.some((pattern) => new RegExp(pattern).test(request.path));
      if (!pathMatch) {
        denials.push({
          rule,
          reason: `Path "${request.path}" does not match any allowed pattern: ${rule.paths.join(', ')}`,
          violation: 'path',
        });
        continue;
      }
    }

    // Check time window
    if (rule.timeWindow) {
      if (!isWithinTimeWindow(rule.timeWindow, now)) {
        denials.push({
          rule,
          reason: `Request outside allowed time window (${rule.timeWindow.start}–${rule.timeWindow.end} ${rule.timeWindow.timezone})`,
          violation: 'time_window',
        });
        continue;
      }
    }

    // All checks passed — this rule allows the request
    return {
      allowed: true,
      matchedRule: rule,
    };
  }

  // No rule allowed the request — use the most specific denial
  const denial = denials[0];
  return {
    allowed: false,
    matchedRule: denial.rule,
    reason: denial.reason,
    violation: denial.violation,
  };
}
