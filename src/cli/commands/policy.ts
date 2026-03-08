/**
 * Policy commands: validate, list, test.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Command } from 'commander';
import { evaluatePolicy, loadPoliciesFromDirectory, loadPolicyFile } from '../../policy/index.js';

export function register(program: Command): void {
  const policyCmd = program.command('policy').description('Manage and validate policy files');

  policyCmd
    .command('validate')
    .description('Validate policy files for syntax and schema errors')
    .argument('<path>', 'Path to a YAML policy file or directory of policy files')
    .action((filePath: string) => {
      const resolved = path.resolve(filePath);

      if (!fs.existsSync(resolved)) {
        console.error(`\n✗ Path not found: ${resolved}\n`);
        process.exit(1);
      }

      const stat = fs.statSync(resolved);
      const results = stat.isDirectory()
        ? loadPoliciesFromDirectory(resolved)
        : [loadPolicyFile(resolved)];

      let hasErrors = false;

      for (const result of results) {
        if (result.valid) {
          console.log(`  ✓ ${result.filePath ?? 'inline'}: valid (agent: ${result.policy?.agent})`);
        } else {
          hasErrors = true;
          console.log(`  ✗ ${result.filePath ?? 'inline'}: invalid`);
          for (const err of result.errors) {
            console.log(`    - ${err.message}`);
          }
        }
      }

      console.log(
        `\n  ${results.filter((r) => r.valid).length}/${results.length} policy file(s) valid.\n`,
      );

      if (hasErrors) {
        process.exit(1);
      }
    });

  policyCmd
    .command('list')
    .description('List all policies and their rules')
    .argument('<path>', 'Path to a policy file or directory')
    .action((filePath: string) => {
      const resolved = path.resolve(filePath);

      if (!fs.existsSync(resolved)) {
        console.error(`\n✗ Path not found: ${resolved}\n`);
        process.exit(1);
      }

      const stat = fs.statSync(resolved);
      const results = stat.isDirectory()
        ? loadPoliciesFromDirectory(resolved)
        : [loadPolicyFile(resolved)];

      const valid = results.filter((r) => r.valid && r.policy);

      if (valid.length === 0) {
        console.log('\n  No valid policy files found.\n');
        return;
      }

      console.log(`\n  ${valid.length} policy(ies):\n`);

      for (const result of valid) {
        const policy = result.policy;
        if (!policy) continue;

        console.log(`  Agent: ${policy.agent}`);
        if (policy.rules.length === 0) {
          console.log('    (no rules)');
        }
        for (const rule of policy.rules) {
          const methods = rule.methods ? rule.methods.join(', ') : '*';
          const paths = rule.paths ? rule.paths.join(', ') : '*';
          const rateLimit = rule.rateLimit ?? 'none';
          console.log(`    → ${rule.service}`);
          console.log(`      methods: ${methods}`);
          console.log(`      paths:   ${paths}`);
          console.log(`      rate:    ${rateLimit}`);
          if (rule.timeWindow) {
            console.log(
              `      time:    ${rule.timeWindow.start}–${rule.timeWindow.end} (${rule.timeWindow.timezone})`,
            );
          }
        }
        console.log();
      }
    });

  policyCmd
    .command('test')
    .description("Test a request against an agent's policy")
    .requiredOption('-a, --agent <name>', 'Agent name to test against')
    .requiredOption('-s, --service <service>', 'Service being accessed')
    .requiredOption('-m, --method <method>', 'HTTP method (GET, POST, etc.)')
    .requiredOption('--path <path>', 'Request path')
    .argument('<policyPath>', 'Path to a policy file or directory')
    .action(
      (
        policyPath: string,
        opts: { agent: string; service: string; method: string; path: string },
      ) => {
        const resolved = path.resolve(policyPath);

        if (!fs.existsSync(resolved)) {
          console.error(`\n✗ Path not found: ${resolved}\n`);
          process.exit(1);
        }

        const stat = fs.statSync(resolved);
        const results = stat.isDirectory()
          ? loadPoliciesFromDirectory(resolved)
          : [loadPolicyFile(resolved)];

        const valid = results.filter((r) => r.valid && r.policy);
        const agentPolicy = valid.find((r) => r.policy?.agent === opts.agent);

        if (!agentPolicy?.policy) {
          console.error(`\n✗ No valid policy found for agent "${opts.agent}"\n`);
          process.exit(1);
        }

        const evaluation = evaluatePolicy(agentPolicy.policy, {
          service: opts.service,
          method: opts.method,
          path: opts.path,
        });

        if (evaluation.allowed) {
          console.log(`\n  ✓ ALLOWED — request matches policy for agent "${opts.agent}"`);
          if (evaluation.matchedRule) {
            console.log(`    Matched rule for service: ${evaluation.matchedRule.service}`);
          }
        } else {
          console.log(`\n  ✗ DENIED — ${evaluation.reason}`);
          console.log(`    Violation type: ${evaluation.violation}`);
        }
        console.log();
      },
    );
}
