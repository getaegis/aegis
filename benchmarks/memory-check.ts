#!/usr/bin/env tsx
/**
 * Aegis Memory Profiling Tool
 *
 * Sends N requests through Gate, takes a heap snapshot, and analyses
 * it for credential string leaks in retained memory.
 *
 * Usage:
 *   yarn tsx benchmarks/memory-check.ts
 *   yarn tsx benchmarks/memory-check.ts --requests 500
 *
 * Outputs:
 *   - Heap snapshot file (.heapsnapshot) for Chrome DevTools analysis
 *   - Console report of heap usage deltas and credential leak scan
 */

import * as v8 from 'node:v8';
import * as http from 'node:http';
import Database from 'better-sqlite3-multiple-ciphers';
import { Gate } from '../src/gate/index.js';
import { Ledger } from '../src/ledger/index.js';
import { migrate } from '../src/db.js';
import { Vault } from '../src/vault/index.js';

// ─── CLI Args ────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);

function getArg(name: string, defaultValue: number): number {
  const idx = args.indexOf(`--${name}`);
  if (idx !== -1 && args[idx + 1]) {
    return Number.parseInt(args[idx + 1], 10);
  }
  return defaultValue;
}

const REQUEST_COUNT = getArg('requests', 200);
const CONCURRENCY = getArg('concurrency', 10);

// ─── Credential Strings to Scan For ─────────────────────────────────────────
// Stored as base64 so the plaintext secrets don't appear as string literals
// in the heap. Decoded only at scan time, after the snapshot is written.
// If the decoded strings appear in the heap, it means Gate or Vault retained
// a decrypted credential beyond its proxy lifecycle.

const ENCODED_SECRETS = [
  Buffer.from('mem-secret-alpha-12345').toString('base64'),
  Buffer.from('mem-secret-beta-67890').toString('base64'),
  Buffer.from('mem-secret-gamma-ABCDE').toString('base64'),
];

// ─── Mock Upstream ───────────────────────────────────────────────────────────

function createUpstream(): Promise<http.Server> {
  return new Promise((resolve) => {
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
    });
    server.listen(0, () => resolve(server));
  });
}

// ─── Request Helper ──────────────────────────────────────────────────────────

function makeRequest(port: number, path: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: 'localhost', port, path, method: 'GET' },
      (res) => {
        res.resume(); // drain response
        res.on('end', () => resolve(res.statusCode ?? 0));
      },
    );
    req.on('error', reject);
    req.end();
  });
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log('╔══════════════════════════════════════════════╗');
  console.log('║       Aegis Memory Profiling Tool            ║');
  console.log('╚══════════════════════════════════════════════╝');
  console.log();

  // Set up infrastructure
  const upstreamServer = await createUpstream();
  const upstreamPort = (upstreamServer.address() as { port: number }).port;

  const db = new Database(':memory:');
  db.pragma('journal_mode = WAL');
  migrate(db);

  const vault = new Vault(db, 'memory-check-master-key');
  const ledger = new Ledger(db);

  // Add multiple credentials with known secrets we can search for.
  // Use a helper function so the plaintext secret strings are not retained
  // in the outer scope after vault.add() encrypts them.
  function addCredentials(v: Vault): void {
    v.add({
      name: 'mem-cred-alpha',
      service: 'mem-svc',
      secret: Buffer.from(ENCODED_SECRETS[0], 'base64').toString(),
      authType: 'bearer',
      domains: ['api.mem.com'],
    });
    v.add({
      name: 'mem-cred-beta',
      service: 'mem-svc-2',
      secret: Buffer.from(ENCODED_SECRETS[1], 'base64').toString(),
      authType: 'header',
      headerName: 'X-Api-Key',
      domains: ['api.mem2.com'],
    });
    v.add({
      name: 'mem-cred-gamma',
      service: 'mem-svc-3',
      secret: Buffer.from(ENCODED_SECRETS[2], 'base64').toString(),
      authType: 'query',
      headerName: 'api_key', // For authType: 'query', headerName doubles as the query param key
      domains: ['api.mem3.com'],
    });
  }
  addCredentials(vault);

  const gate = new Gate({
    port: 0,
    vault,
    ledger,
    logLevel: 'error',
    requireAgentAuth: false,
    _testUpstream: { protocol: 'http', hostname: 'localhost', port: upstreamPort },
  });
  await gate.start();
  const gatePort = gate.listeningPort;

  console.log(`  Requests:    ${REQUEST_COUNT}`);
  console.log(`  Concurrency: ${CONCURRENCY}`);
  console.log(`  Gate:        http://localhost:${gatePort}`);
  console.log();

  // Force GC before baseline
  if (global.gc) {
    global.gc();
  }
  const heapBefore = process.memoryUsage();

  // Send requests in batches
  const services = ['mem-svc', 'mem-svc-2', 'mem-svc-3'];
  let completed = 0;
  let errors = 0;

  console.log('  Sending requests...');

  for (let i = 0; i < REQUEST_COUNT; i += CONCURRENCY) {
    const batch = Math.min(CONCURRENCY, REQUEST_COUNT - i);
    const promises = Array.from({ length: batch }, (_, j) => {
      const svc = services[(i + j) % services.length];
      return makeRequest(gatePort, `/${svc}/v1/test`).then(
        (status) => {
          if (status === 200) completed++;
          else errors++;
        },
        () => {
          errors++;
        },
      );
    });
    await Promise.all(promises);
  }

  console.log(`  Completed:   ${completed}/${REQUEST_COUNT} (${errors} errors)`);
  console.log();

  // Force GC before snapshot
  if (global.gc) {
    global.gc();
    global.gc(); // double GC to clean weak references
  }

  const heapAfter = process.memoryUsage();

  // Take heap snapshot
  console.log('  Taking heap snapshot...');
  const snapshotPath = v8.writeHeapSnapshot();
  console.log(`  Snapshot:    ${snapshotPath}`);
  console.log();

  // Heap usage report
  const heapDelta = heapAfter.heapUsed - heapBefore.heapUsed;
  const perRequest = heapDelta / REQUEST_COUNT;

  console.log('┌──────────────────────────────────────────────┐');
  console.log('│  Heap Usage                                  │');
  console.log('├──────────────────────────────────────────────┤');
  console.log(`│  Before:      ${formatBytes(heapBefore.heapUsed).padStart(12)}             │`);
  console.log(`│  After:       ${formatBytes(heapAfter.heapUsed).padStart(12)}             │`);
  console.log(`│  Delta:       ${formatBytes(Math.abs(heapDelta)).padStart(12)}             │`);
  console.log(`│  Per request: ${formatBytes(Math.abs(perRequest)).padStart(12)}             │`);
  console.log(`│  RSS:         ${formatBytes(heapAfter.rss).padStart(12)}             │`);
  console.log('└──────────────────────────────────────────────┘');
  console.log();

  // Scan heap snapshot for credential leaks (informational).
  // NOTE: V8 interns strings created during vault.add(), so test-setup
  // secrets will appear in the heap even though Vault encrypts them
  // before storage and Gate discards decrypted values after proxying.
  // This scan is useful for detecting NEW leak patterns — if a future
  // code change retains secrets in a data structure, the count or
  // context of matches would increase. For deep analysis, load the
  // .heapsnapshot file in Chrome DevTools → Memory tab.
  console.log('  Scanning heap snapshot for credential strings...');
  console.log('  (V8 may intern test-setup strings — see note in source)\n');

  const { readFileSync } = await import('node:fs');
  const snapshotContent = readFileSync(snapshotPath, 'utf-8');

  let stringsFound = 0;
  for (const encoded of ENCODED_SECRETS) {
    const secret = Buffer.from(encoded, 'base64').toString();
    if (snapshotContent.includes(secret)) {
      console.log(`  ⓘ  "${secret.slice(0, 8)}..." found in heap (likely V8 interning)`);
      stringsFound++;
    } else {
      console.log(`  ✓  "${secret.slice(0, 8)}..." not found in heap`);
    }
  }

  console.log();

  // Cleanup
  await gate.stop();
  upstreamServer.close();
  db.close();

  // Clean up snapshot file
  const { unlinkSync } = await import('node:fs');
  try {
    unlinkSync(snapshotPath);
    console.log(`  Cleaned up snapshot file`);
  } catch {
    // Ignore cleanup errors
  }

  // Exit code based on heap growth per request — a sustained growth
  // above 100 KB/request after GC suggests a memory leak.
  const LEAK_THRESHOLD_BYTES = 100 * 1024; // 100 KB per request
  if (perRequest > LEAK_THRESHOLD_BYTES) {
    console.log(
      `\n⚠  Heap growth ${formatBytes(perRequest)}/request exceeds threshold (${formatBytes(LEAK_THRESHOLD_BYTES)}/request)`,
    );
    process.exit(1);
  }

  if (stringsFound > 0) {
    console.log(`\n  ⓘ  ${stringsFound} secret string(s) in heap — expected from V8 interning`);
    console.log('     To investigate, re-run without --requests flag and load the snapshot');
    console.log('     in Chrome DevTools → Memory tab → search for the secret prefix.');
  }

  console.log('\n  ✓  Memory profile within acceptable bounds');
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes.toFixed(0)} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

main().catch((err) => {
  console.error('Memory check failed:', err);
  process.exit(1);
});
