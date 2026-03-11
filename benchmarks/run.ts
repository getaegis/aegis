#!/usr/bin/env tsx
/**
 * Aegis Gate Benchmark Suite
 *
 * Starts a Gate proxy with a mock upstream and runs autocannon load tests.
 * Reports throughput and latency percentiles (p50, p90, p95, p99).
 *
 * Usage:
 *   yarn tsx benchmarks/run.ts
 *   yarn tsx benchmarks/run.ts --duration 30 --connections 50
 */

import autocannon from 'autocannon';
import Database from 'better-sqlite3-multiple-ciphers';
import * as http from 'node:http';
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

const DURATION = getArg('duration', 10); // seconds
const CONNECTIONS = getArg('connections', 20);
const PIPELINING = getArg('pipelining', 1);

// ─── Mock Upstream ───────────────────────────────────────────────────────────

const RESPONSE_BODY = JSON.stringify({ ok: true, ts: Date.now() });

function createUpstream(): Promise<http.Server> {
  return new Promise((resolve) => {
    const server = http.createServer((_req, res) => {
      res.writeHead(200, {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(RESPONSE_BODY).toString(),
      });
      res.end(RESPONSE_BODY);
    });
    server.listen(0, () => resolve(server));
  });
}

// ─── Benchmark Runner ────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log('╔══════════════════════════════════════════════╗');
  console.log('║       Aegis Gate Benchmark Suite             ║');
  console.log('╚══════════════════════════════════════════════╝');
  console.log();

  // Start mock upstream
  const upstreamServer = await createUpstream();
  const upstreamPort = (upstreamServer.address() as { port: number }).port;
  console.log(`  Upstream:    http://localhost:${upstreamPort}`);

  // Set up in-memory database + vault + ledger
  const db = new Database(':memory:');
  db.pragma('journal_mode = WAL');
  migrate(db);

  const vault = new Vault(db, 'benchmark-master-key');
  const ledger = new Ledger(db);

  // Add a test credential
  vault.add({
    name: 'bench-cred',
    service: 'bench-svc',
    secret: 'bench-api-key-12345',
    authType: 'bearer',
    domains: ['api.bench.com'],
  });

  // Start Gate
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
  console.log(`  Gate:        http://localhost:${gatePort}`);
  console.log(`  Duration:    ${DURATION}s`);
  console.log(`  Connections: ${CONNECTIONS}`);
  console.log(`  Pipelining:  ${PIPELINING}`);
  console.log();

  // Run autocannon
  console.log('  Running benchmark...\n');

  const result = await autocannon({
    url: `http://localhost:${gatePort}/bench-svc/v1/test`,
    duration: DURATION,
    connections: CONNECTIONS,
    pipelining: PIPELINING,
  });

  // Print results
  console.log('┌──────────────────────────────────────────────┐');
  console.log('│  Results                                     │');
  console.log('├──────────────────────────────────────────────┤');
  console.log(`│  Requests/sec:  ${result.requests.average.toFixed(0).padStart(10)}             │`);
  console.log(`│  Throughput:    ${formatBytes(result.throughput.average)}/s          │`);
  console.log('├──────────────────────────────────────────────┤');
  console.log('│  Latency (ms)                                │');
  console.log(`│    p50:         ${result.latency.p50.toFixed(2).padStart(10)}             │`);
  console.log(`│    p90:         ${result.latency.p90.toFixed(2).padStart(10)}             │`);
  console.log(`│    p97_5:       ${result.latency.p97_5.toFixed(2).padStart(10)}             │`);
  console.log(`│    p99:         ${result.latency.p99.toFixed(2).padStart(10)}             │`);
  console.log(`│    avg:         ${result.latency.average.toFixed(2).padStart(10)}             │`);
  console.log(`│    max:         ${result.latency.max.toFixed(2).padStart(10)}             │`);
  console.log('├──────────────────────────────────────────────┤');
  console.log(`│  Total:        ${result.requests.total.toString().padStart(11)} requests     │`);
  console.log(`│  Errors:       ${(result.errors ?? 0).toString().padStart(11)}              │`);
  console.log(`│  Timeouts:     ${(result.timeouts ?? 0).toString().padStart(11)}              │`);
  console.log(`│  Non-2xx:      ${(result.non2xx ?? 0).toString().padStart(11)}              │`);
  console.log('└──────────────────────────────────────────────┘');

  // Cleanup
  await gate.stop();
  upstreamServer.close();
  db.close();

  // Exit code: non-zero if error rate > 1%
  const errorRate = (result.errors ?? 0) / result.requests.total;
  if (errorRate > 0.01) {
    console.log('\n⚠  Error rate exceeds 1% — benchmark FAILED');
    process.exit(1);
  }
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes.toFixed(0)} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

main().catch((err) => {
  console.error('Benchmark failed:', err);
  process.exit(1);
});
