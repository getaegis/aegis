import * as fs from 'node:fs';
import * as http from 'node:http';
import * as path from 'node:path';
import type pino from 'pino';
import { WebSocketServer } from 'ws';
import type { AgentRegistry } from '../agent/index.js';
import type { Ledger, LedgerQuery } from '../ledger/index.js';
import { createLogger } from '../logger/index.js';
import type { UserRegistry } from '../user/index.js';
import type { Vault } from '../vault/index.js';
import { VERSION } from '../version.js';

// ─── Types ───────────────────────────────────────────────────────

export interface DashboardServerOptions {
  /** Port to serve the dashboard on (default: 3200) */
  port: number;
  /** Vault instance for listing credentials */
  vault: Vault;
  /** Ledger for audit log queries and stats */
  ledger: Ledger;
  /** Agent registry for listing agents and grants */
  agentRegistry: AgentRegistry;
  /** User registry for listing RBAC users (optional — RBAC may not be active) */
  userRegistry?: UserRegistry;
  /** Whether Gate is currently running */
  gateRunning: boolean;
  /** Gate port (if running) */
  gatePort: number | null;
  /** Log level */
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
  /** Path to built dashboard static files (default: dist/dashboard) */
  staticDir?: string;
  /** Server start time (for uptime calculation) */
  startTime?: number;
}

// ─── MIME Types ──────────────────────────────────────────────────

const MIME_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.map': 'application/json',
};

// ─── Dashboard Server ───────────────────────────────────────────

/**
 * Dashboard HTTP server — serves the React dashboard and exposes
 * REST API endpoints for credentials, agents, audit log, and stats.
 *
 * Also provides a WebSocket endpoint (/ws) for live audit feed
 * using the `ws` library for reliable frame handling and heartbeats.
 */
export class DashboardServer {
  private server: http.Server | null = null;
  private wss: WebSocketServer | null = null;
  private port: number;
  private vault: Vault;
  private ledger: Ledger;
  private agentRegistry: AgentRegistry;
  private userRegistry: UserRegistry | undefined;
  private gateRunning: boolean;
  private gatePort: number | null;
  private logger: pino.Logger;
  private staticDir: string;
  private startTime: number;

  constructor(options: DashboardServerOptions) {
    this.port = options.port;
    this.vault = options.vault;
    this.ledger = options.ledger;
    this.agentRegistry = options.agentRegistry;
    this.userRegistry = options.userRegistry;
    this.gateRunning = options.gateRunning;
    this.gatePort = options.gatePort;
    this.startTime = options.startTime ?? Date.now();
    this.logger = createLogger({
      module: 'dashboard',
      level: options.logLevel ?? 'info',
    });

    // Static files: look for built dashboard assets
    // Frontend lives in a `public/` subdirectory to avoid colliding
    // with tsc-compiled backend files in the same dist/dashboard/ folder.
    if (options.staticDir) {
      this.staticDir = options.staticDir;
    } else {
      const thisDir = path.dirname(new URL(import.meta.url).pathname);
      // Production: dist/dashboard/dashboard-server.js → dist/dashboard/public
      const prodPath = path.resolve(thisDir, 'public');
      // Development (tsx): src/dashboard/dashboard-server.ts → ../../dashboard/dist
      const devPath = path.resolve(thisDir, '..', '..', 'dashboard', 'dist');

      if (fs.existsSync(path.join(prodPath, 'index.html'))) {
        this.staticDir = prodPath;
      } else {
        this.staticDir = devPath;
      }
    }
  }

  /**
   * Update the Gate running status (for health endpoint).
   */
  setGateStatus(running: boolean, port: number | null): void {
    this.gateRunning = running;
    this.gatePort = port;
  }

  /**
   * Broadcast an audit entry to all connected WebSocket clients.
   * Called from Gate after each request is logged.
   */
  broadcast(entry: {
    id?: number;
    timestamp: string;
    credentialId?: string | null;
    credentialName?: string | null;
    service: string;
    targetDomain: string;
    method: string;
    path: string;
    status: 'allowed' | 'blocked' | 'system';
    blockedReason?: string | null;
    responseCode?: number | null;
    agentName?: string | null;
    agentTokenPrefix?: string | null;
    channel?: 'gate' | 'mcp';
  }): void {
    if (!this.wss || this.wss.clients.size === 0) return;

    const message = JSON.stringify(entry);

    for (const client of this.wss.clients) {
      if (client.readyState === client.OPEN) {
        client.send(message);
      }
    }
  }

  /**
   * Start the dashboard server.
   */
  start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = http.createServer((req, res) => {
        this.handleRequest(req, res);
      });

      // WebSocket server — attached to the HTTP server, only accepts /ws path
      this.wss = new WebSocketServer({ noServer: true });

      this.wss.on('connection', (ws) => {
        this.logger.debug({ clients: this.wss?.clients.size }, 'WebSocket client connected');

        ws.on('close', () => {
          this.logger.debug({ clients: this.wss?.clients.size }, 'WebSocket client disconnected');
        });
      });

      // Handle upgrade — route /ws to the WebSocket server, reject others
      this.server.on('upgrade', (req, socket, head) => {
        const url = new URL(req.url ?? '/', `http://localhost:${this.port}`);
        if (url.pathname === '/ws' && this.wss) {
          this.wss.handleUpgrade(req, socket, head, (ws) => {
            this.wss?.emit('connection', ws, req);
          });
        } else {
          socket.destroy();
        }
      });

      this.server.listen(this.port, () => {
        const addr = this.server?.address();
        if (addr && typeof addr === 'object') {
          this.port = addr.port;
        }
        this.logger.info(
          { port: this.port },
          `Aegis Dashboard listening on http://localhost:${this.port}`,
        );
        resolve();
      });
    });
  }

  /**
   * The port the dashboard server is listening on.
   */
  get listeningPort(): number {
    return this.port;
  }

  /**
   * Stop the dashboard server.
   */
  stop(): Promise<void> {
    return new Promise((resolve) => {
      // Close all WebSocket connections
      if (this.wss) {
        for (const client of this.wss.clients) {
          client.close();
        }
        this.wss.close();
        this.wss = null;
      }

      if (!this.server) {
        resolve();
        return;
      }

      this.server.close(() => {
        this.server = null;
        this.logger.info('Dashboard server stopped');
        resolve();
      });
    });
  }

  // ─── HTTP Request Handler ──────────────────────────────────────

  private handleRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    const url = new URL(req.url ?? '/', `http://localhost:${this.port}`);

    // CORS headers for development (Vite dev server)
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // Route API requests
    if (url.pathname.startsWith('/api/')) {
      this.handleApiRequest(url, res);
      return;
    }

    // Serve static files
    this.serveStatic(url.pathname, res);
  }

  // ─── API Routes ────────────────────────────────────────────────

  private handleApiRequest(url: URL, res: http.ServerResponse): void {
    const apiPath = url.pathname.slice('/api'.length); // e.g. "/health"

    try {
      switch (apiPath) {
        case '/health':
          this.handleHealth(res);
          break;
        case '/stats':
          this.handleStats(url, res);
          break;
        case '/credentials':
          this.handleCredentials(res);
          break;
        case '/agents':
          this.handleAgents(res);
          break;
        case '/requests':
          this.handleRequests(url, res);
          break;
        case '/users':
          this.handleUsers(res);
          break;
        default:
          this.json(res, 404, { error: 'Not found' });
      }
    } catch (err) {
      this.logger.error({ err, path: apiPath }, 'API error');
      this.json(res, 500, { error: 'Internal server error' });
    }
  }

  private handleHealth(res: http.ServerResponse): void {
    this.json(res, 200, {
      status: 'ok',
      version: VERSION,
      uptime: Math.floor((Date.now() - this.startTime) / 1000),
      gate: {
        running: this.gateRunning,
        port: this.gatePort,
      },
    });
  }

  private handleStats(url: URL, res: http.ServerResponse): void {
    const since = url.searchParams.get('since') ?? undefined;
    const stats = this.ledger.stats(since);
    this.json(res, 200, stats);
  }

  private handleCredentials(res: http.ServerResponse): void {
    const credentials = this.vault.list();
    this.json(res, 200, credentials);
  }

  private handleAgents(res: http.ServerResponse): void {
    const agents = this.agentRegistry.list();
    // Enrich with grant info
    const enriched = agents.map((agent) => {
      let grants: string[] = [];
      try {
        grants = this.agentRegistry.listGrants(agent.name);
      } catch {
        // Agent may have been removed mid-request
      }
      return { ...agent, grants };
    });
    this.json(res, 200, enriched);
  }

  private handleRequests(url: URL, res: http.ServerResponse): void {
    const query: LedgerQuery = {};

    const status = url.searchParams.get('status');
    if (status === 'allowed' || status === 'blocked' || status === 'system') {
      query.status = status;
    }

    const service = url.searchParams.get('service');
    if (service) query.service = service;

    const limit = url.searchParams.get('limit');
    if (limit) query.limit = Math.min(parseInt(limit, 10) || 50, 500);

    const since = url.searchParams.get('since');
    if (since) query.since = since;

    const agentName = url.searchParams.get('agent');
    if (agentName) query.agentName = agentName;

    const entries = this.ledger.query(query);
    this.json(res, 200, entries);
  }

  private handleUsers(res: http.ServerResponse): void {
    if (!this.userRegistry) {
      this.json(res, 200, []);
      return;
    }
    const users = this.userRegistry.list();
    this.json(res, 200, users);
  }

  // ─── Static File Serving ───────────────────────────────────────

  private serveStatic(pathname: string, res: http.ServerResponse): void {
    // Normalise path: /foo → /foo, / → /index.html
    const filePath = pathname === '/' ? '/index.html' : pathname;

    // Security: prevent directory traversal
    const resolved = path.resolve(this.staticDir, `.${filePath}`);
    if (!resolved.startsWith(this.staticDir)) {
      this.json(res, 403, { error: 'Forbidden' });
      return;
    }

    // Try to serve the file
    if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) {
      const ext = path.extname(resolved);
      const contentType = MIME_TYPES[ext] ?? 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': contentType });
      fs.createReadStream(resolved).pipe(res);
      return;
    }

    // SPA fallback: serve index.html for unmatched routes
    const indexPath = path.join(this.staticDir, 'index.html');
    if (fs.existsSync(indexPath)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      fs.createReadStream(indexPath).pipe(res);
      return;
    }

    // No static files built yet
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!DOCTYPE html>
<html>
<head><title>Aegis Dashboard</title></head>
<body style="background:#0F1117;color:#E8E6E1;font-family:Inter,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
  <div style="text-align:center">
    <h1 style="color:#C8973E">Aegis Dashboard</h1>
    <p>Dashboard not built yet. Run:</p>
    <pre style="background:#1A1C24;padding:16px;border-radius:6px;color:#C8973E">cd dashboard && yarn install && yarn build</pre>
  </div>
</body>
</html>`);
  }

  // ─── JSON Response Helper ─────────────────────────────────────

  private json(res: http.ServerResponse, status: number, data: unknown): void {
    const body = JSON.stringify(data);
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': Buffer.byteLength(body),
    });
    res.end(body);
  }
}
