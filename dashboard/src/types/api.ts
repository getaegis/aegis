// ─── Dashboard API Types ─────────────────────────────────────────
// Mirror of backend types for the dashboard REST API.

export interface AuditEntry {
  id: number;
  timestamp: string;
  credentialId: string | null;
  credentialName: string | null;
  service: string;
  targetDomain: string;
  method: string;
  path: string;
  status: 'allowed' | 'blocked' | 'system';
  blockedReason: string | null;
  responseCode: number | null;
  agentName: string | null;
  agentTokenPrefix: string | null;
  channel?: 'gate' | 'mcp';
}

export interface Credential {
  id: string;
  name: string;
  service: string;
  authType: string;
  headerName?: string;
  domains: string[];
  scopes: string[];
  expiresAt?: string;
  rateLimit?: string;
  bodyInspection: string;
  createdAt: string;
  updatedAt: string;
}

export interface Agent {
  id: string;
  name: string;
  tokenPrefix: string;
  rateLimit?: string;
  createdAt: string;
  updatedAt: string;
  grants: string[];
}

export interface User {
  id: string;
  name: string;
  role: 'admin' | 'operator' | 'viewer';
  tokenPrefix: string;
  createdAt: string;
  updatedAt: string;
}

export interface DashboardStats {
  total: number;
  allowed: number;
  blocked: number;
  system: number;
  byService: Record<string, number>;
}

export interface HealthStatus {
  status: string;
  version: string;
  uptime: number;
  gate: {
    running: boolean;
    port: number | null;
  };
}
