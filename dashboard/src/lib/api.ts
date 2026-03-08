import type { Agent, AuditEntry, Credential, DashboardStats, HealthStatus, User } from '../types';

const BASE_URL = '/api';

async function fetchJson<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`);
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health(): Promise<HealthStatus> {
    return fetchJson('/health');
  },

  stats(since?: string): Promise<DashboardStats> {
    const params = since ? `?since=${encodeURIComponent(since)}` : '';
    return fetchJson(`/stats${params}`);
  },

  credentials(): Promise<Credential[]> {
    return fetchJson('/credentials');
  },

  agents(): Promise<Agent[]> {
    return fetchJson('/agents');
  },

  users(): Promise<User[]> {
    return fetchJson('/users');
  },

  requests(params?: {
    status?: string;
    service?: string;
    limit?: number;
    since?: string;
  }): Promise<AuditEntry[]> {
    const searchParams = new URLSearchParams();
    if (params?.status) searchParams.set('status', params.status);
    if (params?.service) searchParams.set('service', params.service);
    if (params?.limit) searchParams.set('limit', String(params.limit));
    if (params?.since) searchParams.set('since', params.since);
    const qs = searchParams.toString();
    return fetchJson(`/requests${qs ? `?${qs}` : ''}`);
  },
};
