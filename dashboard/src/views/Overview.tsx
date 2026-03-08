/**
 * Overview — landing view answering "Is everything okay?"
 *
 * Layout:
 *   1. Stat cards row (Active Creds, Agents, Total Requests, Blocked 24h)
 *   2. Traffic chart placeholder (per-service bars)
 *   3. Two-column: Recent Requests | Credential Health + Top Agents
 */

import { KeyRound, Users, Activity, ShieldAlert } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { StatusBadge } from '../components/ui/StatusBadge';
import { useStats } from '../hooks/api/use-stats';
import { useCredentials } from '../hooks/api/use-credentials';
import { useAgents } from '../hooks/api/use-agents';
import { useRequests } from '../hooks/api/use-requests';
import { formatNumber } from '../lib/format';
import type { LucideIcon } from 'lucide-react';

// ─── Stat Card ───────────────────────────────────────────────

interface StatCardProps {
  icon: LucideIcon;
  label: string;
  value: string | number;
  iconColor?: string;
}

function StatCard({ icon: Icon, label, value, iconColor = 'text-secondary' }: StatCardProps): React.ReactElement {
  return (
    <Card>
      <div className="flex items-center gap-3">
        <div className={`rounded-md bg-surface-2 p-2 ${iconColor}`}>
          <Icon size={20} aria-hidden="true" />
        </div>
        <div>
          <p className="text-[12px] uppercase tracking-wider text-secondary">{label}</p>
          <p className="text-[24px] font-semibold leading-8 text-primary">{value}</p>
        </div>
      </div>
    </Card>
  );
}

// ─── Service Bar (lightweight SVG) ──────────────────────────

const SERVICE_COLORS = ['#4A90D9', '#C8973E', '#34A853', '#9B6DB7', '#D97B3A', '#5BB5A2', '#D4616E', '#7B8FA1'];

function ServiceBars({ byService }: { byService: Record<string, number> }): React.ReactElement {
  const entries = Object.entries(byService).sort((a, b) => b[1] - a[1]);
  const max = entries[0]?.[1] ?? 1;

  return (
    <div className="flex flex-col gap-2">
      {entries.map(([service, count], i) => (
        <div key={service} className="flex items-center gap-3">
          <span className="w-24 text-right font-mono text-[12px] text-secondary truncate">{service}</span>
          <div className="flex-1 h-5 rounded-sm bg-surface-2 overflow-hidden">
            <div
              className="h-full rounded-sm transition-all duration-150"
              style={{
                width: `${(count / max) * 100}%`,
                backgroundColor: SERVICE_COLORS[i % SERVICE_COLORS.length],
              }}
            />
          </div>
          <span className="w-12 text-right font-mono text-[12px] text-tertiary">
            {formatNumber(count)}
          </span>
        </div>
      ))}
      {entries.length === 0 && (
        <p className="py-4 text-center text-[13px] text-tertiary">No traffic yet</p>
      )}
    </div>
  );
}

// ─── Credential Health Bar ──────────────────────────────────

function CredentialHealthBar(): React.ReactElement {
  const { data: credentials } = useCredentials();
  const creds = credentials ?? [];

  const now = Date.now();
  const WEEK = 7 * 24 * 60 * 60 * 1000;

  let active = 0;
  let expiring = 0;
  let expired = 0;

  for (const c of creds) {
    if (!c.expiresAt) {
      active++;
    } else {
      const exp = new Date(c.expiresAt).getTime();
      if (exp < now) expired++;
      else if (exp - now < WEEK) expiring++;
      else active++;
    }
  }

  const total = active + expiring + expired;
  if (total === 0) {
    return <p className="text-[13px] text-tertiary">No credentials stored</p>;
  }

  return (
    <div>
      {/* Segmented bar */}
      <div className="flex h-3 gap-0.5 overflow-hidden rounded-sm">
        {active > 0 && (
          <div className="bg-allowed" style={{ width: `${(active / total) * 100}%` }} />
        )}
        {expiring > 0 && (
          <div className="bg-warning" style={{ width: `${(expiring / total) * 100}%` }} />
        )}
        {expired > 0 && (
          <div className="bg-blocked" style={{ width: `${(expired / total) * 100}%` }} />
        )}
      </div>
      {/* Legend */}
      <div className="mt-2 flex gap-4 text-[12px]">
        <span className="text-allowed">{active} active</span>
        {expiring > 0 && <span className="text-warning">{expiring} expiring</span>}
        {expired > 0 && <span className="text-blocked">{expired} expired</span>}
      </div>
    </div>
  );
}

// ─── Overview ───────────────────────────────────────────────

export function Overview(): React.ReactElement {
  const { data: stats, isLoading: statsLoading } = useStats();
  const { data: credentials } = useCredentials();
  const { data: agents } = useAgents();
  const { data: requests } = useRequests({ limit: 8, refetchInterval: 5_000 });

  const recentRequests = requests ?? [];

  return (
    <div className={statsLoading ? 'opacity-60' : ''}>
      {/* Stat cards */}
      <div className="grid grid-cols-[repeat(auto-fit,minmax(200px,1fr))] gap-4">
        <StatCard
          icon={KeyRound}
          label="Active Creds"
          value={credentials?.length ?? '—'}
          iconColor="text-gold"
        />
        <StatCard
          icon={Users}
          label="Agents"
          value={agents?.length ?? '—'}
          iconColor="text-info"
        />
        <StatCard
          icon={Activity}
          label="Total Requests"
          value={stats ? formatNumber(stats.total) : '—'}
        />
        <StatCard
          icon={ShieldAlert}
          label="Blocked"
          value={stats ? formatNumber(stats.blocked) : '—'}
          iconColor="text-blocked"
        />
      </div>

      {/* Traffic by service */}
      <Card title="Traffic by Service" className="mt-4">
        {stats?.byService ? (
          <ServiceBars byService={stats.byService} />
        ) : (
          <p className="py-4 text-center text-[13px] text-tertiary">Loading...</p>
        )}
      </Card>

      {/* Two-column: Recent Requests | Health + Top Agents */}
      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Recent Requests */}
        <Card title="Recent Requests">
          <div className="flex flex-col">
            {recentRequests.length === 0 && (
              <p className="py-4 text-center text-[13px] text-tertiary">No requests yet</p>
            )}
            {recentRequests.map((req) => (
              <div
                key={req.id}
                className={`flex items-center gap-3 border-t border-border-sub px-1 py-2 first:border-t-0 ${
                  req.status === 'blocked' ? 'bg-blocked-bg' : ''
                }`}
              >
                <span className="w-12 font-mono text-[12px] font-medium text-primary">
                  {req.method}
                </span>
                <span className="flex-1 truncate font-mono text-[12px] text-secondary">
                  {req.path}
                </span>
                <span className="font-mono text-[12px] text-tertiary">{req.service}</span>
                <StatusBadge variant={req.status === 'allowed' ? 'allowed' : req.status === 'system' ? 'system' : 'blocked'} />
              </div>
            ))}
          </div>
        </Card>

        {/* Right column: Credential Health + Top Agents */}
        <div className="flex flex-col gap-4">
          <Card title="Credential Health">
            <CredentialHealthBar />
          </Card>

          <Card title="Top Agents">
            {agents && agents.length > 0 ? (
              <div className="flex flex-col gap-2">
                {agents.slice(0, 5).map((agent) => (
                  <div key={agent.id} className="flex items-center justify-between">
                    <span className="font-mono text-[13px] text-primary">{agent.name}</span>
                    <span className="text-[12px] text-tertiary">
                      {agent.grants.length} grant{agent.grants.length !== 1 ? 's' : ''}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-[13px] text-tertiary">No agents registered</p>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}
