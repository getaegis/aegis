/**
 * Credentials — vault credential overview (metadata only, never values)
 *
 * Features:
 *   - Health segmented bar at top
 *   - Card per credential: name, service, domains, status badge, expiry
 *   - Grant count per credential
 */

import { KeyRound, Globe } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { StatusBadge } from '../components/ui/StatusBadge';
import { EmptyState } from '../components/ui/EmptyState';
import { useCredentials } from '../hooks/api/use-credentials';
import { useAgents } from '../hooks/api/use-agents';
import { formatRelativeTime } from '../lib/format';
import type { Credential } from '../types';

// ─── Helpers ─────────────────────────────────────────────────

function credentialStatus(cred: Credential): 'active' | 'expiring' | 'expired' {
  if (!cred.expiresAt) return 'active';
  const exp = new Date(cred.expiresAt).getTime();
  const now = Date.now();
  if (exp < now) return 'expired';
  if (exp - now < 7 * 24 * 60 * 60 * 1000) return 'expiring';
  return 'active';
}

function expiryLabel(cred: Credential): string | null {
  if (!cred.expiresAt) return null;
  const exp = new Date(cred.expiresAt).getTime();
  const now = Date.now();
  if (exp < now) return 'Expired';
  const days = Math.ceil((exp - now) / (24 * 60 * 60 * 1000));
  if (days <= 1) return 'Expires today';
  return `Expires in ${days}d`;
}

// ─── Credentials View ───────────────────────────────────────

export function Credentials(): React.ReactElement {
  const { data: credentials, isLoading } = useCredentials();
  const { data: agents } = useAgents();
  const creds = credentials ?? [];

  // Build a map of credential name → grant count
  const grantCounts = new Map<string, number>();
  if (agents) {
    for (const agent of agents) {
      for (const grant of agent.grants) {
        grantCounts.set(grant, (grantCounts.get(grant) ?? 0) + 1);
      }
    }
  }

  // Health bar stats
  const counts = { active: 0, expiring: 0, expired: 0 };
  for (const c of creds) {
    counts[credentialStatus(c)]++;
  }
  const total = creds.length;

  return (
    <div className={isLoading ? 'opacity-60' : ''}>
      {/* Health bar */}
      {total > 0 && (
        <Card className="mb-4">
          <div className="flex h-3 gap-0.5 overflow-hidden rounded-sm">
            {counts.active > 0 && (
              <div className="bg-allowed" style={{ width: `${(counts.active / total) * 100}%` }} />
            )}
            {counts.expiring > 0 && (
              <div className="bg-warning" style={{ width: `${(counts.expiring / total) * 100}%` }} />
            )}
            {counts.expired > 0 && (
              <div className="bg-blocked" style={{ width: `${(counts.expired / total) * 100}%` }} />
            )}
          </div>
          <div className="mt-2 flex gap-4 text-[12px]">
            <span className="text-allowed">{counts.active} active</span>
            {counts.expiring > 0 && <span className="text-warning">{counts.expiring} expiring</span>}
            {counts.expired > 0 && <span className="text-blocked">{counts.expired} expired</span>}
          </div>
        </Card>
      )}

      {/* Credential cards grid */}
      {creds.length === 0 ? (
        <EmptyState
          icon={KeyRound}
          title="No credentials stored"
          description="Add credentials via the CLI to see them here"
        />
      ) : (
        <div className="grid grid-cols-[repeat(auto-fit,minmax(320px,1fr))] gap-4">
          {creds.map((cred) => {
            const status = credentialStatus(cred);
            const expiry = expiryLabel(cred);
            const grants = grantCounts.get(cred.id) ?? 0;

            return (
              <Card key={cred.id}>
                <div className="flex items-start justify-between">
                  <div>
                    <h4 className="font-mono text-[14px] font-medium text-primary">{cred.name}</h4>
                    <p className="mt-0.5 text-[12px] text-secondary">{cred.service}</p>
                  </div>
                  <StatusBadge variant={status} />
                </div>

                <div className="mt-3 flex flex-col gap-1.5 text-[12px]">
                  <div className="flex items-center gap-2">
                    <Globe size={14} className="text-tertiary" aria-hidden="true" />
                    <span className="font-mono text-secondary">
                      {cred.domains.length > 0 ? cred.domains.join(', ') : 'No domains'}
                    </span>
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="text-tertiary">
                      {cred.authType} · {grants} agent{grants !== 1 ? 's' : ''}
                    </span>
                    {expiry && (
                      <span className={status === 'expired' ? 'text-blocked' : status === 'expiring' ? 'text-warning' : 'text-tertiary'}>
                        {expiry}
                      </span>
                    )}
                  </div>

                  <div className="text-tertiary">
                    Created {formatRelativeTime(cred.createdAt)}
                  </div>
                </div>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
