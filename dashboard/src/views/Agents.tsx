/**
 * Agents — registered agent list with activity summary
 *
 * Features:
 *   - Table: agent name, token prefix, rate limit, grant count, created
 *   - Click to expand: granted credentials list
 *   - Active/inactive status based on registration
 */

import React, { useState } from 'react';
import { Users } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { StatusBadge } from '../components/ui/StatusBadge';
import { EmptyState } from '../components/ui/EmptyState';
import { useAgents } from '../hooks/api/use-agents';
import { formatRelativeTime } from '../lib/format';
import type { Agent } from '../types';

// ─── Expanded Agent Detail ──────────────────────────────────

function AgentDetail({ agent }: { agent: Agent }): React.ReactElement {
  return (
    <div className="border-t border-border-sub bg-surface-2 px-4 py-3 text-[12px]">
      <div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-secondary">
        Granted Credentials
      </div>
      {agent.grants.length > 0 ? (
        <div className="flex flex-wrap gap-2">
          {agent.grants.map((grant) => (
            <span
              key={grant}
              className="rounded-sm bg-surface-3 px-2 py-0.5 font-mono text-[12px] text-primary"
            >
              {grant}
            </span>
          ))}
        </div>
      ) : (
        <span className="text-tertiary">No credential grants</span>
      )}
      {agent.rateLimit && (
        <div className="mt-2">
          <span className="text-tertiary">Rate Limit: </span>
          <span className="font-mono text-primary">{agent.rateLimit}</span>
        </div>
      )}
    </div>
  );
}

// ─── Agents View ────────────────────────────────────────────

export function Agents(): React.ReactElement {
  const { data: agents, isLoading } = useAgents();
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const agentList = agents ?? [];

  if (!isLoading && agentList.length === 0) {
    return (
      <EmptyState
        icon={Users}
        title="No agents registered"
        description="Register agents via the CLI to see them here"
      />
    );
  }

  return (
    <Card className={isLoading ? 'opacity-60' : ''}>
      <div className="overflow-x-auto">
        <table className="w-full table-fixed border-collapse" aria-label="Registered agents">
          <thead>
            <tr className="bg-surface-2">
              <th className="w-[180px] px-3 py-2 text-left text-[12px] font-normal uppercase tracking-wider text-secondary">
                Agent
              </th>
              <th className="w-[140px] px-3 py-2 text-left text-[12px] font-normal uppercase tracking-wider text-secondary">
                Token Prefix
              </th>
              <th className="w-[90px] px-3 py-2 text-left text-[12px] font-normal uppercase tracking-wider text-secondary">
                Status
              </th>
              <th className="w-[80px] px-3 py-2 text-left text-[12px] font-normal uppercase tracking-wider text-secondary">
                Grants
              </th>
              <th className="px-3 py-2 text-left text-[12px] font-normal uppercase tracking-wider text-secondary">
                Created
              </th>
            </tr>
          </thead>
          <tbody>
            {agentList.map((agent, i) => (
              <React.Fragment key={agent.id}>
              <tr
                className={`cursor-pointer border-t border-border-sub transition-colors duration-100 ${
                  i % 2 === 0
                    ? 'bg-surface-1 hover:bg-surface-3'
                    : 'bg-surface-0 hover:bg-surface-3'
                }`}
                onClick={() => setExpandedId(expandedId === agent.id ? null : agent.id)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    setExpandedId(expandedId === agent.id ? null : agent.id);
                  }
                }}
                tabIndex={0}
                role="button"
                aria-expanded={expandedId === agent.id}
              >
                <td className="overflow-hidden truncate px-3 py-2 font-mono text-[13px] font-medium text-primary" title={agent.name}>
                  {agent.name}
                </td>
                <td className="overflow-hidden truncate px-3 py-2 font-mono text-[12px] text-tertiary">
                  {agent.tokenPrefix}...
                </td>
                <td className="px-3 py-2">
                  <StatusBadge variant="active" />
                </td>
                <td className="px-3 py-2 text-[13px] text-secondary">
                  {agent.grants.length}
                </td>
                <td className="overflow-hidden truncate px-3 py-2 text-[12px] text-tertiary">
                  {formatRelativeTime(agent.createdAt)}
                </td>
              </tr>
              {expandedId === agent.id && (
              <tr>
                <td colSpan={5} className="p-0">
                  <AgentDetail agent={agent} />
                </td>
              </tr>
              )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
