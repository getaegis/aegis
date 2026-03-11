/**
 * BlockedRequests — security-focused view of blocked requests
 *
 * Features:
 *   - Filtered to blocked requests only
 *   - Columns: time, agent, service, path, block reason
 *   - Block reason as distinct badge
 *   - CSV/JSON export
 */

import { useState } from 'react';
import { ShieldAlert, Download } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { StatusBadge } from '../components/ui/StatusBadge';
import { EmptyState } from '../components/ui/EmptyState';
import { TimeRangeFilter, isWithinRange } from '../components/ui/TimeRangeFilter';
import type { TimeRange } from '../components/ui/TimeRangeFilter';
import { useRequests } from '../hooks/api/use-requests';
import { formatTimestamp } from '../lib/format';
import type { AuditEntry } from '../types';

// ─── Block Reason Badge ─────────────────────────────────────

const REASON_LABELS: Record<string, string> = {
  no_credential: 'No Credential',
  credential_expired: 'Expired',
  credential_scope: 'Scope Denied',
  agent_auth_missing: 'No Auth',
  agent_auth_invalid: 'Auth Failed',
  agent_scope: 'No Grant',
  policy_violation: 'Policy',
  policy_rate_limit: 'Policy Rate Limit',
  agent_rate_limit: 'Agent Rate Limit',
  credential_rate_limit: 'Rate Limit',
  domain_guard: 'Domain Guard',
  body_inspection: 'Body Scan',
  body_too_large: 'Body Too Large',
  agent_connection_limit: 'Connection Limit',
};

function BlockReasonBadge({ reason }: { reason: string }): React.ReactElement {
  const label = REASON_LABELS[reason] ?? reason;
  return <StatusBadge variant="warning" label={label} />;
}

// ─── Export Helpers ──────────────────────────────────────────

function downloadFile(content: string, filename: string, type: string): void {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function exportCsv(entries: AuditEntry[]): void {
  const headers = ['timestamp', 'agent', 'service', 'method', 'path', 'block_reason', 'target_domain'];
  const rows = entries.map((e) =>
    [e.timestamp, e.agentName ?? '', e.service, e.method, e.path, e.blockedReason ?? '', e.targetDomain].join(','),
  );
  downloadFile([headers.join(','), ...rows].join('\n'), 'aegis-blocked.csv', 'text/csv');
}

function exportJson(entries: AuditEntry[]): void {
  downloadFile(JSON.stringify(entries, null, 2), 'aegis-blocked.json', 'application/json');
}

// ─── BlockedRequests View ───────────────────────────────────

export function BlockedRequests(): React.ReactElement {
  const { data, isLoading } = useRequests({ status: 'blocked', limit: 200, refetchInterval: 10_000 });
  const [serviceFilter, setServiceFilter] = useState('');
  const [timeRange, setTimeRange] = useState<TimeRange>('all');
  const entries = data ?? [];

  const filtered = entries
    .filter((e) => isWithinRange(e.timestamp, timeRange))
    .filter((e) => !serviceFilter || e.service === serviceFilter);

  const services = [...new Set(entries.map((e) => e.service))].sort();

  return (
    <div className="flex flex-col gap-4">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-3">
        <TimeRangeFilter value={timeRange} onChange={setTimeRange} />

        <select
          className="appearance-none rounded-md border border-border bg-surface-0 bg-[url('data:image/svg+xml;charset=utf-8,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%2212%22%20height%3D%2212%22%20viewBox%3D%220%200%2024%2024%22%20fill%3D%22none%22%20stroke%3D%22%239ca3af%22%20stroke-width%3D%222.5%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%3E%3Cpath%20d%3D%22m6%209%206%206%206-6%22%2F%3E%3C%2Fsvg%3E')] bg-[length:12px] bg-[right_8px_center] bg-no-repeat pl-3 pr-8 py-1.5 text-[13px] text-primary focus:border-gold focus:outline-none"
          value={serviceFilter}
          onChange={(e) => setServiceFilter(e.target.value)}
          aria-label="Filter by service"
        >
          <option value="">All Services</option>
          {services.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>

        <span className="text-[13px] text-secondary">
          {filtered.length} blocked request{filtered.length !== 1 ? 's' : ''}
        </span>

        <div className="ml-auto flex gap-2">
          <button
            type="button"
            onClick={() => exportCsv(filtered)}
            disabled={filtered.length === 0}
            className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-[13px] font-medium text-primary hover:bg-surface-3 disabled:text-disabled disabled:hover:bg-transparent"
            aria-label="Export as CSV"
          >
            <Download size={14} aria-hidden="true" />
            CSV
          </button>
          <button
            type="button"
            onClick={() => exportJson(filtered)}
            disabled={filtered.length === 0}
            className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-[13px] font-medium text-primary hover:bg-surface-3 disabled:text-disabled disabled:hover:bg-transparent"
            aria-label="Export as JSON"
          >
            <Download size={14} aria-hidden="true" />
            JSON
          </button>
        </div>
      </div>

      {/* Table */}
      <Card className={isLoading ? 'opacity-60' : ''}>
        {filtered.length === 0 ? (
          <EmptyState
            icon={ShieldAlert}
            title="No blocked requests"
            description="Blocked requests will appear here when Gate denies a request"
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full table-fixed border-collapse" aria-label="Blocked requests">
              <thead>
                <tr className="bg-surface-2">
                  <th className="w-[140px] px-3 py-2 text-left text-[12px] font-normal uppercase tracking-wider text-secondary">Time</th>
                  <th className="w-[100px] px-3 py-2 text-left text-[12px] font-normal uppercase tracking-wider text-secondary">Agent</th>
                  <th className="w-[100px] px-3 py-2 text-left text-[12px] font-normal uppercase tracking-wider text-secondary">Service</th>
                  <th className="w-[80px] px-3 py-2 text-left text-[12px] font-normal uppercase tracking-wider text-secondary">Method</th>
                  <th className="px-3 py-2 text-left text-[12px] font-normal uppercase tracking-wider text-secondary">Path</th>
                  <th className="w-[160px] px-3 py-2 text-left text-[12px] font-normal uppercase tracking-wider text-secondary">Reason</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((entry, i) => (
                  <tr
                    key={entry.id}
                    className={`border-t border-border-sub transition-colors duration-100 ${
                      i % 2 === 0 ? 'bg-blocked-bg hover:bg-surface-3' : 'bg-surface-0 hover:bg-surface-3'
                    }`}
                  >
                    <td className="overflow-hidden truncate whitespace-nowrap px-3 py-2 font-mono text-[12px] text-tertiary">
                      {formatTimestamp(entry.timestamp, true)}
                    </td>
                    <td className="overflow-hidden truncate px-3 py-2 font-mono text-[12px] text-secondary">
                      {entry.agentName ?? '—'}
                    </td>
                    <td className="overflow-hidden truncate px-3 py-2 font-mono text-[12px] text-secondary" title={entry.service}>
                      {entry.service}
                    </td>
                    <td className="overflow-hidden truncate px-3 py-2 font-mono text-[12px] font-medium text-primary">
                      {entry.method}
                    </td>
                    <td className="overflow-hidden truncate px-3 py-2 font-mono text-[12px] text-secondary" title={entry.path}>
                      {entry.path}
                    </td>
                    <td className="px-3 py-2">
                      {entry.blockedReason ? (
                        <BlockReasonBadge reason={entry.blockedReason} />
                      ) : (
                        <span className="text-[12px] text-tertiary">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
