/**
 * RequestFeed — real-time WebSocket feed of Gate requests
 *
 * Features:
 *   - Live auto-scrolling (pausable by scrolling up)
 *   - Filter by service, status, method
 *   - Search by path
 *   - Blocked rows highlighted with Blocked/bg tint
 *   - Click to expand request details
 *   - aria-live for screen readers
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Pause, Play, Radio } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { StatusBadge } from '../components/ui/StatusBadge';
import { EmptyState } from '../components/ui/EmptyState';
import { ConnectionBanner } from '../components/ui/ConnectionBanner';
import { TimeRangeFilter, isWithinRange } from '../components/ui/TimeRangeFilter';
import type { TimeRange } from '../components/ui/TimeRangeFilter';
import { useWebSocket } from '../hooks/use-websocket';
import { useRequests } from '../hooks/api/use-requests';
import { formatTimestamp } from '../lib/format';
import type { AuditEntry } from '../types';

// ─── Filters ─────────────────────────────────────────────────

interface Filters {
  status: string;
  service: string;
  method: string;
  pathSearch: string;
  timeRange: TimeRange;
}

const INITIAL_FILTERS: Filters = { status: '', service: '', method: '', pathSearch: '', timeRange: 'all' };

function matchesFilters(entry: AuditEntry, filters: Filters): boolean {
  if (!isWithinRange(entry.timestamp, filters.timeRange)) return false;
  if (filters.status && entry.status !== filters.status) return false;
  if (filters.service && entry.service !== filters.service) return false;
  if (filters.method && entry.method !== filters.method) return false;
  if (filters.pathSearch && !entry.path.toLowerCase().includes(filters.pathSearch.toLowerCase())) return false;
  return true;
}

// ─── Expanded Row Detail ─────────────────────────────────────

function RequestDetail({ entry }: { entry: AuditEntry }): React.ReactElement {
  return (
    <div className="border-t border-border-sub bg-surface-2 px-4 py-3 text-[12px]">
      <div className="grid grid-cols-2 gap-x-6 gap-y-1">
        <div>
          <span className="text-tertiary">Target Domain: </span>
          <span className="font-mono text-primary">{entry.targetDomain}</span>
        </div>
        <div>
          <span className="text-tertiary">Response: </span>
          <span className="font-mono text-primary">{entry.responseCode ?? '—'}</span>
        </div>
        {entry.credentialName && (
          <div>
            <span className="text-tertiary">Credential: </span>
            <span className="font-mono text-primary">{entry.credentialName}</span>
          </div>
        )}
        {entry.agentName && (
          <div>
            <span className="text-tertiary">Agent: </span>
            <span className="font-mono text-primary">{entry.agentName}</span>
            {entry.agentTokenPrefix && (
              <span className="ml-1 text-tertiary">({entry.agentTokenPrefix}...)</span>
            )}
          </div>
        )}
        {entry.channel === 'mcp' && (
          <div>
            <span className="text-tertiary">Channel: </span>
            <span className="font-mono text-gold">MCP</span>
          </div>
        )}
        {entry.blockedReason && (
          <div className="col-span-2">
            <span className="text-tertiary">Block Reason: </span>
            <span className="font-mono text-blocked">{entry.blockedReason}</span>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── RequestFeed ────────────────────────────────────────────

export function RequestFeed(): React.ReactElement {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [filters, setFilters] = useState<Filters>(INITIAL_FILTERS);
  const [paused, setPaused] = useState(false);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const feedRef = useRef<HTMLDivElement>(null);

  // Poll the ledger every 3s to pick up entries from all sources (MCP, Gate, etc.)
  // WebSocket only carries Gate entries (same process), but MCP runs separately.
  const { data: polledData } = useRequests({ limit: 200, refetchInterval: 3_000 });

  // Seed entries from initial fetch
  useEffect(() => {
    if (polledData && polledData.length > 0) {
      setEntries((prev) => {
        // Merge polled data with live WS entries, dedup by id, keep newest first
        const idSet = new Set(prev.map((e) => e.id));
        const newFromPoll = polledData.filter((e) => !idSet.has(e.id));
        if (newFromPoll.length === 0) return prev;
        return [...newFromPoll, ...prev]
          .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
          .slice(0, 500);
      });
    }
  }, [polledData]);

  // WebSocket for instant live updates (Gate entries)
  const onMessage = useCallback((entry: AuditEntry) => {
    setEntries((prev) => {
      // Avoid duplicates if poll already added this entry
      if (prev.some((e) => e.id === entry.id)) return prev;
      return [entry, ...prev].slice(0, 500);
    });
  }, []);

  const { status: wsStatus, reconnect } = useWebSocket({ onMessage, enabled: true });

  // Auto-scroll to top when new entries arrive (unless paused)
  useEffect(() => {
    if (!paused && feedRef.current) {
      feedRef.current.scrollTop = 0;
    }
  }, [entries.length, paused]);

  // Detect manual scroll to auto-pause
  const handleScroll = useCallback(() => {
    if (feedRef.current && feedRef.current.scrollTop > 50) {
      setPaused(true);
    }
  }, []);

  const filtered = entries.filter((e) => matchesFilters(e, filters));

  // Collect unique services/methods for filter dropdowns
  const services = [...new Set(entries.map((e) => e.service))].sort();
  const methods = [...new Set(entries.map((e) => e.method))].sort();

  return (
    <div className="flex flex-col gap-4">
      <ConnectionBanner status={wsStatus} onReconnect={reconnect} />

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <TimeRangeFilter
          value={filters.timeRange}
          onChange={(range) => setFilters((f) => ({ ...f, timeRange: range }))}
        />

        <select
          className="appearance-none rounded-md border border-border bg-surface-0 bg-[url('data:image/svg+xml;charset=utf-8,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%2212%22%20height%3D%2212%22%20viewBox%3D%220%200%2024%2024%22%20fill%3D%22none%22%20stroke%3D%22%239ca3af%22%20stroke-width%3D%222.5%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%3E%3Cpath%20d%3D%22m6%209%206%206%206-6%22%2F%3E%3C%2Fsvg%3E')] bg-[length:12px] bg-[right_8px_center] bg-no-repeat pl-3 pr-8 py-1.5 text-[13px] text-primary focus:border-gold focus:outline-none"
          value={filters.status}
          onChange={(e) => setFilters((f) => ({ ...f, status: e.target.value }))}
          aria-label="Filter by status"
        >
          <option value="">All Status</option>
          <option value="allowed">Allowed</option>
          <option value="blocked">Blocked</option>
        </select>

        <select
          className="appearance-none rounded-md border border-border bg-surface-0 bg-[url('data:image/svg+xml;charset=utf-8,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%2212%22%20height%3D%2212%22%20viewBox%3D%220%200%2024%2024%22%20fill%3D%22none%22%20stroke%3D%22%239ca3af%22%20stroke-width%3D%222.5%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%3E%3Cpath%20d%3D%22m6%209%206%206%206-6%22%2F%3E%3C%2Fsvg%3E')] bg-[length:12px] bg-[right_8px_center] bg-no-repeat pl-3 pr-8 py-1.5 text-[13px] text-primary focus:border-gold focus:outline-none"
          value={filters.service}
          onChange={(e) => setFilters((f) => ({ ...f, service: e.target.value }))}
          aria-label="Filter by service"
        >
          <option value="">All Services</option>
          {services.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>

        <select
          className="appearance-none rounded-md border border-border bg-surface-0 bg-[url('data:image/svg+xml;charset=utf-8,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%2212%22%20height%3D%2212%22%20viewBox%3D%220%200%2024%2024%22%20fill%3D%22none%22%20stroke%3D%22%239ca3af%22%20stroke-width%3D%222.5%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%3E%3Cpath%20d%3D%22m6%209%206%206%206-6%22%2F%3E%3C%2Fsvg%3E')] bg-[length:12px] bg-[right_8px_center] bg-no-repeat pl-3 pr-8 py-1.5 text-[13px] text-primary focus:border-gold focus:outline-none"
          value={filters.method}
          onChange={(e) => setFilters((f) => ({ ...f, method: e.target.value }))}
          aria-label="Filter by method"
        >
          <option value="">All Methods</option>
          {methods.map((m) => (
            <option key={m} value={m}>{m}</option>
          ))}
        </select>

        <input
          type="text"
          placeholder="Search path..."
          className="rounded-md border border-border bg-surface-0 px-3 py-1.5 font-mono text-[13px] text-primary placeholder:text-tertiary focus:border-gold focus:outline-none"
          value={filters.pathSearch}
          onChange={(e) => setFilters((f) => ({ ...f, pathSearch: e.target.value }))}
          aria-label="Search by path"
        />

        <div className="ml-auto flex items-center gap-2">
          {paused && (
            <span className="text-[11px] font-medium uppercase tracking-wider text-warning">
              Paused
            </span>
          )}
          <button
            type="button"
            onClick={() => setPaused((p) => !p)}
            className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-[13px] font-medium text-primary hover:bg-surface-3"
            aria-label={paused ? 'Resume auto-scroll' : 'Pause auto-scroll'}
          >
            {paused ? <Play size={14} /> : <Pause size={14} />}
            {paused ? 'Resume' : 'Pause'}
          </button>
        </div>
      </div>

      {/* Feed */}
      <Card>
        <div
          ref={feedRef}
          className="max-h-[calc(100vh-240px)] overflow-y-auto"
          onScroll={handleScroll}
          aria-live="polite"
          aria-label="Request feed"
        >
          {filtered.length === 0 ? (
            <EmptyState icon={Radio} title="No requests" description="Requests will appear here in real-time" />
          ) : (
            <table className="w-full table-fixed" aria-label="Request feed table">
              <thead className="sticky top-0 z-10">
                <tr className="bg-surface-2">
                  <th className="w-[100px] px-3 py-2 text-left text-[12px] font-normal uppercase tracking-wider text-secondary">Time</th>
                  <th className="w-[80px] px-3 py-2 text-left text-[12px] font-normal uppercase tracking-wider text-secondary">Method</th>
                  <th className="px-3 py-2 text-left text-[12px] font-normal uppercase tracking-wider text-secondary">Path</th>
                  <th className="w-[110px] px-3 py-2 text-left text-[12px] font-normal uppercase tracking-wider text-secondary">Service</th>
                  <th className="w-[60px] px-3 py-2 text-left text-[12px] font-normal uppercase tracking-wider text-secondary">Source</th>
                  <th className="w-[90px] px-3 py-2 text-left text-[12px] font-normal uppercase tracking-wider text-secondary">Status</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((entry, i) => (
                  <React.Fragment key={entry.id}>
                  <tr
                    className={`cursor-pointer border-t border-border-sub transition-colors duration-100 ${
                      entry.status === 'blocked'
                        ? 'bg-blocked-bg hover:bg-surface-3'
                        : i % 2 === 0
                          ? 'bg-surface-1 hover:bg-surface-3'
                          : 'bg-surface-0 hover:bg-surface-3'
                    }`}
                    onClick={() => setExpandedId(expandedId === entry.id ? null : entry.id)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        setExpandedId(expandedId === entry.id ? null : entry.id);
                      }
                    }}
                    tabIndex={0}
                    role="button"
                    aria-expanded={expandedId === entry.id}
                  >
                    <td className="overflow-hidden truncate px-3 py-2 font-mono text-[12px] text-tertiary">
                      {formatTimestamp(entry.timestamp)}
                    </td>
                    <td className="overflow-hidden truncate px-3 py-2 font-mono text-[12px] font-medium text-primary">
                      {entry.method}
                    </td>
                    <td className="overflow-hidden truncate px-3 py-2 font-mono text-[12px] text-secondary" title={entry.path}>
                      {entry.path}
                    </td>
                    <td className="overflow-hidden truncate px-3 py-2 font-mono text-[12px] text-secondary" title={entry.service}>
                      {entry.service}
                    </td>
                    <td className="px-3 py-2 text-[11px] uppercase tracking-wider text-tertiary">
                      {entry.channel === 'mcp' ? (
                        <span className="rounded bg-surface-3 px-1.5 py-0.5 text-[10px] font-medium text-gold">MCP</span>
                      ) : (
                        <span className="text-tertiary">gate</span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      <StatusBadge variant={entry.status === 'allowed' ? 'allowed' : entry.status === 'system' ? 'system' : 'blocked'} />
                    </td>
                  </tr>
                  {expandedId === entry.id && (
                  <tr>
                    <td colSpan={6} className="p-0">
                      <RequestDetail entry={entry} />
                    </td>
                  </tr>
                  )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </Card>
    </div>
  );
}
