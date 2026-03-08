/**
 * TimeRangeFilter — preset time-range buttons for filtering event tables
 *
 * Renders a group of toggle-style buttons (1h, 24h, 7d, All).
 * Returns the selected range key so the parent can filter by timestamp.
 */

import { Clock } from 'lucide-react';

export type TimeRange = '1h' | '24h' | '7d' | 'all';

const RANGES: { key: TimeRange; label: string }[] = [
  { key: '1h', label: '1h' },
  { key: '24h', label: '24h' },
  { key: '7d', label: '7d' },
  { key: 'all', label: 'All' },
];

/** Returns the cutoff Date for a given range, or null for 'all'. */
export function getTimeCutoff(range: TimeRange): Date | null {
  if (range === 'all') return null;
  const now = Date.now();
  const offsets: Record<Exclude<TimeRange, 'all'>, number> = {
    '1h': 60 * 60 * 1000,
    '24h': 24 * 60 * 60 * 1000,
    '7d': 7 * 24 * 60 * 60 * 1000,
  };
  return new Date(now - offsets[range]);
}

/** Checks whether an ISO timestamp string is within the given range. */
export function isWithinRange(timestamp: string, range: TimeRange): boolean {
  if (range === 'all') return true;
  const cutoff = getTimeCutoff(range);
  if (!cutoff) return true;
  return new Date(timestamp) >= cutoff;
}

interface TimeRangeFilterProps {
  value: TimeRange;
  onChange: (range: TimeRange) => void;
}

export function TimeRangeFilter({ value, onChange }: TimeRangeFilterProps): React.ReactElement {
  return (
    <div className="flex items-center gap-1 rounded-md border border-border bg-surface-0 p-0.5" role="group" aria-label="Filter by time range">
      <Clock size={13} className="ml-1.5 text-tertiary" />
      {RANGES.map(({ key, label }) => (
        <button
          key={key}
          type="button"
          onClick={() => onChange(key)}
          className={`rounded px-2 py-0.5 text-[12px] font-medium transition-colors ${
            value === key
              ? 'bg-gold/15 text-gold'
              : 'text-secondary hover:text-primary'
          }`}
          aria-pressed={value === key}
        >
          {label}
        </button>
      ))}
    </div>
  );
}
