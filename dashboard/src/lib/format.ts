/**
 * Formatting utilities for dashboard display values.
 * Pure functions — no React dependencies.
 */

/** Format large numbers with commas: 4291 → "4,291" */
export function formatNumber(n: number): string {
  return n.toLocaleString('en-US');
}

/** Format ISO timestamp to short display: "14:32:05" or "Mar 8, 14:32" */
export function formatTimestamp(iso: string, includeDate = false): string {
  const d = new Date(iso);
  const time = d.toLocaleTimeString('en-US', { hour12: false });
  if (!includeDate) return time;
  const date = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  return `${date}, ${time}`;
}

/** Format seconds into human-readable uptime: "2d 14h 32m" */
export function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

/** Format a timestamp as relative time: "2m ago", "3h ago", "1d ago" */
export function formatRelativeTime(iso: string): string {
  const now = Date.now();
  const then = new Date(iso).getTime();
  const diffMs = now - then;
  const diffMin = Math.floor(diffMs / 60_000);

  if (diffMin < 1) return 'just now';
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.floor(diffHr / 24);
  return `${diffDay}d ago`;
}
