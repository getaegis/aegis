/**
 * ConnectionBanner — top-level reconnection banner
 *
 * Design system spec:
 *   WebSocket reconnect: Small banner at top "Reconnecting..." in Warning color
 */

import type { ConnectionStatus } from '../../hooks/use-websocket';

interface ConnectionBannerProps {
  status: ConnectionStatus;
  onReconnect?: () => void;
}

export function ConnectionBanner({ status, onReconnect }: ConnectionBannerProps): React.ReactElement | null {
  if (status === 'connected' || status === 'connecting') return null;

  return (
    <div
      className="flex items-center justify-center gap-3 bg-warning-bg px-4 py-1.5 text-[13px] font-medium text-warning"
      role="alert"
      aria-live="polite"
    >
      {status === 'reconnecting' ? 'Reconnecting...' : 'Disconnected from live feed'}
      {status === 'disconnected' && onReconnect && (
        <button
          type="button"
          onClick={onReconnect}
          className="rounded border border-warning/30 px-2 py-0.5 text-[12px] hover:bg-warning/10"
        >
          Retry
        </button>
      )}
    </div>
  );
}
