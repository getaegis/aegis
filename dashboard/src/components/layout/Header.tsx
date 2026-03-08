import type { View } from '../../App';
import { useHealth } from '../../hooks/api/use-health';

const viewLabels: Record<View, string> = {
  overview: 'Overview',
  requests: 'Request Feed',
  credentials: 'Credentials',
  agents: 'Agents',
  users: 'Users',
  blocked: 'Blocked Requests',
};

interface HeaderProps {
  currentView: View;
}

export function Header({ currentView }: HeaderProps): React.ReactElement {
  const { data: health, isError } = useHealth();

  const isConnected = health !== undefined && !isError;

  return (
    <header
      className="flex items-center justify-between border-b border-border bg-surface-0 px-6"
      style={{ height: 'var(--header-height)', minHeight: 'var(--header-height)' }}
    >
      {/* Breadcrumb */}
      <div className="flex items-center gap-2">
        <span className="text-[13px] text-tertiary">Aegis</span>
        <span className="text-[13px] text-tertiary">/</span>
        <span className="text-[13px] font-medium text-primary">{viewLabels[currentView]}</span>
      </div>

      {/* Connection status + version */}
      <div className="flex items-center gap-4">
        {health?.version && (
          <span className="font-mono text-[12px] text-tertiary">v{health.version}</span>
        )}
        <div className="flex items-center gap-2">
          <span
            className={`inline-block h-2 w-2 rounded-full ${
              isConnected ? 'bg-allowed' : 'bg-blocked'
            }`}
            aria-hidden="true"
          />
          <span
            className={`text-[13px] font-medium ${
              isConnected ? 'text-allowed' : 'text-blocked'
            }`}
            aria-label={`Connection status: ${isConnected ? 'Connected' : 'Disconnected'}`}
          >
            {isConnected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
      </div>
    </header>
  );
}
