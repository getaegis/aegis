import { type View } from '../../App';
import {
  LayoutDashboard,
  Radio,
  KeyRound,
  Users,
  UserCog,
  ShieldAlert,
} from 'lucide-react';

interface SidebarProps {
  currentView: View;
  onNavigate: (view: View) => void;
}

const navItems: { view: View; label: string; icon: typeof LayoutDashboard }[] = [
  { view: 'overview', label: 'Overview', icon: LayoutDashboard },
  { view: 'requests', label: 'Request Feed', icon: Radio },
  { view: 'credentials', label: 'Credentials', icon: KeyRound },
  { view: 'agents', label: 'Agents', icon: Users },
  { view: 'users', label: 'Users', icon: UserCog },
  { view: 'blocked', label: 'Blocked', icon: ShieldAlert },
];

export function Sidebar({ currentView, onNavigate }: SidebarProps): React.ReactElement {
  return (
    <aside
      className="flex flex-col border-r border-border bg-surface-0"
      style={{ width: 'var(--sidebar-width)' }}
      role="navigation"
      aria-label="Main navigation"
    >
      {/* Logo */}
      <div
        className="flex items-center gap-3 border-b border-border px-5"
        style={{ height: 'var(--header-height)' }}
      >
        <svg width="24" height="24" viewBox="0 0 100 100" aria-hidden="true">
          <circle cx="50" cy="50" r="45" fill="none" stroke="#C8973E" strokeWidth="5" />
          <circle cx="50" cy="50" r="32" fill="none" stroke="#C8973E" strokeWidth="4" />
          <circle cx="50" cy="50" r="18" fill="none" stroke="#C8973E" strokeWidth="3" />
          <circle cx="50" cy="50" r="5" fill="#C8973E" />
        </svg>
        <span className="text-[15px] font-semibold text-primary">Aegis</span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4">
        <div className="mb-3 px-2 text-[11px] font-medium uppercase tracking-wider text-tertiary">
          Navigation
        </div>
        <ul className="flex flex-col gap-1">
          {navItems.map(({ view, label, icon: Icon }) => {
            const isActive = currentView === view;
            return (
              <li key={view}>
                <button
                  type="button"
                  onClick={() => onNavigate(view)}
                  className={`flex w-full items-center gap-3 rounded-md px-3 py-2 text-[13px] font-medium transition-[color,background-color,border-color] duration-100 ease-in ${
                    isActive
                      ? 'border-l-2 border-gold bg-gold-muted text-primary'
                      : 'border-l-2 border-transparent text-secondary hover:bg-surface-3 hover:text-primary'
                  }`}
                  aria-current={isActive ? 'page' : undefined}
                >
                  <Icon size={20} aria-hidden="true" />
                  {label}
                </button>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* Footer */}
      <div className="border-t border-border px-5 py-3">
        <span className="text-[11px] text-tertiary">Aegis Dashboard</span>
      </div>
    </aside>
  );
}
