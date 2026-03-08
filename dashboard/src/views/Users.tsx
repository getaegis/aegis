/**
 * Users — RBAC user list
 *
 * Design system: Table component pattern
 *   - Header: Surface-2 bg, Caption size (12px), uppercase, Secondary color
 *   - Body: Surface-1 bg, alternating Surface-0 for zebra striping
 *   - Hover: Surface-3 bg
 *   - Cell padding: 8px vertical, 12px horizontal
 *   - Monospace for token prefixes, proportional for labels
 *   - StatusBadge for role display
 */

import { UserCog } from 'lucide-react';
import { Card } from '../components/ui/Card';
import { StatusBadge } from '../components/ui/StatusBadge';
import { EmptyState } from '../components/ui/EmptyState';
import { useUsers } from '../hooks/api/use-users';
import { formatRelativeTime } from '../lib/format';
import type { User } from '../types';

// ─── Role Badge Mapping ─────────────────────────────────────

type BadgeVariant = 'allowed' | 'warning' | 'info';

const roleBadge: Record<User['role'], { variant: BadgeVariant; label: string }> = {
  admin: { variant: 'warning', label: 'ADMIN' },
  operator: { variant: 'info', label: 'OPERATOR' },
  viewer: { variant: 'allowed', label: 'VIEWER' },
};

// ─── Users View ─────────────────────────────────────────────

export function Users(): React.ReactElement {
  const { data: users, isLoading } = useUsers();
  const userList = users ?? [];

  if (!isLoading && userList.length === 0) {
    return (
      <EmptyState
        icon={UserCog}
        title="No users registered"
        description="RBAC is in bootstrap mode — add a user via the CLI to enable access control"
      />
    );
  }

  return (
    <Card className={isLoading ? 'opacity-60' : ''}>
      <div className="overflow-x-auto">
        <table className="w-full table-fixed border-collapse" aria-label="RBAC users">
          <thead>
            <tr className="bg-surface-2">
              <th className="w-[180px] px-3 py-2 text-left text-[12px] font-normal uppercase tracking-wider text-secondary">
                Name
              </th>
              <th className="w-[120px] px-3 py-2 text-left text-[12px] font-normal uppercase tracking-wider text-secondary">
                Role
              </th>
              <th className="w-[160px] px-3 py-2 text-left text-[12px] font-normal uppercase tracking-wider text-secondary">
                Token Prefix
              </th>
              <th className="px-3 py-2 text-left text-[12px] font-normal uppercase tracking-wider text-secondary">
                Created
              </th>
            </tr>
          </thead>
          <tbody>
            {userList.map((user, i) => (
              <tr
                key={user.id}
                className={`border-t border-border-sub transition-colors duration-100 ${
                  i % 2 === 0
                    ? 'bg-surface-1 hover:bg-surface-3'
                    : 'bg-surface-0 hover:bg-surface-3'
                }`}
              >
                <td
                  className="overflow-hidden truncate px-3 py-2 font-mono text-[13px] font-medium text-primary"
                  title={user.name}
                >
                  {user.name}
                </td>
                <td className="px-3 py-2">
                  <StatusBadge
                    variant={roleBadge[user.role].variant}
                    label={roleBadge[user.role].label}
                  />
                </td>
                <td className="overflow-hidden truncate px-3 py-2 font-mono text-[12px] text-tertiary">
                  {user.tokenPrefix}...
                </td>
                <td className="overflow-hidden truncate px-3 py-2 text-[12px] text-tertiary">
                  {formatRelativeTime(user.createdAt)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
