/**
 * EmptyState — centered text + icon for empty data
 *
 * Design system spec:
 *   Empty state: Centered text + icon, no illustration
 */

import type { LucideIcon } from 'lucide-react';

interface EmptyStateProps {
  icon: LucideIcon;
  title: string;
  description?: string;
}

export function EmptyState({ icon: Icon, title, description }: EmptyStateProps): React.ReactElement {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <Icon size={32} className="mb-3 text-tertiary" aria-hidden="true" />
      <p className="text-[14px] font-medium text-secondary">{title}</p>
      {description && <p className="mt-1 text-[13px] text-tertiary">{description}</p>}
    </div>
  );
}
