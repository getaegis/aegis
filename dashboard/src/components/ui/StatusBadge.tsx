/**
 * StatusBadge — pill-shaped status indicator
 *
 * Design system spec:
 *   Padding: 2px 8px, Radius: 4px, Font: Label (11px), weight 500, uppercase
 *   ALLOWED/ACTIVE: green text on allowed-bg
 *   BLOCKED/EXPIRED: red text on blocked-bg
 *   WARNING/EXPIRING: amber text on warning-bg
 *   INFO: blue text on info-bg
 */

type BadgeVariant = 'allowed' | 'blocked' | 'warning' | 'active' | 'expired' | 'expiring' | 'info' | 'system';

const variantStyles: Record<BadgeVariant, string> = {
  allowed: 'bg-allowed-bg text-allowed',
  active: 'bg-allowed-bg text-allowed',
  blocked: 'bg-blocked-bg text-blocked',
  expired: 'bg-blocked-bg text-blocked',
  warning: 'bg-warning-bg text-warning',
  expiring: 'bg-warning-bg text-warning',
  info: 'bg-info-bg text-info',
  system: 'bg-info-bg text-info',
};

interface StatusBadgeProps {
  variant: BadgeVariant;
  /** Override display text. Defaults to variant name uppercase. */
  label?: string;
}

export function StatusBadge({ variant, label }: StatusBadgeProps): React.ReactElement {
  const displayText = label ?? variant.toUpperCase();

  return (
    <span
      className={`inline-block rounded-sm px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide ${variantStyles[variant]}`}
      aria-label={`Status: ${displayText}`}
    >
      {displayText}
    </span>
  );
}
