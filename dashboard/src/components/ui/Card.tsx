/**
 * Card — primary content container
 *
 * Design system spec:
 *   Background: Surface-1, Border: 1px solid Border, Radius: 6px, Padding: 20px
 *   Header: Subtitle weight, optional action aligned right
 */

interface CardProps {
  title?: string;
  description?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}

export function Card({ title, description, action, children, className = '' }: CardProps): React.ReactElement {
  return (
    <div className={`rounded-md border border-border bg-surface-1 p-5 ${className}`}>
      {(title || action) && (
        <div className="mb-4 flex items-start justify-between">
          <div>
            {title && <h3 className="text-[15px] font-medium text-primary">{title}</h3>}
            {description && <p className="mt-0.5 text-[13px] text-secondary">{description}</p>}
          </div>
          {action && <div className="ml-4 flex-shrink-0">{action}</div>}
        </div>
      )}
      {children}
    </div>
  );
}
