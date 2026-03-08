/**
 * DataTable — reusable table component following design system specs
 *
 * Design system spec:
 *   Header: Surface-2 bg, Caption size (12px), uppercase, Secondary color
 *   Body: Surface-1 bg, alternating Surface-0 for zebra striping
 *   Hover: Surface-3 bg
 *   Blocked rows: Blocked/bg tint
 *   Cell padding: 8px vertical, 12px horizontal
 *   Font: Monospace for paths/methods/tokens, proportional for labels
 */

export interface Column<T> {
  key: string;
  header: string;
  /** Render cell content. Receives the row data. */
  render: (row: T) => React.ReactNode;
  /** Additional class for this column's cells */
  className?: string;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  /** Unique key extractor for each row */
  rowKey: (row: T) => string | number;
  /** Should this row have the blocked tint? */
  isBlocked?: (row: T) => boolean;
  /** Called when a row is clicked */
  onRowClick?: (row: T) => void;
  /** aria-label for the table */
  label?: string;
}

export function DataTable<T>({
  columns,
  data,
  rowKey,
  isBlocked,
  onRowClick,
  label = 'Data table',
}: DataTableProps<T>): React.ReactElement {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse" aria-label={label}>
        <thead>
          <tr className="bg-surface-2">
            {columns.map((col) => (
              <th
                key={col.key}
                className="px-3 py-2 text-left text-[12px] font-normal uppercase tracking-wider text-secondary"
              >
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, i) => {
            const blocked = isBlocked?.(row) ?? false;
            return (
              <tr
                key={rowKey(row)}
                className={`border-t border-border-sub transition-colors duration-100 ease-in ${
                  blocked
                    ? 'bg-blocked-bg hover:bg-surface-3'
                    : i % 2 === 0
                      ? 'bg-surface-1 hover:bg-surface-3'
                      : 'bg-surface-0 hover:bg-surface-3'
                } ${onRowClick ? 'cursor-pointer' : ''}`}
                onClick={() => onRowClick?.(row)}
                tabIndex={onRowClick ? 0 : undefined}
                onKeyDown={(e) => {
                  if (onRowClick && (e.key === 'Enter' || e.key === ' ')) {
                    e.preventDefault();
                    onRowClick(row);
                  }
                }}
              >
                {columns.map((col) => (
                  <td key={col.key} className={`px-3 py-2 text-[13px] ${col.className ?? ''}`}>
                    {col.render(row)}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
