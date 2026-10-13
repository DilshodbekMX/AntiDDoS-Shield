/**
 * DataTable - Enterprise data table component
 *
 * Full-featured table with sorting, selection, and responsive design
 */

import { useState, useMemo } from 'react';
import { clsx } from 'clsx';
import {
  ChevronUpIcon,
  ChevronDownIcon,
  ChevronUpDownIcon,
} from '@heroicons/react/20/solid';

export interface Column<T> {
  key: string;
  header: string;
  width?: string;
  align?: 'left' | 'center' | 'right';
  sortable?: boolean;
  /** Custom render function for cell content. */
  render?: (value: unknown, row: T, index: number) => React.ReactNode;
  className?: string;
}

export interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  keyField?: keyof T;
  loading?: boolean;
  emptyMessage?: string;
  sortable?: boolean;
  selectable?: boolean;
  onRowClick?: (row: T, index: number) => void;
  selectedRows?: Set<string | number>;
  onSelectionChange?: (selected: Set<string | number>) => void;
  stickyHeader?: boolean;
  striped?: boolean;
  compact?: boolean;
  className?: string;
}

type SortDirection = 'asc' | 'desc' | null;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function DataTable<T extends Record<string, any> = Record<string, any>>({
  columns,
  data,
  keyField = 'id' as keyof T,
  loading = false,
  emptyMessage = 'No data available',
  sortable = true,
  selectable = false,
  onRowClick,
  selectedRows,
  onSelectionChange,
  stickyHeader = false,
  striped = false,
  compact = false,
  className,
}: DataTableProps<T>) {
  const [sortKey, setSortKey] = useState<string | null>(null);
  const [sortDirection, setSortDirection] = useState<SortDirection>(null);

  const sortedData = useMemo(() => {
    if (!sortKey || !sortDirection) return data;

    return [...data].sort((a, b) => {
      const aVal = a[sortKey];
      const bVal = b[sortKey];

      if (aVal === bVal) return 0;
      if (aVal === null || aVal === undefined) return 1;
      if (bVal === null || bVal === undefined) return -1;

      const comparison = aVal < bVal ? -1 : 1;
      return sortDirection === 'asc' ? comparison : -comparison;
    });
  }, [data, sortKey, sortDirection]);

  const handleSort = (key: string) => {
    if (!sortable) return;

    if (sortKey === key) {
      if (sortDirection === 'asc') {
        setSortDirection('desc');
      } else if (sortDirection === 'desc') {
        setSortKey(null);
        setSortDirection(null);
      }
    } else {
      setSortKey(key);
      setSortDirection('asc');
    }
  };

  const handleSelectAll = () => {
    if (!onSelectionChange) return;

    const allKeys = new Set(data.map(row => row[keyField] as string | number));
    const isAllSelected = selectedRows?.size === data.length;

    onSelectionChange(isAllSelected ? new Set() : allKeys);
  };

  const handleSelectRow = (key: string | number) => {
    if (!onSelectionChange || !selectedRows) return;

    const newSelected = new Set(selectedRows);
    if (newSelected.has(key)) {
      newSelected.delete(key);
    } else {
      newSelected.add(key);
    }
    onSelectionChange(newSelected);
  };

  const getSortIcon = (key: string) => {
    if (sortKey !== key) {
      return <ChevronUpDownIcon className="h-4 w-4 text-slate-500 dark:text-slate-400" />;
    }
    if (sortDirection === 'asc') {
      return <ChevronUpIcon className="h-4 w-4 text-brand-600" />;
    }
    return <ChevronDownIcon className="h-4 w-4 text-brand-600" />;
  };

  // Loading skeleton
  if (loading) {
    return (
      <div className={clsx('table-container overflow-x-auto', className)}>
        <table className="table">
          <thead>
            <tr>
              {columns.map((col, i) => (
                <th key={i} style={{ width: col.width }}>
                  <div className="h-4 w-20 bg-slate-200 dark:bg-slate-700 rounded animate-pulse" />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[...Array(5)].map((_, i) => (
              <tr key={i}>
                {columns.map((_, j) => (
                  <td key={j}>
                    <div className="h-4 w-full bg-slate-100 dark:bg-slate-800 rounded animate-pulse" />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  // Empty state
  if (data.length === 0) {
    return (
      <div className={clsx('table-container', className)}>
        <table className="table">
          <thead>
            <tr>
              {selectable && <th className="w-12" />}
              {columns.map((col, i) => (
                <th key={i} style={{ width: col.width }}>
                  {col.header}
                </th>
              ))}
            </tr>
          </thead>
        </table>
        <div className="flex items-center justify-center py-12 text-slate-500 dark:text-slate-400">
          {emptyMessage}
        </div>
      </div>
    );
  }

  return (
    <div className={clsx('table-container overflow-x-auto', className)}>
      <table className="table">
        <thead className={stickyHeader ? 'sticky top-0 z-10' : ''}>
          <tr>
            {selectable && (
              <th className="w-12">
                <input
                  type="checkbox"
                  checked={selectedRows?.size === data.length}
                  onChange={handleSelectAll}
                  className="h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500"
                />
              </th>
            )}
            {columns.map((col, i) => (
              <th
                key={i}
                style={{ width: col.width }}
                className={clsx(
                  col.align === 'center' && 'text-center',
                  col.align === 'right' && 'text-right',
                  (sortable && col.sortable !== false) && 'cursor-pointer select-none hover:bg-slate-100 dark:hover:bg-slate-700',
                  col.className
                )}
                onClick={() => col.sortable !== false && handleSort(col.key as string)}
              >
                <div className={clsx(
                  'flex items-center gap-1',
                  col.align === 'center' && 'justify-center',
                  col.align === 'right' && 'justify-end'
                )}>
                  {col.header}
                  {sortable && col.sortable !== false && getSortIcon(col.key as string)}
                </div>
              </th>
            ))}
          </tr>
        </thead>
        <tbody className={striped ? 'divide-y-0' : ''}>
          {sortedData.map((row, rowIndex) => {
            const rowKey = row[keyField] as string | number;
            // Use rowKey if defined, otherwise fall back to rowIndex for unique key
            const uniqueKey = rowKey !== undefined && rowKey !== null ? rowKey : `row-${rowIndex}`;
            const isSelected = selectedRows?.has(rowKey);

            return (
              <tr
                key={uniqueKey}
                onClick={() => onRowClick?.(row, rowIndex)}
                className={clsx(
                  onRowClick && 'cursor-pointer',
                  isSelected && 'bg-brand-50 dark:bg-brand-500/10',
                  striped && rowIndex % 2 === 1 && !isSelected && 'bg-slate-50 dark:bg-slate-800/50'
                )}
              >
                {selectable && (
                  <td className="w-12" onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={() => handleSelectRow(rowKey)}
                      className="h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500"
                    />
                  </td>
                )}
                {columns.map((col, colIndex) => (
                  <td
                    key={colIndex}
                    className={clsx(
                      col.align === 'center' && 'text-center',
                      col.align === 'right' && 'text-right',
                      compact && 'py-2',
                      col.className
                    )}
                  >
                    {col.render
                      ? col.render(row[col.key as keyof T] as unknown, row, rowIndex)
                      : String(row[col.key as keyof T] ?? '')}
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

export default DataTable;
