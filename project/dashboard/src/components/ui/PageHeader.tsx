/**
 * PageHeader -- Consistent page header across all pages
 *
 * Provides: title, optional icon, description, and actions slot.
 */

import { clsx } from 'clsx';

interface PageHeaderProps {
  title: string;
  description?: string;
  icon?: React.ComponentType<React.SVGProps<SVGSVGElement>>;
  iconClassName?: string;
  actions?: React.ReactNode;
  className?: string;
}

export function PageHeader({
  title,
  description,
  icon: Icon,
  iconClassName,
  actions,
  className,
}: PageHeaderProps) {
  return (
    <div className={clsx('flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6', className)}>
      <div className="min-w-0">
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
          {Icon && <Icon className={clsx('h-7 w-7 flex-shrink-0', iconClassName || 'text-slate-500 dark:text-slate-400')} />}
          {title}
        </h1>
        {description && (
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{description}</p>
        )}
      </div>
      {actions && (
        <div className="flex flex-wrap items-center gap-2 sm:gap-3 flex-shrink-0">
          {actions}
        </div>
      )}
    </div>
  );
}

export default PageHeader;
