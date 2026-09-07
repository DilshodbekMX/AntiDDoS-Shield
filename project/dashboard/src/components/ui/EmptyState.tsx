/**
 * EmptyState - Empty/no data state component
 *
 * Consistent empty states across the application
 */

// React is auto-imported in JSX
import { clsx } from 'clsx';
import {
  InboxIcon,
  DocumentMagnifyingGlassIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  ServerIcon,
  ChartBarIcon,
} from '@heroicons/react/24/outline';

export type EmptyStateType = 'empty' | 'search' | 'success' | 'error' | 'offline' | 'noData';

export interface EmptyStateProps {
  type?: EmptyStateType;
  icon?: React.ComponentType<React.SVGProps<SVGSVGElement>>;
  title: string;
  description?: string;
  action?: React.ReactNode | {
    label: string;
    onClick: () => void;
  };
  secondaryAction?: React.ReactNode | {
    label: string;
    onClick: () => void;
  };
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const typeConfig = {
  empty: { icon: InboxIcon, color: 'text-slate-500 dark:text-slate-400' },
  search: { icon: DocumentMagnifyingGlassIcon, color: 'text-slate-500 dark:text-slate-400' },
  success: { icon: ShieldCheckIcon, color: 'text-emerald-500' },
  error: { icon: ExclamationTriangleIcon, color: 'text-red-500' },
  offline: { icon: ServerIcon, color: 'text-amber-500' },
  noData: { icon: ChartBarIcon, color: 'text-slate-500 dark:text-slate-400' },
};

const sizeConfig = {
  sm: {
    icon: 'h-10 w-10',
    title: 'text-sm',
    description: 'text-xs',
    button: 'btn-sm',
    padding: 'py-6',
  },
  md: {
    icon: 'h-12 w-12',
    title: 'text-base',
    description: 'text-sm',
    button: '',
    padding: 'py-10',
  },
  lg: {
    icon: 'h-16 w-16',
    title: 'text-lg',
    description: 'text-sm',
    button: '',
    padding: 'py-16',
  },
};

export function EmptyState({
  type = 'empty',
  icon,
  title,
  description,
  action,
  secondaryAction,
  size = 'md',
  className,
}: EmptyStateProps) {
  const config = typeConfig[type];
  const sizes = sizeConfig[size];
  const Icon = icon || config.icon;

  return (
    <div className={clsx(
      'flex flex-col items-center justify-center text-center',
      sizes.padding,
      className
    )}>
      <div className={clsx(
        'flex items-center justify-center rounded-full bg-slate-100 dark:bg-slate-800 p-3 mb-4',
      )}>
        <Icon className={clsx(sizes.icon, config.color)} />
      </div>

      <h3 className={clsx(
        'font-semibold text-slate-900 dark:text-white',
        sizes.title
      )}>
        {title}
      </h3>

      {description && (
        <p className={clsx(
          'mt-1 max-w-sm text-slate-500 dark:text-slate-400',
          sizes.description
        )}>
          {description}
        </p>
      )}

      {(action || secondaryAction) && (
        <div className="mt-6 flex items-center gap-3">
          {action && (
            typeof action === 'object' && action !== null && 'label' in action ? (
              <button
                onClick={(action as { label: string; onClick: () => void }).onClick}
                className={clsx('btn btn-primary', sizes.button)}
              >
                {(action as { label: string; onClick: () => void }).label}
              </button>
            ) : action
          )}
          {secondaryAction && (
            typeof secondaryAction === 'object' && secondaryAction !== null && 'label' in secondaryAction ? (
              <button
                onClick={(secondaryAction as { label: string; onClick: () => void }).onClick}
                className={clsx('btn btn-secondary', sizes.button)}
              >
                {(secondaryAction as { label: string; onClick: () => void }).label}
              </button>
            ) : secondaryAction
          )}
        </div>
      )}
    </div>
  );
}

export default EmptyState;
