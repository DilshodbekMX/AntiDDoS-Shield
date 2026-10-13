/**
 * StatusIndicator - Connection/health status component
 *
 * Animated indicator for system health, connection status
 */

// React is auto-imported in JSX
import { clsx } from 'clsx';

export type StatusType = 'online' | 'offline' | 'warning' | 'error' | 'loading' | 'unknown' | 'healthy' | 'down' | 'success' | 'danger';

export interface StatusIndicatorProps {
  status: StatusType;
  label?: string;
  showPulse?: boolean;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const statusStyles = {
  online: {
    dot: 'bg-emerald-500',
    pulse: 'bg-emerald-400',
    label: 'text-emerald-600 dark:text-emerald-400',
    text: 'Online',
  },
  offline: {
    dot: 'bg-slate-400',
    pulse: '',
    label: 'text-slate-500 dark:text-slate-400',
    text: 'Offline',
  },
  warning: {
    dot: 'bg-amber-500',
    pulse: 'bg-amber-400',
    label: 'text-amber-600 dark:text-amber-400',
    text: 'Warning',
  },
  error: {
    dot: 'bg-red-500',
    pulse: 'bg-red-400',
    label: 'text-red-600 dark:text-red-400',
    text: 'Error',
  },
  loading: {
    dot: 'bg-blue-500',
    pulse: 'bg-blue-400',
    label: 'text-blue-600 dark:text-blue-400',
    text: 'Loading',
  },
  unknown: {
    dot: 'bg-slate-400',
    pulse: '',
    label: 'text-slate-500 dark:text-slate-400',
    text: 'Unknown',
  },
  healthy: {
    dot: 'bg-emerald-500',
    pulse: 'bg-emerald-400',
    label: 'text-emerald-600 dark:text-emerald-400',
    text: 'Healthy',
  },
  down: {
    dot: 'bg-red-500',
    pulse: '',
    label: 'text-red-600 dark:text-red-400',
    text: 'Down',
  },
  success: {
    dot: 'bg-emerald-500',
    pulse: 'bg-emerald-400',
    label: 'text-emerald-600 dark:text-emerald-400',
    text: 'Success',
  },
  danger: {
    dot: 'bg-red-500',
    pulse: 'bg-red-400',
    label: 'text-red-600 dark:text-red-400',
    text: 'Danger',
  },
};

const sizeStyles = {
  sm: { dot: 'h-2 w-2', text: 'text-xs' },
  md: { dot: 'h-2.5 w-2.5', text: 'text-sm' },
  lg: { dot: 'h-3 w-3', text: 'text-sm' },
};

export function StatusIndicator({
  status,
  label,
  showPulse = true,
  size = 'md',
  className,
}: StatusIndicatorProps) {
  const style = statusStyles[status] || statusStyles.unknown;
  const sizeStyle = sizeStyles[size] || sizeStyles.md;
  const shouldPulse = showPulse && (status === 'online' || status === 'warning' || status === 'error' || status === 'loading');

  return (
    <div className={clsx('inline-flex items-center gap-2', className)}>
      <span className="relative flex">
        {/* Pulse animation */}
        {shouldPulse && style.pulse && (
          <span className={clsx(
            'absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping',
            style.pulse
          )} />
        )}
        {/* Static dot */}
        <span className={clsx(
          'relative inline-flex rounded-full',
          sizeStyle.dot,
          style.dot
        )} />
      </span>

      {/* Label */}
      {label !== undefined ? (
        <span className={clsx('font-medium', sizeStyle.text, style.label)}>
          {label}
        </span>
      ) : (
        <span className={clsx('font-medium', sizeStyle.text, style.label)}>
          {style.text}
        </span>
      )}
    </div>
  );
}

export default StatusIndicator;
