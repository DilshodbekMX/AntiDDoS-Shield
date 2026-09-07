/**
 * LoadingSpinner - Loading indicator components
 *
 * Various loading states for different contexts
 */

// React is auto-imported in JSX
import { clsx } from 'clsx';

export interface LoadingSpinnerProps {
  size?: 'xs' | 'sm' | 'md' | 'lg' | 'xl';
  color?: 'brand' | 'white' | 'slate';
  className?: string;
}

const sizeStyles = {
  xs: 'h-3 w-3 border',
  sm: 'h-4 w-4 border-2',
  md: 'h-6 w-6 border-2',
  lg: 'h-8 w-8 border-2',
  xl: 'h-12 w-12 border-3',
};

const colorStyles = {
  brand: 'border-brand-600 border-t-transparent',
  white: 'border-white border-t-transparent',
  slate: 'border-slate-300 border-t-slate-600 dark:border-slate-600 dark:border-t-slate-300',
};

export function LoadingSpinner({
  size = 'md',
  color = 'brand',
  className,
}: LoadingSpinnerProps) {
  return (
    <div
      className={clsx(
        'rounded-full animate-spin',
        sizeStyles[size],
        colorStyles[color],
        className
      )}
      role="status"
      aria-label="Loading"
    />
  );
}

/**
 * LoadingDots - Animated dots loading indicator
 */
export interface LoadingDotsProps {
  size?: 'sm' | 'md' | 'lg';
  color?: string;
  className?: string;
}

export function LoadingDots({
  size = 'md',
  color = 'bg-brand-600',
  className,
}: LoadingDotsProps) {
  const dotSize = size === 'sm' ? 'h-1.5 w-1.5' : size === 'md' ? 'h-2 w-2' : 'h-2.5 w-2.5';
  const gap = size === 'sm' ? 'gap-1' : 'gap-1.5';

  return (
    <div className={clsx('flex items-center', gap, className)}>
      {[0, 1, 2].map((i) => (
        <div
          key={i}
          className={clsx(
            'rounded-full animate-pulse',
            dotSize,
            color
          )}
          style={{
            animationDelay: `${i * 150}ms`,
            animationDuration: '600ms',
          }}
        />
      ))}
    </div>
  );
}

/**
 * LoadingOverlay - Full-screen or container loading overlay
 */
export interface LoadingOverlayProps {
  message?: string;
  fullScreen?: boolean;
  className?: string;
}

export function LoadingOverlay({
  message = 'Loading...',
  fullScreen = false,
  className,
}: LoadingOverlayProps) {
  return (
    <div
      className={clsx(
        'flex flex-col items-center justify-center bg-white/80 dark:bg-slate-900/80 backdrop-blur-sm',
        fullScreen ? 'fixed inset-0 z-50' : 'absolute inset-0 z-10',
        className
      )}
    >
      <LoadingSpinner size="lg" />
      {message && (
        <p className="mt-4 text-sm text-slate-600 dark:text-slate-400">
          {message}
        </p>
      )}
    </div>
  );
}

/**
 * SkeletonText - Text placeholder skeleton
 */
export interface SkeletonTextProps {
  lines?: number;
  className?: string;
}

export function SkeletonText({ lines = 3, className }: SkeletonTextProps) {
  return (
    <div className={clsx('space-y-2', className)}>
      {[...Array(lines)].map((_, i) => (
        <div
          key={i}
          className={clsx(
            'h-4 rounded bg-slate-200 dark:bg-slate-700 animate-pulse',
            i === lines - 1 && 'w-3/4'
          )}
        />
      ))}
    </div>
  );
}

/**
 * SkeletonCard - Card placeholder skeleton
 */
export interface SkeletonCardProps {
  lines?: number;
  className?: string;
}

export function SkeletonCard({ lines = 3, className }: SkeletonCardProps) {
  return (
    <div className={clsx('card p-5 animate-pulse', className)}>
      <div className="flex items-start justify-between">
        <div className="space-y-3 flex-1">
          {[...Array(lines)].map((_, i) => (
            <div
              key={i}
              className={clsx(
                'bg-slate-200 dark:bg-slate-700 rounded',
                i === 0 ? 'h-4 w-24' : i === 1 ? 'h-8 w-32' : 'h-3 w-20'
              )}
            />
          ))}
        </div>
        <div className="h-10 w-10 bg-slate-200 dark:bg-slate-700 rounded-lg" />
      </div>
    </div>
  );
}

export default LoadingSpinner;
