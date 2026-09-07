/**
 * MetricCard - Enterprise KPI Card Component
 *
 * 3-tier visual system:
 * - "featured" (lg): card-featured with gradient accent, prominent value
 * - "standard" (md): regular card with icon and sparkline
 * - "compact" (sm): minimal card for secondary metrics
 */

import { clsx } from 'clsx';
import { ArrowUpIcon, ArrowDownIcon, MinusIcon } from '@heroicons/react/20/solid';
import { Sparkline } from './Sparkline';
import { AnimatedNumber } from './AnimatedNumber';

export interface MetricCardProps {
  title: string;
  value: string | number;
  unit?: string;
  change?: number;
  changeLabel?: string;
  sparklineData?: number[];
  icon?: React.ComponentType<React.SVGProps<SVGSVGElement>>;
  color?: 'brand' | 'success' | 'warning' | 'danger' | 'info' | 'neutral';
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
  trend?: 'up' | 'down' | 'neutral';
  subtitle?: string;
  onClick?: () => void;
  className?: string;
}

const colorStyles = {
  brand: {
    icon: 'text-brand-600 dark:text-brand-400',
    bg: 'bg-brand-50 dark:bg-brand-500/10',
    sparkline: '#6366f1',
    accentBorder: 'border-l-brand-500',
  },
  success: {
    icon: 'text-emerald-600 dark:text-emerald-400',
    bg: 'bg-emerald-50 dark:bg-emerald-500/10',
    sparkline: '#10b981',
    accentBorder: 'border-l-emerald-500',
  },
  warning: {
    icon: 'text-amber-600 dark:text-amber-400',
    bg: 'bg-amber-50 dark:bg-amber-500/10',
    sparkline: '#f59e0b',
    accentBorder: 'border-l-amber-500',
  },
  danger: {
    icon: 'text-red-600 dark:text-red-400',
    bg: 'bg-red-50 dark:bg-red-500/10',
    sparkline: '#ef4444',
    accentBorder: 'border-l-red-500',
  },
  info: {
    icon: 'text-blue-600 dark:text-blue-400',
    bg: 'bg-blue-50 dark:bg-blue-500/10',
    sparkline: '#3b82f6',
    accentBorder: 'border-l-blue-500',
  },
  neutral: {
    icon: 'text-slate-600 dark:text-slate-400',
    bg: 'bg-slate-100 dark:bg-slate-800',
    sparkline: '#64748b',
    accentBorder: 'border-l-slate-500',
  },
};

const sizeStyles = {
  sm: {
    card: 'p-4',
    title: 'text-xs',
    value: 'text-xl',
    icon: 'h-8 w-8',
    iconWrapper: 'p-1.5',
  },
  md: {
    card: 'p-5',
    title: 'text-sm',
    value: 'text-2xl',
    icon: 'h-10 w-10',
    iconWrapper: 'p-2',
  },
  lg: {
    card: 'p-6',
    title: 'text-sm',
    value: 'text-4xl',
    icon: 'h-12 w-12',
    iconWrapper: 'p-2.5',
  },
};

export function MetricCard({
  title,
  value,
  unit,
  change,
  changeLabel,
  sparklineData,
  icon: Icon,
  color = 'brand',
  size = 'md',
  loading = false,
  trend,
  subtitle,
  onClick,
  className,
}: MetricCardProps) {
  const colors = colorStyles[color];
  const sizes = sizeStyles[size];
  const isFeatured = size === 'lg';

  const actualTrend = trend ?? (change !== undefined ? (change > 0 ? 'up' : change < 0 ? 'down' : 'neutral') : undefined);
  const TrendIcon = actualTrend === 'up' ? ArrowUpIcon : actualTrend === 'down' ? ArrowDownIcon : MinusIcon;
  const trendColor = actualTrend === 'up' ? 'text-emerald-600 dark:text-emerald-400' : actualTrend === 'down' ? 'text-red-600 dark:text-red-400' : 'text-slate-500';

  if (loading) {
    return (
      <div className={clsx(
        isFeatured ? 'card-featured' : 'card',
        'animate-pulse',
        sizes.card,
        className
      )}>
        <div className="flex items-start justify-between">
          <div className="space-y-3 flex-1">
            <div className="h-4 w-24 bg-slate-200 dark:bg-slate-700 rounded" />
            <div className="h-8 w-32 bg-slate-200 dark:bg-slate-700 rounded" />
            <div className="h-3 w-20 bg-slate-200 dark:bg-slate-700 rounded" />
          </div>
          <div className="h-10 w-10 bg-slate-200 dark:bg-slate-700 rounded-lg" />
        </div>
      </div>
    );
  }

  return (
    <div
      className={clsx(
        'relative overflow-hidden transition-all duration-200',
        isFeatured ? 'card-featured border-l-4' : 'card',
        isFeatured && colors.accentBorder,
        sizes.card,
        onClick && 'cursor-pointer hover:shadow-lg hover:border-slate-300 dark:hover:border-slate-300 dark:border-slate-600',
        className
      )}
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
    >
      <div className="relative flex items-start justify-between">
        <div className="flex-1 min-w-0">
          {/* Title */}
          <p className={clsx(
            'font-medium text-slate-500 dark:text-slate-400 truncate',
            sizes.title
          )}>
            {title}
          </p>

          {/* Value with animated transitions and tabular-nums */}
          <div className="mt-2 flex items-baseline gap-2">
            <span className={clsx(
              'font-bold tracking-tight text-slate-900 dark:text-white tabular-nums',
              sizes.value
            )}>
              {typeof value === 'number' ? (
                <AnimatedNumber value={value} duration={400} />
              ) : (
                value
              )}
            </span>
            {unit && (
              <span className="text-sm font-medium text-slate-500 dark:text-slate-400">
                {unit}
              </span>
            )}
          </div>

          {/* Subtitle or Change indicator */}
          {(subtitle || change !== undefined) && (
            <div className="mt-2 flex items-center gap-2">
              {change !== undefined && (
                <span className={clsx(
                  'inline-flex items-center gap-0.5 text-sm font-medium',
                  trendColor
                )}>
                  <TrendIcon className="h-4 w-4" />
                  {Math.abs(change).toFixed(1)}%
                </span>
              )}
              {(changeLabel || subtitle) && (
                <span className="text-xs text-slate-500 dark:text-slate-400">
                  {changeLabel || subtitle}
                </span>
              )}
            </div>
          )}

          {/* Sparkline -- inline for standard/compact cards */}
          {!isFeatured && sparklineData && sparklineData.length > 0 && (
            <div className="mt-3 h-8">
              <Sparkline
                data={sparklineData}
                color={colors.sparkline}
                height={32}
              />
            </div>
          )}
        </div>

        {/* Icon */}
        {Icon && (
          <div className={clsx(
            'flex-shrink-0 rounded-lg',
            colors.bg,
            sizes.iconWrapper
          )}>
            <Icon className={clsx(
              colors.icon,
              sizes.icon
            )} />
          </div>
        )}
      </div>

      {/* Sparkline -- full-width below content for featured cards */}
      {isFeatured && sparklineData && sparklineData.length > 0 && (
        <div className="mt-4 h-12 -mx-2">
          <Sparkline
            data={sparklineData}
            color={colors.sparkline}
            height={48}
          />
        </div>
      )}
    </div>
  );
}

export default MetricCard;
