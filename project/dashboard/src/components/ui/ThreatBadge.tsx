/**
 * ThreatBadge - Attack severity indicator
 *
 * Visual badge for threat/attack severity levels
 */

import { clsx } from 'clsx';
import {
  ExclamationTriangleIcon,
  ShieldExclamationIcon,
  ShieldCheckIcon,
  InformationCircleIcon,
} from '@heroicons/react/20/solid';

export type ThreatLevel = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'none' | 0 | 1 | 2 | 3 | 4;

export interface ThreatBadgeProps {
  level: ThreatLevel;
  label?: string;
  showIcon?: boolean;
  size?: 'sm' | 'md' | 'lg';
  animated?: boolean;
  className?: string;
}

const levelConfig = {
  critical: {
    bg: 'bg-red-600 dark:bg-red-500',
    text: 'text-slate-900 dark:text-white',
    icon: ShieldExclamationIcon,
    label: 'Critical',
    ring: 'ring-red-500/50',
  },
  high: {
    bg: 'bg-orange-500 dark:bg-orange-500',
    text: 'text-slate-900 dark:text-white',
    icon: ExclamationTriangleIcon,
    label: 'High',
    ring: 'ring-orange-500/50',
  },
  medium: {
    bg: 'bg-amber-500 dark:bg-amber-500',
    text: 'text-slate-900 dark:text-white',
    icon: ExclamationTriangleIcon,
    label: 'Medium',
    ring: 'ring-amber-500/50',
  },
  low: {
    bg: 'bg-lime-500 dark:bg-lime-500',
    text: 'text-slate-900 dark:text-white',
    icon: InformationCircleIcon,
    label: 'Low',
    ring: 'ring-lime-500/50',
  },
  info: {
    bg: 'bg-blue-500 dark:bg-blue-500',
    text: 'text-slate-900 dark:text-white',
    icon: InformationCircleIcon,
    label: 'Info',
    ring: 'ring-blue-500/50',
  },
  none: {
    bg: 'bg-emerald-500 dark:bg-emerald-500',
    text: 'text-slate-900 dark:text-white',
    icon: ShieldCheckIcon,
    label: 'Normal',
    ring: 'ring-emerald-500/50',
  },
};

// Map numeric levels to string levels
const numericLevelMap: Record<number, keyof typeof levelConfig> = {
  0: 'none',
  1: 'low',
  2: 'medium',
  3: 'high',
  4: 'critical',
};

const sizeConfig = {
  sm: {
    badge: 'px-2 py-0.5 text-xs',
    icon: 'h-3 w-3',
  },
  md: {
    badge: 'px-2.5 py-1 text-xs',
    icon: 'h-3.5 w-3.5',
  },
  lg: {
    badge: 'px-3 py-1.5 text-sm',
    icon: 'h-4 w-4',
  },
};

function normalizeLevel(level: ThreatLevel): keyof typeof levelConfig {
  if (typeof level === 'number') {
    return numericLevelMap[level] || 'none';
  }
  if (level in levelConfig) {
    return level as keyof typeof levelConfig;
  }
  return 'none';
}

export function ThreatBadge({
  level,
  label,
  showIcon = true,
  size = 'md',
  animated = false,
  className,
}: ThreatBadgeProps) {
  const normalizedLevel = normalizeLevel(level);
  const config = levelConfig[normalizedLevel];
  const sizes = sizeConfig[size] || sizeConfig.md;
  const Icon = config.icon;

  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1 rounded-full font-semibold',
        config.bg,
        config.text,
        sizes.badge,
        animated && (normalizedLevel === 'critical' || normalizedLevel === 'high') && 'animate-pulse ring-2 ring-offset-2 ring-offset-white dark:ring-offset-slate-900',
        animated && config.ring,
        className
      )}
    >
      {showIcon && <Icon className={sizes.icon} />}
      {label || config.label}
    </span>
  );
}

/**
 * ThreatLevelBar - Horizontal threat level indicator
 */
export interface ThreatLevelBarProps {
  level: number; // 0-100 or 0-4 for categorical
  max?: number;
  showLabel?: boolean;
  className?: string;
}

export function ThreatLevelBar({
  level,
  max = 100,
  showLabel = true,
  className,
}: ThreatLevelBarProps) {
  const percentage = Math.min(100, Math.max(0, (level / max) * 100));

  const getGradient = () => {
    if (percentage >= 80) return 'from-red-500 to-red-600';
    if (percentage >= 60) return 'from-orange-500 to-orange-600';
    if (percentage >= 40) return 'from-amber-500 to-amber-600';
    if (percentage >= 20) return 'from-lime-500 to-lime-600';
    return 'from-emerald-500 to-emerald-600';
  };

  const getLabel = () => {
    if (percentage >= 80) return 'Critical';
    if (percentage >= 60) return 'High';
    if (percentage >= 40) return 'Medium';
    if (percentage >= 20) return 'Low';
    return 'Normal';
  };

  return (
    <div className={clsx('space-y-1', className)}>
      {showLabel && (
        <div className="flex justify-between text-xs">
          <span className="text-slate-500 dark:text-slate-400">Threat Level</span>
          <span className="font-medium text-slate-700 dark:text-slate-300">{getLabel()}</span>
        </div>
      )}
      <div className="h-2 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-700">
        <div
          className={clsx(
            'h-full rounded-full bg-gradient-to-r transition-all duration-500',
            getGradient()
          )}
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  );
}

export default ThreatBadge;
