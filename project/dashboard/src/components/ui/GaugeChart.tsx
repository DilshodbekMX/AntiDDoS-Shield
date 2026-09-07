/**
 * GaugeChart - Circular progress/gauge component
 *
 * Used for CPU usage, memory, threat level visualization
 */

import { clsx } from 'clsx';

export interface GaugeChartProps {
  value: number;
  max?: number;
  size?: 'sm' | 'md' | 'lg' | 'xl' | number;
  color?: 'brand' | 'success' | 'warning' | 'danger' | 'auto' | string;
  label?: string;
  sublabel?: string;
  showValue?: boolean;
  unit?: string;
  thickness?: number;
  className?: string;
}

const sizeStyles = {
  sm: { size: 64, fontSize: 'text-sm', sublabelSize: 'text-2xs' },
  md: { size: 96, fontSize: 'text-lg', sublabelSize: 'text-xs' },
  lg: { size: 128, fontSize: 'text-2xl', sublabelSize: 'text-sm' },
  xl: { size: 160, fontSize: 'text-3xl', sublabelSize: 'text-sm' },
};

const colorStyles = {
  brand: { stroke: '#6366f1', gradient: ['#818cf8', '#4f46e5'] },
  success: { stroke: '#10b981', gradient: ['#34d399', '#059669'] },
  warning: { stroke: '#f59e0b', gradient: ['#fbbf24', '#d97706'] },
  danger: { stroke: '#ef4444', gradient: ['#f87171', '#dc2626'] },
};

function getAutoColor(percentage: number) {
  if (percentage >= 90) return colorStyles.danger;
  if (percentage >= 70) return colorStyles.warning;
  if (percentage >= 50) return colorStyles.brand;
  return colorStyles.success;
}

function getSizeConfig(size: 'sm' | 'md' | 'lg' | 'xl' | number | undefined) {
  // Default to 'md' if size is undefined
  if (size === undefined || size === null) {
    return sizeStyles.md;
  }

  if (typeof size === 'number') {
    // Custom numeric size - calculate appropriate font size
    let fontSize = 'text-lg';
    let sublabelSize = 'text-xs';
    if (size >= 160) {
      fontSize = 'text-3xl';
      sublabelSize = 'text-sm';
    } else if (size >= 128) {
      fontSize = 'text-2xl';
      sublabelSize = 'text-sm';
    } else if (size >= 96) {
      fontSize = 'text-lg';
      sublabelSize = 'text-xs';
    } else {
      fontSize = 'text-sm';
      sublabelSize = 'text-2xs';
    }
    return { size, fontSize, sublabelSize };
  }

  // Return the size style or default to 'md' if not found
  return sizeStyles[size] || sizeStyles.md;
}

function getColorConfig(color: 'brand' | 'success' | 'warning' | 'danger' | 'auto' | string, percentage: number) {
  // Check if it's a predefined color
  if (color === 'auto') {
    return getAutoColor(percentage);
  }
  if (color in colorStyles) {
    return colorStyles[color as keyof typeof colorStyles];
  }
  // Custom hex color - create gradient from it
  return {
    stroke: color,
    gradient: [color, color], // Same color for both gradient stops
  };
}

export function GaugeChart({
  value = 0,
  max = 100,
  size = 'md',
  color = 'auto',
  label,
  sublabel,
  showValue = true,
  unit = '%',
  thickness = 8,
  className,
}: GaugeChartProps) {
  const percentage = Math.min(100, Math.max(0, (value / max) * 100));
  const sizeConfig = getSizeConfig(size);
  const colorConfig = getColorConfig(color, percentage);

  const radius = (sizeConfig.size - thickness) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (percentage / 100) * circumference;
  const center = sizeConfig.size / 2;

  // Create unique gradient ID
  const gradientId = `gauge-gradient-${Math.random().toString(36).substr(2, 9)}`;

  return (
    <div className={clsx('inline-flex flex-col items-center', className)}>
      <div className="relative" style={{ width: sizeConfig.size, height: sizeConfig.size }}>
        <svg
          width={sizeConfig.size}
          height={sizeConfig.size}
          className="transform -rotate-90"
        >
          {/* Gradient definition */}
          <defs>
            <linearGradient id={gradientId} x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor={colorConfig.gradient[0]} />
              <stop offset="100%" stopColor={colorConfig.gradient[1]} />
            </linearGradient>
          </defs>

          {/* Background circle */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke="currentColor"
            strokeWidth={thickness}
            className="text-slate-200 dark:text-slate-700"
          />

          {/* Progress circle */}
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke={`url(#${gradientId})`}
            strokeWidth={thickness}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            className="transition-all duration-500 ease-out"
          />

          {/* Glow effect for high values */}
          {percentage > 80 && (
            <circle
              cx={center}
              cy={center}
              r={radius}
              fill="none"
              stroke={colorConfig.stroke}
              strokeWidth={thickness + 4}
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              className="opacity-20 blur-sm"
            />
          )}
        </svg>

        {/* Center content */}
        {showValue && (
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className={clsx(
              'font-bold text-slate-900 dark:text-white',
              sizeConfig.fontSize
            )}>
              {Math.round(value)}
              {unit && <span className="text-slate-500 dark:text-slate-400 text-sm ml-0.5">{unit}</span>}
            </span>
            {sublabel && (
              <span className={clsx(
                'text-slate-500 dark:text-slate-400',
                sizeConfig.sublabelSize
              )}>
                {sublabel}
              </span>
            )}
          </div>
        )}
      </div>

      {label && (
        <span className="mt-2 text-sm font-medium text-slate-600 dark:text-slate-400">
          {label}
        </span>
      )}
    </div>
  );
}

export default GaugeChart;
