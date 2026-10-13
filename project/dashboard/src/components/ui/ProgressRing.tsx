/**
 * ProgressRing - Circular progress indicator
 *
 * Lightweight alternative to GaugeChart for inline use
 */

// React is auto-imported in JSX
import { clsx } from 'clsx';

export interface ProgressRingProps {
  value: number;
  max?: number;
  size?: number;
  strokeWidth?: number;
  color?: string;
  trackColor?: string;
  showValue?: boolean;
  className?: string;
}

export function ProgressRing({
  value,
  max = 100,
  size = 40,
  strokeWidth = 4,
  color = '#6366f1',
  trackColor,
  showValue = false,
  className,
}: ProgressRingProps) {
  const percentage = Math.min(100, Math.max(0, (value / max) * 100));
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (percentage / 100) * circumference;
  const center = size / 2;

  return (
    <div className={clsx('relative inline-flex items-center justify-center', className)}>
      <svg width={size} height={size} className="transform -rotate-90">
        {/* Background track */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke={trackColor || 'currentColor'}
          strokeWidth={strokeWidth}
          className={!trackColor ? 'text-slate-200 dark:text-slate-700' : ''}
        />
        {/* Progress */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          className="transition-all duration-300"
        />
      </svg>

      {showValue && (
        <span className="absolute text-2xs font-semibold text-slate-700 dark:text-slate-300">
          {Math.round(percentage)}
        </span>
      )}
    </div>
  );
}

export default ProgressRing;
