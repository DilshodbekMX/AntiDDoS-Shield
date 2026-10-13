/**
 * Statistics Card Component
 */

// React is auto-imported in JSX
import { clsx } from 'clsx';
import { ArrowUpIcon, ArrowDownIcon } from '@heroicons/react/20/solid';

interface StatCardProps {
  title: string;
  value: string | number;
  unit?: string;
  change?: number;
  changeLabel?: string;
  icon?: React.ComponentType<React.SVGProps<SVGSVGElement>>;
  color?: 'blue' | 'green' | 'yellow' | 'red' | 'purple' | 'gray';
  loading?: boolean;
}

const colorClasses = {
  blue: 'bg-blue-500',
  green: 'bg-green-500',
  yellow: 'bg-yellow-500',
  red: 'bg-red-500',
  purple: 'bg-purple-500',
  gray: 'bg-gray-500',
};

const bgClasses = {
  blue: 'bg-blue-50',
  green: 'bg-green-50',
  yellow: 'bg-yellow-50',
  red: 'bg-red-50',
  purple: 'bg-purple-50',
  gray: 'bg-gray-50',
};

export function StatCard({
  title,
  value,
  unit,
  change,
  changeLabel,
  icon: Icon,
  color = 'blue',
  loading = false,
}: StatCardProps) {
  const isPositive = change !== undefined && change >= 0;

  return (
    <div className="overflow-hidden rounded-lg bg-white shadow dark:bg-gray-800">
      <div className="p-5">
        <div className="flex items-center">
          {Icon && (
            <div className={clsx('flex-shrink-0 rounded-md p-3', bgClasses[color])}>
              <Icon className={clsx('h-6 w-6', `text-${color}-600`)} aria-hidden="true" />
            </div>
          )}
          <div className={clsx('flex-1', Icon && 'ml-5')}>
            <p className="text-sm font-medium text-gray-500 dark:text-gray-400 truncate">
              {title}
            </p>
            <div className="flex items-baseline">
              {loading ? (
                <div className="h-8 w-24 animate-pulse rounded bg-gray-200 dark:bg-gray-700" />
              ) : (
                <>
                  <p className="text-2xl font-semibold text-gray-900 dark:text-white">
                    {typeof value === 'number' ? value.toLocaleString() : value}
                  </p>
                  {unit && (
                    <p className="ml-1 text-sm text-gray-500 dark:text-gray-400">{unit}</p>
                  )}
                </>
              )}
            </div>
          </div>
        </div>
        {change !== undefined && (
          <div className="mt-4">
            <div className="flex items-center">
              <span
                className={clsx(
                  'flex items-center text-sm font-medium',
                  isPositive ? 'text-green-600' : 'text-red-600'
                )}
              >
                {isPositive ? (
                  <ArrowUpIcon className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
                ) : (
                  <ArrowDownIcon className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
                )}
                <span className="ml-1">{Math.abs(change).toFixed(1)}%</span>
              </span>
              {changeLabel && (
                <span className="ml-2 text-sm text-gray-500 dark:text-gray-400">
                  {changeLabel}
                </span>
              )}
            </div>
          </div>
        )}
      </div>
      <div className={clsx('h-1', colorClasses[color])} />
    </div>
  );
}

export default StatCard;
