/**
 * Breadcrumbs -- Contextual navigation for nested views
 *
 * Only renders for non-root routes. Shows clickable path segments
 * with human-readable labels.
 */

import { Fragment } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { ChevronRightIcon } from '@heroicons/react/20/solid';
import { clsx } from 'clsx';

const routeLabels: Record<string, string> = {
  'traffic':        'Traffic Analysis',
  'features':       'Feature Monitor',
  'baselines':      'Baselines',
  'assets':         'Protected Assets',
  'attack-history': 'Attack History',
  'rules':          'Access Rules',
  'geo':            'Geo-Blocking',
  'validation':     'Protocol Validation',
  'config':         'Configuration',
  'running-config': 'Running Config',
  'system':         'Health & Alerts',
  'reports':        'Reports',
  'settings':       'Settings',
};

function isIPSegment(seg: string): boolean {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(seg) || seg.includes(':');
}

export function Breadcrumbs() {
  const location = useLocation();
  const segments = location.pathname.split('/').filter(Boolean);

  // Don't render breadcrumbs on root dashboard
  if (segments.length === 0) return null;

  return (
    <nav className="flex items-center gap-1.5 text-sm text-slate-500 dark:text-slate-400 mb-4" aria-label="Breadcrumb">
      <Link to="/" className="hover:text-slate-900 dark:hover:text-slate-200 transition-colors">
        Dashboard
      </Link>
      {segments.map((seg, i) => {
        const isLast = i === segments.length - 1;
        const href = '/' + segments.slice(0, i + 1).join('/');
        const label = routeLabels[seg] || decodeURIComponent(seg);
        const isIP = isIPSegment(seg);

        return (
          <Fragment key={href}>
            <ChevronRightIcon className="h-3.5 w-3.5 text-slate-400 dark:text-slate-600 flex-shrink-0" />
            {isLast ? (
              <span className={clsx('text-slate-900 dark:text-slate-200 font-medium truncate', isIP && 'font-mono')}>
                {label}
              </span>
            ) : (
              <Link
                to={href}
                className={clsx('hover:text-slate-900 dark:hover:text-slate-200 transition-colors truncate', isIP && 'font-mono')}
              >
                {label}
              </Link>
            )}
          </Fragment>
        );
      })}
    </nav>
  );
}

export default Breadcrumbs;
