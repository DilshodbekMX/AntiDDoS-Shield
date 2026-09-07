/**
 * Enterprise Sidebar Navigation
 *
 * Sidebar navigation structure
 * modeled after enterprise security dashboards (Cloudflare, Akamai, Arbor)
 */

import { useEffect, useCallback, useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { clsx } from 'clsx';
import {
  HomeIcon,
  ShieldCheckIcon,
  CogIcon,
  AdjustmentsHorizontalIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  CommandLineIcon,
  ChevronDownIcon,
  ChevronUpIcon,
  ShieldExclamationIcon,
  CpuChipIcon,
  BellAlertIcon,
  WrenchScrewdriverIcon,
  DocumentChartBarIcon,
  ArrowTrendingUpIcon,
  ComputerDesktopIcon,
  LockClosedIcon,
  GlobeAltIcon,
  PresentationChartLineIcon,
  EyeIcon,
  ChartBarSquareIcon,
  ClockIcon,
  BuildingOfficeIcon,
} from '@heroicons/react/24/outline';
import { useUIStore, useAuthStore } from '../../store';
import { Tooltip } from '../ui';
import api from '../../services/api';

// ============================================================================
// Types & Constants
// ============================================================================

interface NavItem {
  name: string;
  href: string;
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
  shortcut?: string;
  badge?: number | string;
  badgeColor?: 'red' | 'yellow' | 'green' | 'blue';
}

interface NavSection {
  id: string;
  name: string;
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
  items: NavItem[];
  defaultOpen?: boolean;
}

// Navigation grouped into 5 sections
const navigationSections: NavSection[] = [
  {
    id: 'overview',
    name: 'Overview',
    icon: HomeIcon,
    defaultOpen: true,
    items: [
      { name: 'Dashboard', href: '/', icon: HomeIcon, shortcut: 'G D' },
      { name: 'Health & Alerts', href: '/system', icon: BellAlertIcon, shortcut: 'G S' },
    ],
  },
  {
    id: 'traffic',
    name: 'Traffic & Detection',
    icon: ArrowTrendingUpIcon,
    defaultOpen: false,
    items: [
      { name: 'Traffic', href: '/traffic', icon: ArrowTrendingUpIcon, shortcut: 'G T' },
      { name: 'Feature Monitor', href: '/features', icon: ChartBarSquareIcon, shortcut: 'G F' },
      { name: 'Feature History', href: '/features/history', icon: ClockIcon, shortcut: 'G H' },
      { name: 'Baselines', href: '/baselines', icon: PresentationChartLineIcon, shortcut: 'G B' },
    ],
  },
  {
    id: 'security',
    name: 'Security',
    icon: ShieldCheckIcon,
    defaultOpen: true,
    items: [
      { name: 'Protected Assets', href: '/assets', icon: ComputerDesktopIcon, shortcut: 'G A' },
      { name: 'Attack History', href: '/attack-history', icon: ShieldExclamationIcon, shortcut: 'G H' },
    ],
  },
  {
    id: 'rules',
    name: 'Rules & Config',
    icon: LockClosedIcon,
    defaultOpen: false,
    items: [
      { name: 'Access Rules', href: '/rules', icon: WrenchScrewdriverIcon, shortcut: 'G R' },
      { name: 'Geo-Blocking', href: '/geo', icon: GlobeAltIcon, shortcut: 'G G' },
      { name: 'Protocol Validation', href: '/validation', icon: ShieldExclamationIcon, shortcut: 'G V' },
      { name: 'Configuration', href: '/config', icon: AdjustmentsHorizontalIcon, shortcut: 'G C' },
      { name: 'Running Config', href: '/running-config', icon: EyeIcon, shortcut: 'G N' },
    ],
  },
  {
    id: 'reports',
    name: 'Reports',
    icon: DocumentChartBarIcon,
    defaultOpen: false,
    items: [
      { name: 'Reports', href: '/reports', icon: DocumentChartBarIcon, shortcut: 'G E' },
    ],
  },
];

// Keyboard shortcut map - consolidated navigation
const shortcutMap: Record<string, string> = {
  'g d': '/',
  'g t': '/traffic',
  'g f': '/features',
  'g a': '/assets',
  'g r': '/rules',
  'g g': '/geo',
  'g v': '/validation',
  'g c': '/config',
  'g n': '/running-config',
  'g b': '/baselines',
  'g h': '/attack-history',
  'g s': '/system',
  'g e': '/reports',
};

// ============================================================================
// Sub-Components
// ============================================================================

interface NavItemComponentProps {
  item: NavItem;
  collapsed: boolean;
  isActive: boolean;
}

function NavItemComponent({ item, collapsed, isActive }: NavItemComponentProps) {
  const content = (
    <NavLink
      to={item.href}
      className={clsx(
        'group relative flex items-center gap-x-3 rounded-lg px-3 py-2 text-sm font-medium transition-all duration-200',
        isActive
          ? 'bg-brand-600 text-white shadow-lg shadow-brand-500/25'
          : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-white',
        collapsed && 'justify-center px-2'
      )}
    >
      <item.icon
        className={clsx(
          'h-5 w-5 shrink-0 transition-colors',
          isActive ? 'text-white' : 'text-slate-400 dark:text-slate-500 group-hover:text-slate-700 dark:group-hover:text-slate-300'
        )}
        aria-hidden="true"
      />
      {!collapsed && (
        <>
          <span className="flex-1 truncate">{item.name}</span>
          {item.badge !== undefined && (
            <span
              className={clsx(
                'ml-auto flex h-5 min-w-[20px] items-center justify-center rounded-full px-1.5 text-xs font-bold',
                item.badgeColor === 'red' && 'bg-red-500 text-white',
                item.badgeColor === 'yellow' && 'bg-yellow-500 text-black',
                item.badgeColor === 'green' && 'bg-emerald-500 text-white',
                item.badgeColor === 'blue' && 'bg-blue-500 text-white',
                !item.badgeColor && 'bg-slate-200 dark:bg-slate-600 text-slate-600 dark:text-slate-200'
              )}
            >
              {typeof item.badge === 'number' && item.badge > 99 ? '99+' : item.badge}
            </span>
          )}
        </>
      )}
    </NavLink>
  );

  if (collapsed) {
    return (
      <Tooltip content={item.name} position="right">
        {content}
      </Tooltip>
    );
  }

  return content;
}

interface NavSectionComponentProps {
  section: NavSection;
  collapsed: boolean;
  currentPath: string;
  isOpen: boolean;
  onToggle: () => void;
}

function NavSectionComponent({
  section,
  collapsed,
  currentPath,
  isOpen,
  onToggle,
}: NavSectionComponentProps) {
  const hasActiveItem = section.items.some(
    (item) => currentPath === item.href || currentPath.startsWith(item.href + '/')
  );

  if (collapsed) {
    return (
      <div className="space-y-1">
        {section.items.map((item) => (
          <NavItemComponent
            key={item.href}
            item={item}
            collapsed={collapsed}
            isActive={currentPath === item.href || currentPath.startsWith(item.href + '/')}
          />
        ))}
      </div>
    );
  }

  return (
    <div className="space-y-1">
      <button
        onClick={onToggle}
        className={clsx(
          'flex w-full items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold uppercase tracking-wider transition-colors',
          hasActiveItem
            ? 'text-brand-600 dark:text-brand-400'
            : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'
        )}
      >
        <section.icon className="h-4 w-4" />
        <span className="flex-1 text-left">{section.name}</span>
        {isOpen ? (
          <ChevronUpIcon className="h-3.5 w-3.5" />
        ) : (
          <ChevronDownIcon className="h-3.5 w-3.5" />
        )}
      </button>

      {isOpen && (
        <div className="ml-2 space-y-0.5">
          {section.items.map((item) => (
            <NavItemComponent
              key={item.href}
              item={item}
              collapsed={collapsed}
              isActive={currentPath === item.href || currentPath.startsWith(item.href + '/')}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// Real-time status badge
function SystemStatusBadge({ collapsed }: { collapsed: boolean }) {
  const { data: connectionStatus } = useQuery({
    queryKey: ['dpdk-connection-nav'],
    queryFn: () => api.getDPDKConnectionStatus(),
    refetchInterval: 5000,
  });

  const { data: anomalyData } = useQuery({
    queryKey: ['anomaly-nav'],
    queryFn: () => api.getRealtimeAnomaly() as Promise<{ active: boolean; level: number; level_name: string }>,
    refetchInterval: 2000,
  });

  // Also check per-IP anomalies to filter out stale global anomaly
  const { data: perIPData } = useQuery({
    queryKey: ['per-ip-anomaly-nav'],
    queryFn: () => api.getRealtimeAnomalyPerIP() as Promise<Record<string, { anomaly_active: boolean; packets_per_sec?: number }>>,
    refetchInterval: 2000,
  });

  const isConnected = connectionStatus?.connected;
  // Only show UNDER ATTACK if there's actual traffic with anomaly
  const hasRealActiveAnomalies = perIPData
    ? Object.values(perIPData).some(entry => entry.anomaly_active && (entry.packets_per_sec ?? 0) > 0)
    : false;
  const isUnderAttack = anomalyData?.active && hasRealActiveAnomalies;

  if (collapsed) {
    return (
      <Tooltip
        content={
          isUnderAttack
            ? `ATTACK: ${anomalyData?.level_name}`
            : isConnected
            ? 'System Operational'
            : 'DPDK Disconnected'
        }
        position="right"
      >
        <div className="flex justify-center py-2">
          <div className="relative">
            <div
              className={clsx(
                'h-3 w-3 rounded-full',
                isUnderAttack
                  ? 'bg-red-500'
                  : isConnected
                  ? 'bg-emerald-500'
                  : 'bg-yellow-500'
              )}
            />
            {(isConnected || isUnderAttack) && (
              <div
                className={clsx(
                  'absolute inset-0 h-3 w-3 rounded-full animate-ping',
                  isUnderAttack ? 'bg-red-500' : 'bg-emerald-500'
                )}
              />
            )}
          </div>
        </div>
      </Tooltip>
    );
  }

  return (
    <div
      className={clsx(
        'rounded-lg border p-3',
        isUnderAttack
          ? 'border-red-500/50 bg-red-500/10'
          : isConnected
          ? 'border-emerald-500/30 bg-emerald-500/5'
          : 'border-yellow-500/30 bg-yellow-500/5'
      )}
    >
      <div className="flex items-center gap-2">
        <div className="relative">
          <div
            className={clsx(
              'h-2.5 w-2.5 rounded-full',
              isUnderAttack
                ? 'bg-red-500'
                : isConnected
                ? 'bg-emerald-500'
                : 'bg-yellow-500'
            )}
          />
          {(isConnected || isUnderAttack) && (
            <div
              className={clsx(
                'absolute inset-0 h-2.5 w-2.5 rounded-full animate-ping',
                isUnderAttack ? 'bg-red-500' : 'bg-emerald-500'
              )}
            />
          )}
        </div>
        <div className="flex-1 min-w-0">
          <p
            className={clsx(
              'text-xs font-medium',
              isUnderAttack
                ? 'text-red-400'
                : isConnected
                ? 'text-emerald-400'
                : 'text-yellow-400'
            )}
          >
            {isUnderAttack
              ? 'UNDER ATTACK'
              : isConnected
              ? 'Operational'
              : 'Disconnected'}
          </p>
          {isUnderAttack && anomalyData && (
            <p className="text-2xs text-red-300/70 truncate">
              Level: {anomalyData.level_name}
            </p>
          )}
        </div>
        {isUnderAttack && (
          <ShieldExclamationIcon className="h-5 w-5 text-red-400 animate-pulse" />
        )}
      </div>
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export function Sidebar() {
  const location = useLocation();
  const { sidebarOpen, toggleSidebar } = useUIStore();
  const { user } = useAuthStore();

  const collapsed = !sidebarOpen;
  const isAdmin = user?.is_admin === true;

  // Fetch attack count for badge
  const { data: perIPSummary } = useQuery({
    queryKey: ['per-ip-summary-nav'],
    queryFn: () => api.getPerIPAnomalySummary() as Promise<{ anomalous_ips: number; total_protected_ips: number }>,
    refetchInterval: 5000,
  });

  // Add badges to navigation items
  const sectionsWithBadges = navigationSections.map((section) => ({
    ...section,
    items: section.items.map((item) => {
      if (item.href === '/assets' && perIPSummary?.total_protected_ips) {
        return {
          ...item,
          badge: perIPSummary.total_protected_ips,
          badgeColor: 'blue' as const,
        };
      }
      return item;
    }),
  }));

  // Accordion state -- only one section open at a time.
  // Initialize to the section containing the current route, or first defaultOpen.
  const [openSectionId, setOpenSectionId] = useState<string | null>(() => {
    const active = navigationSections.find((s) =>
      s.items.some((item) => location.pathname === item.href || location.pathname.startsWith(item.href + '/'))
    );
    return active?.id ?? navigationSections.find((s) => s.defaultOpen)?.id ?? null;
  });

  // Auto-switch open section when navigating to a different section's route
  useEffect(() => {
    const active = navigationSections.find((s) =>
      s.items.some((item) => location.pathname === item.href || location.pathname.startsWith(item.href + '/'))
    );
    if (active && active.id !== openSectionId) {
      setOpenSectionId(active.id);
    }
  }, [location.pathname]); // eslint-disable-line react-hooks/exhaustive-deps

  // Keyboard navigation handler
  const handleKeyDown = useCallback(
    (event: KeyboardEvent) => {
      if (
        event.target instanceof HTMLInputElement ||
        event.target instanceof HTMLTextAreaElement
      ) {
        return;
      }

      if (event.key === '[') {
        event.preventDefault();
        toggleSidebar();
        return;
      }

      if (event.key === 'g' && !event.metaKey && !event.ctrlKey) {
        const handleSecondKey = (e: KeyboardEvent) => {
          const combo = `g ${e.key}`.toLowerCase();
          const href = shortcutMap[combo];
          if (href) {
            e.preventDefault();
            window.location.href = href;
          }
          document.removeEventListener('keydown', handleSecondKey);
        };

        setTimeout(() => {
          document.addEventListener('keydown', handleSecondKey, { once: true });
          setTimeout(() => {
            document.removeEventListener('keydown', handleSecondKey);
          }, 1000);
        }, 0);
      }
    },
    [toggleSidebar]
  );

  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);

  return (
    <div
      className={clsx(
        'fixed inset-y-0 left-0 z-50 flex flex-col transition-all duration-300 ease-in-out',
        'bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800',
        collapsed ? 'w-16' : 'w-64'
      )}
    >
      {/* Logo Section */}
      <div
        className={clsx(
          'flex h-14 shrink-0 items-center border-b border-slate-200 dark:border-slate-800',
          collapsed ? 'justify-center px-2' : 'px-4'
        )}
      >
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="absolute inset-0 bg-brand-500 blur-lg opacity-50" />
            <ShieldCheckIcon className="relative h-7 w-7 text-brand-400" />
          </div>
          {!collapsed && (
            <div className="flex flex-col">
              <span className="text-base font-bold text-slate-900 dark:text-white leading-tight">ShieldNet</span>
              <span className="text-2xs text-slate-500">DDoS Protection</span>
            </div>
          )}
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-3 px-2 space-y-4">
        {sectionsWithBadges.map((section) => (
          <NavSectionComponent
            key={section.id}
            section={section}
            collapsed={collapsed}
            currentPath={location.pathname}
            isOpen={openSectionId === section.id}
            onToggle={() => setOpenSectionId(openSectionId === section.id ? null : section.id)}
          />
        ))}

        {/* Admin Section */}
        {isAdmin && (
          <>
            {!collapsed && <div className="border-t border-slate-200 dark:border-slate-800 my-3" />}
            {collapsed && <div className="border-t border-slate-200 dark:border-slate-800 my-2" />}
            <NavSectionComponent
              section={{
                id: 'admin',
                name: 'Administration',
                icon: CpuChipIcon,
                defaultOpen: false,
                items: [
                  { name: 'Global Settings', href: '/settings', icon: CogIcon },
                  { name: 'Organization', href: '/settings/org', icon: BuildingOfficeIcon },
                ],
              }}
              collapsed={collapsed}
              currentPath={location.pathname}
              isOpen={openSectionId === 'admin'}
              onToggle={() => setOpenSectionId(openSectionId === 'admin' ? null : 'admin')}
            />
          </>
        )}
      </nav>

      {/* Bottom Section */}
      <div className="border-t border-slate-200 dark:border-slate-800 p-3 space-y-3">
        {/* System Status */}
        <SystemStatusBadge collapsed={collapsed} />

        {/* Keyboard Shortcuts Hint */}
        {!collapsed && (
          <div className="flex items-center justify-center text-2xs text-slate-600 gap-1">
            <CommandLineIcon className="h-3 w-3" />
            <span>Press</span>
            <kbd className="rounded bg-slate-200 dark:bg-slate-800 px-1 py-0.5 text-slate-500 dark:text-slate-400">?</kbd>
            <span>for help</span>
          </div>
        )}

        {/* Collapse Toggle */}
        <button
          onClick={toggleSidebar}
          className={clsx(
            'flex w-full items-center justify-center gap-2 rounded-lg py-2 text-sm text-slate-500 dark:text-slate-400 transition-colors hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-white',
            collapsed && 'px-2'
          )}
        >
          {collapsed ? (
            <ChevronRightIcon className="h-5 w-5" />
          ) : (
            <>
              <ChevronLeftIcon className="h-5 w-5" />
              <span className="text-xs">Collapse</span>
              <kbd className="ml-auto rounded bg-slate-200 dark:bg-slate-800 px-1.5 py-0.5 text-2xs text-slate-500">
                [
              </kbd>
            </>
          )}
        </button>
      </div>
    </div>
  );
}

export default Sidebar;
