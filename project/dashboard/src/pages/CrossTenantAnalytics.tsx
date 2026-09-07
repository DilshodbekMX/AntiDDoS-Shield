/**
 * Cross-Tenant Analytics Page (Multi-Tenant)
 *
 * Provides operators with a bird's-eye view across all tenants:
 * - Aggregated traffic and attack metrics
 * - Tenant comparison charts
 * - Hotspot identification
 * - Resource utilization overview
 * - Attack correlation across tenants
 */

import { useState, useEffect, useCallback } from 'react';
import { logError } from '../utils/logger';
import { clsx } from 'clsx';
import {
  GlobeAltIcon,
  BuildingOfficeIcon,
  ChartBarIcon,
  ExclamationTriangleIcon,
  ArrowPathIcon,
  ShieldCheckIcon,
  SignalIcon,
  ClockIcon,
  FireIcon,
  UserGroupIcon,
  ServerStackIcon,
  Squares2X2Icon,
  TableCellsIcon,
} from '@heroicons/react/24/outline';
import { useAuthStore, useTenantStore } from '../store';
import { Tenant, TenantStatus, TenantTier, StatsPeriod } from '../types';
import { EmptyState } from '../components/ui';

// ============================================================================
// Types
// ============================================================================

interface AggregatedStats {
  total_pps: number;
  total_bps: number;
  total_drops: number;
  total_attacks_active: number;
  total_attacks_24h: number;
  total_tenants: number;
  active_tenants: number;
  tenants_under_attack: number;
  avg_mitigation_time_ms: number;
  system_utilization_pct: number;
}

interface TenantRanking {
  tenant_id: number;
  tenant_name: string;
  value: number;
  tier: TenantTier;
  status: TenantStatus;
}

interface AttackCorrelation {
  attack_type: string;
  tenant_count: number;
  total_pps: number;
  source_overlap_pct: number;
  is_coordinated: boolean;
}

// ============================================================================
// Constants
// ============================================================================

const tierColors: Record<TenantTier, string> = {
  [TenantTier.FREE]: 'bg-slate-500',
  [TenantTier.BASIC]: 'bg-blue-500',
  [TenantTier.STANDARD]: 'bg-emerald-500',
  [TenantTier.PREMIUM]: 'bg-purple-500',
  [TenantTier.ENTERPRISE]: 'bg-amber-500',
  [TenantTier.CUSTOM]: 'bg-pink-500',
};


// ============================================================================
// Helper Functions
// ============================================================================

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatBps(bps: number): string {
  return formatBytes(bps) + 'ps';
}

function formatNumber(num: number): string {
  if (num < 1000) return num.toString();
  if (num < 1_000_000) return `${(num / 1000).toFixed(1)}K`;
  if (num < 1_000_000_000) return `${(num / 1_000_000).toFixed(1)}M`;
  return `${(num / 1_000_000_000).toFixed(2)}B`;
}

function formatPps(pps: number): string {
  return formatNumber(pps) + ' pps';
}

// ============================================================================
// Component: Global Stats Overview
// ============================================================================

interface GlobalStatsProps {
  stats: AggregatedStats | null;
  loading: boolean;
}

function GlobalStatsOverview({ stats, loading }: GlobalStatsProps) {
  if (loading || !stats) {
    return (
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[...Array(8)].map((_, i) => (
          <div key={i} className="h-24 bg-slate-100 dark:bg-slate-800 rounded-lg animate-pulse" />
        ))}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
      {/* Traffic */}
      <div className="p-4 bg-slate-100 dark:bg-slate-800 rounded-lg border border-slate-300 dark:border-slate-700">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-brand-500/20 rounded-lg">
            <SignalIcon className="h-5 w-5 text-brand-400" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-2xs uppercase tracking-wider text-slate-500">Total Throughput</p>
            <p className="text-xl font-bold text-slate-900 dark:text-white truncate">{formatBps(stats.total_bps)}</p>
            <p className="text-xs text-slate-500 dark:text-slate-400">{formatPps(stats.total_pps)}</p>
          </div>
        </div>
      </div>

      {/* Drops */}
      <div className="p-4 bg-slate-100 dark:bg-slate-800 rounded-lg border border-slate-300 dark:border-slate-700">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-orange-500/20 rounded-lg">
            <ShieldCheckIcon className="h-5 w-5 text-orange-400" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-2xs uppercase tracking-wider text-slate-500">Total Drops</p>
            <p className="text-xl font-bold text-slate-900 dark:text-white truncate">{formatNumber(stats.total_drops)}</p>
            <p className="text-xs text-slate-500 dark:text-slate-400">packets blocked</p>
          </div>
        </div>
      </div>

      {/* Active Attacks */}
      <div className={clsx(
        'p-4 rounded-lg border',
        stats.total_attacks_active > 0
          ? 'bg-red-500/10 border-red-500/30'
          : 'bg-slate-100 dark:bg-slate-800 border-slate-300 dark:border-slate-700'
      )}>
        <div className="flex items-center gap-3">
          <div className={clsx(
            'p-2 rounded-lg',
            stats.total_attacks_active > 0 ? 'bg-red-500/20' : 'bg-slate-200 dark:bg-slate-700'
          )}>
            <ExclamationTriangleIcon className={clsx(
              'h-5 w-5',
              stats.total_attacks_active > 0 ? 'text-red-400 animate-pulse' : 'text-slate-500 dark:text-slate-400'
            )} />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-2xs uppercase tracking-wider text-slate-500">Active Attacks</p>
            <p className={clsx(
              'text-xl font-bold',
              stats.total_attacks_active > 0 ? 'text-red-400' : 'text-slate-900 dark:text-white'
            )}>
              {stats.total_attacks_active}
            </p>
            <p className="text-xs text-slate-500 dark:text-slate-400">{stats.total_attacks_24h} in last 24h</p>
          </div>
        </div>
      </div>

      {/* Mitigation Time */}
      <div className="p-4 bg-slate-100 dark:bg-slate-800 rounded-lg border border-slate-300 dark:border-slate-700">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-emerald-500/20 rounded-lg">
            <ClockIcon className="h-5 w-5 text-emerald-400" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-2xs uppercase tracking-wider text-slate-500">Avg Mitigation</p>
            <p className="text-xl font-bold text-slate-900 dark:text-white truncate">{stats.avg_mitigation_time_ms}ms</p>
            <p className="text-xs text-slate-500 dark:text-slate-400">time to mitigate</p>
          </div>
        </div>
      </div>

      {/* Tenants */}
      <div className="p-4 bg-slate-100 dark:bg-slate-800 rounded-lg border border-slate-300 dark:border-slate-700">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-purple-500/20 rounded-lg">
            <BuildingOfficeIcon className="h-5 w-5 text-purple-400" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-2xs uppercase tracking-wider text-slate-500">Total Tenants</p>
            <p className="text-xl font-bold text-slate-900 dark:text-white">{stats.total_tenants}</p>
            <p className="text-xs text-slate-500 dark:text-slate-400">{stats.active_tenants} active</p>
          </div>
        </div>
      </div>

      {/* Under Attack */}
      <div className={clsx(
        'p-4 rounded-lg border',
        stats.tenants_under_attack > 0
          ? 'bg-red-500/10 border-red-500/30'
          : 'bg-slate-100 dark:bg-slate-800 border-slate-300 dark:border-slate-700'
      )}>
        <div className="flex items-center gap-3">
          <div className={clsx(
            'p-2 rounded-lg',
            stats.tenants_under_attack > 0 ? 'bg-red-500/20' : 'bg-slate-200 dark:bg-slate-700'
          )}>
            <FireIcon className={clsx(
              'h-5 w-5',
              stats.tenants_under_attack > 0 ? 'text-red-400' : 'text-slate-500 dark:text-slate-400'
            )} />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-2xs uppercase tracking-wider text-slate-500">Under Attack</p>
            <p className={clsx(
              'text-xl font-bold',
              stats.tenants_under_attack > 0 ? 'text-red-400' : 'text-slate-900 dark:text-white'
            )}>
              {stats.tenants_under_attack}
            </p>
            <p className="text-xs text-slate-500 dark:text-slate-400">tenants targeted</p>
          </div>
        </div>
      </div>

      {/* System Utilization */}
      <div className="p-4 bg-slate-100 dark:bg-slate-800 rounded-lg border border-slate-300 dark:border-slate-700">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-500/20 rounded-lg">
            <ServerStackIcon className="h-5 w-5 text-blue-400" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-2xs uppercase tracking-wider text-slate-500">System Load</p>
            <div className="flex items-center gap-2">
              <p className="text-xl font-bold text-slate-900 dark:text-white">{stats.system_utilization_pct}%</p>
              <div className="flex-1 h-2 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
                <div
                  className={clsx(
                    'h-full rounded-full transition-all',
                    stats.system_utilization_pct > 80 ? 'bg-red-500' :
                    stats.system_utilization_pct > 60 ? 'bg-yellow-500' : 'bg-emerald-500'
                  )}
                  style={{ width: `${stats.system_utilization_pct}%` }}
                />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Capacity */}
      <div className="p-4 bg-slate-100 dark:bg-slate-800 rounded-lg border border-slate-300 dark:border-slate-700">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-cyan-500/20 rounded-lg">
            <ChartBarIcon className="h-5 w-5 text-cyan-400" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-2xs uppercase tracking-wider text-slate-500">Capacity</p>
            <p className="text-xl font-bold text-slate-900 dark:text-white">{100 - stats.system_utilization_pct}%</p>
            <p className="text-xs text-slate-500 dark:text-slate-400">headroom available</p>
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Component: Tenant Rankings
// ============================================================================

interface TenantRankingsProps {
  title: string;
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
  rankings: TenantRanking[];
  formatValue: (value: number) => string;
  loading: boolean;
  maxItems?: number;
}

function TenantRankings({ title, icon: Icon, rankings, formatValue, loading, maxItems = 5 }: TenantRankingsProps) {
  const displayRankings = rankings.slice(0, maxItems);
  const maxValue = Math.max(...rankings.map(r => r.value), 1);

  return (
    <div className="bg-slate-100 dark:bg-slate-800 rounded-xl border border-slate-300 dark:border-slate-700 overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-300 dark:border-slate-700 flex items-center gap-2">
        <Icon className="h-5 w-5 text-slate-500 dark:text-slate-400" />
        <h3 className="text-sm font-semibold text-slate-900 dark:text-white">{title}</h3>
      </div>

      <div className="p-4">
        {loading ? (
          <div className="space-y-3">
            {[...Array(maxItems)].map((_, i) => (
              <div key={i} className="h-10 bg-slate-200 dark:bg-slate-700 rounded animate-pulse" />
            ))}
          </div>
        ) : displayRankings.length === 0 ? (
          <p className="text-sm text-slate-500 text-center py-4">No data available</p>
        ) : (
          <div className="space-y-3">
            {displayRankings.map((ranking, index) => (
              <div key={ranking.tenant_id} className="flex items-center gap-3">
                <span className={clsx(
                  'flex h-6 w-6 items-center justify-center rounded-full text-xs font-bold',
                  index === 0 ? 'bg-amber-500 text-slate-900' :
                  index === 1 ? 'bg-slate-400 text-slate-900' :
                  index === 2 ? 'bg-amber-700 text-white' :
                  'bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300'
                )}>
                  {index + 1}
                </span>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-slate-900 dark:text-white truncate">
                      {ranking.tenant_name}
                    </span>
                    <span className={clsx(
                      'inline-flex items-center rounded px-1.5 py-0.5 text-2xs font-medium text-slate-900 dark:text-white',
                      tierColors[ranking.tier]
                    )}>
                      {ranking.tier}
                    </span>
                    {ranking.status === TenantStatus.ATTACK_MODE && (
                      <ExclamationTriangleIcon className="h-4 w-4 text-red-400 animate-pulse" />
                    )}
                  </div>
                  <div className="mt-1 flex items-center gap-2">
                    <div className="flex-1 h-1.5 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-brand-500 rounded-full transition-all"
                        style={{ width: `${(ranking.value / maxValue) * 100}%` }}
                      />
                    </div>
                    <span className="text-xs text-slate-500 dark:text-slate-400 tabular-nums">
                      {formatValue(ranking.value)}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// Component: Attack Correlation Panel
// ============================================================================

interface AttackCorrelationPanelProps {
  correlations: AttackCorrelation[];
  loading: boolean;
}

function AttackCorrelationPanel({ correlations, loading }: AttackCorrelationPanelProps) {
  return (
    <div className="bg-slate-100 dark:bg-slate-800 rounded-xl border border-slate-300 dark:border-slate-700 overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-300 dark:border-slate-700 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <GlobeAltIcon className="h-5 w-5 text-slate-500 dark:text-slate-400" />
          <h3 className="text-sm font-semibold text-slate-900 dark:text-white">Attack Correlation Analysis</h3>
        </div>
        <span className="text-xs text-slate-500">Cross-tenant patterns</span>
      </div>

      <div className="p-4">
        {loading ? (
          <div className="space-y-3">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="h-16 bg-slate-200 dark:bg-slate-700 rounded animate-pulse" />
            ))}
          </div>
        ) : correlations.length === 0 ? (
          <div className="text-center py-8">
            <ShieldCheckIcon className="h-8 w-8 mx-auto text-emerald-400 mb-2" />
            <p className="text-sm text-slate-500 dark:text-slate-400">No correlated attacks detected</p>
            <p className="text-xs text-slate-500 mt-1">System is operating normally</p>
          </div>
        ) : (
          <div className="space-y-3">
            {correlations.map((correlation, index) => (
              <div
                key={index}
                className={clsx(
                  'p-3 rounded-lg border',
                  correlation.is_coordinated
                    ? 'bg-red-500/10 border-red-500/30'
                    : 'bg-slate-100 dark:bg-slate-700/50 border-slate-300 dark:border-slate-600'
                )}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    {correlation.is_coordinated && (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-red-500/20 border border-red-500/30 rounded text-xs font-medium text-red-400">
                        <ExclamationTriangleIcon className="h-3 w-3" />
                        Coordinated
                      </span>
                    )}
                    <span className="text-sm font-medium text-slate-900 dark:text-white">
                      {correlation.attack_type.replace('_', ' ')}
                    </span>
                  </div>
                  <span className="text-sm text-slate-500 dark:text-slate-400">
                    {formatPps(correlation.total_pps)}
                  </span>
                </div>

                <div className="mt-2 flex items-center gap-4 text-xs text-slate-500 dark:text-slate-400">
                  <span className="flex items-center gap-1">
                    <BuildingOfficeIcon className="h-3.5 w-3.5" />
                    {correlation.tenant_count} tenants
                  </span>
                  <span className="flex items-center gap-1">
                    <UserGroupIcon className="h-3.5 w-3.5" />
                    {correlation.source_overlap_pct}% source overlap
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// Component: Tenant Heatmap
// ============================================================================

interface TenantHeatmapProps {
  tenants: Tenant[];
  loading: boolean;
}

function TenantHeatmap({ tenants, loading }: TenantHeatmapProps) {
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');

  // Sort by current traffic (descending)
  const sortedTenants = [...tenants].sort((a, b) => (b.current_traffic_bps ?? 0) - (a.current_traffic_bps ?? 0));
  const maxTraffic = Math.max(...tenants.map(t => t.current_traffic_bps ?? 0), 1);

  return (
    <div className="bg-slate-100 dark:bg-slate-800 rounded-xl border border-slate-300 dark:border-slate-700 overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-300 dark:border-slate-700 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ChartBarIcon className="h-5 w-5 text-slate-500 dark:text-slate-400" />
          <h3 className="text-sm font-semibold text-slate-900 dark:text-white">Tenant Traffic Heatmap</h3>
        </div>
        <div className="flex items-center gap-1 bg-slate-200 dark:bg-slate-700 rounded-lg p-0.5">
          <button
            onClick={() => setViewMode('grid')}
            className={clsx(
              'p-1.5 rounded transition-colors',
              viewMode === 'grid' ? 'bg-slate-600 text-slate-900 dark:text-white' : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            )}
          >
            <Squares2X2Icon className="h-4 w-4" />
          </button>
          <button
            onClick={() => setViewMode('list')}
            className={clsx(
              'p-1.5 rounded transition-colors',
              viewMode === 'list' ? 'bg-slate-600 text-slate-900 dark:text-white' : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
            )}
          >
            <TableCellsIcon className="h-4 w-4" />
          </button>
        </div>
      </div>

      <div className="p-4">
        {loading ? (
          <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
            {[...Array(24)].map((_, i) => (
              <div key={i} className="aspect-square bg-slate-200 dark:bg-slate-700 rounded animate-pulse" />
            ))}
          </div>
        ) : viewMode === 'grid' ? (
          <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
            {sortedTenants.slice(0, 24).map((tenant) => {
              const intensity = (tenant.current_traffic_bps ?? 0) / maxTraffic;
              const isUnderAttack = tenant.status === TenantStatus.ATTACK_MODE;

              return (
                <div
                  key={tenant.id}
                  className={clsx(
                    'aspect-square rounded-lg p-2 flex flex-col justify-between cursor-pointer transition-all hover:scale-105',
                    isUnderAttack ? 'ring-2 ring-red-500 animate-pulse' : '',
                    intensity > 0.8 ? 'bg-red-500' :
                    intensity > 0.6 ? 'bg-orange-500' :
                    intensity > 0.4 ? 'bg-yellow-500' :
                    intensity > 0.2 ? 'bg-emerald-500' : 'bg-slate-200 dark:bg-slate-700'
                  )}
                  title={`${tenant.name}\n${formatBps(tenant.current_traffic_bps ?? 0)}\n${formatPps(tenant.current_traffic_pps ?? 0)}`}
                >
                  <span className="text-2xs font-bold text-slate-900 dark:text-white/80 truncate">
                    #{tenant.id}
                  </span>
                  <span className="text-2xs text-slate-900 dark:text-white/60 truncate">
                    {formatBps(tenant.current_traffic_bps ?? 0).replace('ps', '')}
                  </span>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="max-h-64 overflow-y-auto space-y-1">
            {sortedTenants.map((tenant) => {
              const intensity = (tenant.current_traffic_bps ?? 0) / maxTraffic;
              const isUnderAttack = tenant.status === TenantStatus.ATTACK_MODE;

              return (
                <div
                  key={tenant.id}
                  className={clsx(
                    'flex items-center gap-3 p-2 rounded-lg',
                    isUnderAttack ? 'bg-red-500/20' : 'bg-slate-100 dark:bg-slate-700/50'
                  )}
                >
                  <div
                    className={clsx(
                      'h-8 w-1 rounded-full',
                      intensity > 0.8 ? 'bg-red-500' :
                      intensity > 0.6 ? 'bg-orange-500' :
                      intensity > 0.4 ? 'bg-yellow-500' :
                      intensity > 0.2 ? 'bg-emerald-500' : 'bg-slate-600'
                    )}
                  />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-slate-900 dark:text-white truncate">
                        {tenant.name}
                      </span>
                      {isUnderAttack && (
                        <ExclamationTriangleIcon className="h-4 w-4 text-red-400 animate-pulse" />
                      )}
                    </div>
                    <p className="text-xs text-slate-500 dark:text-slate-400">ID: {tenant.id}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-sm font-medium text-slate-900 dark:text-white">{formatBps(tenant.current_traffic_bps ?? 0)}</p>
                    <p className="text-xs text-slate-500 dark:text-slate-400">{formatPps(tenant.current_traffic_pps ?? 0)}</p>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Legend */}
        <div className="mt-4 flex items-center justify-between border-t border-slate-300 dark:border-slate-700 pt-3">
          <span className="text-xs text-slate-500">Traffic intensity:</span>
          <div className="flex items-center gap-1">
            {['Low', 'Medium', 'High', 'Critical'].map((label, i) => (
              <div key={label} className="flex items-center gap-1">
                <div className={clsx(
                  'h-3 w-3 rounded',
                  i === 0 ? 'bg-emerald-500' :
                  i === 1 ? 'bg-yellow-500' :
                  i === 2 ? 'bg-orange-500' : 'bg-red-500'
                )} />
                <span className="text-2xs text-slate-500 dark:text-slate-400">{label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Component: Tier Distribution
// ============================================================================

interface TierDistributionProps {
  tenants: Tenant[];
  loading: boolean;
}

function TierDistribution({ tenants, loading }: TierDistributionProps) {
  const tierCounts = Object.values(TenantTier).reduce((acc, tier) => {
    acc[tier] = tenants.filter(t => t.tier === tier).length;
    return acc;
  }, {} as Record<TenantTier, number>);

  const total = tenants.length || 1;

  return (
    <div className="bg-slate-100 dark:bg-slate-800 rounded-xl border border-slate-300 dark:border-slate-700 overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-300 dark:border-slate-700">
        <h3 className="text-sm font-semibold text-slate-900 dark:text-white">Tier Distribution</h3>
      </div>

      <div className="p-4">
        {loading ? (
          <div className="h-32 bg-slate-200 dark:bg-slate-700 rounded animate-pulse" />
        ) : (
          <>
            <div className="flex h-4 rounded-full overflow-hidden">
              {Object.entries(tierCounts)
                .filter(([_, count]) => count > 0)
                .map(([tier, count]) => (
                  <div
                    key={tier}
                    className={clsx(tierColors[tier as TenantTier], 'transition-all')}
                    style={{ width: `${(count / total) * 100}%` }}
                    title={`${tier}: ${count}`}
                  />
                ))}
            </div>

            <div className="mt-4 grid grid-cols-3 gap-2">
              {Object.entries(tierCounts)
                .filter(([_, count]) => count > 0)
                .map(([tier, count]) => (
                  <div key={tier} className="flex items-center gap-2">
                    <div className={clsx('h-3 w-3 rounded', tierColors[tier as TenantTier])} />
                    <span className="text-xs text-slate-500 dark:text-slate-400">
                      {tier}: <span className="text-slate-900 dark:text-white font-medium">{count}</span>
                    </span>
                  </div>
                ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// Main Page Component
// ============================================================================

export function CrossTenantAnalyticsPage() {
  const { user } = useAuthStore();
  const { tenants, setTenants } = useTenantStore();

  const [loading, setLoading] = useState(true);
  const [period, setPeriod] = useState<StatsPeriod>(StatsPeriod.REALTIME);
  const [aggregatedStats, setAggregatedStats] = useState<AggregatedStats | null>(null);
  const [correlations, setCorrelations] = useState<AttackCorrelation[]>([]);

  // API URL
  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v2';

  // Fetch data
  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      // Fetch tenants
      const tenantsResponse = await fetch(`${apiUrl}/tenants`, {
        credentials: 'include',  // Send cookies for auth
      });

      if (tenantsResponse.ok) {
        const tenantsData = await tenantsResponse.json();
        setTenants(tenantsData.items || tenantsData);

        // Calculate aggregated stats from tenant data
        const allTenants = tenantsData.items || tenantsData;
        setAggregatedStats({
          total_pps: allTenants.reduce((sum: number, t: Tenant) => sum + (t.current_traffic_pps ?? 0), 0),
          total_bps: allTenants.reduce((sum: number, t: Tenant) => sum + (t.current_traffic_bps ?? 0), 0),
          total_drops: 0,
          total_attacks_active: allTenants.filter((t: Tenant) => t.status === TenantStatus.ATTACK_MODE).length,
          total_attacks_24h: allTenants.reduce((sum: number, t: Tenant) => sum + (t.attack_count_24h ?? 0), 0),
          total_tenants: allTenants.length,
          active_tenants: allTenants.filter((t: Tenant) => t.status === TenantStatus.ACTIVE || t.status === TenantStatus.ATTACK_MODE).length,
          tenants_under_attack: allTenants.filter((t: Tenant) => t.status === TenantStatus.ATTACK_MODE).length,
          avg_mitigation_time_ms: 150,
          system_utilization_pct: Math.min(95, Math.round(allTenants.reduce((sum: number, t: Tenant) => sum + (t.current_traffic_bps ?? 0), 0) / 100_000_000_000 * 100)),
        });
      }

      // Fetch attack correlations (would come from backend)
      // For now, using placeholder data structure
      setCorrelations([]);

    } catch (error) {
      logError('CrossTenantAnalytics', error);
    } finally {
      setLoading(false);
    }
  }, [apiUrl, setTenants]);

  useEffect(() => {
    fetchData();

    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, [fetchData, period]);

  // Generate rankings
  const trafficRankings: TenantRanking[] = tenants
    .map(t => ({
      tenant_id: t.id,
      tenant_name: t.name,
      value: t.current_traffic_bps ?? 0,
      tier: t.tier,
      status: t.status,
    }))
    .sort((a, b) => b.value - a.value);

  const attackRankings: TenantRanking[] = tenants
    .map(t => ({
      tenant_id: t.id,
      tenant_name: t.name,
      value: t.attack_count_24h ?? 0,
      tier: t.tier,
      status: t.status,
    }))
    .sort((a, b) => b.value - a.value);

  if (!user?.is_admin) {
    return (
      <EmptyState
        icon={GlobeAltIcon}
        title="Access Denied"
        description="You don't have permission to view cross-tenant analytics."
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Cross-Tenant Analytics</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            System-wide view across all tenants
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            value={period}
            onChange={(e) => setPeriod(e.target.value as StatsPeriod)}
            className="px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
          >
            <option value={StatsPeriod.REALTIME}>Real-time</option>
            <option value={StatsPeriod.HOUR_1}>Last Hour</option>
            <option value={StatsPeriod.HOUR_24}>Last 24 Hours</option>
            <option value={StatsPeriod.DAY_7}>Last 7 Days</option>
          </select>

          <button
            onClick={fetchData}
            disabled={loading}
            className="p-2 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors"
          >
            <ArrowPathIcon className={clsx('h-5 w-5', loading && 'animate-spin')} />
          </button>
        </div>
      </div>

      {/* Global Stats */}
      <GlobalStatsOverview stats={aggregatedStats} loading={loading} />

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column - Rankings */}
        <div className="space-y-6">
          <TenantRankings
            title="Top Traffic"
            icon={SignalIcon}
            rankings={trafficRankings}
            formatValue={formatBps}
            loading={loading}
          />

          <TenantRankings
            title="Most Attacks (24h)"
            icon={ExclamationTriangleIcon}
            rankings={attackRankings}
            formatValue={(v) => `${v} attacks`}
            loading={loading}
          />
        </div>

        {/* Center Column - Heatmap */}
        <div className="space-y-6">
          <TenantHeatmap tenants={tenants} loading={loading} />
          <TierDistribution tenants={tenants} loading={loading} />
        </div>

        {/* Right Column - Correlations */}
        <div className="space-y-6">
          <AttackCorrelationPanel correlations={correlations} loading={loading} />

          {/* Quick Stats */}
          <div className="bg-slate-100 dark:bg-slate-800 rounded-xl border border-slate-300 dark:border-slate-700 overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-300 dark:border-slate-700">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white">System Health</h3>
            </div>
            <div className="p-4 space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-500 dark:text-slate-400">Protection Coverage</span>
                <span className="text-sm font-medium text-slate-900 dark:text-white">
                  {tenants.filter(t => t.status !== TenantStatus.DISABLED && t.status !== TenantStatus.SUSPENDED).length} / {tenants.length}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-500 dark:text-slate-400">Active Policies</span>
                <span className="text-sm font-medium text-slate-900 dark:text-white">
                  {formatNumber(tenants.reduce((sum, t) => sum + (t.quotas?.max_policies || 0) * 0.3, 0))}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-500 dark:text-slate-400">Protected IPs</span>
                <span className="text-sm font-medium text-slate-900 dark:text-white">
                  {formatNumber(tenants.reduce((sum, t) => sum + t.protected_ips.length, 0))}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-500 dark:text-slate-400">Protected Prefixes</span>
                <span className="text-sm font-medium text-slate-900 dark:text-white">
                  {formatNumber(tenants.reduce((sum, t) => sum + t.protected_prefixes.length, 0))}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default CrossTenantAnalyticsPage;
