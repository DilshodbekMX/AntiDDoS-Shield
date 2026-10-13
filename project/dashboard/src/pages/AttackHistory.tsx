/**
 * Attack History Page
 *
 * Shows historical attack data from the database with filtering,
 * sorting, and detail expansion.
 */

import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { clsx } from 'clsx';
import {
  ShieldExclamationIcon,
  FunnelIcon,
  ArrowPathIcon,
  ChevronDownIcon,
  ChevronUpIcon,
  ClockIcon,
  CheckCircleIcon,
  FireIcon,
  XCircleIcon,
} from '@heroicons/react/24/outline';
import { MetricCard, EmptyState, PageHeader } from '../components/ui';
import { AttackTimeline } from '../components/Dashboard/AttackTimeline';
import api from '../services/api';
import { formatNumber, formatPPS, formatBPS } from '../utils/formatting';

function formatDuration(startedAt: string, endedAt?: string): string {
  const start = new Date(startedAt).getTime();
  const end = endedAt ? new Date(endedAt).getTime() : Date.now();
  const seconds = Math.floor((end - start) / 1000);

  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const hours = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${mins}m`;
}

function formatTimeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

const SEVERITY_STYLES: Record<string, { bg: string; text: string; dot: string }> = {
  critical: { bg: 'bg-red-500/10', text: 'text-red-400', dot: 'bg-red-500' },
  high: { bg: 'bg-orange-500/10', text: 'text-orange-400', dot: 'bg-orange-500' },
  medium: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', dot: 'bg-yellow-500' },
  low: { bg: 'bg-green-500/10', text: 'text-green-400', dot: 'bg-green-500' },
};

const ATTACK_TYPE_LABELS: Record<string, string> = {
  syn_flood: 'SYN Flood',
  udp_flood: 'UDP Flood',
  icmp_flood: 'ICMP Flood',
  http_flood: 'HTTP Flood',
  dns_amplification: 'DNS Amplification',
  ntp_amplification: 'NTP Amplification',
  slowloris: 'Slowloris',
  volumetric: 'Volumetric',
  unknown: 'Unknown',
};

type StatusFilter = 'all' | 'active' | 'ended';
type SeverityFilter = '' | 'critical' | 'high' | 'medium' | 'low';

export function AttackHistoryPage() {
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const perPage = 20;

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['attacks', page, statusFilter, severityFilter],
    queryFn: () =>
      api.getAttacks({
        page,
        per_page: perPage,
        is_active: statusFilter === 'all' ? undefined : statusFilter === 'active',
        severity: severityFilter || undefined,
      }),
    refetchInterval: 10000,
  });

  const attacks = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / perPage));

  // Stats
  const activeCount = attacks.filter(a => a.is_active).length;
  const mitigatedCount = attacks.filter(a => a.mitigated).length;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Attack History"
        description="Historical attack detection and mitigation records"
        icon={ShieldExclamationIcon}
        iconClassName="text-red-400"
        actions={
          <button onClick={() => refetch()} className="btn-secondary btn-sm inline-flex items-center gap-2">
            <ArrowPathIcon className="h-4 w-4" />
            Refresh
          </button>
        }
      />

      {/* Stats cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard
          title="Total Attacks"
          value={formatNumber(total)}
          icon={ShieldExclamationIcon}
          color="neutral"
        />
        <MetricCard
          title="Active Now"
          value={String(activeCount)}
          icon={FireIcon}
          color={activeCount > 0 ? 'danger' : 'success'}
        />
        <MetricCard
          title="Mitigated"
          value={String(mitigatedCount)}
          icon={CheckCircleIcon}
          color="success"
        />
        <MetricCard
          title="Page"
          value={`${page} / ${totalPages}`}
          icon={ClockIcon}
          color="neutral"
        />
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3 sm:gap-4">
        <div className="flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400">
          <FunnelIcon className="h-4 w-4" />
          Filter:
        </div>
        <div className="flex gap-2">
          {(['all', 'active', 'ended'] as StatusFilter[]).map(s => (
            <button
              key={s}
              onClick={() => { setStatusFilter(s); setPage(1); }}
              className={clsx(
                'px-3 py-1.5 text-xs rounded-lg transition-colors',
                statusFilter === s
                  ? 'bg-indigo-500/20 text-indigo-600 dark:text-indigo-300 border border-indigo-500/30'
                  : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-300 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700'
              )}
            >
              {s === 'all' ? 'All' : s === 'active' ? 'Active' : 'Ended'}
            </button>
          ))}
        </div>
        <select
          value={severityFilter}
          onChange={e => { setSeverityFilter(e.target.value as SeverityFilter); setPage(1); }}
          className="px-3 py-1.5 text-xs bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-slate-700 rounded-lg"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      {/* Attack Timeline Visualization */}
      {attacks.length > 0 && (
        <AttackTimeline
          attacks={attacks}
          selectedId={expandedId}
          onSelectAttack={(id) => {
            setExpandedId(expandedId === id ? null : id);
            // Scroll the corresponding table row into view
            requestAnimationFrame(() => {
              document.getElementById(`attack-row-${id}`)?.scrollIntoView({
                behavior: 'smooth',
                block: 'center',
              });
            });
          }}
        />
      )}

      {/* Table */}
      <div className="bg-white dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 rounded-xl overflow-x-auto">
        {isLoading ? (
          <div className="p-12 text-center text-slate-400">Loading attacks...</div>
        ) : attacks.length === 0 ? (
          <EmptyState
            icon={ShieldExclamationIcon}
            title="No attacks found"
            description="No attack records match the current filters."
          />
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-700">
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">Status</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">Time</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">Target</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">Type</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">Severity</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">Duration</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">Peak PPS</th>
                <th className="px-4 py-3 text-right text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">Peak BPS</th>
                <th className="px-4 py-3 text-center text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-700/50">
              {attacks.map(attack => {
                const severity = SEVERITY_STYLES[attack.severity] ?? SEVERITY_STYLES.low;
                const isExpanded = expandedId === attack.id;
                return (
                  <React.Fragment key={attack.id}>
                    <tr
                      id={`attack-row-${attack.id}`}
                      className={clsx(
                        'hover:bg-slate-50 dark:hover:bg-slate-700/30 transition-colors cursor-pointer',
                        attack.is_active && 'bg-red-500/5',
                        expandedId === attack.id && 'bg-slate-50 dark:bg-slate-700/40',
                      )}
                      onClick={() => setExpandedId(isExpanded ? null : attack.id)}
                    >
                      <td className="px-4 py-3">
                        {attack.is_active ? (
                          <span className="flex items-center gap-1.5 text-xs text-red-400">
                            <span className="h-2 w-2 rounded-full bg-red-500 animate-pulse" />
                            Active
                          </span>
                        ) : attack.mitigated ? (
                          <span className="flex items-center gap-1.5 text-xs text-green-400">
                            <CheckCircleIcon className="h-4 w-4" />
                            Mitigated
                          </span>
                        ) : (
                          <span className="flex items-center gap-1.5 text-xs text-slate-400">
                            <XCircleIcon className="h-4 w-4" />
                            Ended
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <div className="text-sm text-slate-700 dark:text-slate-300">
                          {new Date(attack.started_at).toLocaleString()}
                        </div>
                        <div className="text-xs text-slate-500">
                          {formatTimeAgo(attack.started_at)}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <code className="text-sm text-indigo-600 dark:text-indigo-300">{attack.target_ip}</code>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-sm text-slate-700 dark:text-slate-300">
                          {ATTACK_TYPE_LABELS[attack.attack_type] ?? attack.attack_type}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={clsx(
                          'inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium',
                          severity.bg, severity.text
                        )}>
                          <span className={clsx('h-1.5 w-1.5 rounded-full', severity.dot)} />
                          {attack.severity.toUpperCase()}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm text-slate-700 dark:text-slate-300">
                        {formatDuration(attack.started_at, attack.ended_at)}
                      </td>
                      <td className="px-4 py-3 text-sm text-slate-700 dark:text-slate-300 text-right font-mono">
                        {formatPPS(attack.peak_pps)}
                      </td>
                      <td className="px-4 py-3 text-sm text-slate-700 dark:text-slate-300 text-right font-mono">
                        {formatBPS(attack.peak_bps)}
                      </td>
                      <td className="px-4 py-3 text-center">
                        {isExpanded ? (
                          <ChevronUpIcon className="h-4 w-4 text-slate-400 mx-auto" />
                        ) : (
                          <ChevronDownIcon className="h-4 w-4 text-slate-400 mx-auto" />
                        )}
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr key={`${attack.id}-detail`}>
                        <td colSpan={9} className="px-6 py-4 bg-slate-50 dark:bg-slate-800/80">
                          <AttackDetail attackId={attack.id} />
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-between items-center">
          <span className="text-sm text-slate-500 dark:text-slate-400">
            Showing {(page - 1) * perPage + 1}–{Math.min(page * perPage, total)} of {total}
          </span>
          <div className="flex gap-2">
            <button
              disabled={page <= 1}
              onClick={() => setPage(p => p - 1)}
              className="px-3 py-1.5 text-sm bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 rounded-lg disabled:opacity-40 hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors"
            >
              Previous
            </button>
            <button
              disabled={page >= totalPages}
              onClick={() => setPage(p => p + 1)}
              className="px-3 py-1.5 text-sm bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 rounded-lg disabled:opacity-40 hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

/**
 * Expanded row detail: fetches full attack info.
 */
function AttackDetail({ attackId }: { attackId: string }) {
  const { data: attack, isLoading } = useQuery({
    queryKey: ['attack', attackId],
    queryFn: () => api.getAttack(attackId),
  });

  if (isLoading) return <div className="text-sm text-slate-400">Loading details...</div>;
  if (!attack) return <div className="text-sm text-red-400">Failed to load attack details</div>;

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      <div>
        <span className="text-xs text-slate-500 block">Source IPs</span>
        <span className="text-sm text-slate-700 dark:text-slate-300 font-mono">{formatNumber(attack.source_ips_count)}</span>
      </div>
      <div>
        <span className="text-xs text-slate-500 block">Packets Dropped</span>
        <span className="text-sm text-slate-700 dark:text-slate-300 font-mono">{formatNumber(attack.total_packets_dropped)}</span>
      </div>
      <div>
        <span className="text-xs text-slate-500 block">Mitigation Time</span>
        <span className="text-sm text-slate-700 dark:text-slate-300 font-mono">
          {attack.mitigation_time_ms ? `${attack.mitigation_time_ms.toFixed(0)} ms` : 'N/A'}
        </span>
      </div>
      <div>
        <span className="text-xs text-slate-500 block">ML Confidence</span>
        <span className="text-sm text-slate-700 dark:text-slate-300 font-mono">
          {attack.ml_confidence ? `${(attack.ml_confidence * 100).toFixed(1)}%` : 'N/A'}
        </span>
      </div>
      {attack.top_source_ips && attack.top_source_ips.length > 0 && (
        <div className="col-span-2 md:col-span-4">
          <span className="text-xs text-slate-500 block mb-1">Top Source IPs</span>
          <div className="flex flex-wrap gap-2">
            {attack.top_source_ips.slice(0, 10).map(ip => (
              <code key={ip} className="text-xs bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 px-2 py-0.5 rounded">
                {ip}
              </code>
            ))}
          </div>
        </div>
      )}
      {attack.signatures_matched && attack.signatures_matched.length > 0 && (
        <div className="col-span-2 md:col-span-4">
          <span className="text-xs text-slate-500 block mb-1">Signatures Matched</span>
          <div className="flex flex-wrap gap-2">
            {attack.signatures_matched.map(sig => (
              <span key={sig} className="text-xs bg-indigo-500/20 text-indigo-600 dark:text-indigo-300 px-2 py-0.5 rounded">
                {sig}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
