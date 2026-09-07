/**
 * Protected Assets Page
 *
 * Displays all protected IP addresses with their real-time status,
 * traffic metrics, and anomaly detection state.
 */

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { clsx } from 'clsx';
import {
  ComputerDesktopIcon,
  ExclamationTriangleIcon,
  ShieldCheckIcon,
  ArrowPathIcon,
  MagnifyingGlassIcon,
  FunnelIcon,
  ChevronRightIcon,
  ArrowTrendingUpIcon,
  SignalIcon,
  FireIcon,
} from '@heroicons/react/24/outline';
import {
  MetricCard,
  DataTable,
  EmptyState,
  ThreatBadge,
  PageHeader,
} from '../components/ui';
import api from '../services/api';
import { formatBytes, formatNumber } from '../utils/formatting';

interface ProtectedAsset {
  dst_ip_str: string;
  has_traffic_data: boolean;
  packets_per_sec: number;
  bytes_per_sec: number;
  flows_per_sec: number;
  total_packets: number;
  active_flows: number;
  syn_per_sec: number;
  tcp_ratio: number;
  udp_ratio: number;
  icmp_ratio: number;
  unique_src_ips: number;
  unique_flows: number;
  heavy_hitter_count: number;
  anomaly_active: boolean;
  anomaly_level: number;
  anomaly_level_name: string;
  max_z_score: number;
  attack_type_name: string;
  anomaly_protocol_name: string;
  anomaly_dst_port: number;
}

interface PerIPStatsResponse {
  protected_ips: ProtectedAsset[];
  count: number;
  totals: {
    packets_per_sec: number;
    bytes_per_sec: number;
    total_packets: number;
  };
}

interface PerIPSummary {
  total_protected_ips: number;
  anomalous_ips: number;
  healthy_ips: number;
  max_severity_level: number;
  max_severity_name: string;
}

type FilterType = 'all' | 'healthy' | 'under_attack';
type SortField = 'ip' | 'pps' | 'bps' | 'anomaly';

export function AssetsPage() {
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState('');
  const [filter, setFilter] = useState<FilterType>('all');
  const [sortField, setSortField] = useState<SortField>('pps');
  const [sortDesc, setSortDesc] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Fetch per-IP stats
  const { data: perIPStats, refetch, isLoading } = useQuery({
    queryKey: ['per-ip-stats-assets'],
    queryFn: () => api.getPerIPStats() as Promise<PerIPStatsResponse>,
    refetchInterval: 2000,
  });

  // Fetch summary
  const { data: summary } = useQuery({
    queryKey: ['per-ip-summary-assets'],
    queryFn: () => api.getPerIPAnomalySummary() as Promise<PerIPSummary>,
    refetchInterval: 2000,
  });

  const handleRefresh = async () => {
    setRefreshing(true);
    await refetch();
    setRefreshing(false);
  };

  // Filter and sort assets
  const assets = perIPStats?.protected_ips || [];
  const filteredAssets = assets
    .filter((asset) => {
      // Search filter
      if (searchQuery && !asset.dst_ip_str.includes(searchQuery)) {
        return false;
      }
      // Status filter
      if (filter === 'healthy' && asset.anomaly_active) return false;
      if (filter === 'under_attack' && !asset.anomaly_active) return false;
      return true;
    })
    .sort((a, b) => {
      let cmp = 0;
      switch (sortField) {
        case 'ip':
          cmp = a.dst_ip_str.localeCompare(b.dst_ip_str);
          break;
        case 'pps':
          cmp = a.packets_per_sec - b.packets_per_sec;
          break;
        case 'bps':
          cmp = a.bytes_per_sec - b.bytes_per_sec;
          break;
        case 'anomaly':
          cmp = (a.anomaly_active ? 1 : 0) - (b.anomaly_active ? 1 : 0) ||
                a.anomaly_level - b.anomaly_level;
          break;
      }
      return sortDesc ? -cmp : cmp;
    });

  const getThreatLevel = (level: number): 'critical' | 'high' | 'medium' | 'low' | 'none' => {
    if (level >= 4) return 'critical';
    if (level >= 3) return 'high';
    if (level >= 2) return 'medium';
    if (level >= 1) return 'low';
    return 'none';
  };

  // Table columns
  const columns = [
    {
      key: 'dst_ip_str',
      header: 'IP Address',
      sortable: true,
      render: (_value: unknown, row: ProtectedAsset) => (
        <div className="flex items-center gap-3">
          <div
            className={clsx(
              'h-2.5 w-2.5 rounded-full',
              row.anomaly_active
                ? 'bg-red-500 animate-pulse'
                : row.has_traffic_data
                ? 'bg-emerald-500'
                : 'bg-slate-500'
            )}
          />
          <div>
            <span className="font-mono text-sm font-medium text-slate-900 dark:text-white">{row.dst_ip_str}</span>
            {row.anomaly_active && (
              <p className="text-xs text-red-400">{row.attack_type_name}</p>
            )}
            {!row.has_traffic_data && !row.anomaly_active && (
              <p className="text-xs text-slate-500">No traffic data</p>
            )}
          </div>
        </div>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      render: (_value: unknown, row: ProtectedAsset) =>
        row.anomaly_active ? (
          <ThreatBadge level={getThreatLevel(row.anomaly_level)} size="sm" />
        ) : row.has_traffic_data ? (
          <span className="badge badge-success">Healthy</span>
        ) : (
          <span className="badge bg-slate-200 dark:bg-slate-700 text-slate-500 dark:text-slate-400">Offline</span>
        ),
    },
    {
      key: 'packets_per_sec',
      header: 'Traffic',
      sortable: true,
      render: (_value: unknown, row: ProtectedAsset) => (
        <div className="text-right">
          <div className="text-sm font-medium text-slate-900 dark:text-white">
            {formatNumber(row.packets_per_sec)} pps
          </div>
          <div className="text-xs text-slate-500 dark:text-slate-400">
            {formatBytes(row.bytes_per_sec)}/s
          </div>
        </div>
      ),
    },
    {
      key: 'protocol',
      header: 'Protocol Mix',
      render: (_value: unknown, row: ProtectedAsset) => (
        <div className="flex items-center gap-1">
          <div className="flex h-2 w-24 rounded-full overflow-hidden bg-slate-200 dark:bg-slate-700">
            <div
              className="bg-blue-500"
              style={{ width: `${row.tcp_ratio}%` }}
              title={`TCP: ${row.tcp_ratio}%`}
            />
            <div
              className="bg-green-500"
              style={{ width: `${row.udp_ratio}%` }}
              title={`UDP: ${row.udp_ratio}%`}
            />
            <div
              className="bg-yellow-500"
              style={{ width: `${row.icmp_ratio}%` }}
              title={`ICMP: ${row.icmp_ratio}%`}
            />
          </div>
          <span className="text-2xs text-slate-500">
            T:{row.tcp_ratio} U:{row.udp_ratio}
          </span>
        </div>
      ),
    },
    {
      key: 'unique_src_ips',
      header: 'Sources',
      sortable: true,
      render: (val: unknown) => (
        <span className="text-sm text-slate-700 dark:text-slate-300">{formatNumber(val as number)}</span>
      ),
    },
    {
      key: 'max_z_score',
      header: 'Z-Score',
      sortable: true,
      render: (val: unknown, row: ProtectedAsset) => (
        <span
          className={clsx(
            'text-sm font-mono',
            row.anomaly_active ? 'text-red-400' : 'text-slate-500 dark:text-slate-400'
          )}
        >
          {(val as number).toFixed(2)}
        </span>
      ),
    },
    {
      key: 'actions',
      header: '',
      render: (_value: unknown, row: ProtectedAsset) => (
        <button
          onClick={() => navigate(`/assets/${encodeURIComponent(row.dst_ip_str)}`)}
          className="btn-ghost p-1 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white"
        >
          <ChevronRightIcon className="h-5 w-5" />
        </button>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Protected Assets"
        description="Monitor and manage protected IP addresses"
        actions={
          <button onClick={handleRefresh} disabled={refreshing} className="btn-primary inline-flex items-center gap-2">
            <ArrowPathIcon className={clsx('h-4 w-4', refreshing && 'animate-spin')} />
            Refresh
          </button>
        }
      />

      {/* Summary Cards */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          title="Total Assets"
          value={summary?.total_protected_ips || 0}
          icon={ComputerDesktopIcon}
          color="info"
          subtitle="Protected IPs"
        />
        <MetricCard
          title="Healthy"
          value={summary?.healthy_ips || 0}
          icon={ShieldCheckIcon}
          color="success"
          subtitle="No anomalies detected"
        />
        <MetricCard
          title="Under Attack"
          value={summary?.anomalous_ips || 0}
          icon={FireIcon}
          color={(summary?.anomalous_ips || 0) > 0 ? 'danger' : 'success'}
          subtitle="Active threats"
        />
        <MetricCard
          title="Max Severity"
          value={summary?.max_severity_name || 'NONE'}
          icon={ExclamationTriangleIcon}
          color={
            (summary?.max_severity_level || 0) >= 3
              ? 'danger'
              : (summary?.max_severity_level || 0) >= 1
              ? 'warning'
              : 'success'
          }
          subtitle={`Level ${summary?.max_severity_level || 0}`}
        />
      </div>

      {/* Traffic Summary */}
      {perIPStats?.totals && (
        <div className="grid grid-cols-1 gap-5 sm:grid-cols-3">
          <MetricCard
            title="Total Inbound"
            value={formatNumber(perIPStats.totals.packets_per_sec)}
            unit="pps"
            icon={ArrowTrendingUpIcon}
            color="brand"
          />
          <MetricCard
            title="Total Bandwidth"
            value={formatBytes(perIPStats.totals.bytes_per_sec)}
            unit="/s"
            icon={SignalIcon}
            color="info"
          />
          <MetricCard
            title="Total Packets"
            value={formatNumber(perIPStats.totals.total_packets)}
            icon={ComputerDesktopIcon}
            color="neutral"
          />
        </div>
      )}

      {/* Filters and Search */}
      <div className="card">
        <div className="flex flex-wrap items-center gap-4 p-4 border-b border-slate-300 dark:border-slate-700">
          {/* Search */}
          <div className="relative flex-1 min-w-[200px]">
            <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500 dark:text-slate-400" />
            <input
              type="text"
              placeholder="Search by IP address..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="input pl-9 w-full"
            />
          </div>

          {/* Status Filter */}
          <div className="flex items-center gap-2">
            <FunnelIcon className="h-4 w-4 text-slate-500 dark:text-slate-400" />
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value as FilterType)}
              className="input"
            >
              <option value="all">All Assets</option>
              <option value="healthy">Healthy Only</option>
              <option value="under_attack">Under Attack</option>
            </select>
          </div>

          {/* Sort */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-500 dark:text-slate-400">Sort by:</span>
            <select
              value={sortField}
              onChange={(e) => setSortField(e.target.value as SortField)}
              className="input"
            >
              <option value="pps">Traffic (PPS)</option>
              <option value="bps">Bandwidth</option>
              <option value="anomaly">Threat Level</option>
              <option value="ip">IP Address</option>
            </select>
            <button
              onClick={() => setSortDesc(!sortDesc)}
              className="btn-ghost p-2"
              title={sortDesc ? 'Descending' : 'Ascending'}
            >
              {sortDesc ? '↓' : '↑'}
            </button>
          </div>
        </div>

        {/* Assets Table */}
        {filteredAssets.length > 0 ? (
          <DataTable
            columns={columns}
            data={filteredAssets}
            keyField="dst_ip_str"
            onRowClick={(row: ProtectedAsset) => navigate(`/assets/${encodeURIComponent(row.dst_ip_str)}`)}
          />
        ) : (
          <EmptyState
            icon={isLoading ? ArrowPathIcon : ComputerDesktopIcon}
            title={isLoading ? 'Loading...' : 'No Protected Assets'}
            description={
              isLoading
                ? 'Fetching asset data from DPDK...'
                : searchQuery
                ? 'No assets match your search criteria'
                : 'No protected IPs detected. Ensure traffic is flowing through the datapath.'
            }
          />
        )}
      </div>
    </div>
  );
}

export default AssetsPage;
