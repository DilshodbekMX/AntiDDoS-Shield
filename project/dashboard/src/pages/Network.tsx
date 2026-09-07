/**
 * Network Page
 *
 * Comprehensive network monitoring:
 * - Per-port traffic visualization
 * - Real-time packet statistics
 * - Protocol distribution
 * - Interface health metrics
 * - Traffic history charts
 */

import { useState, useMemo, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { clsx } from 'clsx';
import {
  SignalIcon,
  ArrowDownTrayIcon,
  ArrowUpTrayIcon,
  ChartBarIcon,
  ExclamationTriangleIcon,
  ServerStackIcon,
  WifiIcon,
  BoltIcon,
} from '@heroicons/react/24/outline';
import {
  MetricCard,
  StatusIndicator,
  EmptyState,
  LoadingSpinner,
} from '../components/ui';
import api from '../services/api';

// ============================================================================
// Types
// ============================================================================

interface PortStats {
  port_id: number;
  rx_packets: number;
  tx_packets: number;
  rx_bytes: number;
  tx_bytes: number;
  dropped: number;
  rx_pps: number;
  tx_pps: number;
  rx_bps: number;
  tx_bps: number;
  rx_mbps: number;
  tx_mbps: number;
  rx_kpps: number;
  tx_kpps: number;
  errors?: number;
}

interface RealtimeStats {
  timestamp: number;
  timestamp_str: string;
  connected: boolean;
  ports: Record<string, PortStats>;
}

interface TrafficHistory {
  timestamp: number;
  rx_mbps: number;
  tx_mbps: number;
  rx_pps: number;
  tx_pps: number;
  dropped: number;
}

// ============================================================================
// Helpers
// ============================================================================

function formatBytes(bytes: number): string {
  if (bytes >= 1e12) return `${(bytes / 1e12).toFixed(2)} TB`;
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(2)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(2)} MB`;
  if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(2)} KB`;
  return `${bytes} B`;
}

function formatNumber(num: number): string {
  if (num >= 1e9) return `${(num / 1e9).toFixed(2)}B`;
  if (num >= 1e6) return `${(num / 1e6).toFixed(2)}M`;
  if (num >= 1e3) return `${(num / 1e3).toFixed(2)}K`;
  return num.toFixed(0);
}

function formatRate(mbps: number): string {
  if (mbps >= 1000) return `${(mbps / 1000).toFixed(2)} Gbps`;
  return `${mbps.toFixed(2)} Mbps`;
}

// ============================================================================
// Sub-components
// ============================================================================

function TrafficChart({
  data,
  height = 120,
  showLegend = true,
}: {
  data: TrafficHistory[];
  height?: number;
  showLegend?: boolean;
}) {
  const maxRx = Math.max(...data.map(d => d.rx_mbps), 1);
  const maxTx = Math.max(...data.map(d => d.tx_mbps), 1);
  const maxValue = Math.max(maxRx, maxTx);

  return (
    <div>
      <svg
        width="100%"
        height={height}
        viewBox={`0 0 ${data.length} ${height}`}
        preserveAspectRatio="none"
        className="overflow-visible"
      >
        {/* RX Area */}
        <path
          d={`M 0 ${height} ${data.map((d, i) => `L ${i} ${height - (d.rx_mbps / maxValue) * (height - 10)}`).join(' ')} L ${data.length - 1} ${height} Z`}
          fill="url(#rxGradient)"
          opacity="0.3"
        />
        {/* RX Line */}
        <path
          d={`M ${data.map((d, i) => `${i} ${height - (d.rx_mbps / maxValue) * (height - 10)}`).join(' L ')}`}
          fill="none"
          stroke="#3b82f6"
          strokeWidth="2"
        />

        {/* TX Area */}
        <path
          d={`M 0 ${height} ${data.map((d, i) => `L ${i} ${height - (d.tx_mbps / maxValue) * (height - 10)}`).join(' ')} L ${data.length - 1} ${height} Z`}
          fill="url(#txGradient)"
          opacity="0.3"
        />
        {/* TX Line */}
        <path
          d={`M ${data.map((d, i) => `${i} ${height - (d.tx_mbps / maxValue) * (height - 10)}`).join(' L ')}`}
          fill="none"
          stroke="#10b981"
          strokeWidth="2"
        />

        <defs>
          <linearGradient id="rxGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#3b82f6" />
            <stop offset="100%" stopColor="#3b82f6" stopOpacity="0" />
          </linearGradient>
          <linearGradient id="txGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#10b981" />
            <stop offset="100%" stopColor="#10b981" stopOpacity="0" />
          </linearGradient>
        </defs>
      </svg>

      {showLegend && (
        <div className="flex items-center justify-center gap-6 mt-2">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-blue-500" />
            <span className="text-xs text-slate-500 dark:text-slate-400">RX (Inbound)</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-emerald-500" />
            <span className="text-xs text-slate-500 dark:text-slate-400">TX (Outbound)</span>
          </div>
        </div>
      )}
    </div>
  );
}

function PortDetailCard({
  port,
  portId,
  history,
  isSelected,
  onSelect,
}: {
  port: PortStats;
  portId: string;
  history: TrafficHistory[];
  isSelected: boolean;
  onSelect: () => void;
}) {
  const hasIssues = port.dropped > 0 || (port.errors || 0) > 0;
  const totalTraffic = port.rx_bytes + port.tx_bytes;
  const totalPackets = port.rx_packets + port.tx_packets;

  return (
    <div
      className={clsx(
        'card p-5 cursor-pointer transition-all',
        isSelected && 'ring-2 ring-brand-500',
        hasIssues && !isSelected && 'ring-1 ring-amber-500/50'
      )}
      onClick={onSelect}
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className={clsx(
            'p-2.5 rounded-xl',
            hasIssues ? 'bg-amber-50 dark:bg-amber-500/10' : 'bg-blue-50 dark:bg-blue-500/10'
          )}>
            <WifiIcon className={clsx(
              'h-6 w-6',
              hasIssues ? 'text-amber-600 dark:text-amber-400' : 'text-blue-600 dark:text-blue-400'
            )} />
          </div>
          <div>
            <h3 className="font-bold text-lg text-slate-900 dark:text-white">Port {portId}</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">DPDK Interface</p>
          </div>
        </div>
        <StatusIndicator
          status={hasIssues ? 'warning' : 'healthy'}
          label={hasIssues ? 'Issues' : 'Healthy'}
          size="sm"
        />
      </div>

      {/* Mini Chart */}
      {history.length > 1 && (
        <div className="mb-4 -mx-2">
          <TrafficChart data={history.slice(-30)} height={60} showLegend={false} />
        </div>
      )}

      {/* Traffic Stats */}
      <div className="grid grid-cols-2 gap-4 mb-4">
        <div className="p-3 rounded-lg bg-blue-50 dark:bg-blue-500/10">
          <div className="flex items-center gap-2 mb-1">
            <ArrowDownTrayIcon className="h-4 w-4 text-blue-600 dark:text-blue-400" />
            <span className="text-xs text-blue-600 dark:text-blue-400 font-medium">RX</span>
          </div>
          <p className="text-xl font-bold text-slate-900 dark:text-white">
            {formatRate(port.rx_mbps || 0)}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            {formatNumber(port.rx_pps || 0)} pps
          </p>
        </div>

        <div className="p-3 rounded-lg bg-emerald-50 dark:bg-emerald-500/10">
          <div className="flex items-center gap-2 mb-1">
            <ArrowUpTrayIcon className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
            <span className="text-xs text-emerald-600 dark:text-emerald-400 font-medium">TX</span>
          </div>
          <p className="text-xl font-bold text-slate-900 dark:text-white">
            {formatRate(port.tx_mbps || 0)}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            {formatNumber(port.tx_pps || 0)} pps
          </p>
        </div>
      </div>

      {/* Totals */}
      <div className="grid grid-cols-2 gap-4 text-sm">
        <div>
          <p className="text-slate-500 dark:text-slate-400">Total Traffic</p>
          <p className="font-semibold text-slate-900 dark:text-white">{formatBytes(totalTraffic)}</p>
        </div>
        <div>
          <p className="text-slate-500 dark:text-slate-400">Total Packets</p>
          <p className="font-semibold text-slate-900 dark:text-white">{formatNumber(totalPackets)}</p>
        </div>
      </div>

      {/* Issues */}
      {hasIssues && (
        <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-700">
          <div className="flex items-center gap-4 text-sm">
            {port.dropped > 0 && (
              <span className="flex items-center gap-1 text-amber-600 dark:text-amber-400">
                <ExclamationTriangleIcon className="h-4 w-4" />
                {formatNumber(port.dropped)} dropped
              </span>
            )}
            {(port.errors || 0) > 0 && (
              <span className="flex items-center gap-1 text-red-600 dark:text-red-400">
                <ExclamationTriangleIcon className="h-4 w-4" />
                {formatNumber(port.errors || 0)} errors
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function PortDetailPanel({ port, portId, history }: { port: PortStats; portId: string; history: TrafficHistory[] }) {
  return (
    <div className="card p-6">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-brand-50 dark:bg-brand-500/10">
            <SignalIcon className="h-7 w-7 text-brand-600 dark:text-brand-400" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-slate-900 dark:text-white">Port {portId} Details</h2>
            <p className="text-sm text-slate-500 dark:text-slate-400">Real-time interface statistics</p>
          </div>
        </div>
      </div>

      {/* Traffic Chart */}
      <div className="mb-6">
        <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-3">Traffic History (Last 60s)</h3>
        <div className="bg-slate-50 dark:bg-slate-800/50 rounded-xl p-4">
          {history.length > 1 ? (
            <TrafficChart data={history} height={150} />
          ) : (
            <div className="h-[150px] flex items-center justify-center text-slate-500 dark:text-slate-400">
              Collecting data...
            </div>
          )}
        </div>
      </div>

      {/* Detailed Stats Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="p-4 rounded-lg bg-slate-50 dark:bg-slate-800/50">
          <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">RX Rate</p>
          <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">{formatRate(port.rx_mbps || 0)}</p>
        </div>
        <div className="p-4 rounded-lg bg-slate-50 dark:bg-slate-800/50">
          <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">TX Rate</p>
          <p className="text-2xl font-bold text-emerald-600 dark:text-emerald-400">{formatRate(port.tx_mbps || 0)}</p>
        </div>
        <div className="p-4 rounded-lg bg-slate-50 dark:bg-slate-800/50">
          <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">RX Packets/s</p>
          <p className="text-2xl font-bold text-slate-900 dark:text-white">{formatNumber(port.rx_pps || 0)}</p>
        </div>
        <div className="p-4 rounded-lg bg-slate-50 dark:bg-slate-800/50">
          <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">TX Packets/s</p>
          <p className="text-2xl font-bold text-slate-900 dark:text-white">{formatNumber(port.tx_pps || 0)}</p>
        </div>
      </div>

      {/* Packet Counters */}
      <div className="mb-6">
        <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-3">Packet Counters</h3>
        <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 dark:bg-slate-800">
              <tr>
                <th className="px-4 py-3 text-left text-slate-600 dark:text-slate-400 font-medium">Metric</th>
                <th className="px-4 py-3 text-right text-slate-600 dark:text-slate-400 font-medium">RX (Inbound)</th>
                <th className="px-4 py-3 text-right text-slate-600 dark:text-slate-400 font-medium">TX (Outbound)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
              <tr>
                <td className="px-4 py-3 text-slate-900 dark:text-white">Total Packets</td>
                <td className="px-4 py-3 text-right font-mono text-slate-700 dark:text-slate-300">{port.rx_packets.toLocaleString()}</td>
                <td className="px-4 py-3 text-right font-mono text-slate-700 dark:text-slate-300">{port.tx_packets.toLocaleString()}</td>
              </tr>
              <tr>
                <td className="px-4 py-3 text-slate-900 dark:text-white">Total Bytes</td>
                <td className="px-4 py-3 text-right font-mono text-slate-700 dark:text-slate-300">{formatBytes(port.rx_bytes)}</td>
                <td className="px-4 py-3 text-right font-mono text-slate-700 dark:text-slate-300">{formatBytes(port.tx_bytes)}</td>
              </tr>
              <tr>
                <td className="px-4 py-3 text-slate-900 dark:text-white">Rate (Mbps)</td>
                <td className="px-4 py-3 text-right font-mono text-blue-600 dark:text-blue-400">{(port.rx_mbps || 0).toFixed(2)}</td>
                <td className="px-4 py-3 text-right font-mono text-emerald-600 dark:text-emerald-400">{(port.tx_mbps || 0).toFixed(2)}</td>
              </tr>
              <tr>
                <td className="px-4 py-3 text-slate-900 dark:text-white">Rate (Kpps)</td>
                <td className="px-4 py-3 text-right font-mono text-slate-700 dark:text-slate-300">{(port.rx_kpps || 0).toFixed(2)}</td>
                <td className="px-4 py-3 text-right font-mono text-slate-700 dark:text-slate-300">{(port.tx_kpps || 0).toFixed(2)}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Error Counters */}
      <div>
        <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-3">Error Counters</h3>
        <div className="grid grid-cols-2 gap-4">
          <div className={clsx(
            'p-4 rounded-lg border',
            port.dropped > 0
              ? 'border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-500/10'
              : 'border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50'
          )}>
            <div className="flex items-center justify-between">
              <span className="text-slate-600 dark:text-slate-400">Dropped Packets</span>
              <span className={clsx(
                'text-xl font-bold',
                port.dropped > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-slate-900 dark:text-white'
              )}>
                {formatNumber(port.dropped)}
              </span>
            </div>
          </div>
          <div className={clsx(
            'p-4 rounded-lg border',
            (port.errors || 0) > 0
              ? 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-500/10'
              : 'border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50'
          )}>
            <div className="flex items-center justify-between">
              <span className="text-slate-600 dark:text-slate-400">Errors</span>
              <span className={clsx(
                'text-xl font-bold',
                (port.errors || 0) > 0 ? 'text-red-600 dark:text-red-400' : 'text-slate-900 dark:text-white'
              )}>
                {formatNumber(port.errors || 0)}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export default function NetworkPage() {
  const [selectedPort, setSelectedPort] = useState<string | null>(null);
  const [trafficHistory, setTrafficHistory] = useState<Record<string, TrafficHistory[]>>({});

  // Fetch realtime stats
  const { data: realtimeData, isLoading } = useQuery({
    queryKey: ['realtime-stats-network'],
    queryFn: () => api.getRealtimeStats() as Promise<RealtimeStats>,
    refetchInterval: 1000,
  });

  // Fetch connection status
  const { data: connectionData } = useQuery({
    queryKey: ['dpdk-connection-network'],
    queryFn: () => api.getDPDKConnectionStatus(),
    refetchInterval: 5000,
  });

  // Update traffic history when new data arrives
  useEffect(() => {
    if (realtimeData?.ports) {
      const now = Date.now();
      setTrafficHistory(prev => {
        const updated = { ...prev };
        Object.entries(realtimeData.ports).forEach(([portId, port]) => {
          const portStats = port as PortStats;
          const newPoint: TrafficHistory = {
            timestamp: now,
            rx_mbps: portStats.rx_mbps || 0,
            tx_mbps: portStats.tx_mbps || 0,
            rx_pps: portStats.rx_pps || 0,
            tx_pps: portStats.tx_pps || 0,
            dropped: portStats.dropped || 0,
          };

          if (!updated[portId]) {
            updated[portId] = [];
          }
          updated[portId] = [...updated[portId].slice(-59), newPoint];
        });
        return updated;
      });
    }
  }, [realtimeData]);

  // Auto-select first port if none selected
  useEffect(() => {
    if (!selectedPort && realtimeData?.ports) {
      const ports = Object.keys(realtimeData.ports);
      if (ports.length > 0) {
        setSelectedPort(ports[0]);
      }
    }
  }, [realtimeData, selectedPort]);

  // Aggregate stats
  const aggregateStats = useMemo(() => {
    if (!realtimeData?.ports) return null;

    const ports = Object.values(realtimeData.ports) as PortStats[];
    return {
      totalRxMbps: ports.reduce((sum, p) => sum + (p.rx_mbps || 0), 0),
      totalTxMbps: ports.reduce((sum, p) => sum + (p.tx_mbps || 0), 0),
      totalRxPps: ports.reduce((sum, p) => sum + (p.rx_pps || 0), 0),
      totalTxPps: ports.reduce((sum, p) => sum + (p.tx_pps || 0), 0),
      totalDropped: ports.reduce((sum, p) => sum + (p.dropped || 0), 0),
      totalErrors: ports.reduce((sum, p) => sum + (p.errors || 0), 0),
      totalRxBytes: ports.reduce((sum, p) => sum + (p.rx_bytes || 0), 0),
      totalTxBytes: ports.reduce((sum, p) => sum + (p.tx_bytes || 0), 0),
      portCount: ports.length,
    };
  }, [realtimeData]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  const ports = realtimeData?.ports || {};
  const portIds = Object.keys(ports);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Network Monitoring</h1>
          <p className="text-slate-500 dark:text-slate-400">Real-time DPDK interface statistics</p>
        </div>

        <div className="flex items-center gap-3">
          <div className={clsx(
            'flex items-center gap-2 px-4 py-2 rounded-lg',
            connectionData?.connected
              ? 'bg-emerald-50 dark:bg-emerald-500/10'
              : 'bg-red-50 dark:bg-red-500/10'
          )}>
            <BoltIcon className={clsx(
              'h-5 w-5',
              connectionData?.connected
                ? 'text-emerald-600 dark:text-emerald-400'
                : 'text-red-600 dark:text-red-400'
            )} />
            <span className={clsx(
              'font-medium',
              connectionData?.connected
                ? 'text-emerald-700 dark:text-emerald-400'
                : 'text-red-700 dark:text-red-400'
            )}>
              {connectionData?.connected ? 'DPDK Connected' : 'DPDK Disconnected'}
            </span>
          </div>
        </div>
      </div>

      {/* Top Metrics */}
      {aggregateStats && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
          <MetricCard
            title="Total RX"
            value={formatRate(aggregateStats.totalRxMbps)}
            icon={ArrowDownTrayIcon}
            color="info"
            size="sm"
          />
          <MetricCard
            title="Total TX"
            value={formatRate(aggregateStats.totalTxMbps)}
            icon={ArrowUpTrayIcon}
            color="success"
            size="sm"
          />
          <MetricCard
            title="RX Packets/s"
            value={formatNumber(aggregateStats.totalRxPps)}
            icon={ChartBarIcon}
            color="brand"
            size="sm"
          />
          <MetricCard
            title="TX Packets/s"
            value={formatNumber(aggregateStats.totalTxPps)}
            icon={ChartBarIcon}
            color="brand"
            size="sm"
          />
          <MetricCard
            title="Dropped"
            value={formatNumber(aggregateStats.totalDropped)}
            icon={ExclamationTriangleIcon}
            color={aggregateStats.totalDropped > 0 ? 'warning' : 'neutral'}
            size="sm"
          />
          <MetricCard
            title="Active Ports"
            value={aggregateStats.portCount.toString()}
            icon={ServerStackIcon}
            color="neutral"
            size="sm"
          />
        </div>
      )}

      {/* Main Content */}
      {portIds.length > 0 ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Port Cards */}
          <div className="lg:col-span-1 space-y-4">
            <h2 className="text-lg font-semibold text-slate-900 dark:text-white flex items-center gap-2">
              <WifiIcon className="h-5 w-5 text-slate-500" />
              Interfaces
            </h2>
            <div className="space-y-4">
              {portIds.map(portId => (
                <PortDetailCard
                  key={portId}
                  port={ports[portId] as PortStats}
                  portId={portId}
                  history={trafficHistory[portId] || []}
                  isSelected={selectedPort === portId}
                  onSelect={() => setSelectedPort(portId)}
                />
              ))}
            </div>
          </div>

          {/* Selected Port Details */}
          <div className="lg:col-span-2">
            {selectedPort && ports[selectedPort] ? (
              <PortDetailPanel
                port={ports[selectedPort] as PortStats}
                portId={selectedPort}
                history={trafficHistory[selectedPort] || []}
              />
            ) : (
              <div className="card p-12 text-center">
                <SignalIcon className="h-12 w-12 text-slate-300 dark:text-slate-600 mx-auto mb-4" />
                <p className="text-slate-500 dark:text-slate-400">Select a port to view details</p>
              </div>
            )}
          </div>
        </div>
      ) : (
        <EmptyState
          icon={SignalIcon}
          title="No Network Interfaces"
          description={
            connectionData?.connected
              ? "No DPDK ports are currently active"
              : "Connect to DPDK to view network interfaces"
          }
        />
      )}
    </div>
  );
}
