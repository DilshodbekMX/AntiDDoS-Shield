/**
 * Traffic Analysis Page
 *
 * Enterprise traffic monitoring with real-time DPDK data,
 * protocol distribution charts, and system resource visualization.
 */

import { useState, useMemo, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon,
  ServerIcon,
  ChartBarIcon,
  FunnelIcon,
  ArrowPathIcon,
  InformationCircleIcon,
} from '@heroicons/react/24/outline';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
} from 'recharts';
import {
  MetricCard,
  StatusIndicator,
  DataTable,
  EmptyState,
  PageHeader,
} from '../components/ui';
import { IPScopeSelector } from '../components/IPScopeSelector';
import { useIPScopeStore } from '../store';
import { usePerIPHistory } from '../hooks/usePerIPHistory';
import api from '../services/api';
import { formatBytes, formatNumber, formatPPS, formatBPS } from '../utils/formatting';

type TimeRange = '1m' | '5m' | '15m' | '1h' | '6h' | '24h' | '7d' | '30d';

const timeRangeLabels: Record<TimeRange, string> = {
  '1m': '1 Min',
  '5m': '5 Min',
  '15m': '15 Min',
  '1h': '1 Hour',
  '6h': '6 Hours',
  '24h': '24 Hours',
  '7d': '7 Days',
  '30d': '30 Days',
};

// Historical ranges use traffic_rollups from the database
const HISTORICAL_RANGES = new Set<TimeRange>(['6h', '24h', '7d', '30d']);

// Resolution mapping for historical queries
const HISTORICAL_RESOLUTION: Record<string, string> = {
  '6h': '5m',
  '24h': '5m',
  '7d': '1h',
  '30d': '1h',
};

// Hours for each historical range
const HISTORICAL_HOURS: Record<string, number> = {
  '6h': 6,
  '24h': 24,
  '7d': 168,
  '30d': 720,
};

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
  rx_mbps?: number;
  tx_mbps?: number;
  rx_kpps?: number;
  tx_kpps?: number;
}

interface RealtimeStats {
  connected: boolean;
  uptime_seconds?: number;
  timestamp?: number;
  ports: Record<string, PortStats> | PortStats[];
  totals?: {
    rx_packets: number;
    tx_packets: number;
    rx_bytes: number;
    tx_bytes: number;
    dropped: number;
    rx_pps: number;
    tx_pps: number;
    rx_bps: number;
    tx_bps: number;
  };
}

interface TrafficData {
  connected: boolean;
  protocol_stats: {
    tcp: { packets: number; bytes: number; pps: number };
    udp: { packets: number; bytes: number; pps: number };
    icmp: { packets: number; bytes: number; pps: number };
    other: { packets: number; bytes: number; pps: number };
  };
  drop_reasons: Record<string, number>;
  drop_reasons_total: Record<string, number>;
  total_dropped: number;
}

const PROTOCOL_COLORS = {
  TCP: '#3b82f6',
  UDP: '#10b981',
  ICMP: '#f59e0b',
  Other: '#6b7280',
};

export function TrafficPage() {
  const [timeRange, setTimeRange] = useState<TimeRange>('5m');
  const [refreshing, setRefreshing] = useState(false);
  const { selectedIP } = useIPScopeStore();
  const { addSample, getHistory } = usePerIPHistory();

  // Fetch real-time stats (2s refresh for performance balance)
  const { data: realtimeStats, isLoading: statsLoading, refetch } = useQuery({
    queryKey: ['realtime-stats'],
    queryFn: () => api.getRealtimeStats() as Promise<RealtimeStats>,
    refetchInterval: 2000,
  });

  // Fetch per-IP stats when IP selected
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data: perIPStats } = useQuery<any>({
    queryKey: ['per-ip-stats-traffic'],
    queryFn: () => api.getPerIPStats(),
    refetchInterval: 2000,
    enabled: !!selectedIP,
  });

  const isHistorical = HISTORICAL_RANGES.has(timeRange);

  // Fetch port-level stats history (for realtime Traffic Timeline chart)
  const { data: portHistory } = useQuery({
    queryKey: ['port-stats-history', timeRange],
    queryFn: () => api.getPortStatsHistory(timeRange === '1m' ? 60 : timeRange === '5m' ? 300 : timeRange === '15m' ? 900 : 3600),
    refetchInterval: 5000,
    enabled: !isHistorical,
  });

  // Fetch historical traffic from DB rollups (for 6h+ ranges)
  const { data: historicalData } = useQuery({
    queryKey: ['traffic-history', timeRange],
    queryFn: () => {
      const hours = HISTORICAL_HOURS[timeRange] || 24;
      const end = new Date().toISOString();
      const start = new Date(Date.now() - hours * 3600 * 1000).toISOString();
      const resolution = HISTORICAL_RESOLUTION[timeRange] || '5m';
      return api.getTrafficHistory(start, end, resolution);
    },
    refetchInterval: timeRange === '6h' ? 30000 : timeRange === '24h' ? 60000 : 300000,
    enabled: isHistorical,
  });

  // Fetch traffic data
  const { data: trafficData } = useQuery({
    queryKey: ['realtime-traffic'],
    queryFn: () => api.getRealtimeTraffic() as Promise<TrafficData>,
    refetchInterval: 2000,
  });

  // Extract selected IP data from per-IP stats
  const selectedIPData = useMemo(() => {
    if (!selectedIP || !perIPStats) return null;
    const ips = perIPStats?.protected_ips || [];
    return ips.find((ip: Record<string, unknown>) => ip.dst_ip_str === selectedIP) as Record<string, unknown> | undefined || null;
  }, [selectedIP, perIPStats]);

  // Accumulate per-IP history for chart
  useEffect(() => {
    if (selectedIP && selectedIPData) {
      addSample(selectedIP, {
        packets_per_sec: (selectedIPData.packets_per_sec as number) || 0,
        bytes_per_sec: (selectedIPData.bytes_per_sec as number) || 0,
      });
    }
  }, [selectedIP, selectedIPData, addSample]);

  const handleRefresh = async () => {
    setRefreshing(true);
    await refetch();
    setRefreshing(false);
  };

  // Normalize ports data (can be array or object)
  const ports = useMemo(() => {
    if (!realtimeStats?.ports) return [];
    if (Array.isArray(realtimeStats.ports)) return realtimeStats.ports;
    return Object.values(realtimeStats.ports);
  }, [realtimeStats]);

  // Calculate totals from ports if not provided
  const totals = useMemo(() => {
    if (realtimeStats?.totals) return realtimeStats.totals;
    return {
      rx_packets: ports.reduce((sum, p) => sum + (p.rx_packets || 0), 0),
      tx_packets: ports.reduce((sum, p) => sum + (p.tx_packets || 0), 0),
      rx_bytes: ports.reduce((sum, p) => sum + (p.rx_bytes || 0), 0),
      tx_bytes: ports.reduce((sum, p) => sum + (p.tx_bytes || 0), 0),
      dropped: ports.reduce((sum, p) => sum + (p.dropped || 0), 0),
      rx_pps: ports.reduce((sum, p) => sum + (p.rx_pps || 0), 0),
      tx_pps: ports.reduce((sum, p) => sum + (p.tx_pps || 0), 0),
      rx_bps: ports.reduce((sum, p) => sum + (p.rx_bps || 0), 0),
      tx_bps: ports.reduce((sum, p) => sum + (p.tx_bps || 0), 0),
    };
  }, [realtimeStats, ports]);

  const protocolStats = trafficData?.protocol_stats;

  // Protocol chart data -- per-IP ratios when IP selected, global otherwise
  const protocolChartData = useMemo(() => {
    if (selectedIP && selectedIPData) {
      const pps = (selectedIPData.packets_per_sec as number) || 0;
      const tcpR = (selectedIPData.tcp_ratio as number) || 0;
      const udpR = (selectedIPData.udp_ratio as number) || 0;
      const icmpR = (selectedIPData.icmp_ratio as number) || 0;
      const otherR = (selectedIPData.other_ratio as number) || 0;
      return [
        { name: 'TCP', value: tcpR, pps: Math.round(pps * tcpR / 100) },
        { name: 'UDP', value: udpR, pps: Math.round(pps * udpR / 100) },
        { name: 'ICMP', value: icmpR, pps: Math.round(pps * icmpR / 100) },
        { name: 'Other', value: otherR, pps: Math.round(pps * otherR / 100) },
      ].filter(d => d.value > 0);
    }
    if (!protocolStats) return [];
    return [
      { name: 'TCP', value: protocolStats.tcp.packets, pps: protocolStats.tcp.pps },
      { name: 'UDP', value: protocolStats.udp.packets, pps: protocolStats.udp.pps },
      { name: 'ICMP', value: protocolStats.icmp.packets, pps: protocolStats.icmp.pps },
      { name: 'Other', value: protocolStats.other.packets, pps: protocolStats.other.pps },
    ].filter(d => d.value > 0);
  }, [protocolStats, selectedIP, selectedIPData]);

  // In per-IP mode, values are percentages (0-100). In global mode, values are packet counts.
  const totalProtocolPackets = protocolChartData.reduce((sum, d) => sum + d.value, 0) || 1;

  // Traffic history chart data -- per-IP, historical rollups, or port-level realtime
  const trafficChartData = useMemo(() => {
    if (selectedIP) {
      const ipHistory = getHistory(selectedIP);
      return ipHistory.map((s) => ({
        time: s.timestamp_str,
        rx: s.rx_bps * 8, // convert bytes/s to bits/s for formatBPS
        tx: 0,
      }));
    }

    // Historical mode: use traffic rollups from DB
    if (isHistorical && historicalData) {
      interface HistoryPoint { timestamp: string; pps: number; bps: number; drops: number; attacks: number }
      return (historicalData as unknown as HistoryPoint[]).map((point) => {
        const t = new Date(point.timestamp);
        const timeStr = timeRange === '7d' || timeRange === '30d'
          ? `${t.getMonth() + 1}/${t.getDate()} ${t.getHours()}:${String(t.getMinutes()).padStart(2, '0')}`
          : `${t.getHours()}:${String(t.getMinutes()).padStart(2, '0')}`;
        return {
          time: timeStr,
          rx: point.bps || 0,
          tx: 0,
        };
      });
    }

    // Realtime mode: use port-level history
    interface PortHistorySample {
      timestamp: number;
      timestamp_str: string;
      ports: Record<string, { rx_bps?: number; tx_bps?: number; rx_pps?: number; tx_pps?: number; dropped?: number }>;
    }
    const history = (portHistory as unknown as PortHistorySample[]) || [];
    return history.slice(-60).map((sample, idx) => {
      const portValues = Object.values(sample.ports || {});
      return {
        time: sample.timestamp_str || idx.toString(),
        rx: portValues.reduce((sum, p) => sum + (p.rx_bps || 0), 0),
        tx: portValues.reduce((sum, p) => sum + (p.tx_bps || 0), 0),
      };
    });
  }, [portHistory, historicalData, isHistorical, timeRange, selectedIP, getHistory]);

  // Port table columns
  const portColumns = [
    { key: 'port_id', header: 'Port', sortable: true, render: (v: unknown) => (
      <div className="flex items-center gap-2">
        <span className="h-2 w-2 rounded-full bg-emerald-500" />
        <span className="font-medium">Port {v as number}</span>
      </div>
    )},
    { key: 'rx_packets', header: 'RX Packets', sortable: true, render: (v: unknown) => formatNumber(v as number) },
    { key: 'tx_packets', header: 'TX Packets', sortable: true, render: (v: unknown) => formatNumber(v as number) },
    { key: 'rx_rate', header: 'RX Rate', sortable: false, render: (_: unknown, row: PortStats) =>
      <span className="text-blue-600 dark:text-blue-400">{formatPPS(row.rx_pps || 0)}</span>
    },
    { key: 'tx_rate', header: 'TX Rate', sortable: false, render: (_: unknown, row: PortStats) =>
      <span className="text-emerald-600 dark:text-emerald-400">{formatPPS(row.tx_pps || 0)}</span>
    },
    { key: 'dropped', header: 'Dropped', sortable: true, render: (_: unknown, row: PortStats) =>
      <span className="text-red-600 dark:text-red-400 font-medium">{formatNumber(row.dropped || 0)}</span>
    },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Traffic Analysis"
        description="Real-time traffic monitoring and protocol analysis"
        actions={
          <>
            <StatusIndicator
              status={realtimeStats?.connected ? 'online' : 'offline'}
              label={realtimeStats?.connected ? 'DPDK Connected' : 'Disconnected'}
            />
            <IPScopeSelector />
            <div className="flex flex-wrap rounded-lg border border-slate-200 dark:border-slate-700 overflow-hidden">
              {(Object.keys(timeRangeLabels) as TimeRange[]).map((range) => (
                <button
                  key={range}
                  onClick={() => setTimeRange(range)}
                  className={`px-3 py-1.5 text-sm font-medium transition-colors ${
                    timeRange === range
                      ? 'bg-brand-600 text-white'
                      : 'bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700'
                  }`}
                >
                  {timeRangeLabels[range]}
                </button>
              ))}
            </div>
            <button onClick={handleRefresh} disabled={refreshing} className="btn-secondary btn-sm">
              <ArrowPathIcon className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
            </button>
          </>
        }
      />

      {/* Per-IP info banner */}
      {selectedIP && (
        <div className="flex items-center gap-2 rounded-lg bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 px-4 py-2.5 text-sm text-blue-700 dark:text-blue-300">
          <InformationCircleIcon className="h-4 w-4 flex-shrink-0" />
          <span>Showing data for <strong className="font-mono">{selectedIP}</strong>. Outbound, drop stats, port table, and drop reasons are global-only.</span>
        </div>
      )}

      {/* Primary KPIs */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          title="Inbound Rate"
          value={selectedIP && selectedIPData
            ? formatPPS((selectedIPData.packets_per_sec as number) || 0)
            : formatPPS(totals.rx_pps)}
          subtitle={selectedIP && selectedIPData
            ? `${formatBytes((selectedIPData.bytes_per_sec as number) || 0)}/s`
            : formatBPS(totals.rx_bps)}
          icon={ArrowTrendingDownIcon}
          color="info"
          loading={statsLoading}
        />
        <MetricCard
          title="Outbound Rate"
          value={selectedIP ? 'N/A' : formatPPS(totals.tx_pps)}
          subtitle={selectedIP ? 'Global only' : formatBPS(totals.tx_bps)}
          icon={ArrowTrendingUpIcon}
          color={selectedIP ? 'neutral' : 'success'}
          loading={statsLoading}
        />
        <MetricCard
          title="Packets Dropped"
          value={selectedIP ? 'N/A' : formatNumber(totals.dropped)}
          subtitle={selectedIP ? 'Global only' : `${formatNumber(trafficData?.total_dropped || 0)} total filtered`}
          icon={FunnelIcon}
          color={selectedIP ? 'neutral' : (totals.dropped > 0 ? 'warning' : 'neutral')}
          loading={statsLoading}
        />
        <MetricCard
          title="Total Throughput"
          value={selectedIP && selectedIPData
            ? formatBytes((selectedIPData.bytes_per_sec as number) || 0) + '/s'
            : formatBytes(totals.rx_bytes)}
          subtitle={selectedIP ? 'Per-IP inbound only' : `TX: ${formatBytes(totals.tx_bytes)}`}
          icon={ChartBarIcon}
          color="brand"
          loading={statsLoading}
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Traffic Timeline */}
        <div className="lg:col-span-2 card">
          <div className="card-header">
            <h3 className="card-title">Traffic Timeline{selectedIP ? ` — ${selectedIP}` : ''}</h3>
            <span className="text-xs text-slate-500">
              {selectedIP ? 'Client-side history' : isHistorical ? `Last ${timeRangeLabels[timeRange]} (from DB)` : `Last ${timeRangeLabels[timeRange]}`}
            </span>
          </div>
          <div className="p-4">
            {trafficChartData.length > 0 ? (
              <ResponsiveContainer width="100%" height={280}>
                <AreaChart data={trafficChartData}>
                  <defs>
                    <linearGradient id="rxGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="txGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-slate-200 dark:stroke-slate-700" />
                  <XAxis dataKey="time" tick={false} />
                  <YAxis tickFormatter={(v) => formatBPS(v)} tick={{ fill: '#94a3b8', fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1e293b',
                      border: 'none',
                      borderRadius: '0.5rem',
                      color: '#f1f5f9',
                    }}
                    formatter={(value: number, name: string) => [
                      formatBPS(value),
                      name === 'rx' ? 'Inbound' : 'Outbound'
                    ]}
                  />
                  <Area type="linear" dataKey="rx" stroke="#3b82f6" fill="url(#rxGradient)" strokeWidth={2} />
                  <Area type="linear" dataKey="tx" stroke="#10b981" fill="url(#txGradient)" strokeWidth={2} />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[280px] flex items-center justify-center text-slate-500 dark:text-slate-400">
                No traffic data available
              </div>
            )}
          </div>
        </div>

        {/* Protocol Distribution */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Protocol Distribution{selectedIP ? ` — ${selectedIP}` : ''}</h3>
          </div>
          <div className="p-4">
            {protocolChartData.length > 0 ? (
              <>
                <ResponsiveContainer width="100%" height={180}>
                  <PieChart>
                    <Pie
                      data={protocolChartData}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={75}
                      dataKey="value"
                      stroke="none"
                    >
                      {protocolChartData.map((entry) => (
                        <Cell
                          key={entry.name}
                          fill={PROTOCOL_COLORS[entry.name as keyof typeof PROTOCOL_COLORS]}
                        />
                      ))}
                    </Pie>
                    <Tooltip
                      formatter={(value: number, name: string) => [
                        `${formatNumber(value)} (${((value / totalProtocolPackets) * 100).toFixed(1)}%)`,
                        name
                      ]}
                    />
                  </PieChart>
                </ResponsiveContainer>
                <div className="mt-4 space-y-2">
                  {protocolChartData.map((proto) => (
                    <div key={proto.name} className="flex items-center justify-between text-sm">
                      <div className="flex items-center gap-2">
                        <span
                          className="h-3 w-3 rounded-full"
                          style={{ backgroundColor: PROTOCOL_COLORS[proto.name as keyof typeof PROTOCOL_COLORS] }}
                        />
                        <span className="text-slate-700 dark:text-slate-300">{proto.name}</span>
                      </div>
                      <div className="text-right">
                        <span className="font-medium text-slate-900 dark:text-white">
                          {((proto.value / totalProtocolPackets) * 100).toFixed(1)}%
                        </span>
                        <span className="ml-2 text-slate-500 text-xs">
                          {formatPPS(proto.pps)}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="h-[280px] flex items-center justify-center text-slate-500 dark:text-slate-400">
                No protocol data
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Port Statistics Table -- hidden in per-IP view */}
      {selectedIP ? (
        <div className="flex items-center gap-2 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 px-4 py-3 text-sm text-slate-500 dark:text-slate-400">
          <InformationCircleIcon className="h-4 w-4 flex-shrink-0" />
          <span>Port-level statistics available in global view.</span>
        </div>
      ) : ports.length > 0 ? (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Port Statistics</h3>
            <span className="badge badge-info">{ports.length} ports</span>
          </div>
          <DataTable
            columns={portColumns}
            data={ports}
            keyField="port_id"
          />
        </div>
      ) : !statsLoading && (
        <EmptyState
          icon={ServerIcon}
          title="No Port Data"
          description="No DPDK ports detected. Ensure the datapath is running."
        />
      )}

      {/* Drop Reasons -- hidden in per-IP view */}
      {!selectedIP && trafficData?.drop_reasons_total && Object.keys(trafficData.drop_reasons_total).length > 0 && (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Drop Reasons</h3>
            <span className="badge badge-warning">{formatNumber(trafficData.total_dropped)} total dropped</span>
          </div>
          <div className="p-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {Object.entries(trafficData.drop_reasons_total)
                .sort(([, a], [, b]) => b - a)
                .slice(0, 12)
                .map(([reason, total]) => {
                  const rate = trafficData.drop_reasons?.[reason] || 0;
                  return (
                    <div
                      key={reason}
                      className="flex items-center justify-between p-3 rounded-lg bg-slate-50 dark:bg-slate-800/50"
                    >
                      <span className="text-sm text-slate-700 dark:text-slate-300 capitalize">
                        {reason.replace(/_/g, ' ')}
                      </span>
                      <div className="text-right">
                        <span className="text-sm font-semibold text-red-600 dark:text-red-400">
                          {formatNumber(total)}
                        </span>
                        {rate > 0 && (
                          <span className="text-xs text-slate-500 dark:text-slate-400 ml-1.5">
                            {formatNumber(rate)}/s
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default TrafficPage;
