/**
 * System Status Page
 *
 * Real-time system health monitoring:
 * - DPDK Core status and utilization
 * - Service health (Layer 1/2/3 pipeline)
 * - Network interface metrics
 * - Memory and hugepage usage
 * - Recent system alerts
 */

import { useState, useMemo, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { clsx } from 'clsx';
import {
  ServerStackIcon,
  CpuChipIcon,
  CircleStackIcon,
  SignalIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ArrowPathIcon,
  ClockIcon,
  BoltIcon,
  WifiIcon,
  TrashIcon,
} from '@heroicons/react/24/outline';
import {
  MetricCard,
  StatusIndicator,
  EmptyState,
  LoadingSpinner,
  PageHeader,
} from '../components/ui';
import api from '../services/api';
import { formatBytes, formatNumber } from '../utils/formatting';

// ============================================================================
// Types
// ============================================================================

interface LcoreInfo {
  lcore_id: number;
  is_active: boolean;
  utilization_pct: number;
}

interface MempoolInfo {
  name: string;
  size: number;
  usage_pct: number;
}

interface SysmonData {
  dpdk: {
    lcores: LcoreInfo[];
    avg_lcore_utilization: number;
    mempools: MempoolInfo[];
    hugepage_total_mb: number;
    hugepage_used_mb: number;
    hugepage_usage_pct: number;
  };
  system: {
    avg_cpu_usage: number;
    mem_total_gb: number;
    mem_used_gb: number;
    mem_available_gb: number;
    mem_usage_pct: number;
    load_1min: number;
    load_5min: number;
    load_15min: number;
  };
}

interface PortStats {
  port_id: number;
  rx_packets: number;
  tx_packets: number;
  rx_bytes: number;
  tx_bytes: number;
  dropped: number;
  rx_pps: number;
  tx_pps: number;
  rx_mbps: number;
  tx_mbps: number;
  errors?: number;
}

interface RealtimeStats {
  timestamp: number;
  connected: boolean;
  ports: Record<string, PortStats>;
}

interface ServiceStatus {
  name: string;
  status: 'healthy' | 'degraded' | 'down' | 'unknown';
  latency?: number;
  lastCheck: Date;
  details?: string;
}

// ============================================================================
// Helpers
// ============================================================================

function getStatusColor(status: string): string {
  switch (status) {
    case 'healthy': return 'text-emerald-600 dark:text-emerald-400';
    case 'degraded': return 'text-amber-600 dark:text-amber-400';
    case 'down': return 'text-red-600 dark:text-red-400';
    default: return 'text-slate-500 dark:text-slate-400';
  }
}

function getStatusBg(status: string): string {
  switch (status) {
    case 'healthy': return 'bg-emerald-50 dark:bg-emerald-500/10';
    case 'degraded': return 'bg-amber-50 dark:bg-amber-500/10';
    case 'down': return 'bg-red-50 dark:bg-red-500/10';
    default: return 'bg-slate-100 dark:bg-slate-800';
  }
}

function getUtilizationColor(pct: number): string {
  if (pct >= 90) return '#ef4444'; // red
  if (pct >= 70) return '#f59e0b'; // amber
  if (pct >= 50) return '#eab308'; // yellow
  return '#10b981'; // green
}

// ============================================================================
// Sub-components
// ============================================================================

function ServiceHealthCard({ service }: { service: ServiceStatus }) {
  const StatusIcon = service.status === 'healthy'
    ? CheckCircleIcon
    : service.status === 'down'
      ? XCircleIcon
      : ExclamationTriangleIcon;

  return (
    <div className={clsx(
      'p-4 rounded-xl border transition-all',
      service.status === 'healthy' && 'border-emerald-200 dark:border-emerald-800 bg-emerald-50/50 dark:bg-emerald-500/5',
      service.status === 'degraded' && 'border-amber-200 dark:border-amber-800 bg-amber-50/50 dark:bg-amber-500/5',
      service.status === 'down' && 'border-red-200 dark:border-red-800 bg-red-50/50 dark:bg-red-500/5',
      service.status === 'unknown' && 'border-slate-200 dark:border-slate-700 bg-slate-50/50 dark:bg-slate-800/50',
    )}>
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <StatusIcon className={clsx('h-5 w-5', getStatusColor(service.status))} />
          <span className="font-semibold text-slate-900 dark:text-white">{service.name}</span>
        </div>
        <span className={clsx(
          'px-2 py-0.5 rounded-full text-xs font-medium capitalize',
          getStatusBg(service.status),
          getStatusColor(service.status)
        )}>
          {service.status}
        </span>
      </div>

      {service.latency !== undefined && (
        <div className="flex items-center gap-1 text-sm text-slate-600 dark:text-slate-400">
          <ClockIcon className="h-4 w-4" />
          <span>{service.latency.toFixed(1)}ms latency</span>
        </div>
      )}

      {service.details && (
        <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">{service.details}</p>
      )}
    </div>
  );
}

function LcoreCard({ lcore }: { lcore: LcoreInfo }) {
  const color = getUtilizationColor(lcore.utilization_pct);

  return (
    <div className={clsx(
      'p-3 rounded-lg border transition-all',
      lcore.is_active
        ? 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800'
        : 'border-slate-100 dark:border-slate-800 bg-slate-50 dark:bg-slate-900 opacity-60'
    )}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-medium text-slate-900 dark:text-white">
          Core {lcore.lcore_id}
        </span>
        <span className={clsx(
          'text-xs px-1.5 py-0.5 rounded',
          lcore.is_active
            ? 'bg-emerald-100 dark:bg-emerald-500/20 text-emerald-700 dark:text-emerald-400'
            : 'bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400'
        )}>
          {lcore.is_active ? 'Active' : 'Idle'}
        </span>
      </div>

      <div className="relative h-2 bg-slate-100 dark:bg-slate-700 rounded-full overflow-hidden">
        <div
          className="absolute inset-y-0 left-0 rounded-full transition-all duration-500"
          style={{
            width: `${lcore.utilization_pct}%`,
            backgroundColor: color,
          }}
        />
      </div>

      <div className="mt-1 text-right">
        <span className="text-xs font-medium" style={{ color }}>
          {lcore.utilization_pct.toFixed(1)}%
        </span>
      </div>
    </div>
  );
}

function NetworkPortCard({ port, portId }: { port: PortStats; portId: string }) {
  const hasDrops = port.dropped > 0;
  const hasErrors = (port.errors || 0) > 0;
  const hasIssues = hasDrops || hasErrors;

  const issueLabel = hasIssues
    ? [hasDrops && `${formatNumber(port.dropped)} drops`, hasErrors && `${formatNumber(port.errors || 0)} errs`]
        .filter(Boolean).join(', ')
    : 'Healthy';

  return (
    <div className={clsx(
      'card p-4',
      hasIssues && 'ring-2 ring-amber-500/30'
    )}>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="p-2 rounded-lg bg-blue-50 dark:bg-blue-500/10">
            <WifiIcon className="h-5 w-5 text-blue-600 dark:text-blue-400" />
          </div>
          <div>
            <h4 className="font-semibold text-slate-900 dark:text-white">Port {portId}</h4>
            <p className="text-xs text-slate-500 dark:text-slate-400">DPDK NIC</p>
          </div>
        </div>
        <StatusIndicator
          status={hasIssues ? 'warning' : 'healthy'}
          label={issueLabel}
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">RX Traffic</p>
          <p className="text-lg font-bold text-slate-900 dark:text-white">
            {port.rx_mbps?.toFixed(2) || '0.00'} <span className="text-sm font-normal">Mbps</span>
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            {formatNumber(port.rx_pps || 0)} pps
          </p>
        </div>

        <div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">TX Traffic</p>
          <p className="text-lg font-bold text-slate-900 dark:text-white">
            {port.tx_mbps?.toFixed(2) || '0.00'} <span className="text-sm font-normal">Mbps</span>
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            {formatNumber(port.tx_pps || 0)} pps
          </p>
        </div>

        <div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Total RX</p>
          <p className="text-sm font-medium text-slate-700 dark:text-slate-300">
            {formatBytes(port.rx_bytes || 0)}
          </p>
        </div>

        <div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Total TX</p>
          <p className="text-sm font-medium text-slate-700 dark:text-slate-300">
            {formatBytes(port.tx_bytes || 0)}
          </p>
        </div>
      </div>

      {hasIssues && (
        <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-700">
          <div className="flex items-center gap-4 text-sm">
            {hasDrops && (
              <span className="text-amber-600 dark:text-amber-400">
                <ExclamationTriangleIcon className="h-4 w-4 inline mr-1" />
                {formatNumber(port.dropped)} dropped
              </span>
            )}
            {hasErrors && (
              <span className="text-red-600 dark:text-red-400">
                <XCircleIcon className="h-4 w-4 inline mr-1" />
                {formatNumber(port.errors || 0)} errors
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function AlertItem({ alert }: { alert: { severity: string; message: string; time: Date } }) {
  const severityColors = {
    critical: 'bg-red-100 dark:bg-red-500/20 text-red-700 dark:text-red-400 border-red-200 dark:border-red-800',
    warning: 'bg-amber-100 dark:bg-amber-500/20 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-800',
    info: 'bg-blue-100 dark:bg-blue-500/20 text-blue-700 dark:text-blue-400 border-blue-200 dark:border-blue-800',
  };

  return (
    <div className={clsx(
      'px-4 py-3 rounded-lg border',
      severityColors[alert.severity as keyof typeof severityColors] || severityColors.info
    )}>
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-2">
          <ExclamationTriangleIcon className="h-5 w-5 flex-shrink-0 mt-0.5" />
          <p className="text-sm font-medium">{alert.message}</p>
        </div>
        <span className="text-xs opacity-75 whitespace-nowrap">
          {alert.time.toLocaleTimeString()}
        </span>
      </div>
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export default function SystemPage() {
  const [refreshKey, setRefreshKey] = useState(0);
  const [resetStep, setResetStep] = useState<'idle' | 'select' | 'confirm' | 'typing'>('idle');
  const [resetResult, setResetResult] = useState<{
    status: string;
    message?: string;
  } | null>(null);
  const [resetOptions, setResetOptions] = useState({
    clear_per_ip_data: true,
    clear_attacks: true,
    clear_traffic: true,
    reset_configs: true,
  });
  const [confirmText, setConfirmText] = useState('');
  const queryClient = useQueryClient();

  // Fetch system monitoring data
  const { data: sysmonData, isLoading: sysmonLoading } = useQuery({
    queryKey: ['sysmon', refreshKey],
    queryFn: () => api.getRealtimeSysmon() as Promise<SysmonData>,
    refetchInterval: 2000,
  });

  // Fetch realtime stats for port info
  const { data: realtimeData, isLoading: realtimeLoading } = useQuery({
    queryKey: ['realtime-stats', refreshKey],
    queryFn: () => api.getRealtimeStats() as Promise<RealtimeStats>,
    refetchInterval: 2000,
  });

  // Fetch connection status
  const { data: connectionData } = useQuery({
    queryKey: ['dpdk-connection', refreshKey],
    queryFn: () => api.getDPDKConnectionStatus(),
    refetchInterval: 5000,
  });

  // Reset data mutation
  const resetMutation = useMutation({
    mutationFn: (options?: {
      clear_per_ip_data?: boolean;
      clear_attacks?: boolean;
      clear_traffic?: boolean;
      reset_configs?: boolean;
      reason?: string;
    }) => api.systemReset(options),
    onSuccess: (data) => {
      setResetResult({
        status: data.overall_status,
        message: data.overall_status === 'success'
          ? 'Factory reset completed successfully. All selected data has been cleared.'
          : 'Some operations failed — check system logs for details.',
      });
      setResetStep('idle');
      setConfirmText('');
      queryClient.invalidateQueries();
    },
    onError: (error: Error) => {
      setResetResult({
        status: 'error',
        message: error.message || 'Failed to reset data',
      });
      setResetStep('idle');
      setConfirmText('');
    },
  });

  const handleResetData = useCallback(() => {
    resetMutation.mutate({
      ...resetOptions,
      reason: 'Manual factory reset from System page',
    });
  }, [resetMutation, resetOptions]);

  const resetItemCount = Object.values(resetOptions).filter(Boolean).length;
  const canProceedToConfirm = resetItemCount > 0;

  // Derive service health from actual connection and system data
  const services: ServiceStatus[] = useMemo(() => {
    const isConnected = connectionData?.connected;
    const cpuUsage = sysmonData?.system?.avg_cpu_usage || 0;

    const activeCores = sysmonData?.dpdk?.lcores?.filter(l => l.is_active).length || 0;
    const totalCores = sysmonData?.dpdk?.lcores?.length || 0;

    return [
      {
        name: 'Layer 1 - Packet Processing',
        status: isConnected ? 'healthy' : 'down',
        lastCheck: new Date(),
        details: isConnected
          ? `DPDK fast-path active — ${activeCores}/${totalCores} cores`
          : 'DPDK not connected',
      },
      {
        name: 'Layer 2 - Anomaly Detection',
        status: isConnected ? (cpuUsage > 90 ? 'degraded' : 'healthy') : 'unknown',
        lastCheck: new Date(),
        details: isConnected
          ? cpuUsage > 90 ? `High CPU load (${cpuUsage.toFixed(1)}%)` : 'Statistical analysis running'
          : 'Waiting for DPDK connection',
      },
      {
        name: 'Backend API',
        status: 'healthy',
        lastCheck: new Date(),
        details: 'FastAPI server responding',
      },
    ];
  }, [connectionData, sysmonData]);

  // Generate alerts from system state
  const recentAlerts = useMemo(() => {
    const alerts: { severity: string; message: string; time: Date }[] = [];
    const now = new Date();

    // Generate alerts based on actual system metrics
    if (sysmonData?.system?.avg_cpu_usage && sysmonData.system.avg_cpu_usage > 85) {
      alerts.push({
        severity: 'warning',
        message: `High CPU utilization detected (${sysmonData.system.avg_cpu_usage.toFixed(1)}%)`,
        time: now,
      });
    }

    if (sysmonData?.system?.mem_usage_pct && sysmonData.system.mem_usage_pct > 90) {
      alerts.push({
        severity: 'warning',
        message: `High memory usage (${sysmonData.system.mem_usage_pct.toFixed(1)}%)`,
        time: now,
      });
    }

    if (sysmonData?.dpdk?.hugepage_usage_pct && sysmonData.dpdk.hugepage_usage_pct > 95) {
      alerts.push({
        severity: 'critical',
        message: `Hugepage memory nearly exhausted (${sysmonData.dpdk.hugepage_usage_pct.toFixed(1)}%)`,
        time: now,
      });
    }

    if (!connectionData?.connected) {
      alerts.push({
        severity: 'critical',
        message: 'DPDK datapath disconnected - packet processing offline',
        time: now,
      });
    }

    // Check for any lcores with high utilization
    const highUtilCores = sysmonData?.dpdk?.lcores?.filter(l => l.is_active && l.utilization_pct > 90) || [];
    if (highUtilCores.length > 0) {
      alerts.push({
        severity: 'warning',
        message: `High utilization on ${highUtilCores.length} DPDK core(s) (>90%)`,
        time: now,
      });
    }

    // Check for mempool exhaustion
    const criticalPools = sysmonData?.dpdk?.mempools?.filter(p => p.usage_pct >= 95) || [];
    const warningPools = sysmonData?.dpdk?.mempools?.filter(p => p.usage_pct >= 90 && p.usage_pct < 95) || [];
    if (criticalPools.length > 0) {
      alerts.push({
        severity: 'critical',
        message: `Mempool near exhaustion: ${criticalPools.map(p => `${p.name} (${p.usage_pct.toFixed(0)}%)`).join(', ')}`,
        time: now,
      });
    }
    if (warningPools.length > 0) {
      alerts.push({
        severity: 'warning',
        message: `High mempool usage: ${warningPools.map(p => `${p.name} (${p.usage_pct.toFixed(0)}%)`).join(', ')}`,
        time: now,
      });
    }

    // Check for port drops/errors
    if (realtimeData?.ports) {
      for (const [portId, port] of Object.entries(realtimeData.ports)) {
        const p = port as PortStats;
        if (p.dropped > 0) {
          alerts.push({
            severity: 'warning',
            message: `Port ${portId}: ${formatNumber(p.dropped)} packets dropped`,
            time: now,
          });
        }
        if ((p.errors || 0) > 0) {
          alerts.push({
            severity: 'warning',
            message: `Port ${portId}: ${formatNumber(p.errors || 0)} errors detected`,
            time: now,
          });
        }
      }
    }

    return alerts;
  }, [sysmonData, connectionData, realtimeData]);

  const overallHealth = useMemo(() => {
    const downServices = services.filter(s => s.status === 'down').length;
    const degradedServices = services.filter(s => s.status === 'degraded').length;

    if (downServices > 0) return 'critical';
    if (degradedServices > 0) return 'degraded';
    return 'healthy';
  }, [services]);

  const handleRefresh = () => setRefreshKey(k => k + 1);

  if (sysmonLoading || realtimeLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="System Status"
        description="Real-time infrastructure health monitoring"
        actions={
          <>
            <div className={clsx(
              'flex items-center gap-2 px-4 py-2 rounded-lg',
              overallHealth === 'healthy' && 'bg-emerald-50 dark:bg-emerald-500/10',
              overallHealth === 'degraded' && 'bg-amber-50 dark:bg-amber-500/10',
              overallHealth === 'critical' && 'bg-red-50 dark:bg-red-500/10',
            )}>
              {overallHealth === 'healthy' ? (
                <CheckCircleIcon className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
              ) : overallHealth === 'degraded' ? (
                <ExclamationTriangleIcon className="h-5 w-5 text-amber-600 dark:text-amber-400" />
              ) : (
                <XCircleIcon className="h-5 w-5 text-red-600 dark:text-red-400" />
              )}
              <span className={clsx('font-semibold capitalize', getStatusColor(overallHealth))}>
                {overallHealth === 'healthy' ? 'All Systems Operational' : `System ${overallHealth}`}
              </span>
            </div>
            <button
              onClick={handleRefresh}
              className="p-2 text-slate-500 dark:text-slate-300 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
              title="Refresh data"
            >
              <ArrowPathIcon className="h-5 w-5" />
            </button>
          </>
        }
      />

      {/* Stale data warning */}
      {!connectionData?.connected && (
        <div className="flex items-center gap-3 p-3 rounded-lg bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-800">
          <ExclamationTriangleIcon className="h-5 w-5 text-amber-500 flex-shrink-0" />
          <p className="text-sm text-amber-700 dark:text-amber-400">
            DPDK datapath is disconnected. Displayed metrics may be stale or unavailable.
          </p>
        </div>
      )}

      {/* Top Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="DPDK Connection"
          value={connectionData?.connected ? 'Connected' : 'Disconnected'}
          icon={BoltIcon}
          color={connectionData?.connected ? 'success' : 'danger'}
          subtitle={connectionData?.connected ? 'Fast-path active' : 'Check DPDK service'}
        />

        <MetricCard
          title="Load Average"
          value={`${(sysmonData?.system?.load_1min || 0).toFixed(2)}`}
          icon={ClockIcon}
          color={(sysmonData?.system?.load_1min || 0) > 4 ? 'danger' : 'info'}
          subtitle={`5m: ${(sysmonData?.system?.load_5min || 0).toFixed(2)} / 15m: ${(sysmonData?.system?.load_15min || 0).toFixed(2)}`}
        />

        <MetricCard
          title="Avg CPU Usage"
          value={`${(sysmonData?.system?.avg_cpu_usage || 0).toFixed(1)}%`}
          icon={CpuChipIcon}
          color={(sysmonData?.system?.avg_cpu_usage || 0) > 80 ? 'danger' : 'brand'}
          subtitle={`${sysmonData?.dpdk?.lcores?.length || 0} logical cores`}
        />

        <MetricCard
          title="Memory Usage"
          value={`${(sysmonData?.system?.mem_usage_pct || 0).toFixed(1)}%`}
          icon={CircleStackIcon}
          color={(sysmonData?.system?.mem_usage_pct || 0) > 85 ? 'warning' : 'brand'}
          subtitle={`${(sysmonData?.system?.mem_used_gb || 0).toFixed(1)} / ${(sysmonData?.system?.mem_total_gb || 0).toFixed(1)} GB`}
        />
      </div>

      {/* Service Health */}
      <div className="card p-6">
        <div className="flex items-center gap-2 mb-4">
          <ServerStackIcon className="h-5 w-5 text-slate-500" />
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Service Health</h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {services.map((service, idx) => (
            <ServiceHealthCard key={idx} service={service} />
          ))}
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* DPDK Cores */}
        <div className="lg:col-span-2 card p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <CpuChipIcon className="h-5 w-5 text-slate-500" />
              <h2 className="text-lg font-semibold text-slate-900 dark:text-white">DPDK Core Utilization</h2>
            </div>
            <div className="text-sm text-slate-500 dark:text-slate-400">
              Avg: <span className="font-semibold text-slate-900 dark:text-white">
                {(sysmonData?.dpdk?.avg_lcore_utilization || 0).toFixed(1)}%
              </span>
            </div>
          </div>

          {sysmonData?.dpdk?.lcores && sysmonData.dpdk.lcores.length > 0 ? (
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3">
              {sysmonData.dpdk.lcores.map((lcore) => (
                <LcoreCard key={lcore.lcore_id} lcore={lcore} />
              ))}
            </div>
          ) : (
            <EmptyState
              icon={CpuChipIcon}
              title="No Core Data"
              description="DPDK core information not available"
            />
          )}
        </div>

        {/* Memory & Hugepages */}
        <div className="card p-6">
          <div className="flex items-center gap-2 mb-4">
            <CircleStackIcon className="h-5 w-5 text-slate-500" />
            <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Memory</h2>
          </div>

          <div className="space-y-6">
            {/* System Memory */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-slate-600 dark:text-slate-400">System RAM</span>
                <span className="text-sm font-medium text-slate-900 dark:text-white">
                  {(sysmonData?.system?.mem_used_gb || 0).toFixed(1)} / {(sysmonData?.system?.mem_total_gb || 0).toFixed(1)} GB
                </span>
              </div>
              <div className="h-3 bg-slate-100 dark:bg-slate-700 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{
                    width: `${sysmonData?.system?.mem_usage_pct || 0}%`,
                    backgroundColor: getUtilizationColor(sysmonData?.system?.mem_usage_pct || 0),
                  }}
                />
              </div>
            </div>

            {/* Hugepages */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-slate-600 dark:text-slate-400">Hugepages</span>
                <span className="text-sm font-medium text-slate-900 dark:text-white">
                  {(sysmonData?.dpdk?.hugepage_used_mb || 0)} / {(sysmonData?.dpdk?.hugepage_total_mb || 0)} MB
                </span>
              </div>
              <div className="h-3 bg-slate-100 dark:bg-slate-700 rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{
                    width: `${sysmonData?.dpdk?.hugepage_usage_pct || 0}%`,
                    backgroundColor: getUtilizationColor(sysmonData?.dpdk?.hugepage_usage_pct || 0),
                  }}
                />
              </div>
            </div>

            {/* Mempools */}
            {sysmonData?.dpdk?.mempools && sysmonData.dpdk.mempools.length > 0 && (
              <div>
                <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">DPDK Mempools</h3>
                <div className="space-y-3">
                  {sysmonData.dpdk.mempools.slice(0, 4).map((pool, idx) => (
                    <div key={idx}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs text-slate-500 dark:text-slate-400 truncate max-w-[150px]">
                          {pool.name}
                        </span>
                        <span className="text-xs font-medium text-slate-700 dark:text-slate-300">
                          {pool.usage_pct.toFixed(1)}%
                        </span>
                      </div>
                      <div className="h-1.5 bg-slate-100 dark:bg-slate-700 rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${pool.usage_pct}%`,
                            backgroundColor: getUtilizationColor(pool.usage_pct),
                          }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Network Interfaces */}
      <div className="card p-6">
        <div className="flex items-center gap-2 mb-4">
          <SignalIcon className="h-5 w-5 text-slate-500" />
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Network Interfaces</h2>
        </div>

        {realtimeData?.ports && Object.keys(realtimeData.ports).length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {Object.entries(realtimeData.ports).map(([portId, port]) => (
              <NetworkPortCard key={portId} portId={portId} port={port as PortStats} />
            ))}
          </div>
        ) : (
          <EmptyState
            icon={SignalIcon}
            title="No Network Interfaces"
            description="DPDK network ports not available"
          />
        )}
      </div>

      {/* Active Alerts */}
      <div className="card p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <ExclamationTriangleIcon className="h-5 w-5 text-slate-500" />
            <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Active Alerts</h2>
          </div>
          {recentAlerts.length > 0 && (
            <span className="px-2 py-1 bg-amber-100 dark:bg-amber-500/20 text-amber-700 dark:text-amber-400 text-xs font-medium rounded-full">
              {recentAlerts.length} active
            </span>
          )}
        </div>

        {recentAlerts.length > 0 ? (
          <div className="space-y-3">
            {recentAlerts.map((alert, idx) => (
              <AlertItem key={idx} alert={alert} />
            ))}
          </div>
        ) : (
          <EmptyState
            icon={CheckCircleIcon}
            title="No Active Alerts"
            description="All systems operating within normal parameters"
          />
        )}
      </div>

      {/* Data Management */}
      <div className="card p-6">
        <div className="flex items-center gap-2 mb-4">
          <TrashIcon className="h-5 w-5 text-slate-500" />
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Data Management</h2>
        </div>

        {/* Result banner */}
        {resetResult && (
          <div className={clsx(
            'mb-4 p-4 rounded-lg text-sm flex items-start gap-3',
            resetResult.status === 'success'
              ? 'bg-emerald-50 dark:bg-emerald-500/10 border border-emerald-200 dark:border-emerald-800'
              : 'bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-800'
          )}>
            {resetResult.status === 'success' ? (
              <CheckCircleIcon className="h-5 w-5 text-emerald-500 flex-shrink-0 mt-0.5" />
            ) : (
              <XCircleIcon className="h-5 w-5 text-red-500 flex-shrink-0 mt-0.5" />
            )}
            <div>
              <p className={clsx(
                'font-medium',
                resetResult.status === 'success' ? 'text-emerald-800 dark:text-emerald-300' : 'text-red-800 dark:text-red-300'
              )}>
                {resetResult.status === 'success' ? 'Reset Complete' : 'Reset Failed'}
              </p>
              <p className={clsx(
                'mt-1',
                resetResult.status === 'success' ? 'text-emerald-700 dark:text-emerald-400' : 'text-red-700 dark:text-red-400'
              )}>
                {resetResult.message}
              </p>
            </div>
            <button
              onClick={() => setResetResult(null)}
              className="ml-auto text-slate-500 dark:text-slate-300 hover:text-slate-600 dark:hover:text-slate-200"
            >
              <XCircleIcon className="h-4 w-4" />
            </button>
          </div>
        )}

        <div className="p-5 rounded-lg bg-red-50 dark:bg-red-500/5 border border-red-200 dark:border-red-900">
          {/* Step indicator */}
          <div className="flex items-center gap-2 mb-4">
            <div className="flex items-center gap-1.5 text-xs font-medium text-slate-500 dark:text-slate-400">
              {['Select', 'Review', 'Confirm'].map((label, i) => {
                const stepIndex = i;
                const currentIndex = resetStep === 'idle' ? -1 : resetStep === 'select' ? 0 : resetStep === 'confirm' ? 1 : 2;
                const isActive = stepIndex <= currentIndex;
                return (
                  <span key={label} className="flex items-center gap-1.5">
                    {i > 0 && <span className={clsx('w-6 h-px', isActive ? 'bg-red-400' : 'bg-slate-300 dark:bg-slate-700')} />}
                    <span className={clsx(
                      'inline-flex items-center justify-center w-5 h-5 rounded-full text-[10px] font-bold',
                      isActive
                        ? 'bg-red-500 text-white'
                        : 'bg-slate-200 dark:bg-slate-700 text-slate-500 dark:text-slate-400'
                    )}>
                      {i + 1}
                    </span>
                    <span className={isActive ? 'text-red-600 dark:text-red-400' : ''}>{label}</span>
                  </span>
                );
              })}
            </div>
          </div>

          {/* IDLE state */}
          {resetStep === 'idle' && (
            <div>
              <div className="flex items-start gap-3 mb-4">
                <ExclamationTriangleIcon className="h-6 w-6 text-red-500 flex-shrink-0 mt-0.5" />
                <div>
                  <h3 className="font-semibold text-red-800 dark:text-red-300">Factory Reset</h3>
                  <p className="text-sm text-red-700 dark:text-red-400 mt-1">
                    Permanently clear all system data and reset configurations to factory defaults.
                    This operation cannot be undone.
                  </p>
                </div>
              </div>
              <button
                onClick={() => { setResetResult(null); setResetStep('select'); }}
                className="btn-danger text-sm"
              >
                <TrashIcon className="h-4 w-4 mr-2" />
                Begin Factory Reset
              </button>
            </div>
          )}

          {/* STEP 1: Select what to reset */}
          {resetStep === 'select' && (
            <div>
              <h3 className="font-semibold text-red-800 dark:text-red-300 mb-1">Step 1: Select data to clear</h3>
              <p className="text-xs text-red-600 dark:text-red-400 mb-4">Choose which components to reset. All selected items will be permanently deleted.</p>

              <div className="space-y-2 mb-5">
                {[
                  {
                    key: 'reset_configs' as const,
                    label: 'Configuration',
                    desc: 'Reset all Layer 1 and Layer 2 settings to factory defaults. Removes config snapshots.',
                    icon: '',
                  },
                  {
                    key: 'clear_per_ip_data' as const,
                    label: 'Anomaly Detection Data',
                    desc: 'Clear per-IP anomaly states, learned baselines, traffic features, and baseline files.',
                    icon: '',
                  },
                  {
                    key: 'clear_attacks' as const,
                    label: 'Attack History',
                    desc: 'Delete all attack records and detection logs from the database.',
                    icon: '',
                  },
                  {
                    key: 'clear_traffic' as const,
                    label: 'Traffic Samples',
                    desc: 'Clear captured traffic samples and packet buffer from memory.',
                    icon: '',
                  },
                ].map(item => (
                  <label
                    key={item.key}
                    className={clsx(
                      'flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors',
                      resetOptions[item.key]
                        ? 'bg-red-100 dark:bg-red-500/15 border-red-300 dark:border-red-700'
                        : 'bg-white dark:bg-slate-800/50 border-slate-200 dark:border-slate-700 hover:border-red-300 dark:hover:border-red-700'
                    )}
                  >
                    <input
                      type="checkbox"
                      checked={resetOptions[item.key]}
                      onChange={(e) => setResetOptions(prev => ({ ...prev, [item.key]: e.target.checked }))}
                      className="mt-1 h-4 w-4 rounded border-slate-300 text-red-600 focus:ring-red-500"
                    />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm">{item.icon}</span>
                        <span className="text-sm font-medium text-slate-900 dark:text-white">{item.label}</span>
                      </div>
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{item.desc}</p>
                    </div>
                  </label>
                ))}
              </div>

              <div className="flex items-center gap-3">
                <button
                  onClick={() => setResetStep('confirm')}
                  disabled={!canProceedToConfirm}
                  className={clsx(
                    'btn-danger text-sm',
                    !canProceedToConfirm && 'opacity-50 cursor-not-allowed'
                  )}
                >
                  Continue — {resetItemCount} item{resetItemCount !== 1 ? 's' : ''} selected
                </button>
                <button
                  onClick={() => { setResetStep('idle'); setConfirmText(''); }}
                  className="btn-secondary text-sm"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {/* STEP 2: Review + type confirmation */}
          {resetStep === 'confirm' && (
            <div>
              <h3 className="font-semibold text-red-800 dark:text-red-300 mb-1">Step 2: Review and confirm</h3>
              <p className="text-xs text-red-600 dark:text-red-400 mb-4">Review your selections carefully. This action is irreversible.</p>

              <div className="mb-4 p-3 rounded-lg bg-red-100 dark:bg-red-500/15 border border-red-300 dark:border-red-700">
                <p className="text-xs font-medium text-red-800 dark:text-red-300 mb-2">The following will be permanently deleted:</p>
                <ul className="space-y-1">
                  {resetOptions.reset_configs && (
                    <li className="text-xs text-red-700 dark:text-red-400 flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-red-500 flex-shrink-0" />
                      All Layer 1 &amp; Layer 2 configurations — reset to defaults
                    </li>
                  )}
                  {resetOptions.clear_per_ip_data && (
                    <li className="text-xs text-red-700 dark:text-red-400 flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-red-500 flex-shrink-0" />
                      Per-IP anomaly data, learned baselines, and baseline files
                    </li>
                  )}
                  {resetOptions.clear_attacks && (
                    <li className="text-xs text-red-700 dark:text-red-400 flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-red-500 flex-shrink-0" />
                      All attack records from database
                    </li>
                  )}
                  {resetOptions.clear_traffic && (
                    <li className="text-xs text-red-700 dark:text-red-400 flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-red-500 flex-shrink-0" />
                      Traffic samples and packet buffer
                    </li>
                  )}
                </ul>
              </div>

              <div className="mb-4">
                <label className="block text-xs font-medium text-red-800 dark:text-red-300 mb-1.5">
                  Type <span className="font-mono bg-red-200 dark:bg-red-800 px-1.5 py-0.5 rounded text-red-900 dark:text-red-200">RESET</span> to confirm
                </label>
                <input
                  type="text"
                  value={confirmText}
                  onChange={(e) => setConfirmText(e.target.value)}
                  placeholder="Type RESET here..."
                  className="w-64 px-3 py-2 text-sm rounded-lg border border-red-300 dark:border-red-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white placeholder-slate-400 focus:ring-2 focus:ring-red-500 focus:border-red-500"
                  autoFocus
                  spellCheck={false}
                />
              </div>

              <div className="flex items-center gap-3">
                <button
                  onClick={handleResetData}
                  disabled={confirmText !== 'RESET' || resetMutation.isPending}
                  className={clsx(
                    'text-sm font-medium px-4 py-2 rounded-lg flex items-center transition-all',
                    confirmText === 'RESET'
                      ? 'bg-red-600 hover:bg-red-700 text-white shadow-sm'
                      : 'bg-slate-200 dark:bg-slate-700 text-slate-400 dark:text-slate-500 cursor-not-allowed'
                  )}
                >
                  {resetMutation.isPending ? (
                    <>
                      <ArrowPathIcon className="h-4 w-4 animate-spin mr-2" />
                      Resetting...
                    </>
                  ) : (
                    <>
                      <ExclamationTriangleIcon className="h-4 w-4 mr-2" />
                      Execute Factory Reset
                    </>
                  )}
                </button>
                <button
                  onClick={() => { setResetStep('select'); setConfirmText(''); }}
                  disabled={resetMutation.isPending}
                  className="btn-secondary text-sm"
                >
                  Back
                </button>
                <button
                  onClick={() => { setResetStep('idle'); setConfirmText(''); }}
                  disabled={resetMutation.isPending}
                  className="text-sm text-slate-500 hover:text-slate-700 dark:hover:text-slate-200 dark:text-slate-300"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
