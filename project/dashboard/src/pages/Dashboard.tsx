/**
 * Enterprise Dashboard Page
 *
 * Premium real-time DPDK monitoring with enterprise-grade UI components
 * Matching Cloudflare, Akamai, Arbor styling standards
 */

import { useState, useMemo, useEffect, useSyncExternalStore } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  BoltIcon,
  ArrowTrendingUpIcon,
  InformationCircleIcon,
} from '@heroicons/react/24/outline';
import { TrafficChart, AttackEvent } from '../components/Dashboard/TrafficChart';
import { AttackStatus } from '../components/Dashboard/AttackStatus';
import { HeroStatusBanner } from '../components/Dashboard/HeroStatusBanner';
import { ContextualActionCards } from '../components/Dashboard/ContextualActionCards';
import { LearningStatus } from '../components/Dashboard/LearningStatus';
import { MetricCard } from '../components/ui';
import { WidgetErrorBoundary } from '../components/ErrorBoundary';
import { IPScopeSelector } from '../components/IPScopeSelector';
import toast from 'react-hot-toast';
import { useIPScopeStore, useNotificationStore } from '../store';
import { usePerIPHistory } from '../hooks/usePerIPHistory';
import api from '../services/api';
import { AttackType, AttackSeverity, PerIPAnomalyEntry, PerIPStatsEntry } from '../types';
import { formatBytes, formatNumber } from '../utils/formatting';

// Pause polling when tab is hidden (saves bandwidth/battery/backend load)
function usePageVisible(): boolean {
  return useSyncExternalStore(
    (cb) => { document.addEventListener('visibilitychange', cb); return () => document.removeEventListener('visibilitychange', cb); },
    () => document.visibilityState === 'visible',
    () => true,
  );
}

export function Dashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const { selectedIP } = useIPScopeStore();
  const { addSample, getHistory } = usePerIPHistory();
  const isVisible = usePageVisible();

  // Polling intervals: only poll when tab is visible
  const fast = isVisible ? 2000 : false;   // 2s for real-time data
  const slow = isVisible ? 5000 : false;   // 5s for less critical data

  // Fetch real-time stats from DPDK
  const { data: realtimeStats, isLoading: statsLoading, refetch: refetchStats } = useQuery({
    queryKey: ['realtime-stats'],
    queryFn: () => api.getRealtimeStats(),
    refetchInterval: fast,
  });

  // Fetch stats history for the chart and sparklines
  const { data: statsHistory, isLoading: historyLoading } = useQuery({
    queryKey: ['realtime-stats-history'],
    queryFn: () => api.getRealtimeStatsHistory(60),
    refetchInterval: slow,
  });

  // Fetch anomaly detection status
  const { data: anomalyData, isLoading: anomalyLoading } = useQuery({
    queryKey: ['realtime-anomaly'],
    queryFn: () => api.getRealtimeAnomaly(),
    refetchInterval: fast,
  });

  // Fetch per-IP anomaly summary
  const { data: perIPSummary } = useQuery({
    queryKey: ['per-ip-anomaly-summary'],
    queryFn: () => api.getPerIPAnomalySummary(),
    refetchInterval: fast,
  });

  // Fetch per-IP anomalies for attack list
  const { data: perIPAnomalies, isLoading: perIPLoading } = useQuery({
    queryKey: ['per-ip-anomaly'],
    queryFn: () => api.getPerIPAnomaly(),
    refetchInterval: fast,
  });

  // Fetch per-IP stats for traffic totals
  const { data: perIPStats } = useQuery({
    queryKey: ['per-ip-stats-dashboard'],
    queryFn: () => api.getPerIPStats(),
    refetchInterval: fast,
  });

  // Fetch DPDK connection status
  const { data: connectionStatus } = useQuery({
    queryKey: ['dpdk-connection'],
    queryFn: () => api.getDPDKConnectionStatus(),
    refetchInterval: slow,
  });

  const handleRefresh = async () => {
    setRefreshing(true);
    await refetchStats();
    setRefreshing(false);
  };

  // Extract selected IP's data from per-IP stats (already fetched every 2s)
  const selectedIPData = useMemo((): PerIPStatsEntry | null => {
    if (!selectedIP) return null;
    const ips = perIPStats?.protected_ips || [];
    return ips.find((ip) => ip.dst_ip_str === selectedIP) || null;
  }, [selectedIP, perIPStats]);

  // Extract selected IP's anomaly data
  const selectedIPAnomaly = useMemo((): PerIPAnomalyEntry | null => {
    if (!selectedIP) return null;
    const anomalies = perIPAnomalies?.per_ip_anomalies || [];
    return anomalies.find((a) => a.dst_ip_str === selectedIP) || null;
  }, [selectedIP, perIPAnomalies]);

  // Accumulate per-IP history for chart
  useEffect(() => {
    if (selectedIP && selectedIPData) {
      addSample(selectedIP, {
        packets_per_sec: (selectedIPData.packets_per_sec as number) || 0,
        bytes_per_sec: (selectedIPData.bytes_per_sec as number) || 0,
      });
    }
  }, [selectedIP, selectedIPData, addSample]);

  // Calculate totals from per-IP stats
  // This ensures consistent metrics: sum of all protected IPs
  const portStats = realtimeStats?.ports || {};
  const ports = Object.values(portStats);

  // Port-level stats (rates are per-second, dropped is cumulative)
  // NOTE: C code computes rx_bps/tx_bps as bits per second (bytes_diff * 8),
  // but formatBytes() expects bytes. Convert bits -> bytes by dividing by 8.
  const portTotalDropped = ports.reduce((sum, p) => sum + (p.dropped || 0), 0);
  const portTotalRxPps = ports.reduce((sum, p) => sum + (p.rx_pps || 0), 0);
  const portTotalRxBps = ports.reduce((sum, p) => sum + (p.rx_bps || 0), 0) / 8;
  // FIX: Per-port stats don't include drop_pps (only cumulative 'dropped').
  // Use latest traffic history sample which correctly computes drop_pps
  // from cumulative drop-reason counter deltas.
  const latestHistorySample = (statsHistory || []).slice(-1)[0];
  const portTotalDropPps = latestHistorySample?.drop_pps || 0;

  // Per-IP stats
  const perIPTotals = (perIPStats as { totals?: { packets_per_sec: number; bytes_per_sec: number; total_packets: number } })?.totals;

  // Use per-IP aggregated bytes/sec (already in bytes) as primary source.
  // Per-IP features track actual datapath traffic; port stats are fallback.
  const perIPBps = perIPTotals?.bytes_per_sec || 0;
  const perIPPps = perIPTotals?.packets_per_sec || 0;

  // Use per-IP data when available, fall back to port-level stats (now in bytes)
  const totalRxBps = perIPBps || portTotalRxBps;
  const totalRxPps = perIPPps || portTotalRxPps;
  const totalDropped = portTotalDropped;

  // Calculate drop rate from per-second rates (not cumulative totals)
  // Uses drop_pps / rx_pps for CURRENT drop rate, not lifetime average
  const dropRate = portTotalRxPps > 0
    ? Math.min(100, Math.max(0, (portTotalDropPps / portTotalRxPps) * 100))
    : 0;

  // Per-IP or global display values
  const displayRxBps = selectedIP && selectedIPData
    ? (selectedIPData.bytes_per_sec as number) || 0
    : totalRxBps;
  const displayRxPps = selectedIP && selectedIPData
    ? (selectedIPData.packets_per_sec as number) || 0
    : totalRxPps;
  const displayDropRate = selectedIP ? null : dropRate; // Drop rate not tracked per-IP

  // Generate sparkline data from history
  const sparklineData = useMemo(() => {
    if (selectedIP) {
      const ipHistory = getHistory(selectedIP);
      if (ipHistory.length === 0) return { rxBps: undefined, txBps: undefined, rxPps: undefined, drops: undefined };
      return {
        rxBps: ipHistory.map(s => s.rx_bps),
        txBps: undefined,
        rxPps: ipHistory.map(s => s.rx_pps),
        drops: undefined,
      };
    }
    const history = statsHistory || [];
    if (history.length === 0) {
      return {
        rxBps: undefined,
        txBps: undefined,
        rxPps: undefined,
        drops: undefined,
      };
    }
    return {
      rxBps: history.map(s => s.rx_bps || s.bps || 0),
      txBps: history.map(s => s.tx_bps || 0),
      rxPps: history.map(s => s.rx_pps || s.pps || 0),
      drops: history.map(s => s.drop_pps || 0),
    };
  }, [statsHistory, selectedIP, getHistory]);

  // Chart data with inbound/outbound split
  // When per-IP selected, use client-side accumulated history
  const chartData = useMemo(() => {
    if (selectedIP) {
      const ipHistory = getHistory(selectedIP);
      return ipHistory.map((s) => ({
        timestamp: s.timestamp_str,
        rx_bps: s.rx_bps,
        tx_bps: 0,
        drop_bps: 0,
        rx_pps: s.rx_pps,
        tx_pps: 0,
        drop_pps: 0,
        fwd_bps: s.fwd_bps,
        fwd_pps: s.fwd_pps,
      }));
    }
    return (statsHistory || []).map((stat) => {
      const rx_bps = stat.rx_bps || stat.bps || 0;
      const tx_bps = stat.tx_bps || 0;
      const fwd_bps = stat.fwd_bps || Math.max(0, rx_bps - (stat.drop_bps || 0));
      const drop_bps = stat.drop_bps || Math.max(0, rx_bps - fwd_bps);
      const rx_pps = stat.rx_pps || stat.pps || 0;
      const drop_pps = stat.drop_pps || 0;
      const fwd_pps = stat.fwd_pps || Math.max(0, rx_pps - drop_pps);
      return {
        timestamp: stat.timestamp_str || new Date(stat.timestamp).toLocaleTimeString(),
        rx_bps,
        tx_bps,
        drop_bps,
        rx_pps,
        tx_pps: stat.tx_pps || 0,
        drop_pps,
        fwd_bps,
        fwd_pps,
      };
    });
  }, [selectedIP, getHistory, statsHistory]);

  // Convert per-IP anomalies to attack format for AttackStatus component
  // Only include IPs with active anomalies; filter to selected IP if set
  const activeAttacks = (perIPAnomalies?.per_ip_anomalies || [])
    .filter(a => a.anomaly_active && (!selectedIP || a.dst_ip_str === selectedIP))
    .map(a => ({
      id: a.dst_ip_str,
      target_ip: a.dst_ip_str,
      target_port: a.anomaly_dst_port || undefined,
      attack_type: (a.attack_type_name || 'unknown').toLowerCase() as AttackType,
      severity: (a.level_name || 'low').toLowerCase() as AttackSeverity,
      protocol: a.anomaly_protocol_name,
      started_at: a.started_at || '',
      duration_seconds: a.duration_sec || 0,
      peak_pps: a.packets_per_sec || (a.bytes_per_sec > 0 ? Math.max(1, Math.round(a.bytes_per_sec / 54)) : 0),
      peak_bps: a.bytes_per_sec || 0,
      source_ips_count: a.unique_src_ips || 0,
      is_active: true,
      mitigated: false,
      ml_confidence: a.max_z_score > 0 ? Math.min(100, Math.round(a.max_z_score * 5)) : undefined,
      spoofed_mode: a.spoofed_mode || false,
      randomness_pct: a.randomness_pct || 0,
      rate_limit_pct: a.rate_limit_pct ?? 100,
      cusum_triggered: a.cusum_triggered,
      jsd_triggered: a.jsd_triggered,
      fast_triggered: a.fast_triggered,
      confidence_pct: a.confidence,
      sensitivity_preset: a.sensitivity_preset,
      learning_phase: a.learning_phase,
      cool_down_remaining_sec: a.cool_down_remaining_sec,
      peak_z_feature_name: a.peak_z_feature_name,
      total_packets_dropped: 0,
      total_bytes_dropped: 0,
      top_source_ips: [],
      signatures_matched: [],
    }));

  const isConnected = connectionStatus?.connected || realtimeStats?.connected;

  // Determine active anomaly status -- per-IP when selected, global otherwise.
  // Alert-only detections (mitigation_active=false) during learning phase
  // should NOT show as "ATTACK IN PROGRESS" to avoid false alarm fatigue.
  const hasActiveAnomaly = selectedIP && selectedIPAnomaly
    ? selectedIPAnomaly.anomaly_active
    : anomalyData?.active && anomalyData?.mitigation_active !== false;
  const currentAnomalyLevel = selectedIP && selectedIPAnomaly
    ? selectedIPAnomaly.level || 0
    : anomalyData?.level || 0;
  const currentAnomalyLevelName = selectedIP && selectedIPAnomaly
    ? selectedIPAnomaly.level_name || 'Normal'
    : anomalyData?.level_name || 'Normal';

  // Derive attack event markers for the traffic chart
  const attackEvents = useMemo((): AttackEvent[] => {
    return (perIPAnomalies?.per_ip_anomalies || [])
      .filter(a => a.anomaly_active && a.started_at)
      .map(a => ({
        timestamp: new Date(a.started_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        label: `${a.attack_type_name || 'Anomaly'} on ${a.dst_ip_str}`,
        severity: (a.level >= 4 ? 'critical' : a.level >= 3 ? 'high' : a.level >= 2 ? 'medium' : 'low') as AttackEvent['severity'],
      }));
  }, [perIPAnomalies]);

  // Wire attack state transitions to notification store
  const addNotification = useNotificationStore((s) => s.addNotification);
  const [prevAttackState, setPrevAttackState] = useState<boolean | null>(null);

  useEffect(() => {
    // Skip initial render (no transition yet)
    if (prevAttackState === null) {
      setPrevAttackState(!!hasActiveAnomaly);
      return;
    }

    const isAttacking = !!hasActiveAnomaly;
    if (isAttacking !== prevAttackState) {
      if (isAttacking && activeAttacks.length > 0) {
        const primary = activeAttacks[0];
        const title = `Attack Detected — ${primary.attack_type.toUpperCase()}`;
        const message = `${primary.target_ip}${primary.target_port ? ':' + primary.target_port : ''} under ${primary.severity} severity attack. ${activeAttacks.length > 1 ? `${activeAttacks.length} IPs targeted.` : ''}`;
        addNotification({ type: 'error', title, message });
        toast.error(title, { duration: 8000, id: 'attack-start' });
      } else if (!isAttacking) {
        addNotification({
          type: 'success',
          title: 'Attack Mitigated',
          message: 'All active threats have been resolved. Traffic is normal.',
        });
        toast.success('Attack mitigated — traffic is normal', { duration: 5000, id: 'attack-end' });
      }
      setPrevAttackState(isAttacking);
    }
  }, [hasActiveAnomaly, activeAttacks, prevAttackState, addNotification]);

  return (
    <div className="space-y-6">
      {/* Hero Status Banner -- single source of truth for system status */}
      <HeroStatusBanner
        isConnected={!!isConnected}
        hasActiveAnomaly={!!hasActiveAnomaly}
        anomalyLevel={currentAnomalyLevel}
        anomalyLevelName={currentAnomalyLevelName}
        anomalyData={anomalyData}
        totalRxBps={totalRxBps}
        protectedAssetCount={perIPSummary?.total_protected_ips || 0}
        anomalousIpCount={perIPSummary?.anomalous_ips || 0}
        selectedIP={selectedIP}
        selectedIPAnomaly={selectedIPAnomaly}
        onRefresh={handleRefresh}
        refreshing={refreshing}
      >
        <IPScopeSelector />
      </HeroStatusBanner>

      {/* Per-IP info banner */}
      {selectedIP && (
        <div className="flex items-center gap-2 rounded-lg bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 px-4 py-2.5 text-sm text-blue-700 dark:text-blue-300">
          <InformationCircleIcon className="h-4 w-4 flex-shrink-0" />
          <span>Showing data for <strong className="font-mono">{selectedIP}</strong>. TX, drop rate, and sparklines for outbound/drops are global-only metrics.</span>
        </div>
      )}

      {/* Hero Metrics -- 2 featured cards with accent borders */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <MetricCard
          title="Inbound Traffic"
          value={formatBytes(displayRxBps) + '/s'}
          icon={ArrowTrendingUpIcon}
          color="info"
          size="lg"
          sparklineData={sparklineData.rxBps}
          loading={statsLoading}
          subtitle={selectedIP ? 'Per-IP bandwidth' : 'Current bandwidth'}
          className="animate-stagger-1"
        />
        <MetricCard
          title="Security Status"
          value={hasActiveAnomaly ? currentAnomalyLevelName : 'Protected'}
          icon={hasActiveAnomaly ? ExclamationTriangleIcon : ShieldCheckIcon}
          color={hasActiveAnomaly ? (currentAnomalyLevel >= 3 ? 'danger' : 'warning') : 'success'}
          size="lg"
          loading={anomalyLoading}
          subtitle={hasActiveAnomaly
            ? `${perIPSummary?.anomalous_ips || 0} threatened \u00b7 Z\u2265${anomalyData?.current_threshold?.toFixed(1) || '?'}`
            : `${perIPSummary?.total_protected_ips || 0} assets \u00b7 Z\u2265${anomalyData?.current_threshold?.toFixed(1) || '?'}`}
          className="animate-stagger-2"
        />
      </div>

      {/* Secondary Metrics -- 2 compact cards */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
        <MetricCard
          title="Packet Rate"
          value={formatNumber(displayRxPps)}
          unit="pps"
          icon={BoltIcon}
          color="brand"
          size="sm"
          sparklineData={sparklineData.rxPps}
          loading={statsLoading}
          subtitle={selectedIP ? 'Per-IP packets/sec' : 'Packets per second'}
          className="animate-stagger-3"
        />
        <div className={selectedIP ? 'opacity-50 pointer-events-none' : ''}>
          <MetricCard
            title="Drop Rate"
            value={displayDropRate != null ? displayDropRate.toFixed(2) : 'N/A'}
            unit={displayDropRate != null ? '%' : undefined}
            icon={ShieldCheckIcon}
            color={selectedIP ? 'neutral' : (dropRate > 10 ? 'danger' : dropRate > 5 ? 'warning' : 'success')}
            size="sm"
            loading={statsLoading}
            subtitle={selectedIP ? 'Only available in global view' : `${formatNumber(totalDropped)} total dropped`}
            className="animate-stagger-4"
          />
        </div>
      </div>

      {/* Learning Status -- only shown when not yet mature */}
      <WidgetErrorBoundary>
        <LearningStatus collapseWhenMature={true} />
      </WidgetErrorBoundary>

      {/* Contextual Action Cards -- data-driven quick actions */}
      <ContextualActionCards
        anomalousIpCount={perIPSummary?.anomalous_ips || 0}
        totalProtectedIps={perIPSummary?.total_protected_ips || 0}
        detectionCount={anomalyData?.detection_count || 0}
        dropRate={dropRate}
      />

      {/* Charts and Attack Status */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Traffic Chart - 2/3 width */}
        <div className="lg:col-span-2">
          <div className="card">
            <div className="card-header flex items-center justify-between">
              <h3 className="card-title">Traffic Overview{selectedIP ? ` \u2014 ${selectedIP}` : ''}</h3>
              <span className="text-xs text-slate-500 dark:text-slate-400">
                {selectedIP ? 'Client-side history' : 'Last 60 samples'}
              </span>
            </div>
            <div className="p-4">
              <WidgetErrorBoundary>
                <TrafficChart
                  data={chartData}
                  loading={historyLoading}
                  height={400}
                  attackEvents={attackEvents}
                />
              </WidgetErrorBoundary>
            </div>
          </div>
        </div>

        {/* Attack Status - 1/3 width */}
        <div className="lg:col-span-1">
          <WidgetErrorBoundary>
            <AttackStatus
              attacks={activeAttacks}
              loading={perIPLoading}
              protectedAssetCount={perIPSummary?.total_protected_ips || 0}
            />
          </WidgetErrorBoundary>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
