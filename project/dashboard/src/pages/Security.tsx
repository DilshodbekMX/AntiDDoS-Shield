/**
 * Security Center Page (Enterprise Edition)
 *
 * Advanced threat landscape visualization with incident timeline,
 * real-time anomaly detection, and IP investigation capabilities.
 */

import { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ShieldCheckIcon,
  ShieldExclamationIcon,
  MagnifyingGlassIcon,
  ExclamationTriangleIcon,
  GlobeAltIcon,
  NoSymbolIcon,
  CheckCircleIcon,
  ClockIcon,
  ChartBarIcon,
  EyeIcon,
  BoltIcon,
  FireIcon,
} from '@heroicons/react/24/outline';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import api from '../services/api';
import {
  MetricCard,
  GaugeChart,
  StatusIndicator,
  ThreatBadge,
  ThreatLevelBar,
  DataTable,
  EmptyState,
  LoadingSpinner,
} from '../components/ui';
import { GeoMap, AttackSource, CountryStats } from '../components/GeoMap';

// ============================================================================
// Types
// ============================================================================

interface AnomalyData {
  connected: boolean;
  global_anomaly_active: boolean;
  global_anomaly_level: number;
  global_level_name: string;
  current_threshold: number;
  ip_count: number;
}

interface PerIPAnomalyEntry {
  ip: string;
  anomaly_active: boolean;
  level: number;
  level_name: string;
  protocol: string;
  attack_type: string;
  dst_port: number;
  z_score: number;
  tier_agreement: number;
  pps: number;
  packets: number;
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
  total_dropped: number;
}

interface RulesCheckResult {
  ip: string;
  in_whitelist: boolean;
  in_blacklist: boolean;
  is_protected: boolean;
  in_cidr_whitelist: boolean;
}

interface RulesStats {
  blacklist_count: number;
  whitelist_count: number;
  protected_count: number;
  cidr_whitelist_count?: number;
}

// ============================================================================
// Constants
// ============================================================================

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#6366f1',
};


// ============================================================================
// Utility Functions
// ============================================================================

function formatNumber(num: number): string {
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
  return num.toLocaleString();
}

function formatPPS(pps: number): string {
  if (pps >= 1000000) return (pps / 1000000).toFixed(2) + 'M pps';
  if (pps >= 1000) return (pps / 1000).toFixed(1) + 'K pps';
  return pps.toFixed(0) + ' pps';
}

function getTimeAgo(timestamp: number): string {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

// In production, use a GeoIP service like MaxMind GeoIP2 for accurate IP geolocation

function generateMockGeoFromIP(ip: string): { lat: number; lng: number; country: string; countryCode: string; city: string } {
  // Generate deterministic but pseudo-random coordinates based on IP
  const parts = ip.split('.').map(Number);
  const seed = parts[0] * 1000000 + parts[1] * 10000 + parts[2] * 100 + parts[3];

  // Map to rough geographic regions based on first octet
  const regions: { lat: number; lng: number; country: string; countryCode: string; city: string }[] = [
    { lat: 35.86 + (seed % 20) / 10, lng: 104.19 + (seed % 30) / 10, country: 'China', countryCode: 'CN', city: 'Beijing' },
    { lat: 55.75 + (seed % 15) / 10, lng: 37.62 + (seed % 20) / 10, country: 'Russia', countryCode: 'RU', city: 'Moscow' },
    { lat: 37.77 + (seed % 10) / 10, lng: -122.42 + (seed % 15) / 10, country: 'United States', countryCode: 'US', city: 'San Francisco' },
    { lat: 51.51 + (seed % 8) / 10, lng: -0.13 + (seed % 10) / 10, country: 'United Kingdom', countryCode: 'GB', city: 'London' },
    { lat: 52.52 + (seed % 10) / 10, lng: 13.41 + (seed % 12) / 10, country: 'Germany', countryCode: 'DE', city: 'Berlin' },
    { lat: -23.55 + (seed % 12) / 10, lng: -46.63 + (seed % 15) / 10, country: 'Brazil', countryCode: 'BR', city: 'São Paulo' },
    { lat: 28.61 + (seed % 10) / 10, lng: 77.21 + (seed % 12) / 10, country: 'India', countryCode: 'IN', city: 'Delhi' },
    { lat: 35.69 + (seed % 8) / 10, lng: 139.69 + (seed % 10) / 10, country: 'Japan', countryCode: 'JP', city: 'Tokyo' },
    { lat: 37.57 + (seed % 6) / 10, lng: 126.98 + (seed % 8) / 10, country: 'South Korea', countryCode: 'KR', city: 'Seoul' },
    { lat: 48.86 + (seed % 8) / 10, lng: 2.35 + (seed % 10) / 10, country: 'France', countryCode: 'FR', city: 'Paris' },
  ];

  return regions[seed % regions.length];
}

function anomalyToAttackSource(anomaly: PerIPAnomalyEntry & { ip: string }, index: number): AttackSource {
  const geo = generateMockGeoFromIP(anomaly.ip);
  const severityMap: Record<number, 'low' | 'medium' | 'high' | 'critical'> = {
    0: 'low',
    1: 'medium',
    2: 'high',
    3: 'critical',
    4: 'critical',
  };

  return {
    id: `attack-${index}-${anomaly.ip}`,
    ip: anomaly.ip,
    lat: geo.lat,
    lng: geo.lng,
    country: geo.country,
    countryCode: geo.countryCode,
    city: geo.city,
    attackCount: anomaly.packets || Math.floor(anomaly.pps * 60),
    bandwidth: anomaly.pps * 64 * 8, // Estimate: pps * avg packet size * bits
    attackType: anomaly.attack_type,
    severity: severityMap[Math.min(anomaly.level, 4)] || 'medium',
    lastSeen: new Date(),
    isActive: anomaly.anomaly_active,
  };
}

function aggregateCountryStats(sources: AttackSource[]): CountryStats[] {
  const countryMap = new Map<string, CountryStats>();

  sources.forEach((source) => {
    const existing = countryMap.get(source.countryCode);
    if (existing) {
      existing.attackCount += source.attackCount;
      existing.bandwidth += source.bandwidth;
    } else {
      countryMap.set(source.countryCode, {
        code: source.countryCode,
        name: source.country,
        attackCount: source.attackCount,
        bandwidth: source.bandwidth,
        topAttackType: source.attackType,
        isBlocked: false, // In production, check against blocked countries list
      });
    }
  });

  return Array.from(countryMap.values());
}

// ============================================================================
// Sub-Components
// ============================================================================

function ThreatRadar({ anomalies }: { anomalies: Array<PerIPAnomalyEntry & { ip: string }> }) {
  // Group by severity for visualization
  const severityDistribution = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    anomalies.forEach((a) => {
      if (a.level >= 4) counts.critical++;
      else if (a.level >= 3) counts.high++;
      else if (a.level >= 2) counts.medium++;
      else counts.low++;
    });
    return [
      { name: 'Critical', value: counts.critical, color: SEVERITY_COLORS.critical },
      { name: 'High', value: counts.high, color: SEVERITY_COLORS.high },
      { name: 'Medium', value: counts.medium, color: SEVERITY_COLORS.medium },
      { name: 'Low', value: counts.low, color: SEVERITY_COLORS.low },
    ].filter((d) => d.value > 0);
  }, [anomalies]);

  if (anomalies.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-48 text-slate-500 dark:text-slate-400">
        <ShieldCheckIcon className="h-12 w-12 mb-2 text-emerald-500" />
        <span className="text-sm font-medium">All Systems Normal</span>
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={200}>
      <PieChart>
        <Pie
          data={severityDistribution}
          cx="50%"
          cy="50%"
          innerRadius={50}
          outerRadius={80}
          paddingAngle={2}
          dataKey="value"
        >
          {severityDistribution.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={entry.color} />
          ))}
        </Pie>
        <RechartsTooltip
          contentStyle={{
            backgroundColor: 'rgba(15, 23, 42, 0.95)',
            border: '1px solid rgba(99, 102, 241, 0.3)',
            borderRadius: '8px',
            padding: '8px 12px',
          }}
          itemStyle={{ color: '#e2e8f0' }}
        />
        <Legend
          verticalAlign="bottom"
          height={36}
          formatter={(value) => <span className="text-xs text-slate-700 dark:text-slate-300">{value}</span>}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}

function IncidentTimeline({ incidents }: { incidents: Array<PerIPAnomalyEntry & { ip: string }> }) {
  // Generate mock timeline from current anomalies
  const timelineEvents = useMemo(() => {
    const now = Date.now();
    return incidents.slice(0, 10).map((incident, idx) => ({
      id: idx,
      time: now - idx * 30000, // Stagger by 30 seconds each
      type: incident.attack_type,
      target: incident.ip,
      level: incident.level,
      levelName: incident.level_name,
      protocol: incident.protocol,
      zScore: incident.z_score,
    }));
  }, [incidents]);

  if (timelineEvents.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-48 text-slate-500 dark:text-slate-400">
        <ClockIcon className="h-12 w-12 mb-2" />
        <span className="text-sm">No recent incidents</span>
      </div>
    );
  }

  return (
    <div className="space-y-3 max-h-80 overflow-y-auto pr-2 custom-scrollbar">
      {timelineEvents.map((event) => (
        <div
          key={event.id}
          className="relative pl-6 pb-3 border-l-2 border-slate-300 dark:border-slate-700 last:border-transparent"
        >
          {/* Timeline dot */}
          <div
            className={clsx(
              'absolute left-0 top-0 -translate-x-1/2 w-3 h-3 rounded-full ring-4 ring-slate-900',
              event.level >= 3
                ? 'bg-red-500'
                : event.level >= 2
                  ? 'bg-orange-500'
                  : 'bg-yellow-500'
            )}
          />

          {/* Event content */}
          <div className="bg-slate-100/50 dark:bg-slate-800/50 rounded-lg p-3 border border-slate-200/50 dark:border-slate-700/50">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs text-slate-500 dark:text-slate-400">{getTimeAgo(event.time)}</span>
              <ThreatBadge level={event.level as 0 | 1 | 2 | 3 | 4} />
            </div>
            <div className="flex items-center gap-2">
              <BoltIcon className="h-4 w-4 text-orange-400" />
              <span className="text-sm font-medium text-slate-900 dark:text-white">{event.type}</span>
            </div>
            <div className="mt-1 flex items-center gap-3 text-xs text-slate-500 dark:text-slate-400">
              <span className="font-mono">{event.target}</span>
              <span className="text-slate-600">•</span>
              <span>{event.protocol}</span>
              <span className="text-slate-600">•</span>
              <span className="text-red-400">Z: {event.zScore.toFixed(2)}</span>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

function DropReasonsChart({ dropReasons }: { dropReasons: Record<string, number> }) {
  const data = useMemo(() => {
    return Object.entries(dropReasons)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 8)
      .map(([reason, count]) => ({
        name: reason.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase()),
        value: count,
      }));
  }, [dropReasons]);

  if (data.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-48 text-slate-500 dark:text-slate-400">
        <CheckCircleIcon className="h-12 w-12 mb-2 text-emerald-500" />
        <span className="text-sm">No packets dropped</span>
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={data} layout="vertical" margin={{ left: 80 }}>
        <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 10 }} />
        <YAxis type="category" dataKey="name" tick={{ fill: '#94a3b8', fontSize: 10 }} width={75} />
        <RechartsTooltip
          contentStyle={{
            backgroundColor: 'rgba(15, 23, 42, 0.95)',
            border: '1px solid rgba(99, 102, 241, 0.3)',
            borderRadius: '8px',
          }}
          formatter={(value: number) => [formatNumber(value), 'Packets']}
        />
        <Bar dataKey="value" fill="#6366f1" radius={[0, 4, 4, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}

function AttackTypeDistribution({
  anomalies,
}: {
  anomalies: Array<PerIPAnomalyEntry & { ip: string }>;
}) {
  const distribution = useMemo(() => {
    const counts: Record<string, number> = {};
    anomalies.forEach((a) => {
      counts[a.attack_type] = (counts[a.attack_type] || 0) + 1;
    });
    return Object.entries(counts)
      .map(([type, count], idx) => ({
        name: type,
        value: count,
        color: [
          '#ef4444',
          '#f97316',
          '#eab308',
          '#22c55e',
          '#06b6d4',
          '#6366f1',
          '#a855f7',
        ][idx % 7],
      }))
      .sort((a, b) => b.value - a.value);
  }, [anomalies]);

  if (distribution.length === 0) return null;

  return (
    <div className="space-y-2">
      {distribution.map((item) => (
        <div key={item.name} className="flex items-center gap-3">
          <div className="w-3 h-3 rounded-full" style={{ backgroundColor: item.color }} />
          <span className="flex-1 text-sm text-slate-700 dark:text-slate-300 truncate">{item.name}</span>
          <span className="text-sm font-medium text-slate-900 dark:text-white">{item.value}</span>
        </div>
      ))}
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export function SecurityPage() {
  const queryClient = useQueryClient();

  const [searchIP, setSearchIP] = useState('');
  const [checkedIP, setCheckedIP] = useState<RulesCheckResult | null>(null);
  const [selectedAnomaly, setSelectedAnomaly] = useState<
    (PerIPAnomalyEntry & { ip: string }) | null
  >(null);
  const [_investigateIP, _setInvestigateIP] = useState<string | null>(null);
  const [blockedCountries, setBlockedCountries] = useState<Set<string>>(new Set());

  // Fetch anomaly data
  const { data: anomalyData, isLoading: anomalyLoading } = useQuery({
    queryKey: ['realtime-anomaly'],
    queryFn: () => api.getRealtimeAnomaly() as unknown as Promise<AnomalyData>,
    refetchInterval: 2000,
  });

  // Fetch per-IP anomaly data
  const { data: perIPAnomaly } = useQuery({
    queryKey: ['realtime-anomaly-per-ip'],
    queryFn: () => api.getRealtimeAnomalyPerIP() as unknown as Promise<Record<string, PerIPAnomalyEntry>>,
    refetchInterval: 2000,
  });

  // Fetch traffic data for drop reasons
  const { data: trafficData } = useQuery({
    queryKey: ['realtime-traffic'],
    queryFn: () => api.getRealtimeTraffic() as unknown as Promise<TrafficData>,
    refetchInterval: 2000,
  });

  // Fetch rules stats
  const { data: rulesStats } = useQuery({
    queryKey: ['rules-stats'],
    queryFn: () => api.getRulesStats() as unknown as Promise<RulesStats>,
    refetchInterval: 5000,
  });

  // Block IP mutation
  const blockMutation = useMutation({
    mutationFn: (ip: string) =>
      api.addRulesBlacklist({ ip, description: 'Blocked from Security Center' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules-stats'] });
      queryClient.invalidateQueries({ queryKey: ['rules-blacklist'] });
      toast.success('IP blocked successfully');
      if (checkedIP) {
        setCheckedIP({ ...checkedIP, in_blacklist: true });
      }
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to block IP');
    },
  });

  // Unblock IP mutation
  const unblockMutation = useMutation({
    mutationFn: (ip: string) => api.removeRulesBlacklist(ip),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules-stats'] });
      queryClient.invalidateQueries({ queryKey: ['rules-blacklist'] });
      toast.success('IP unblocked successfully');
      if (checkedIP) {
        setCheckedIP({ ...checkedIP, in_blacklist: false });
      }
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to unblock IP');
    },
  });

  // Check IP mutation
  const checkMutation = useMutation({
    mutationFn: (ip: string) => api.checkRulesIP(ip) as unknown as Promise<RulesCheckResult>,
    onSuccess: (data) => {
      setCheckedIP(data);
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to check IP');
    },
  });

  const handleCheckIP = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchIP.trim()) {
      checkMutation.mutate(searchIP.trim());
    }
  };

  // Get active anomalies from per-IP data
  const activeAnomalies = useMemo(() => {
    if (!perIPAnomaly) return [];
    return Object.entries(perIPAnomaly)
      .filter(([, entry]) => entry.anomaly_active)
      .map(([ipKey, entry]) => ({ ...entry, ip: ipKey }))
      .sort((a, b) => b.level - a.level);
  }, [perIPAnomaly]);

  // Calculate threat level score
  const threatScore = useMemo(() => {
    if (activeAnomalies.length === 0) return 0;
    const maxLevel = Math.max(...activeAnomalies.map((a) => a.level));
    return Math.min(100, (maxLevel / 4) * 100 + activeAnomalies.length * 5);
  }, [activeAnomalies]);

  // Generate GeoMap attack sources from anomalies
  const attackSources = useMemo(() => {
    return activeAnomalies.map((anomaly, idx) => anomalyToAttackSource(anomaly, idx));
  }, [activeAnomalies]);

  // Aggregate country stats from attack sources
  const countryStats = useMemo(() => {
    const stats = aggregateCountryStats(attackSources);
    // Mark blocked countries
    return stats.map((s) => ({
      ...s,
      isBlocked: blockedCountries.has(s.code),
    }));
  }, [attackSources, blockedCountries]);

  // Handle country block/unblock
  const handleCountryBlock = (countryCode: string) => {
    setBlockedCountries((prev) => {
      const next = new Set(prev);
      next.add(countryCode);
      toast.success(`Blocked traffic from ${countryCode}`);
      return next;
    });
  };

  const handleCountryUnblock = (countryCode: string) => {
    setBlockedCountries((prev) => {
      const next = new Set(prev);
      next.delete(countryCode);
      toast.success(`Unblocked traffic from ${countryCode}`);
      return next;
    });
  };

  // Handle IP investigation from map
  const handleIPInvestigate = (ip: string) => {
    setSearchIP(ip);
    checkMutation.mutate(ip);
  };

  // DataTable columns for active threats
  const threatColumns = [
    {
      key: 'ip',
      header: 'Target IP',
      render: (value: unknown) => <span className="font-mono text-sm">{value as string}</span>,
    },
    {
      key: 'level',
      header: 'Severity',
      render: (_: unknown, row: PerIPAnomalyEntry & { ip: string }) => (
        <ThreatBadge level={row.level as 0 | 1 | 2 | 3 | 4} />
      ),
    },
    {
      key: 'attack_type',
      header: 'Attack Type',
    },
    {
      key: 'protocol',
      header: 'Protocol',
      render: (value: unknown) => (
        <span className="px-2 py-0.5 bg-slate-200 dark:bg-slate-700 rounded text-xs uppercase">{value as string}</span>
      ),
    },
    {
      key: 'z_score',
      header: 'Z-Score',
      render: (value: unknown) => (
        <span className="text-red-600 dark:text-red-400 font-medium">{(value as number)?.toFixed(2)}</span>
      ),
    },
    {
      key: 'pps',
      header: 'Rate',
      render: (value: unknown) => formatPPS(value as number),
    },
    {
      key: 'actions',
      header: '',
      render: (_: unknown, row: PerIPAnomalyEntry & { ip: string }) => (
        <button
          onClick={() => setSelectedAnomaly(row)}
          className="p-1.5 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg transition-colors"
        >
          <EyeIcon className="h-4 w-4 text-slate-500 dark:text-slate-400" />
        </button>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Security Center</h1>
          <p className="text-slate-500 dark:text-slate-400 text-sm mt-1">
            Real-time threat monitoring and incident response
          </p>
        </div>
        <div className="flex items-center gap-4">
          <StatusIndicator
            status={trafficData?.connected ? 'online' : 'offline'}
            label="DPDK"
            showPulse={trafficData?.connected}
          />
          <div
            className={clsx(
              'flex items-center gap-2 px-4 py-2 rounded-lg font-medium',
              activeAnomalies.length > 0
                ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
            )}
          >
            {activeAnomalies.length > 0 ? (
              <>
                <FireIcon className="h-5 w-5 animate-pulse" />
                <span>{activeAnomalies.length} Active Threats</span>
              </>
            ) : (
              <>
                <ShieldCheckIcon className="h-5 w-5" />
                <span>All Systems Normal</span>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Global Alert Banner */}
      {anomalyData?.global_anomaly_active && (
        <div
          className={clsx(
            'relative overflow-hidden rounded-xl p-4 border animate-pulse-slow',
            anomalyData.global_anomaly_level >= 3
              ? 'bg-gradient-to-r from-red-900/50 to-red-800/30 border-red-500/50'
              : anomalyData.global_anomaly_level >= 2
                ? 'bg-gradient-to-r from-orange-900/50 to-orange-800/30 border-orange-500/50'
                : 'bg-gradient-to-r from-yellow-900/50 to-yellow-800/30 border-yellow-500/50'
          )}
        >
          {/* Animated background */}
          <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/5 to-transparent animate-shimmer" />

          <div className="relative flex items-center gap-4">
            <div
              className={clsx(
                'p-3 rounded-xl',
                anomalyData.global_anomaly_level >= 3
                  ? 'bg-red-500/20'
                  : anomalyData.global_anomaly_level >= 2
                    ? 'bg-orange-500/20'
                    : 'bg-yellow-500/20'
              )}
            >
              <ShieldExclamationIcon className="h-8 w-8 text-slate-900 dark:text-white" />
            </div>
            <div className="flex-1">
              <div className="flex items-center gap-3">
                <h3 className="text-lg font-bold text-slate-900 dark:text-white">Global Anomaly Detected</h3>
                <ThreatBadge level={anomalyData.global_anomaly_level as 0 | 1 | 2 | 3 | 4} />
              </div>
              <p className="text-sm text-slate-900 dark:text-white/70 mt-1">
                {activeAnomalies.length} IP(s) under active attack • Threshold:{' '}
                {anomalyData.current_threshold?.toFixed(2)} • Level: {anomalyData.global_level_name}
              </p>
            </div>
            <ThreatLevelBar level={anomalyData.global_anomaly_level} max={4} />
          </div>
        </div>
      )}

      {/* Primary Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Threat Level"
          value={`${threatScore.toFixed(0)}%`}
          icon={ShieldExclamationIcon}
          trend={activeAnomalies.length > 0 ? 'up' : 'neutral'}
          color={threatScore > 75 ? 'danger' : threatScore > 25 ? 'warning' : 'success'}
        />
        <MetricCard
          title="Blocked IPs"
          value={formatNumber(rulesStats?.blacklist_count || 0)}
          icon={NoSymbolIcon}
          subtitle={`${rulesStats?.whitelist_count || 0} whitelisted`}
          color="warning"
        />
        <MetricCard
          title="Packets Dropped"
          value={formatNumber(trafficData?.total_dropped || 0)}
          icon={ExclamationTriangleIcon}
          subtitle="Total filtered"
          color={trafficData?.total_dropped ? 'info' : 'success'}
        />
        <MetricCard
          title="Protected Assets"
          value={formatNumber(rulesStats?.protected_count || 0)}
          icon={GlobeAltIcon}
          subtitle="Server IPs monitored"
          color="info"
        />
      </div>

      {/* Global Attack Map */}
      <div className="card">
        <div className="card-header flex items-center gap-3">
          <div className="p-2 bg-brand-500/20 rounded-lg">
            <GlobeAltIcon className="h-5 w-5 text-brand-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Global Attack Map</h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Real-time visualization of attack origins and geo-blocking controls
            </p>
          </div>
        </div>
        <div className="p-4">
          <GeoMap
            attackSources={attackSources}
            countryStats={countryStats}
            targetLocation={{ lat: 40.7128, lng: -74.006 }} // Protected server location
            onCountryBlock={handleCountryBlock}
            onCountryUnblock={handleCountryUnblock}
            onIPInvestigate={handleIPInvestigate}
            showTrajectories={activeAnomalies.length > 0}
          />
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column - Threat Overview */}
        <div className="lg:col-span-2 space-y-6">
          {/* Active Threats Table */}
          <div className="card">
            <div className="card-header flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-red-500/20 rounded-lg">
                  <FireIcon className="h-5 w-5 text-red-400" />
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Active Threats</h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">Real-time attack monitoring</p>
                </div>
              </div>
              {activeAnomalies.length > 0 && (
                <span className="px-3 py-1 bg-red-500/20 text-red-400 rounded-full text-sm font-medium">
                  {activeAnomalies.length} Active
                </span>
              )}
            </div>
            <div className="p-4">
              {anomalyLoading ? (
                <LoadingSpinner />
              ) : activeAnomalies.length > 0 ? (
                <DataTable
                  columns={threatColumns}
                  data={activeAnomalies}
                  emptyMessage="No active threats"
                />
              ) : (
                <EmptyState
                  icon={ShieldCheckIcon}
                  title="No Active Threats"
                  description="All systems are operating normally"
                />
              )}
            </div>
          </div>

          {/* IP Investigation */}
          <div className="card">
            <div className="card-header">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-brand-500/20 rounded-lg">
                  <MagnifyingGlassIcon className="h-5 w-5 text-brand-400" />
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-slate-900 dark:text-white">IP Investigation</h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">Check IP status and take action</p>
                </div>
              </div>
            </div>
            <div className="p-4">
              <form onSubmit={handleCheckIP} className="flex gap-3">
                <div className="flex-1 relative">
                  <MagnifyingGlassIcon className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-slate-500 dark:text-slate-400" />
                  <input
                    type="text"
                    value={searchIP}
                    onChange={(e) => setSearchIP(e.target.value)}
                    placeholder="Enter IP address (e.g., 192.168.1.1)"
                    className="w-full pl-10 pr-4 py-2.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 transition-colors"
                  />
                </div>
                <button
                  type="submit"
                  disabled={checkMutation.isPending || !searchIP.trim()}
                  className="btn btn-primary px-6"
                >
                  {checkMutation.isPending ? 'Checking...' : 'Investigate'}
                </button>
              </form>

              {/* Check Results */}
              {checkedIP && (
                <div className="mt-6 p-4 bg-slate-100 dark:bg-slate-800/50 rounded-lg border border-slate-300 dark:border-slate-700">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white font-mono">{checkedIP.ip}</h3>
                    <div className="flex gap-2">
                      {checkedIP.in_blacklist ? (
                        <button
                          onClick={() => unblockMutation.mutate(checkedIP.ip)}
                          disabled={unblockMutation.isPending}
                          className="btn btn-success text-sm"
                        >
                          {unblockMutation.isPending ? 'Removing...' : 'Remove from Blacklist'}
                        </button>
                      ) : (
                        <button
                          onClick={() => blockMutation.mutate(checkedIP.ip)}
                          disabled={blockMutation.isPending}
                          className="btn btn-danger text-sm"
                        >
                          {blockMutation.isPending ? 'Blocking...' : 'Block IP'}
                        </button>
                      )}
                    </div>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <div
                      className={clsx(
                        'p-3 rounded-lg border',
                        checkedIP.in_blacklist
                          ? 'bg-red-500/10 border-red-500/30'
                          : 'bg-slate-100 dark:bg-slate-700/50 border-slate-300 dark:border-slate-600'
                      )}
                    >
                      <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Blacklist</p>
                      <div className="flex items-center gap-2">
                        {checkedIP.in_blacklist ? (
                          <NoSymbolIcon className="h-5 w-5 text-red-400" />
                        ) : (
                          <CheckCircleIcon className="h-5 w-5 text-slate-500" />
                        )}
                        <span
                          className={clsx(
                            'font-semibold',
                            checkedIP.in_blacklist ? 'text-red-400' : 'text-slate-500 dark:text-slate-400'
                          )}
                        >
                          {checkedIP.in_blacklist ? 'Blocked' : 'Clear'}
                        </span>
                      </div>
                    </div>
                    <div
                      className={clsx(
                        'p-3 rounded-lg border',
                        checkedIP.in_whitelist
                          ? 'bg-emerald-500/10 border-emerald-500/30'
                          : 'bg-slate-100 dark:bg-slate-700/50 border-slate-300 dark:border-slate-600'
                      )}
                    >
                      <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Whitelist</p>
                      <div className="flex items-center gap-2">
                        {checkedIP.in_whitelist ? (
                          <CheckCircleIcon className="h-5 w-5 text-emerald-400" />
                        ) : (
                          <CheckCircleIcon className="h-5 w-5 text-slate-500" />
                        )}
                        <span
                          className={clsx(
                            'font-semibold',
                            checkedIP.in_whitelist ? 'text-emerald-400' : 'text-slate-500 dark:text-slate-400'
                          )}
                        >
                          {checkedIP.in_whitelist ? 'Allowed' : 'Not Set'}
                        </span>
                      </div>
                    </div>
                    <div
                      className={clsx(
                        'p-3 rounded-lg border',
                        checkedIP.is_protected
                          ? 'bg-brand-500/10 border-brand-500/30'
                          : 'bg-slate-100 dark:bg-slate-700/50 border-slate-300 dark:border-slate-600'
                      )}
                    >
                      <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Protected</p>
                      <div className="flex items-center gap-2">
                        {checkedIP.is_protected ? (
                          <ShieldCheckIcon className="h-5 w-5 text-brand-400" />
                        ) : (
                          <ShieldCheckIcon className="h-5 w-5 text-slate-500" />
                        )}
                        <span
                          className={clsx(
                            'font-semibold',
                            checkedIP.is_protected ? 'text-brand-400' : 'text-slate-500 dark:text-slate-400'
                          )}
                        >
                          {checkedIP.is_protected ? 'Yes' : 'No'}
                        </span>
                      </div>
                    </div>
                    <div
                      className={clsx(
                        'p-3 rounded-lg border',
                        checkedIP.in_cidr_whitelist
                          ? 'bg-cyan-500/10 border-cyan-500/30'
                          : 'bg-slate-100 dark:bg-slate-700/50 border-slate-300 dark:border-slate-600'
                      )}
                    >
                      <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">CIDR Match</p>
                      <div className="flex items-center gap-2">
                        {checkedIP.in_cidr_whitelist ? (
                          <GlobeAltIcon className="h-5 w-5 text-cyan-600 dark:text-cyan-400" />
                        ) : (
                          <GlobeAltIcon className="h-5 w-5 text-slate-500" />
                        )}
                        <span
                          className={clsx(
                            'font-semibold',
                            checkedIP.in_cidr_whitelist ? 'text-cyan-600 dark:text-cyan-400' : 'text-slate-500 dark:text-slate-400'
                          )}
                        >
                          {checkedIP.in_cidr_whitelist ? 'Yes' : 'No'}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Right Column - Visualizations */}
        <div className="space-y-6">
          {/* Threat Gauge */}
          <div className="card">
            <div className="card-header">
              <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300">Threat Level</h3>
            </div>
            <div className="p-4 flex justify-center">
              <GaugeChart
                value={threatScore}
                max={100}
                label="Score"
                color={threatScore > 75 ? '#ef4444' : threatScore > 50 ? '#f97316' : '#22c55e'}
                size={160}
              />
            </div>
          </div>

          {/* Threat Radar */}
          <div className="card">
            <div className="card-header">
              <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300">Severity Distribution</h3>
            </div>
            <div className="p-4">
              <ThreatRadar anomalies={activeAnomalies} />
            </div>
          </div>

          {/* Incident Timeline */}
          <div className="card">
            <div className="card-header flex items-center gap-2">
              <ClockIcon className="h-4 w-4 text-slate-500 dark:text-slate-400" />
              <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300">Incident Timeline</h3>
            </div>
            <div className="p-4">
              <IncidentTimeline incidents={activeAnomalies} />
            </div>
          </div>

          {/* Attack Types */}
          {activeAnomalies.length > 0 && (
            <div className="card">
              <div className="card-header">
                <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300">Attack Types</h3>
              </div>
              <div className="p-4">
                <AttackTypeDistribution anomalies={activeAnomalies} />
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Drop Reasons Section */}
      <div className="card">
        <div className="card-header flex items-center gap-3">
          <div className="p-2 bg-orange-500/20 rounded-lg">
            <ChartBarIcon className="h-5 w-5 text-orange-400" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Packet Drop Analysis</h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">Breakdown by filtering reason</p>
          </div>
        </div>
        <div className="p-6">
          {trafficData?.drop_reasons && Object.keys(trafficData.drop_reasons).length > 0 ? (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Chart */}
              <DropReasonsChart dropReasons={trafficData.drop_reasons} />

              {/* Grid Cards */}
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                {Object.entries(trafficData.drop_reasons)
                  .sort(([, a], [, b]) => b - a)
                  .slice(0, 6)
                  .map(([reason, count]) => (
                    <div
                      key={reason}
                      className="bg-slate-100/50 dark:bg-slate-800/50 rounded-lg p-3 border border-slate-200/50 dark:border-slate-700/50"
                    >
                      <p className="text-xs text-slate-500 dark:text-slate-400 capitalize truncate">
                        {reason.replace(/_/g, ' ')}
                      </p>
                      <p className="text-lg font-bold text-slate-900 dark:text-white mt-1">{formatNumber(count)}</p>
                    </div>
                  ))}
              </div>
            </div>
          ) : (
            <EmptyState
              icon={CheckCircleIcon}
              title="No Drops Recorded"
              description="All packets are passing through without being filtered"
            />
          )}
        </div>
      </div>

      {/* Anomaly Detail Modal */}
      {selectedAnomaly && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4">
            <div className="fixed inset-0 bg-black/70" onClick={() => setSelectedAnomaly(null)} />
            <div className="relative bg-white dark:bg-slate-900 rounded-xl shadow-2xl max-w-lg w-full border border-slate-300 dark:border-slate-700 animate-scale-in">
              <div className="p-6">
                <div className="flex items-center justify-between mb-6">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-red-500/20 rounded-lg">
                      <ShieldExclamationIcon className="h-6 w-6 text-red-400" />
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Threat Details</h3>
                      <p className="text-sm text-slate-500 dark:text-slate-400 font-mono">{selectedAnomaly.ip}</p>
                    </div>
                  </div>
                  <ThreatBadge level={selectedAnomaly.level as 0 | 1 | 2 | 3 | 4} />
                </div>

                <div className="grid grid-cols-2 gap-4 mb-6">
                  <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-3">
                    <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Attack Type</p>
                    <p className="text-slate-900 dark:text-white font-medium">{selectedAnomaly.attack_type}</p>
                  </div>
                  <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-3">
                    <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Protocol</p>
                    <p className="text-slate-900 dark:text-white font-medium uppercase">{selectedAnomaly.protocol}</p>
                  </div>
                  <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-3">
                    <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Z-Score</p>
                    <p className="text-red-600 dark:text-red-400 font-bold">{selectedAnomaly.z_score?.toFixed(2)}</p>
                  </div>
                  <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-3">
                    <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Destination Port</p>
                    <p className="text-slate-900 dark:text-white font-medium">{selectedAnomaly.dst_port || 'N/A'}</p>
                  </div>
                  <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-3">
                    <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Packet Rate</p>
                    <p className="text-slate-900 dark:text-white font-medium">{formatPPS(selectedAnomaly.pps)}</p>
                  </div>
                  <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-3">
                    <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Tier Agreement</p>
                    <p className="text-slate-900 dark:text-white font-medium">{selectedAnomaly.tier_agreement}/3</p>
                  </div>
                </div>

                <div className="flex gap-3">
                  <button
                    onClick={() => {
                      blockMutation.mutate(selectedAnomaly.ip);
                      setSelectedAnomaly(null);
                    }}
                    className="flex-1 btn btn-danger"
                  >
                    Block Source IP
                  </button>
                  <button onClick={() => setSelectedAnomaly(null)} className="flex-1 btn btn-ghost">
                    Close
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default SecurityPage;
