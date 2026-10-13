/**
 * Unified Threat Center (Consolidated Dashboard)
 *
 * Combines Security and Attacks pages into a single comprehensive
 * threat management interface with tabbed navigation.
 */

import { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
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
  SparklesIcon,
  XMarkIcon,
  PlusIcon,
  CpuChipIcon,
  ArrowPathIcon,
  BeakerIcon,
} from '@heroicons/react/24/outline';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  XAxis,
  YAxis,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import api from '../services/api';
import { useTenantStore } from '../store';
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
  timestamp: number;
  timestamp_str: string;
  active: boolean;
  level: number;
  level_name: string;
  tier_agreement: number;
  max_z_score: number;
  confidence: number;
  primary_feature: number;
  primary_feature_name: string;
  duration_sec: number;
  cool_down_remaining: number;
  baselines_frozen: boolean;
  tier1_ready: boolean;
  tier2_ready_count: number;
  tier3_ready_count: number;
  baseline_updates: number;
  detection_cycles: number;
  detection_count: number;
  packets_per_sec: number;
  bytes_per_sec: number;
  syn_per_sec: number;
  unique_src_ips: number;
  unique_flows: number;
  heavy_hitters: number;
  rate_limit_pct: number;
}

interface PerIPAnomalyEntry {
  dst_ip: number;
  dst_ip_str: string;
  anomaly_active: boolean;
  level: number;
  level_name: string;
  max_z_score: number;
  tier_agreement: number;
  anomalous_feature_count: number;
  start_time_ns: number;
  last_update_ns: number;
  anomaly_protocol: number;
  anomaly_protocol_name: string;
  attack_type: number;
  attack_type_name: string;
  anomaly_dst_port: number;
  // Traffic stats from per-IP features
  packets_per_sec: number;
  bytes_per_sec: number;
  unique_src_ips: number;
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
}

interface Layer3Summary {
  status: string;
  total_attackers: number;
  total_signatures: number;
  packet_ring_fill: number;
  attack_targets: Array<{
    ip: string;
    level: number;
    level_name: string;
    protocol: string;
    attack_type: string;
    dst_port: number;
    z_score: number;
    tier_agreement: number;
  }>;
}

interface SignatureEntry {
  id: number;
  name: string;
  protocol: string;
  pattern: string;
  enabled: boolean;
  hits: number;
  created: string;
}

interface AttackerEntry {
  src_ip: string;
  packets: number;
  bytes: number;
  first_seen: string;
  last_seen: string;
  score: number;
}

// ============================================================================
// Constants
// ============================================================================

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
};

const ATTACK_TYPE_COLORS = [
  '#6366f1', '#8b5cf6', '#a855f7', '#d946ef', '#ec4899', '#f43f5e', '#ef4444',
];

type TabType = 'overview' | 'threats' | 'analysis' | 'signatures' | 'investigate';

// ============================================================================
// Utility Functions
// ============================================================================

function formatNumber(num: number | undefined | null): string {
  if (num === undefined || num === null) return '0';
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
  return num.toLocaleString();
}

function formatBytes(bytes: number | undefined | null): string {
  if (bytes === undefined || bytes === null || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}


function formatTimeAgo(dateString: string): string {
  if (!dateString) return 'N/A';
  const date = new Date(dateString);
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function getTimeAgo(timestamp: number): string {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function isPrivateIP(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return false;
  // RFC 1918 private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  // Loopback 127.x.x.x
  if (parts[0] === 127) return true;
  return false;
}

function generateMockGeoFromIP(ip: string): { lat: number; lng: number; country: string; countryCode: string; city: string; isPrivate: boolean } {
  // For private IPs, return a special "datacenter" location marker
  if (isPrivateIP(ip)) {
    return {
      lat: 0,
      lng: 0,
      country: 'Private Network',
      countryCode: 'PRIV',
      city: 'Internal',
      isPrivate: true,
    };
  }

  const parts = ip.split('.').map(Number);
  const seed = parts[0] * 1000000 + parts[1] * 10000 + parts[2] * 100 + parts[3];
  const regions = [
    { lat: 35.86 + (seed % 20) / 10, lng: 104.19 + (seed % 30) / 10, country: 'China', countryCode: 'CN', city: 'Beijing' },
    { lat: 55.75 + (seed % 15) / 10, lng: 37.62 + (seed % 20) / 10, country: 'Russia', countryCode: 'RU', city: 'Moscow' },
    { lat: 37.77 + (seed % 10) / 10, lng: -122.42 + (seed % 15) / 10, country: 'United States', countryCode: 'US', city: 'San Francisco' },
    { lat: 51.51 + (seed % 8) / 10, lng: -0.13 + (seed % 10) / 10, country: 'United Kingdom', countryCode: 'GB', city: 'London' },
    { lat: 52.52 + (seed % 10) / 10, lng: 13.41 + (seed % 12) / 10, country: 'Germany', countryCode: 'DE', city: 'Berlin' },
    { lat: -23.55 + (seed % 12) / 10, lng: -46.63 + (seed % 15) / 10, country: 'Brazil', countryCode: 'BR', city: 'São Paulo' },
    { lat: 28.61 + (seed % 10) / 10, lng: 77.21 + (seed % 12) / 10, country: 'India', countryCode: 'IN', city: 'Delhi' },
    { lat: 35.69 + (seed % 8) / 10, lng: 139.69 + (seed % 10) / 10, country: 'Japan', countryCode: 'JP', city: 'Tokyo' },
  ];
  return { ...regions[seed % regions.length], isPrivate: false };
}

function anomalyToAttackSource(anomaly: PerIPAnomalyEntry & { ip: string }, index: number): AttackSource {
  const geo = generateMockGeoFromIP(anomaly.ip);
  const severityMap: Record<number, 'low' | 'medium' | 'high' | 'critical'> = {
    0: 'low', 1: 'medium', 2: 'high', 3: 'critical', 4: 'critical',
  };
  const pps = anomaly.packets_per_sec || 0;
  return {
    id: `attack-${index}-${anomaly.ip}`,
    ip: anomaly.ip,
    lat: geo.lat,
    lng: geo.lng,
    country: geo.country,
    countryCode: geo.countryCode,
    city: geo.city,
    attackCount: Math.floor(pps * 60),  // Estimate packets in last minute
    bandwidth: pps * 64 * 8,  // Estimate bandwidth (64 byte avg packet)
    attackType: anomaly.attack_type_name,
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
        isBlocked: false,
      });
    }
  });
  return Array.from(countryMap.values());
}

// ============================================================================
// Sub-Components
// ============================================================================

function ThreatRadar({ anomalies }: { anomalies: Array<PerIPAnomalyEntry & { ip: string }> }) {
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
        <Pie data={severityDistribution} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={2} dataKey="value">
          {severityDistribution.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={entry.color} />
          ))}
        </Pie>
        <RechartsTooltip contentStyle={{ backgroundColor: 'rgba(15, 23, 42, 0.95)', border: '1px solid rgba(99, 102, 241, 0.3)', borderRadius: '8px' }} />
        <Legend verticalAlign="bottom" height={36} formatter={(value) => <span className="text-xs text-slate-700 dark:text-slate-300">{value}</span>} />
      </PieChart>
    </ResponsiveContainer>
  );
}

function IncidentTimeline({ incidents }: { incidents: Array<PerIPAnomalyEntry & { ip: string }> }) {
  const timelineEvents = useMemo(() => {
    const now = Date.now();
    return incidents.slice(0, 8).map((incident, idx) => ({
      id: idx,
      time: now - idx * 30000,
      type: incident.attack_type_name,
      target: incident.ip,
      level: incident.level,
      protocol: incident.anomaly_protocol_name,
      zScore: incident.max_z_score,
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
    <div className="space-y-3 max-h-72 overflow-y-auto pr-2">
      {timelineEvents.map((event) => (
        <div key={event.id} className="relative pl-6 pb-3 border-l-2 border-slate-300 dark:border-slate-700 last:border-transparent">
          <div className={clsx('absolute left-0 top-0 -translate-x-1/2 w-3 h-3 rounded-full ring-4 ring-slate-900',
            event.level >= 3 ? 'bg-red-500' : event.level >= 2 ? 'bg-orange-500' : 'bg-yellow-500'
          )} />
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
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

function MLConfidenceChart({ attacks }: { attacks: Layer3Summary['attack_targets'] }) {
  const radarData = useMemo(() => {
    const avgZScore = attacks.length > 0 ? attacks.reduce((s, a) => s + a.z_score, 0) / attacks.length : 0;
    const avgTier = attacks.length > 0 ? attacks.reduce((s, a) => s + a.tier_agreement, 0) / attacks.length : 0;
    const maxLevel = attacks.length > 0 ? Math.max(...attacks.map((a) => a.level)) : 0;
    const protocolDiversity = new Set(attacks.map((a) => a.protocol)).size;
    return [
      { metric: 'Z-Score', value: Math.min(100, avgZScore * 10), fullMark: 100 },
      { metric: 'Tier Agreement', value: (avgTier / 3) * 100, fullMark: 100 },
      { metric: 'Severity', value: (maxLevel / 4) * 100, fullMark: 100 },
      { metric: 'Attack Count', value: Math.min(100, attacks.length * 10), fullMark: 100 },
      { metric: 'Protocol Mix', value: protocolDiversity * 25, fullMark: 100 },
    ];
  }, [attacks]);

  if (attacks.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-slate-500 dark:text-slate-400">
        <BeakerIcon className="h-12 w-12 mb-2" />
        <span className="text-sm">No attack data for analysis</span>
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={280}>
      <RadarChart data={radarData}>
        <PolarGrid stroke="#334155" />
        <PolarAngleAxis dataKey="metric" tick={{ fill: '#94a3b8', fontSize: 11 }} />
        <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fill: '#94a3b8', fontSize: 10 }} />
        <Radar name="Confidence" dataKey="value" stroke="#6366f1" fill="#6366f1" fillOpacity={0.3} />
      </RadarChart>
    </ResponsiveContainer>
  );
}

function AttackTypeBreakdown({ attacks }: { attacks: Layer3Summary['attack_targets'] }) {
  const breakdown = useMemo(() => {
    const counts: Record<string, number> = {};
    attacks.forEach((a) => { counts[a.attack_type] = (counts[a.attack_type] || 0) + 1; });
    return Object.entries(counts)
      .map(([type, count], idx) => ({ name: type, value: count, color: ATTACK_TYPE_COLORS[idx % ATTACK_TYPE_COLORS.length] }))
      .sort((a, b) => b.value - a.value);
  }, [attacks]);

  if (breakdown.length === 0) return null;

  return (
    <ResponsiveContainer width="100%" height={200}>
      <PieChart>
        <Pie data={breakdown} cx="50%" cy="50%" innerRadius={40} outerRadius={70} paddingAngle={2} dataKey="value">
          {breakdown.map((entry, index) => <Cell key={`cell-${index}`} fill={entry.color} />)}
        </Pie>
        <RechartsTooltip contentStyle={{ backgroundColor: 'rgba(15, 23, 42, 0.95)', border: '1px solid rgba(99, 102, 241, 0.3)', borderRadius: '8px' }} />
        <Legend verticalAlign="bottom" height={36} formatter={(value) => <span className="text-xs text-slate-700 dark:text-slate-300">{value}</span>} />
      </PieChart>
    </ResponsiveContainer>
  );
}

function TierAgreementVisualization({ tierAgreement }: { tierAgreement: number }) {
  return (
    <div className="flex items-center gap-1">
      {[1, 2, 3].map((tier) => (
        <div key={tier} className={clsx('w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold transition-all',
          tier <= tierAgreement ? 'bg-emerald-500 text-white shadow-lg shadow-emerald-500/30' : 'bg-slate-200 dark:bg-slate-700 text-slate-500'
        )}>{tier}</div>
      ))}
    </div>
  );
}

function AttackerScoreBar({ score }: { score: number }) {
  const percentage = score * 100;
  const color = percentage > 70 ? 'bg-red-500' : percentage > 40 ? 'bg-orange-500' : 'bg-yellow-500';
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
        <div className={clsx('h-full rounded-full transition-all', color)} style={{ width: `${percentage}%` }} />
      </div>
      <span className={clsx('text-xs font-bold', percentage > 70 ? 'text-red-600 dark:text-red-400' : percentage > 40 ? 'text-orange-600 dark:text-orange-400' : 'text-yellow-600 dark:text-yellow-400')}>
        {percentage.toFixed(0)}%
      </span>
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
        <RechartsTooltip contentStyle={{ backgroundColor: 'rgba(15, 23, 42, 0.95)', border: '1px solid rgba(99, 102, 241, 0.3)', borderRadius: '8px' }} formatter={(value: number) => [formatNumber(value), 'Packets']} />
        <Bar dataKey="value" fill="#6366f1" radius={[0, 4, 4, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export function ThreatCenter() {
  const queryClient = useQueryClient();
  const { currentTenant } = useTenantStore();
  const tenantId = currentTenant?.id || null;  // null = global/all tenants

  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [searchIP, setSearchIP] = useState('');
  const [checkedIP, setCheckedIP] = useState<RulesCheckResult | null>(null);
  const [selectedAttack, setSelectedAttack] = useState<Layer3Summary['attack_targets'][0] | null>(null);
  const [blockedCountries, setBlockedCountries] = useState<Set<string>>(new Set());
  const [showAddSignature, setShowAddSignature] = useState(false);
  const [signatureForm, setSignatureForm] = useState({
    name: '', protocol: 'tcp', pattern: '', src_ip: '', dst_ip: '', src_port: '', dst_port: '', action: 'drop',
  });

  // ==================== API Queries ====================

  const { data: anomalyData, isLoading: anomalyLoading } = useQuery({
    queryKey: ['realtime-anomaly'],
    queryFn: () => api.getRealtimeAnomaly() as Promise<AnomalyData>,
    refetchInterval: 2000,
  });

  // Per-IP anomaly data (filtered by tenant)
  const { data: perIPAnomaly } = useQuery({
    queryKey: ['realtime-anomaly-per-ip', tenantId],
    queryFn: () => api.getRealtimeAnomalyPerIP(tenantId ?? undefined) as unknown as Promise<Record<string, PerIPAnomalyEntry>>,
    refetchInterval: 2000,
  });

  const { data: trafficData } = useQuery({
    queryKey: ['realtime-traffic'],
    queryFn: () => api.getRealtimeTraffic() as Promise<TrafficData>,
    refetchInterval: 2000,
  });

  const { data: rulesStats } = useQuery({
    queryKey: ['rules-stats'],
    queryFn: () => api.getRulesStats() as unknown as Promise<RulesStats>,
    refetchInterval: 5000,
  });

  const { data: layer3Summary } = useQuery({
    queryKey: ['layer3-summary'],
    queryFn: () => api.getLayer3Summary() as unknown as Promise<Layer3Summary>,
    refetchInterval: 2000,
  });

  const { data: signaturesData, isLoading: signaturesLoading } = useQuery({
    queryKey: ['layer3-signatures'],
    queryFn: () => api.getLayer3Signatures() as Promise<{ signatures: SignatureEntry[]; count: number }>,
    enabled: activeTab === 'signatures',
    refetchInterval: 5000,
  });

  const { data: attackersData, isLoading: attackersLoading } = useQuery({
    queryKey: ['layer3-attackers'],
    queryFn: () => api.getLayer3Attackers(50) as Promise<{ attackers: AttackerEntry[]; count: number }>,
    enabled: activeTab === 'threats',
    refetchInterval: 5000,
  });

  // ==================== Mutations ====================

  const blockMutation = useMutation({
    mutationFn: (ip: string) => api.addRulesBlacklist({ ip, description: 'Blocked from Threat Center' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules-stats'] });
      toast.success('IP blocked successfully');
      if (checkedIP) setCheckedIP({ ...checkedIP, in_blacklist: true });
    },
    onError: (error: Error) => toast.error(error.message || 'Failed to block IP'),
  });

  const unblockMutation = useMutation({
    mutationFn: (ip: string) => api.removeRulesBlacklist(ip),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules-stats'] });
      toast.success('IP unblocked');
      if (checkedIP) setCheckedIP({ ...checkedIP, in_blacklist: false });
    },
    onError: (error: Error) => toast.error(error.message || 'Failed to unblock IP'),
  });

  const checkMutation = useMutation({
    mutationFn: (ip: string) => api.checkRulesIP(ip) as unknown as Promise<RulesCheckResult>,
    onSuccess: (data) => setCheckedIP(data),
    onError: (error: Error) => toast.error(error.message || 'Failed to check IP'),
  });

  const generateMutation = useMutation({
    mutationFn: () => api.generateLayer3Signatures(),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['layer3-signatures'] });
      toast.success(`Generated ${data.generated} signatures`);
    },
    onError: (error: Error) => toast.error(error.message || 'Failed to generate signatures'),
  });

  const addSignatureMutation = useMutation({
    mutationFn: (sig: typeof signatureForm) => api.addLayer3Signature({
      name: sig.name, protocol: sig.protocol, pattern: sig.pattern || undefined,
      src_ip: sig.src_ip || undefined, dst_ip: sig.dst_ip || undefined,
      src_port: sig.src_port ? parseInt(sig.src_port) : undefined,
      dst_port: sig.dst_port ? parseInt(sig.dst_port) : undefined, action: sig.action,
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['layer3-signatures'] });
      toast.success('Signature added');
      setShowAddSignature(false);
      setSignatureForm({ name: '', protocol: 'tcp', pattern: '', src_ip: '', dst_ip: '', src_port: '', dst_port: '', action: 'drop' });
    },
    onError: (error: Error) => toast.error(error.message || 'Failed to add signature'),
  });

  const deleteSignatureMutation = useMutation({
    mutationFn: (sigId: number) => api.deleteLayer3Signature(sigId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['layer3-signatures'] });
      toast.success('Signature removed');
    },
    onError: (error: Error) => toast.error(error.message || 'Failed to delete signature'),
  });

  const toggleSignatureMutation = useMutation({
    mutationFn: ({ sigId, enabled }: { sigId: number; enabled: boolean }) =>
      enabled ? api.enableLayer3Signature(sigId) : api.disableLayer3Signature(sigId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['layer3-signatures'] }),
    onError: (error: Error) => toast.error(error.message || 'Failed to toggle signature'),
  });

  // ==================== Computed Values ====================

  const activeAnomalies = useMemo(() => {
    if (!perIPAnomaly) return [];
    // Filter out stale anomalies (no traffic but anomaly flag still set)
    return Object.entries(perIPAnomaly)
      .filter(([, entry]) => entry.anomaly_active && (entry.packets_per_sec ?? 0) > 0)
      .map(([ip, entry]) => ({ ip, ...entry }))
      .sort((a, b) => b.level - a.level);
  }, [perIPAnomaly]);

  const attackTargets = layer3Summary?.attack_targets || [];
  // Consider both global anomaly status AND per-IP anomalies for attack detection
  const globalAnomalyActive = anomalyData?.active === true;
  const isUnderAttack = globalAnomalyActive || activeAnomalies.length > 0 || attackTargets.length > 0;

  const threatScore = useMemo(() => {
    if (activeAnomalies.length === 0) return 0;
    const maxLevel = Math.max(...activeAnomalies.map((a) => a.level));
    return Math.min(100, (maxLevel / 4) * 100 + activeAnomalies.length * 5);
  }, [activeAnomalies]);

  const mlConfidence = useMemo(() => {
    if (attackTargets.length === 0) return 0;
    const avgTier = attackTargets.reduce((s, a) => s + a.tier_agreement, 0) / attackTargets.length;
    const avgZScore = attackTargets.reduce((s, a) => s + a.z_score, 0) / attackTargets.length;
    return Math.min(100, (avgTier / 3) * 50 + Math.min(50, avgZScore * 5));
  }, [attackTargets]);

  // Filter out private IPs from map visualization - they don't have real geo locations
  // Note: These are PROTECTED IPs under attack, not attack sources
  const attackSources = useMemo(() => {
    return activeAnomalies
      .filter((a) => !isPrivateIP(a.ip))
      .map((a, idx) => anomalyToAttackSource(a, idx));
  }, [activeAnomalies]);
  const countryStats = useMemo(() => {
    const stats = aggregateCountryStats(attackSources);
    return stats.map((s) => ({ ...s, isBlocked: blockedCountries.has(s.code) }));
  }, [attackSources, blockedCountries]);

  // ==================== Event Handlers ====================

  const handleCheckIP = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchIP.trim()) checkMutation.mutate(searchIP.trim());
  };

  const handleCountryBlock = (countryCode: string) => {
    setBlockedCountries((prev) => { const next = new Set(prev); next.add(countryCode); toast.success(`Blocked traffic from ${countryCode}`); return next; });
  };

  const handleCountryUnblock = (countryCode: string) => {
    setBlockedCountries((prev) => { const next = new Set(prev); next.delete(countryCode); toast.success(`Unblocked traffic from ${countryCode}`); return next; });
  };

  const handleIPInvestigate = (ip: string) => {
    setSearchIP(ip);
    setActiveTab('investigate');
    checkMutation.mutate(ip);
  };

  // ==================== Table Columns ====================

  const threatColumns = [
    { key: 'ip', header: 'Protected IP', render: (value: unknown) => <span className="font-mono text-sm">{value as string}</span> },
    { key: 'level', header: 'Severity', render: (_: unknown, row: PerIPAnomalyEntry & { ip: string }) => <ThreatBadge level={row.level as 0 | 1 | 2 | 3 | 4} /> },
    { key: 'attack_type_name', header: 'Attack Type' },
    { key: 'anomaly_protocol_name', header: 'Protocol', render: (value: unknown) => <span className="px-2 py-0.5 bg-slate-200 dark:bg-slate-700 rounded text-xs uppercase">{value as string}</span> },
    { key: 'max_z_score', header: 'Z-Score', render: (value: unknown) => <span className="text-red-600 dark:text-red-400 font-medium">{(value as number)?.toFixed(2)}</span> },
    { key: 'tier_agreement', header: 'ML Tiers', render: (value: unknown) => <TierAgreementVisualization tierAgreement={value as number} /> },
    { key: 'actions', header: '', render: (_: unknown, row: PerIPAnomalyEntry & { ip: string }) => (
      <button onClick={() => setSelectedAttack(row as unknown as Layer3Summary['attack_targets'][0])} className="p-1.5 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg">
        <EyeIcon className="h-4 w-4 text-slate-500 dark:text-slate-400" />
      </button>
    )},
  ];

  const signatureColumns = [
    { key: 'id', header: 'ID', render: (value: unknown) => <span className="text-slate-500">#{value as number}</span> },
    { key: 'name', header: 'Name' },
    { key: 'protocol', header: 'Protocol', render: (value: unknown) => <span className="px-2 py-0.5 bg-slate-200 dark:bg-slate-700 rounded text-xs uppercase">{value as string}</span> },
    { key: 'hits', header: 'Hits', render: (value: unknown) => formatNumber(value as number) },
    { key: 'enabled', header: 'Status', render: (value: unknown, row: SignatureEntry) => (
      <button onClick={() => toggleSignatureMutation.mutate({ sigId: row.id, enabled: !(value as boolean) })}
        className={clsx('px-2 py-1 rounded-full text-xs font-medium', (value as boolean) ? 'bg-emerald-500/20 text-emerald-400' : 'bg-slate-200 dark:bg-slate-700 text-slate-500 dark:text-slate-400')}>
        {(value as boolean) ? 'Enabled' : 'Disabled'}
      </button>
    )},
    { key: 'delete', header: '', render: (_: unknown, row: SignatureEntry) => (
      <button onClick={() => deleteSignatureMutation.mutate(row.id)} className="p-1.5 hover:bg-red-500/20 rounded-lg text-red-400">
        <XMarkIcon className="h-4 w-4" />
      </button>
    )},
  ];

  const attackerColumns = [
    { key: 'src_ip', header: 'Source IP', render: (value: unknown) => <span className="font-mono text-sm">{value as string}</span> },
    { key: 'packets', header: 'Packets', render: (value: unknown) => formatNumber(value as number) },
    { key: 'bytes', header: 'Data', render: (value: unknown) => formatBytes(value as number) },
    { key: 'last_seen', header: 'Last Seen', render: (value: unknown) => <span className="text-slate-500 dark:text-slate-400 text-sm">{formatTimeAgo(value as string)}</span> },
    { key: 'score', header: 'Threat Score', render: (value: unknown) => <AttackerScoreBar score={value as number} /> },
  ];

  // ==================== Render ====================

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Threat Center</h1>
          <p className="text-slate-500 dark:text-slate-400 text-sm mt-1">Unified security monitoring and threat response</p>
        </div>
        <div className="flex items-center gap-4">
          <StatusIndicator status={trafficData?.connected ? 'online' : 'offline'} label="DPDK" showPulse={trafficData?.connected} />
          <div className={clsx('flex items-center gap-2 px-4 py-2 rounded-lg font-medium',
            isUnderAttack ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30')}>
            {isUnderAttack ? (
              <><FireIcon className="h-5 w-5 animate-pulse" /><span>{
                activeAnomalies.length > 0
                  ? `${activeAnomalies.length} Active Threats`
                  : globalAnomalyActive
                    ? `Attack Detected (${anomalyData?.level_name || 'Unknown'})`
                    : `${attackTargets.length} ML Targets`
              }</span></>
            ) : (
              <><ShieldCheckIcon className="h-5 w-5" /><span>All Systems Normal</span></>
            )}
          </div>
        </div>
      </div>

      {/* Global Alert Banner */}
      {anomalyData?.active && (
        <div className={clsx('relative overflow-hidden rounded-xl p-4 border animate-pulse-slow',
          anomalyData.level >= 3 ? 'bg-gradient-to-r from-red-900/50 to-red-800/30 border-red-500/50' :
          anomalyData.level >= 2 ? 'bg-gradient-to-r from-orange-900/50 to-orange-800/30 border-orange-500/50' :
          'bg-gradient-to-r from-yellow-900/50 to-yellow-800/30 border-yellow-500/50')}>
          <div className="relative flex items-center gap-4">
            <div className={clsx('p-3 rounded-xl', anomalyData.level >= 3 ? 'bg-red-500/20' : 'bg-orange-500/20')}>
              <ShieldExclamationIcon className="h-8 w-8 text-slate-900 dark:text-white" />
            </div>
            <div className="flex-1">
              <div className="flex items-center gap-3">
                <h3 className="text-lg font-bold text-slate-900 dark:text-white">Global Anomaly Detected</h3>
                <ThreatBadge level={anomalyData.level as 0 | 1 | 2 | 3 | 4} />
              </div>
              <p className="text-sm text-slate-900 dark:text-white/70 mt-1">
                {activeAnomalies.length} IP(s) under attack • Level: {anomalyData.level_name}
              </p>
            </div>
            <ThreatLevelBar level={anomalyData.level} max={4} />
          </div>
        </div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <MetricCard title="Threat Level" value={`${threatScore.toFixed(0)}%`} icon={ShieldExclamationIcon} color={threatScore > 75 ? 'danger' : threatScore > 25 ? 'warning' : 'success'} />
        <MetricCard title="Active Attacks" value={activeAnomalies.length.toString()} icon={FireIcon} color={activeAnomalies.length > 0 ? 'danger' : 'success'} />
        <MetricCard title="Blocked IPs" value={formatNumber(rulesStats?.blacklist_count || 0)} icon={NoSymbolIcon} color="warning" />
        <MetricCard title="Signatures" value={formatNumber(layer3Summary?.total_signatures || 0)} icon={SparklesIcon} color="info" />
        <MetricCard title="Packets Dropped" value={formatNumber(trafficData?.total_dropped || 0)} icon={ExclamationTriangleIcon} color={trafficData?.total_dropped ? 'info' : 'success'} />
      </div>

      {/* Tabs */}
      <div className="border-b border-slate-300 dark:border-slate-700">
        <nav className="-mb-px flex space-x-6 overflow-x-auto">
          {[
            { id: 'overview', label: 'Overview', icon: GlobeAltIcon },
            { id: 'threats', label: 'Active Threats', icon: FireIcon, count: activeAnomalies.length },
            { id: 'analysis', label: 'ML Analysis', icon: CpuChipIcon },
            { id: 'signatures', label: 'Signatures', icon: SparklesIcon, count: layer3Summary?.total_signatures },
            { id: 'investigate', label: 'Investigate', icon: MagnifyingGlassIcon },
          ].map((tab) => (
            <button key={tab.id} onClick={() => setActiveTab(tab.id as TabType)}
              className={clsx('flex items-center gap-2 py-4 px-1 border-b-2 font-medium text-sm whitespace-nowrap',
                activeTab === tab.id ? 'border-brand-500 text-brand-400' : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300')}>
              <tab.icon className="h-5 w-5" />
              {tab.label}
              {tab.count !== undefined && tab.count > 0 && (
                <span className={clsx('ml-1 px-2 py-0.5 rounded-full text-xs font-medium',
                  activeTab === tab.id ? 'bg-brand-500/20 text-brand-400' : 'bg-slate-200 dark:bg-slate-700 text-slate-500 dark:text-slate-400')}>{tab.count}</span>
              )}
            </button>
          ))}
        </nav>
      </div>

      {/* ==================== OVERVIEW TAB ==================== */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Global Attack Map */}
          <div className="card">
            <div className="card-header flex items-center gap-3">
              <div className="p-2 bg-brand-500/20 rounded-lg"><GlobeAltIcon className="h-5 w-5 text-brand-400" /></div>
              <div>
                <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Global Attack Map</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  {attackSources.length > 0
                    ? 'Real-time visualization of public IPs under attack'
                    : activeAnomalies.length > 0
                      ? 'Private IPs under attack (not shown on map)'
                      : 'No active attacks with geo-location data'}
                </p>
              </div>
            </div>
            <div className="p-4">
              <GeoMap
                attackSources={attackSources}
                countryStats={countryStats}
                targetLocation={{ lat: 40.7128, lng: -74.006 }}
                onCountryBlock={handleCountryBlock}
                onCountryUnblock={handleCountryUnblock}
                onIPInvestigate={handleIPInvestigate}
                showTrajectories={isUnderAttack}
                totalActiveThreats={activeAnomalies.length}
              />
            </div>
          </div>

          {/* Overview Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Threat Gauge */}
            <div className="card">
              <div className="card-header"><h3 className="text-sm font-medium text-slate-700 dark:text-slate-300">Threat Level</h3></div>
              <div className="p-4 flex justify-center">
                <GaugeChart value={threatScore} max={100} label="Score" color={threatScore > 75 ? '#ef4444' : threatScore > 50 ? '#f97316' : '#22c55e'} size={160} />
              </div>
            </div>

            {/* Severity Distribution */}
            <div className="card">
              <div className="card-header"><h3 className="text-sm font-medium text-slate-700 dark:text-slate-300">Severity Distribution</h3></div>
              <div className="p-4"><ThreatRadar anomalies={activeAnomalies} /></div>
            </div>

            {/* Incident Timeline */}
            <div className="card">
              <div className="card-header flex items-center gap-2">
                <ClockIcon className="h-4 w-4 text-slate-500 dark:text-slate-400" />
                <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300">Recent Incidents</h3>
              </div>
              <div className="p-4"><IncidentTimeline incidents={activeAnomalies} /></div>
            </div>
          </div>

          {/* Drop Reasons */}
          {trafficData?.drop_reasons && Object.keys(trafficData.drop_reasons).length > 0 && (
            <div className="card">
              <div className="card-header flex items-center gap-3">
                <div className="p-2 bg-orange-500/20 rounded-lg"><ChartBarIcon className="h-5 w-5 text-orange-400" /></div>
                <div>
                  <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Packet Drop Analysis</h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">Breakdown by filtering reason</p>
                </div>
              </div>
              <div className="p-6"><DropReasonsChart dropReasons={trafficData.drop_reasons} /></div>
            </div>
          )}
        </div>
      )}

      {/* ==================== THREATS TAB ==================== */}
      {activeTab === 'threats' && (
        <div className="space-y-6">
          {/* Protected Assets Under Attack */}
          <div className="card">
            <div className="card-header flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-red-500/20 rounded-lg"><FireIcon className="h-5 w-5 text-red-400" /></div>
                <div>
                  <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Protected Assets Under Attack</h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">Protected destination IPs receiving anomalous traffic</p>
                </div>
              </div>
              {activeAnomalies.length > 0 && (
                <span className="px-3 py-1 bg-red-500/20 text-red-400 rounded-full text-sm font-medium">{activeAnomalies.length} Under Attack</span>
              )}
            </div>
            <div className="p-4">
              {anomalyLoading ? <LoadingSpinner /> : activeAnomalies.length > 0 ? (
                <DataTable columns={threatColumns} data={activeAnomalies} emptyMessage="No assets under attack" />
              ) : (
                <EmptyState icon={ShieldCheckIcon} title="No Assets Under Attack" description="All protected assets are operating normally" />
              )}
            </div>
          </div>

          {/* Top Attackers */}
          <div className="card">
            <div className="card-header flex items-center gap-3">
              <div className="p-2 bg-orange-500/20 rounded-lg"><ExclamationTriangleIcon className="h-5 w-5 text-orange-400" /></div>
              <div>
                <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Top Attackers</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">Source IPs ranked by threat score</p>
              </div>
            </div>
            <div className="p-4">
              {attackersLoading ? <LoadingSpinner /> : attackersData?.attackers?.length ? (
                <DataTable columns={attackerColumns} data={attackersData.attackers} emptyMessage="No attackers" />
              ) : (
                <EmptyState icon={ExclamationTriangleIcon} title="No Attackers Recorded" description="Attacker data will appear when threats are detected" />
              )}
            </div>
          </div>
        </div>
      )}

      {/* ==================== ANALYSIS TAB ==================== */}
      {activeTab === 'analysis' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="card">
            <div className="card-header flex items-center gap-3">
              <div className="p-2 bg-purple-500/20 rounded-lg"><CpuChipIcon className="h-5 w-5 text-purple-400" /></div>
              <div>
                <h2 className="text-lg font-semibold text-slate-900 dark:text-white">ML Confidence Analysis</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">Multi-dimensional threat assessment</p>
              </div>
            </div>
            <div className="p-4"><MLConfidenceChart attacks={attackTargets} /></div>
          </div>

          <div className="card">
            <div className="card-header flex items-center gap-3">
              <div className="p-2 bg-cyan-500/20 rounded-lg"><ChartBarIcon className="h-5 w-5 text-cyan-400" /></div>
              <div>
                <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Attack Type Distribution</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">Classification breakdown</p>
              </div>
            </div>
            <div className="p-4">
              {attackTargets.length > 0 ? <AttackTypeBreakdown attacks={attackTargets} /> : (
                <EmptyState icon={ChartBarIcon} title="No Data" description="Attack distribution appears when threats are detected" />
              )}
            </div>
          </div>

          <div className="card lg:col-span-2">
            <div className="card-header"><h3 className="text-lg font-semibold text-slate-900 dark:text-white">Model Performance Metrics</h3></div>
            <div className="p-6">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
                <div className="text-center">
                  <GaugeChart value={mlConfidence} max={100} label="Confidence" color="#6366f1" size={120} />
                  <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">Overall Confidence</p>
                </div>
                <div className="text-center">
                  <GaugeChart value={attackTargets.length > 0 ? (attackTargets.reduce((s, a) => s + a.tier_agreement, 0) / attackTargets.length / 3) * 100 : 100} max={100} label="Agreement" color="#22c55e" size={120} />
                  <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">Tier Agreement</p>
                </div>
                <div className="text-center">
                  <GaugeChart value={(layer3Summary?.packet_ring_fill || 0) * 100} max={100} label="Buffer" color="#f59e0b" size={120} />
                  <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">Ring Buffer</p>
                </div>
                <div className="text-center">
                  <GaugeChart value={attackTargets.length > 0 ? Math.min(100, attackTargets.reduce((s, a) => s + a.z_score, 0) / attackTargets.length * 10) : 0} max={100} label="Z-Score" color="#ef4444" size={120} />
                  <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">Avg Z-Score</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ==================== SIGNATURES TAB ==================== */}
      {activeTab === 'signatures' && (
        <div className="space-y-4">
          <div className="flex justify-end gap-3">
            <button onClick={() => generateMutation.mutate()} disabled={generateMutation.isPending || !isUnderAttack} className="btn btn-secondary flex items-center gap-2">
              <ArrowPathIcon className={clsx('h-4 w-4', generateMutation.isPending && 'animate-spin')} />
              {generateMutation.isPending ? 'Generating...' : 'Auto-Generate'}
            </button>
            <button onClick={() => setShowAddSignature(true)} className="btn btn-primary flex items-center gap-2">
              <PlusIcon className="h-4 w-4" />Add Signature
            </button>
          </div>
          <div className="card">
            <div className="card-header flex items-center gap-3">
              <div className="p-2 bg-purple-500/20 rounded-lg"><SparklesIcon className="h-5 w-5 text-purple-400" /></div>
              <div>
                <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Dynamic Signatures</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">ML-generated and custom attack signatures</p>
              </div>
            </div>
            <div className="p-4">
              {signaturesLoading ? <LoadingSpinner /> : signaturesData?.signatures?.length ? (
                <DataTable columns={signatureColumns} data={signaturesData.signatures} emptyMessage="No signatures" />
              ) : (
                <EmptyState icon={SparklesIcon} title="No Signatures Configured" description="Add custom signatures or auto-generate from active attacks"
                  action={<button onClick={() => setShowAddSignature(true)} className="btn btn-primary mt-4"><PlusIcon className="h-4 w-4 mr-2" />Add Signature</button>} />
              )}
            </div>
          </div>
        </div>
      )}

      {/* ==================== INVESTIGATE TAB ==================== */}
      {activeTab === 'investigate' && (
        <div className="card">
          <div className="card-header">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-brand-500/20 rounded-lg"><MagnifyingGlassIcon className="h-5 w-5 text-brand-400" /></div>
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
                <input type="text" value={searchIP} onChange={(e) => setSearchIP(e.target.value)}
                  placeholder="Enter IP address (e.g., 192.168.1.1)"
                  className="w-full pl-10 pr-4 py-2.5 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:border-brand-500 focus:ring-1 focus:ring-brand-500" />
              </div>
              <button type="submit" disabled={checkMutation.isPending || !searchIP.trim()} className="btn btn-primary px-6">
                {checkMutation.isPending ? 'Checking...' : 'Investigate'}
              </button>
            </form>

            {checkedIP && (
              <div className="mt-6 p-4 bg-slate-100 dark:bg-slate-800/50 rounded-lg border border-slate-300 dark:border-slate-700">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold text-slate-900 dark:text-white font-mono">{checkedIP.ip}</h3>
                  <div className="flex gap-2">
                    {checkedIP.in_blacklist ? (
                      <button onClick={() => unblockMutation.mutate(checkedIP.ip)} disabled={unblockMutation.isPending} className="btn btn-success text-sm">
                        {unblockMutation.isPending ? 'Removing...' : 'Remove from Blacklist'}
                      </button>
                    ) : checkedIP.is_protected ? (
                      <Link to={`/assets/${encodeURIComponent(checkedIP.ip)}`} className="btn btn-primary text-sm">
                        View Asset Details
                      </Link>
                    ) : (
                      <button onClick={() => blockMutation.mutate(checkedIP.ip)} disabled={blockMutation.isPending} className="btn btn-danger text-sm">
                        {blockMutation.isPending ? 'Blocking...' : 'Block IP'}
                      </button>
                    )}
                  </div>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <div className={clsx('p-3 rounded-lg border', checkedIP.in_blacklist ? 'bg-red-500/10 border-red-500/30' : 'bg-slate-100 dark:bg-slate-700/50 border-slate-300 dark:border-slate-600')}>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Blacklist</p>
                    <div className="flex items-center gap-2">
                      {checkedIP.in_blacklist ? <NoSymbolIcon className="h-5 w-5 text-red-400" /> : <CheckCircleIcon className="h-5 w-5 text-slate-500" />}
                      <span className={clsx('font-semibold', checkedIP.in_blacklist ? 'text-red-400' : 'text-slate-500 dark:text-slate-400')}>{checkedIP.in_blacklist ? 'Blocked' : 'Clear'}</span>
                    </div>
                  </div>
                  <div className={clsx('p-3 rounded-lg border', checkedIP.in_whitelist ? 'bg-emerald-500/10 border-emerald-500/30' : 'bg-slate-100 dark:bg-slate-700/50 border-slate-300 dark:border-slate-600')}>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Whitelist</p>
                    <div className="flex items-center gap-2">
                      <CheckCircleIcon className={clsx('h-5 w-5', checkedIP.in_whitelist ? 'text-emerald-400' : 'text-slate-500')} />
                      <span className={clsx('font-semibold', checkedIP.in_whitelist ? 'text-emerald-400' : 'text-slate-500 dark:text-slate-400')}>{checkedIP.in_whitelist ? 'Allowed' : 'Not Set'}</span>
                    </div>
                  </div>
                  <div className={clsx('p-3 rounded-lg border', checkedIP.is_protected ? 'bg-brand-500/10 border-brand-500/30' : 'bg-slate-100 dark:bg-slate-700/50 border-slate-300 dark:border-slate-600')}>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Protected</p>
                    <div className="flex items-center gap-2">
                      <ShieldCheckIcon className={clsx('h-5 w-5', checkedIP.is_protected ? 'text-brand-400' : 'text-slate-500')} />
                      <span className={clsx('font-semibold', checkedIP.is_protected ? 'text-brand-400' : 'text-slate-500 dark:text-slate-400')}>{checkedIP.is_protected ? 'Yes' : 'No'}</span>
                    </div>
                  </div>
                  <div className={clsx('p-3 rounded-lg border', checkedIP.in_cidr_whitelist ? 'bg-cyan-500/10 border-cyan-500/30' : 'bg-slate-100 dark:bg-slate-700/50 border-slate-300 dark:border-slate-600')}>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">CIDR Match</p>
                    <div className="flex items-center gap-2">
                      <GlobeAltIcon className={clsx('h-5 w-5', checkedIP.in_cidr_whitelist ? 'text-cyan-600 dark:text-cyan-400' : 'text-slate-500')} />
                      <span className={clsx('font-semibold', checkedIP.in_cidr_whitelist ? 'text-cyan-600 dark:text-cyan-400' : 'text-slate-500 dark:text-slate-400')}>{checkedIP.in_cidr_whitelist ? 'Yes' : 'No'}</span>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Protected Asset Under Attack Modal */}
      {selectedAttack && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4">
            <div className="fixed inset-0 bg-black/70" onClick={() => setSelectedAttack(null)} />
            <div className="relative bg-white dark:bg-slate-900 rounded-xl shadow-2xl max-w-lg w-full border border-slate-300 dark:border-slate-700 animate-scale-in">
              <div className="p-6">
                <div className="flex items-center justify-between mb-6">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-red-500/20 rounded-lg"><ShieldExclamationIcon className="h-6 w-6 text-red-400" /></div>
                    <div>
                      <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Protected Asset Under Attack</h3>
                      <p className="text-sm text-slate-500 dark:text-slate-400 font-mono">{selectedAttack.ip} (destination)</p>
                    </div>
                  </div>
                  <ThreatBadge level={selectedAttack.level as 0 | 1 | 2 | 3 | 4} />
                </div>
                <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3 mb-4">
                  <p className="text-xs text-amber-400">
                    This is a <strong>protected IP</strong> that is receiving anomalous traffic.
                    The attacker source IPs are not shown here.
                  </p>
                </div>
                <div className="grid grid-cols-2 gap-4 mb-6">
                  <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-3">
                    <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Attack Type</p>
                    <p className="text-slate-900 dark:text-white font-medium">{(selectedAttack as unknown as PerIPAnomalyEntry).attack_type_name || selectedAttack.attack_type}</p>
                  </div>
                  <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-3">
                    <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Protocol</p>
                    <p className="text-slate-900 dark:text-white font-medium uppercase">{(selectedAttack as unknown as PerIPAnomalyEntry).anomaly_protocol_name || selectedAttack.protocol}</p>
                  </div>
                  <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-3">
                    <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Z-Score</p>
                    <p className="text-red-600 dark:text-red-400 font-bold">{((selectedAttack as unknown as PerIPAnomalyEntry).max_z_score || selectedAttack.z_score)?.toFixed(2)}</p>
                  </div>
                  <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-3">
                    <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Destination Port</p>
                    <p className="text-slate-900 dark:text-white font-medium">{(selectedAttack as unknown as PerIPAnomalyEntry).anomaly_dst_port || selectedAttack.dst_port || 'N/A'}</p>
                  </div>
                </div>
                <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4 mb-6">
                  <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">ML Tier Agreement</p>
                  <div className="flex items-center justify-between">
                    <TierAgreementVisualization tierAgreement={selectedAttack.tier_agreement} />
                    <span className="text-lg font-bold text-slate-900 dark:text-white">{selectedAttack.tier_agreement}/3 tiers</span>
                  </div>
                </div>
                <div className="flex gap-3">
                  <button onClick={() => { setSearchIP(selectedAttack.ip); setActiveTab('investigate'); setSelectedAttack(null); }} className="flex-1 btn btn-primary">Investigate</button>
                  <button onClick={() => setSelectedAttack(null)} className="flex-1 btn btn-ghost">Close</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Add Signature Modal */}
      {showAddSignature && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4">
            <div className="fixed inset-0 bg-black/70" onClick={() => setShowAddSignature(false)} />
            <div className="relative bg-white dark:bg-slate-900 rounded-xl shadow-2xl max-w-md w-full border border-slate-300 dark:border-slate-700 animate-scale-in">
              <div className="p-6">
                <div className="flex items-center justify-between mb-6">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-purple-500/20 rounded-lg"><SparklesIcon className="h-6 w-6 text-purple-400" /></div>
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Add Signature</h3>
                  </div>
                  <button onClick={() => setShowAddSignature(false)} className="p-2 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg"><XMarkIcon className="h-5 w-5 text-slate-500 dark:text-slate-400" /></button>
                </div>
                <form onSubmit={(e) => { e.preventDefault(); addSignatureMutation.mutate(signatureForm); }} className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Name</label>
                    <input type="text" value={signatureForm.name} onChange={(e) => setSignatureForm((f) => ({ ...f, name: e.target.value }))}
                      className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500" required />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Protocol</label>
                    <select value={signatureForm.protocol} onChange={(e) => setSignatureForm((f) => ({ ...f, protocol: e.target.value }))}
                      className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500">
                      <option value="tcp">TCP</option>
                      <option value="udp">UDP</option>
                      <option value="icmp">ICMP</option>
                    </select>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Source IP</label>
                      <input type="text" value={signatureForm.src_ip} onChange={(e) => setSignatureForm((f) => ({ ...f, src_ip: e.target.value }))}
                        placeholder="Optional" className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:border-brand-500" />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Dest IP</label>
                      <input type="text" value={signatureForm.dst_ip} onChange={(e) => setSignatureForm((f) => ({ ...f, dst_ip: e.target.value }))}
                        placeholder="Optional" className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:border-brand-500" />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Source Port</label>
                      <input type="number" value={signatureForm.src_port} onChange={(e) => setSignatureForm((f) => ({ ...f, src_port: e.target.value }))}
                        placeholder="Optional" className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:border-brand-500" />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Dest Port</label>
                      <input type="number" value={signatureForm.dst_port} onChange={(e) => setSignatureForm((f) => ({ ...f, dst_port: e.target.value }))}
                        placeholder="Optional" className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:border-brand-500" />
                    </div>
                  </div>
                  <div className="flex justify-end gap-3 pt-4">
                    <button type="button" onClick={() => setShowAddSignature(false)} className="btn btn-ghost">Cancel</button>
                    <button type="submit" disabled={addSignatureMutation.isPending} className="btn btn-primary">
                      {addSignatureMutation.isPending ? 'Adding...' : 'Add Signature'}
                    </button>
                  </div>
                </form>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default ThreatCenter;
