/**
 * IP Investigation Tool
 *
 * Comprehensive IP investigation modal with:
 * - IP reputation & threat intelligence
 * - Historical traffic patterns
 * - Attack history timeline
 * - Geolocation details
 * - Quick actions (block, whitelist, challenge)
 */

import { useState, useEffect, useMemo } from 'react';
import {
  XMarkIcon,
  ShieldCheckIcon,
  ShieldExclamationIcon,
  GlobeAltIcon,
  ChartBarIcon,
  ClockIcon,
  ServerIcon,
  ExclamationTriangleIcon,
  NoSymbolIcon,
  CheckCircleIcon,
  MagnifyingGlassIcon,
  DocumentDuplicateIcon,
  ArrowTopRightOnSquareIcon,
  BoltIcon,
  EyeIcon,
  FlagIcon,
} from '@heroicons/react/24/outline';
import { clsx } from 'clsx';
import { format, formatDistanceToNow, subDays } from 'date-fns';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import toast from 'react-hot-toast';

// ============================================================================
// Types
// ============================================================================

export interface IPDetails {
  ip: string;
  version: 'ipv4' | 'ipv6';
  asn?: string;
  asnOrg?: string;
  isp?: string;
  country?: string;
  countryCode?: string;
  city?: string;
  region?: string;
  timezone?: string;
  latitude?: number;
  longitude?: number;
  isProxy?: boolean;
  isVpn?: boolean;
  isTor?: boolean;
  isHosting?: boolean;
}

export interface ReputationData {
  score: number;  // 0-100, higher = more malicious
  category: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  firstSeen?: Date;
  lastSeen?: Date;
  totalRequests?: number;
  blockedRequests?: number;
  threatTypes?: string[];
  sources?: string[];
}

export interface TrafficHistoryPoint {
  timestamp: Date;
  requests: number;
  bytes: number;
  blocked: number;
}

export interface AttackEvent {
  id: string;
  timestamp: Date;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  duration: number;
  packetsBlocked: number;
  bytesBlocked: number;
  mitigationAction: string;
}

export interface IPInvestigationData {
  details: IPDetails;
  reputation: ReputationData;
  trafficHistory: TrafficHistoryPoint[];
  attacks: AttackEvent[];
  relatedIPs?: string[];
  notes?: string[];
}

export interface IPInvestigationProps {
  ip: string;
  isOpen: boolean;
  onClose: () => void;
  onBlock?: (ip: string) => void;
  onWhitelist?: (ip: string) => void;
  onChallenge?: (ip: string) => void;
  onAddToWatchlist?: (ip: string) => void;
}

// ============================================================================
// Constants
// ============================================================================

const TABS = [
  { id: 'overview', label: 'Overview', icon: EyeIcon },
  { id: 'traffic', label: 'Traffic', icon: ChartBarIcon },
  { id: 'attacks', label: 'Attacks', icon: ShieldExclamationIcon },
  { id: 'intelligence', label: 'Intelligence', icon: GlobeAltIcon },
];

const REPUTATION_COLORS = {
  clean: { bg: 'bg-emerald-100 dark:bg-emerald-900/30', text: 'text-emerald-700 dark:text-emerald-400', color: '#10b981' },
  suspicious: { bg: 'bg-yellow-100 dark:bg-yellow-900/30', text: 'text-yellow-700 dark:text-yellow-400', color: '#eab308' },
  malicious: { bg: 'bg-red-100 dark:bg-red-900/30', text: 'text-red-700 dark:text-red-400', color: '#ef4444' },
  unknown: { bg: 'bg-slate-100 dark:bg-slate-700', text: 'text-slate-700 dark:text-slate-300', color: '#64748b' },
};

// Generate mock data for demo
// NOTE: sample/demo generator only — returns randomly generated placeholder values,
// NOT live threat intelligence. Wire to a real reputation/API lookup before use.
function generateSampleData(ip: string): IPInvestigationData {
  const isHighRisk = ip.startsWith('185.') || ip.startsWith('45.');

  return {
    details: {
      ip,
      version: ip.includes(':') ? 'ipv6' : 'ipv4',
      asn: `AS${Math.floor(Math.random() * 50000 + 1000)}`,
      asnOrg: isHighRisk ? 'Bulletproof Hosting Ltd' : 'Generic Cloud Provider Inc',
      isp: isHighRisk ? 'Shadow Networks' : 'Amazon Web Services',
      country: isHighRisk ? 'Russia' : 'United States',
      countryCode: isHighRisk ? 'RU' : 'US',
      city: isHighRisk ? 'Moscow' : 'Ashburn',
      region: isHighRisk ? 'Moscow Oblast' : 'Virginia',
      timezone: isHighRisk ? 'Europe/Moscow' : 'America/New_York',
      latitude: isHighRisk ? 55.7558 : 39.0438,
      longitude: isHighRisk ? 37.6173 : -77.4874,
      isProxy: isHighRisk,
      isVpn: Math.random() > 0.7,
      isTor: Math.random() > 0.9,
      isHosting: Math.random() > 0.5,
    },
    reputation: {
      score: isHighRisk ? Math.floor(Math.random() * 30 + 70) : Math.floor(Math.random() * 40),
      category: isHighRisk ? 'malicious' : Math.random() > 0.7 ? 'suspicious' : 'clean',
      firstSeen: subDays(new Date(), Math.floor(Math.random() * 365)),
      lastSeen: subDays(new Date(), Math.floor(Math.random() * 7)),
      totalRequests: Math.floor(Math.random() * 100000 + 1000),
      blockedRequests: isHighRisk ? Math.floor(Math.random() * 50000) : Math.floor(Math.random() * 100),
      threatTypes: isHighRisk ? ['DDoS', 'Port Scan', 'Brute Force'] : [],
      sources: ['Internal', 'AbuseIPDB', 'Spamhaus', 'VirusTotal'],
    },
    trafficHistory: Array.from({ length: 24 }, (_, i) => ({
      timestamp: subDays(new Date(), 23 - i),
      requests: Math.floor(Math.random() * (isHighRisk ? 10000 : 1000) + 100),
      bytes: Math.floor(Math.random() * (isHighRisk ? 1e9 : 1e7)),
      blocked: Math.floor(Math.random() * (isHighRisk ? 5000 : 50)),
    })),
    attacks: isHighRisk ? [
      {
        id: '1',
        timestamp: subDays(new Date(), 2),
        type: 'SYN Flood',
        severity: 'critical',
        duration: 3600,
        packetsBlocked: 12500000,
        bytesBlocked: 1.2e10,
        mitigationAction: 'Rate Limited + Blackholed',
      },
      {
        id: '2',
        timestamp: subDays(new Date(), 5),
        type: 'UDP Flood',
        severity: 'high',
        duration: 1800,
        packetsBlocked: 5000000,
        bytesBlocked: 8e9,
        mitigationAction: 'Rate Limited',
      },
      {
        id: '3',
        timestamp: subDays(new Date(), 12),
        type: 'HTTP Flood',
        severity: 'medium',
        duration: 900,
        packetsBlocked: 500000,
        bytesBlocked: 2e8,
        mitigationAction: 'Challenge Issued',
      },
    ] : [],
    relatedIPs: isHighRisk ? ['185.143.223.12', '185.143.223.15', '45.95.147.8'] : [],
    notes: isHighRisk ? ['Part of known botnet C2 infrastructure', 'Previously used in DDoS-for-hire service'] : [],
  };
}

// ============================================================================
// Sub-components
// ============================================================================

function ReputationGauge({ score, category }: { score: number; category: string }) {
  const config = REPUTATION_COLORS[category as keyof typeof REPUTATION_COLORS] || REPUTATION_COLORS.unknown;

  return (
    <div className="relative w-40 h-20">
      {/* Background arc */}
      <svg viewBox="0 0 100 50" className="w-full h-full">
        <path
          d="M 10 50 A 40 40 0 0 1 90 50"
          fill="none"
          stroke="currentColor"
          strokeWidth="8"
          className="text-slate-200 dark:text-slate-700"
        />
        {/* Colored arc based on score */}
        <path
          d="M 10 50 A 40 40 0 0 1 90 50"
          fill="none"
          stroke={config.color}
          strokeWidth="8"
          strokeDasharray={`${(score / 100) * 126} 126`}
          strokeLinecap="round"
        />
      </svg>
      {/* Score display */}
      <div className="absolute inset-0 flex flex-col items-center justify-end pb-1">
        <span className="text-2xl font-bold text-slate-900 dark:text-white">{score}</span>
        <span className={clsx('text-xs font-medium capitalize', config.text)}>{category}</span>
      </div>
    </div>
  );
}

function InfoRow({ label, value, icon: Icon, copyable }: { label: string; value?: string | null; icon?: React.ComponentType<React.SVGProps<SVGSVGElement>>; copyable?: boolean }) {
  if (!value) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(value);
    toast.success('Copied to clipboard');
  };

  return (
    <div className="flex items-center justify-between py-2 border-b border-slate-100 dark:border-slate-700 last:border-0">
      <div className="flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400">
        {Icon && <Icon className="h-4 w-4" />}
        <span>{label}</span>
      </div>
      <div className="flex items-center gap-2">
        <span className="text-sm font-medium text-slate-900 dark:text-white">{value}</span>
        {copyable && (
          <button
            onClick={handleCopy}
            className="p-1 text-slate-500 dark:text-slate-300 hover:text-slate-600 dark:hover:text-slate-200 rounded"
            title="Copy"
          >
            <DocumentDuplicateIcon className="h-3.5 w-3.5" />
          </button>
        )}
      </div>
    </div>
  );
}

function AttackTimelineItem({ attack }: { attack: AttackEvent }) {
  const severityConfig = {
    low: 'border-l-green-500 bg-green-50 dark:bg-green-900/10',
    medium: 'border-l-yellow-500 bg-yellow-50 dark:bg-yellow-900/10',
    high: 'border-l-orange-500 bg-orange-50 dark:bg-orange-900/10',
    critical: 'border-l-red-500 bg-red-50 dark:bg-red-900/10',
  };

  return (
    <div className={clsx('border-l-4 pl-4 py-3 rounded-r-lg', severityConfig[attack.severity])}>
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-900 dark:text-white">{attack.type}</span>
            <span
              className={clsx(
                'px-2 py-0.5 rounded text-xs font-medium capitalize',
                attack.severity === 'critical' && 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
                attack.severity === 'high' && 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400',
                attack.severity === 'medium' && 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400',
                attack.severity === 'low' && 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
              )}
            >
              {attack.severity}
            </span>
          </div>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            {format(attack.timestamp, 'MMM d, yyyy HH:mm')} • Duration: {Math.floor(attack.duration / 60)} min
          </p>
        </div>
        <div className="text-right text-sm">
          <p className="text-slate-900 dark:text-white font-medium">
            {(attack.packetsBlocked / 1e6).toFixed(2)}M packets blocked
          </p>
          <p className="text-slate-500 dark:text-slate-400">
            {(attack.bytesBlocked / 1e9).toFixed(2)} GB
          </p>
        </div>
      </div>
      <p className="text-sm text-slate-600 dark:text-slate-300 mt-2">
        <span className="text-slate-500 dark:text-slate-400">Mitigation:</span> {attack.mitigationAction}
      </p>
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export function IPInvestigation({
  ip,
  isOpen,
  onClose,
  onBlock,
  onWhitelist,
  onChallenge,
  onAddToWatchlist,
}: IPInvestigationProps) {
  const [activeTab, setActiveTab] = useState('overview');
  const [searchIp, setSearchIp] = useState(ip);

  // Update search when prop changes
  useEffect(() => {
    setSearchIp(ip);
  }, [ip]);

  // Sample data only — replace with a real API/reputation lookup before production use.
  const data = useMemo(() => generateSampleData(searchIp), [searchIp]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    // Trigger re-fetch by updating searchIp
    // The useMemo will regenerate data
  };

  const handleExternalLookup = (service: string) => {
    const urls: Record<string, string> = {
      abuseipdb: `https://www.abuseipdb.com/check/${searchIp}`,
      virustotal: `https://www.virustotal.com/gui/ip-address/${searchIp}`,
      shodan: `https://www.shodan.io/host/${searchIp}`,
      whois: `https://who.is/whois-ip/ip-address/${searchIp}`,
    };
    window.open(urls[service], '_blank');
  };

  if (!isOpen) return null;

  const repConfig = REPUTATION_COLORS[data.reputation.category] || REPUTATION_COLORS.unknown;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex min-h-full items-center justify-center p-4">
        <div className="fixed inset-0 bg-black/50" onClick={onClose} />

        <div className="relative bg-white dark:bg-slate-900 rounded-xl shadow-xl w-full max-w-4xl max-h-[90vh] overflow-hidden">
          {/* Header */}
          <div className="sticky top-0 z-10 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-700">
            <div className="flex items-center justify-between p-4">
              <div className="flex items-center gap-4">
                <div className={clsx('p-2 rounded-lg', repConfig.bg)}>
                  <MagnifyingGlassIcon className={clsx('h-5 w-5', repConfig.text)} />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-slate-900 dark:text-white">IP Investigation</h2>
                  <p className="text-sm text-amber-600 dark:text-amber-400 font-medium">
                    Sample data — randomly generated placeholder values, not live threat intelligence
                  </p>
                </div>
              </div>
              <button
                onClick={onClose}
                className="p-2 text-slate-500 dark:text-slate-300 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
              >
                <XMarkIcon className="h-5 w-5" />
              </button>
            </div>

            {/* Search Bar */}
            <form onSubmit={handleSearch} className="px-4 pb-4">
              <div className="relative">
                <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-500 dark:text-slate-400" />
                <input
                  type="text"
                  value={searchIp}
                  onChange={(e) => setSearchIp(e.target.value)}
                  placeholder="Enter IP address to investigate..."
                  className="w-full pl-10 pr-4 py-2.5 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-400"
                />
              </div>
            </form>

            {/* Tabs */}
            <div className="px-4 flex gap-1">
              {TABS.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={clsx(
                    'flex items-center gap-2 px-4 py-2.5 text-sm font-medium rounded-t-lg transition-colors',
                    activeTab === tab.id
                      ? 'bg-slate-100 dark:bg-slate-800 text-brand-600 dark:text-brand-400'
                      : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-200 dark:text-slate-300'
                  )}
                >
                  <tab.icon className="h-4 w-4" />
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          {/* Content */}
          <div className="p-6 overflow-y-auto max-h-[calc(90vh-200px)]">
            {/* Overview Tab */}
            {activeTab === 'overview' && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Reputation */}
                <div className="card">
                  <div className="card-header">
                    <h3 className="font-semibold text-slate-900 dark:text-white">Reputation Score</h3>
                  </div>
                  <div className="card-body flex flex-col items-center">
                    <ReputationGauge score={data.reputation.score} category={data.reputation.category} />

                    <div className="mt-4 w-full space-y-2">
                      <InfoRow
                        label="First Seen"
                        value={data.reputation.firstSeen ? formatDistanceToNow(data.reputation.firstSeen, { addSuffix: true }) : undefined}
                        icon={ClockIcon}
                      />
                      <InfoRow
                        label="Last Seen"
                        value={data.reputation.lastSeen ? formatDistanceToNow(data.reputation.lastSeen, { addSuffix: true }) : undefined}
                        icon={ClockIcon}
                      />
                      <InfoRow
                        label="Total Requests"
                        value={data.reputation.totalRequests?.toLocaleString()}
                        icon={ChartBarIcon}
                      />
                      <InfoRow
                        label="Blocked Requests"
                        value={data.reputation.blockedRequests?.toLocaleString()}
                        icon={NoSymbolIcon}
                      />
                    </div>

                    {data.reputation.threatTypes && data.reputation.threatTypes.length > 0 && (
                      <div className="mt-4 w-full">
                        <p className="text-sm text-slate-500 dark:text-slate-400 mb-2">Threat Types</p>
                        <div className="flex flex-wrap gap-2">
                          {data.reputation.threatTypes.map((type) => (
                            <span
                              key={type}
                              className="px-2 py-1 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 text-xs font-medium rounded"
                            >
                              {type}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Geolocation */}
                <div className="card">
                  <div className="card-header">
                    <h3 className="font-semibold text-slate-900 dark:text-white">Geolocation & Network</h3>
                  </div>
                  <div className="card-body space-y-2">
                    <InfoRow label="IP Address" value={data.details.ip} icon={ServerIcon} copyable />
                    <InfoRow label="Country" value={data.details.country} icon={GlobeAltIcon} />
                    <InfoRow label="City" value={data.details.city} />
                    <InfoRow label="Region" value={data.details.region} />
                    <InfoRow label="ASN" value={data.details.asn} copyable />
                    <InfoRow label="Organization" value={data.details.asnOrg} />
                    <InfoRow label="ISP" value={data.details.isp} />
                    <InfoRow label="Timezone" value={data.details.timezone} />

                    {/* Flags */}
                    <div className="pt-3 flex flex-wrap gap-2">
                      {data.details.isProxy && (
                        <span className="px-2 py-1 bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-400 text-xs font-medium rounded flex items-center gap-1">
                          <ExclamationTriangleIcon className="h-3 w-3" />
                          Proxy
                        </span>
                      )}
                      {data.details.isVpn && (
                        <span className="px-2 py-1 bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400 text-xs font-medium rounded flex items-center gap-1">
                          <ShieldCheckIcon className="h-3 w-3" />
                          VPN
                        </span>
                      )}
                      {data.details.isTor && (
                        <span className="px-2 py-1 bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-400 text-xs font-medium rounded flex items-center gap-1">
                          <GlobeAltIcon className="h-3 w-3" />
                          Tor Exit
                        </span>
                      )}
                      {data.details.isHosting && (
                        <span className="px-2 py-1 bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400 text-xs font-medium rounded flex items-center gap-1">
                          <ServerIcon className="h-3 w-3" />
                          Hosting
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Quick Actions */}
                <div className="md:col-span-2 card">
                  <div className="card-header">
                    <h3 className="font-semibold text-slate-900 dark:text-white">Quick Actions</h3>
                  </div>
                  <div className="card-body">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      <button
                        onClick={() => onBlock?.(searchIp)}
                        className="flex flex-col items-center gap-2 p-4 bg-red-50 dark:bg-red-900/20 hover:bg-red-100 dark:hover:bg-red-900/30 rounded-lg transition-colors group"
                      >
                        <NoSymbolIcon className="h-6 w-6 text-red-600 dark:text-red-400" />
                        <span className="text-sm font-medium text-red-700 dark:text-red-300">Block IP</span>
                      </button>
                      <button
                        onClick={() => onWhitelist?.(searchIp)}
                        className="flex flex-col items-center gap-2 p-4 bg-emerald-50 dark:bg-emerald-900/20 hover:bg-emerald-100 dark:hover:bg-emerald-900/30 rounded-lg transition-colors group"
                      >
                        <CheckCircleIcon className="h-6 w-6 text-emerald-600 dark:text-emerald-400" />
                        <span className="text-sm font-medium text-emerald-700 dark:text-emerald-300">Whitelist</span>
                      </button>
                      <button
                        onClick={() => onChallenge?.(searchIp)}
                        className="flex flex-col items-center gap-2 p-4 bg-amber-50 dark:bg-amber-900/20 hover:bg-amber-100 dark:hover:bg-amber-900/30 rounded-lg transition-colors group"
                      >
                        <BoltIcon className="h-6 w-6 text-amber-600 dark:text-amber-400" />
                        <span className="text-sm font-medium text-amber-700 dark:text-amber-300">Challenge</span>
                      </button>
                      <button
                        onClick={() => onAddToWatchlist?.(searchIp)}
                        className="flex flex-col items-center gap-2 p-4 bg-blue-50 dark:bg-blue-900/20 hover:bg-blue-100 dark:hover:bg-blue-900/30 rounded-lg transition-colors group"
                      >
                        <FlagIcon className="h-6 w-6 text-blue-600 dark:text-blue-400" />
                        <span className="text-sm font-medium text-blue-700 dark:text-blue-300">Watchlist</span>
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Traffic Tab */}
            {activeTab === 'traffic' && (
              <div className="space-y-6">
                <div className="card">
                  <div className="card-header">
                    <h3 className="font-semibold text-slate-900 dark:text-white">Traffic History (Last 24 Days)</h3>
                  </div>
                  <div className="card-body">
                    <div className="h-64">
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={data.trafficHistory}>
                          <defs>
                            <linearGradient id="requestsGradient" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
                              <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                            </linearGradient>
                            <linearGradient id="blockedGradient" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                              <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                            </linearGradient>
                          </defs>
                          <XAxis
                            dataKey="timestamp"
                            tickFormatter={(val) => format(new Date(val), 'MMM d')}
                            tick={{ fontSize: 11 }}
                            tickLine={false}
                            axisLine={false}
                          />
                          <YAxis tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
                          <Tooltip
                            content={({ active, payload }) => {
                              if (!active || !payload?.length) return null;
                              const data = payload[0].payload;
                              return (
                                <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg p-3 shadow-lg">
                                  <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">
                                    {format(new Date(data.timestamp), 'MMM d, yyyy')}
                                  </p>
                                  <p className="text-sm text-slate-900 dark:text-white">
                                    Requests: <span className="font-semibold">{data.requests.toLocaleString()}</span>
                                  </p>
                                  <p className="text-sm text-red-600 dark:text-red-400">
                                    Blocked: <span className="font-semibold">{data.blocked.toLocaleString()}</span>
                                  </p>
                                </div>
                              );
                            }}
                          />
                          <Area
                            type="linear"
                            dataKey="requests"
                            stroke="#6366f1"
                            fill="url(#requestsGradient)"
                            strokeWidth={2}
                          />
                          <Area
                            type="linear"
                            dataKey="blocked"
                            stroke="#ef4444"
                            fill="url(#blockedGradient)"
                            strokeWidth={2}
                          />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                    <div className="mt-4 flex items-center justify-center gap-6 text-sm">
                      <div className="flex items-center gap-2">
                        <div className="w-3 h-3 rounded-full bg-brand-500" />
                        <span className="text-slate-600 dark:text-slate-300">Total Requests</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <div className="w-3 h-3 rounded-full bg-red-500" />
                        <span className="text-slate-600 dark:text-slate-300">Blocked</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Traffic stats */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                  {[
                    { label: 'Total Requests', value: data.reputation.totalRequests?.toLocaleString() || '0' },
                    { label: 'Blocked', value: data.reputation.blockedRequests?.toLocaleString() || '0' },
                    { label: 'Block Rate', value: `${((data.reputation.blockedRequests || 0) / (data.reputation.totalRequests || 1) * 100).toFixed(1)}%` },
                    { label: 'Data Transferred', value: `${(data.trafficHistory.reduce((s, h) => s + h.bytes, 0) / 1e9).toFixed(2)} GB` },
                  ].map((stat) => (
                    <div key={stat.label} className="card">
                      <div className="card-body text-center">
                        <p className="text-xs text-slate-500 dark:text-slate-400">{stat.label}</p>
                        <p className="text-xl font-bold text-slate-900 dark:text-white">{stat.value}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Attacks Tab */}
            {activeTab === 'attacks' && (
              <div className="space-y-4">
                {data.attacks.length > 0 ? (
                  <>
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="font-semibold text-slate-900 dark:text-white">
                        Attack History ({data.attacks.length} events)
                      </h3>
                    </div>
                    <div className="space-y-4">
                      {data.attacks.map((attack) => (
                        <AttackTimelineItem key={attack.id} attack={attack} />
                      ))}
                    </div>
                  </>
                ) : (
                  <div className="text-center py-12">
                    <ShieldCheckIcon className="h-12 w-12 mx-auto text-emerald-500 mb-3" />
                    <p className="text-lg font-medium text-slate-900 dark:text-white">No Attack History</p>
                    <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                      This IP has no recorded attack events
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* Intelligence Tab */}
            {activeTab === 'intelligence' && (
              <div className="space-y-6">
                {/* External Lookups */}
                <div className="card">
                  <div className="card-header">
                    <h3 className="font-semibold text-slate-900 dark:text-white">External Intelligence Sources</h3>
                  </div>
                  <div className="card-body">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      {[
                        { id: 'abuseipdb', name: 'AbuseIPDB', color: 'bg-red-500' },
                        { id: 'virustotal', name: 'VirusTotal', color: 'bg-blue-500' },
                        { id: 'shodan', name: 'Shodan', color: 'bg-orange-500' },
                        { id: 'whois', name: 'WHOIS', color: 'bg-slate-500' },
                      ].map((service) => (
                        <button
                          key={service.id}
                          onClick={() => handleExternalLookup(service.id)}
                          className="flex items-center gap-3 p-3 bg-slate-50 dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
                        >
                          <div className={clsx('w-2 h-2 rounded-full', service.color)} />
                          <span className="text-sm font-medium text-slate-900 dark:text-white">{service.name}</span>
                          <ArrowTopRightOnSquareIcon className="h-4 w-4 text-slate-500 dark:text-slate-400 ml-auto" />
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Related IPs */}
                {data.relatedIPs && data.relatedIPs.length > 0 && (
                  <div className="card">
                    <div className="card-header">
                      <h3 className="font-semibold text-slate-900 dark:text-white">Related IPs</h3>
                    </div>
                    <div className="card-body">
                      <div className="space-y-2">
                        {data.relatedIPs.map((relatedIp) => (
                          <button
                            key={relatedIp}
                            onClick={() => setSearchIp(relatedIp)}
                            className="w-full flex items-center justify-between p-3 bg-slate-50 dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
                          >
                            <span className="font-mono text-sm text-slate-900 dark:text-white">{relatedIp}</span>
                            <MagnifyingGlassIcon className="h-4 w-4 text-slate-500 dark:text-slate-400" />
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {/* Notes */}
                {data.notes && data.notes.length > 0 && (
                  <div className="card">
                    <div className="card-header">
                      <h3 className="font-semibold text-slate-900 dark:text-white">Intelligence Notes</h3>
                    </div>
                    <div className="card-body">
                      <ul className="space-y-2">
                        {data.notes.map((note, i) => (
                          <li key={i} className="flex items-start gap-2 text-sm text-slate-600 dark:text-slate-300">
                            <ExclamationTriangleIcon className="h-4 w-4 text-amber-500 mt-0.5 shrink-0" />
                            {note}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                )}

                {/* Data Sources */}
                <div className="card">
                  <div className="card-header">
                    <h3 className="font-semibold text-slate-900 dark:text-white">Data Sources</h3>
                  </div>
                  <div className="card-body">
                    <div className="flex flex-wrap gap-2">
                      {data.reputation.sources?.map((source) => (
                        <span
                          key={source}
                          className="px-3 py-1.5 bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 text-sm rounded-lg"
                        >
                          {source}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default IPInvestigation;
