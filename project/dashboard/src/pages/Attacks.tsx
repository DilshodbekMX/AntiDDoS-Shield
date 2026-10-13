/**
 * Attack Analysis Page (Enterprise Edition)
 *
 * Advanced attack analysis with ML confidence visualization,
 * attack attribution, dynamic signatures, and real-time monitoring.
 */

import { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useUIStore } from '../store';
import {
  ShieldExclamationIcon,
  ExclamationTriangleIcon,
  EyeIcon,
  SparklesIcon,
  XMarkIcon,
  PlusIcon,
  ChartBarIcon,
  CpuChipIcon,
  FireIcon,
  ArrowPathIcon,
  BeakerIcon,
} from '@heroicons/react/24/outline';
import {
  PieChart,
  Pie,
  Cell,
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
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
  DataTable,
  EmptyState,
  LoadingSpinner,
} from '../components/ui';

// ============================================================================
// Types
// ============================================================================

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

const ATTACK_TYPE_COLORS = [
  '#6366f1',
  '#8b5cf6',
  '#a855f7',
  '#d946ef',
  '#ec4899',
  '#f43f5e',
  '#ef4444',
];

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

// ============================================================================
// Sub-Components
// ============================================================================

function MLConfidenceChart({
  attacks,
}: {
  attacks: Layer3Summary['attack_targets'];
}) {
  const { darkMode } = useUIStore();
  const radarData = useMemo(() => {
    // Generate radar data from attack characteristics
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
        <PolarGrid stroke={darkMode ? '#334155' : '#cbd5e1'} />
        <PolarAngleAxis dataKey="metric" tick={{ fill: '#94a3b8', fontSize: 11 }} />
        <PolarRadiusAxis
          angle={30}
          domain={[0, 100]}
          tick={{ fill: '#94a3b8', fontSize: 10 }}
        />
        <Radar
          name="Confidence"
          dataKey="value"
          stroke="#6366f1"
          fill="#6366f1"
          fillOpacity={0.3}
        />
        <RechartsTooltip
          contentStyle={{
            backgroundColor: 'rgba(15, 23, 42, 0.95)',
            border: '1px solid rgba(99, 102, 241, 0.3)',
            borderRadius: '8px',
          }}
        />
      </RadarChart>
    </ResponsiveContainer>
  );
}

function AttackTypeBreakdown({
  attacks,
}: {
  attacks: Layer3Summary['attack_targets'];
}) {
  const breakdown = useMemo(() => {
    const counts: Record<string, number> = {};
    attacks.forEach((a) => {
      counts[a.attack_type] = (counts[a.attack_type] || 0) + 1;
    });
    return Object.entries(counts)
      .map(([type, count], idx) => ({
        name: type,
        value: count,
        color: ATTACK_TYPE_COLORS[idx % ATTACK_TYPE_COLORS.length],
      }))
      .sort((a, b) => b.value - a.value);
  }, [attacks]);

  if (breakdown.length === 0) return null;

  return (
    <ResponsiveContainer width="100%" height={200}>
      <PieChart>
        <Pie
          data={breakdown}
          cx="50%"
          cy="50%"
          innerRadius={40}
          outerRadius={70}
          paddingAngle={2}
          dataKey="value"
        >
          {breakdown.map((entry, index) => (
            <Cell key={`cell-${index}`} fill={entry.color} />
          ))}
        </Pie>
        <RechartsTooltip
          contentStyle={{
            backgroundColor: 'rgba(15, 23, 42, 0.95)',
            border: '1px solid rgba(99, 102, 241, 0.3)',
            borderRadius: '8px',
          }}
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

function TierAgreementVisualization({ tierAgreement }: { tierAgreement: number }) {
  return (
    <div className="flex items-center gap-1">
      {[1, 2, 3].map((tier) => (
        <div
          key={tier}
          className={clsx(
            'w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold transition-all',
            tier <= tierAgreement
              ? 'bg-emerald-500 text-white shadow-lg shadow-emerald-500/30'
              : 'bg-slate-200 dark:bg-slate-700 text-slate-500'
          )}
        >
          {tier}
        </div>
      ))}
    </div>
  );
}

function AttackerScoreBar({ score }: { score: number }) {
  const percentage = score * 100;
  const color =
    percentage > 70 ? 'bg-red-500' : percentage > 40 ? 'bg-orange-500' : 'bg-yellow-500';

  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
        <div
          className={clsx('h-full rounded-full transition-all', color)}
          style={{ width: `${percentage}%` }}
        />
      </div>
      <span
        className={clsx(
          'text-xs font-bold',
          percentage > 70 ? 'text-red-400' : percentage > 40 ? 'text-orange-400' : 'text-yellow-400'
        )}
      >
        {percentage.toFixed(0)}%
      </span>
    </div>
  );
}

// ============================================================================
// Tab Components
// ============================================================================

type TabType = 'attacks' | 'signatures' | 'attackers' | 'analysis';

// ============================================================================
// Main Component
// ============================================================================

export function AttacksPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>('attacks');
  const [selectedAttack, setSelectedAttack] = useState<
    Layer3Summary['attack_targets'][0] | null
  >(null);
  const [showAddSignature, setShowAddSignature] = useState(false);
  const [signatureForm, setSignatureForm] = useState({
    name: '',
    protocol: 'tcp',
    pattern: '',
    src_ip: '',
    dst_ip: '',
    src_port: '',
    dst_port: '',
    action: 'drop',
  });

  // Fetch Layer 3 summary
  const { data: layer3Summary, isLoading: summaryLoading } = useQuery({
    queryKey: ['layer3-summary'],
    queryFn: () => api.getLayer3Summary() as unknown as Promise<Layer3Summary>,
    refetchInterval: 2000,
  });

  // Fetch signatures
  const { data: signaturesData, isLoading: signaturesLoading } = useQuery({
    queryKey: ['layer3-signatures'],
    queryFn: () =>
      api.getLayer3Signatures() as Promise<{ signatures: SignatureEntry[]; count: number }>,
    enabled: activeTab === 'signatures',
    refetchInterval: 5000,
  });

  // Fetch attackers
  const { data: attackersData, isLoading: attackersLoading } = useQuery({
    queryKey: ['layer3-attackers'],
    queryFn: () =>
      api.getLayer3Attackers(50) as Promise<{ attackers: AttackerEntry[]; count: number }>,
    enabled: activeTab === 'attackers',
    refetchInterval: 5000,
  });

  // Generate signatures mutation
  const generateMutation = useMutation({
    mutationFn: () => api.generateLayer3Signatures(),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['layer3-signatures'] });
      toast.success(`Generated ${data.generated} signatures`);
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to generate signatures');
    },
  });

  // Add signature mutation
  const addSignatureMutation = useMutation({
    mutationFn: (sig: typeof signatureForm) =>
      api.addLayer3Signature({
        name: sig.name,
        protocol: sig.protocol,
        pattern: sig.pattern || undefined,
        src_ip: sig.src_ip || undefined,
        dst_ip: sig.dst_ip || undefined,
        src_port: sig.src_port ? parseInt(sig.src_port) : undefined,
        dst_port: sig.dst_port ? parseInt(sig.dst_port) : undefined,
        action: sig.action,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['layer3-signatures'] });
      toast.success('Signature added');
      setShowAddSignature(false);
      setSignatureForm({
        name: '',
        protocol: 'tcp',
        pattern: '',
        src_ip: '',
        dst_ip: '',
        src_port: '',
        dst_port: '',
        action: 'drop',
      });
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to add signature');
    },
  });

  // Delete signature mutation
  const deleteSignatureMutation = useMutation({
    mutationFn: (sigId: number) => api.deleteLayer3Signature(sigId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['layer3-signatures'] });
      toast.success('Signature removed');
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to delete signature');
    },
  });

  // Toggle signature mutation
  const toggleSignatureMutation = useMutation({
    mutationFn: ({ sigId, enabled }: { sigId: number; enabled: boolean }) =>
      enabled ? api.enableLayer3Signature(sigId) : api.disableLayer3Signature(sigId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['layer3-signatures'] });
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to toggle signature');
    },
  });

  const attackTargets = layer3Summary?.attack_targets || [];
  const isUnderAttack = attackTargets.length > 0;

  // ML confidence score
  const mlConfidence = useMemo(() => {
    if (attackTargets.length === 0) return 0;
    const avgTier = attackTargets.reduce((s, a) => s + a.tier_agreement, 0) / attackTargets.length;
    const avgZScore = attackTargets.reduce((s, a) => s + a.z_score, 0) / attackTargets.length;
    return Math.min(100, (avgTier / 3) * 50 + Math.min(50, avgZScore * 5));
  }, [attackTargets]);

  // Attack table columns
  const attackColumns = [
    {
      key: 'ip',
      header: 'Target IP',
      render: (value: unknown) => <span className="font-mono text-sm">{value as string}</span>,
    },
    {
      key: 'level',
      header: 'Severity',
      render: (_: unknown, row: Layer3Summary['attack_targets'][0]) => (
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
      key: 'dst_port',
      header: 'Port',
      render: (value: unknown) => (value as number) || 'N/A',
    },
    {
      key: 'z_score',
      header: 'Z-Score',
      render: (value: unknown) => (
        <span className="text-red-600 dark:text-red-400 font-medium">{(value as number)?.toFixed(2)}</span>
      ),
    },
    {
      key: 'tier_agreement',
      header: 'ML Tiers',
      render: (value: unknown) => <TierAgreementVisualization tierAgreement={value as number} />,
    },
    {
      key: 'actions',
      header: '',
      render: (_: unknown, row: Layer3Summary['attack_targets'][0]) => (
        <button
          onClick={() => setSelectedAttack(row)}
          className="p-1.5 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg transition-colors"
        >
          <EyeIcon className="h-4 w-4 text-slate-500 dark:text-slate-400" />
        </button>
      ),
    },
  ];

  // Signature table columns
  const signatureColumns = [
    {
      key: 'id',
      header: 'ID',
      render: (value: unknown) => <span className="text-slate-500">#{value as number}</span>,
    },
    {
      key: 'name',
      header: 'Name',
    },
    {
      key: 'protocol',
      header: 'Protocol',
      render: (value: unknown) => (
        <span className="px-2 py-0.5 bg-slate-200 dark:bg-slate-700 rounded text-xs uppercase">{value as string}</span>
      ),
    },
    {
      key: 'pattern',
      header: 'Pattern',
      render: (value: unknown) => (
        <span className="font-mono text-xs text-slate-500 dark:text-slate-400">{(value as string) || '-'}</span>
      ),
    },
    {
      key: 'hits',
      header: 'Hits',
      render: (value: unknown) => formatNumber(value as number),
    },
    {
      key: 'enabled',
      header: 'Status',
      render: (value: unknown, row: SignatureEntry) => (
        <button
          onClick={() => toggleSignatureMutation.mutate({ sigId: row.id, enabled: !(value as boolean) })}
          className={clsx(
            'px-2 py-1 rounded-full text-xs font-medium transition-colors',
            value
              ? 'bg-emerald-500/20 text-emerald-400 hover:bg-emerald-500/30'
              : 'bg-slate-200 dark:bg-slate-700 text-slate-500 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-600'
          )}
        >
          {value ? 'Enabled' : 'Disabled'}
        </button>
      ),
    },
    {
      key: 'delete',
      header: '',
      render: (_: unknown, row: SignatureEntry) => (
        <button
          onClick={() => deleteSignatureMutation.mutate(row.id)}
          disabled={deleteSignatureMutation.isPending}
          className="p-1.5 hover:bg-red-500/20 rounded-lg transition-colors text-red-400"
        >
          <XMarkIcon className="h-4 w-4" />
        </button>
      ),
    },
  ];

  // Attacker table columns
  const attackerColumns = [
    {
      key: 'src_ip',
      header: 'Source IP',
      render: (value: unknown) => <span className="font-mono text-sm">{value as string}</span>,
    },
    {
      key: 'packets',
      header: 'Packets',
      render: (value: unknown) => formatNumber(value as number),
    },
    {
      key: 'bytes',
      header: 'Data',
      render: (value: unknown) => formatBytes(value as number),
    },
    {
      key: 'first_seen',
      header: 'First Seen',
      render: (value: unknown) => (
        <span className="text-slate-500 dark:text-slate-400 text-sm">{formatTimeAgo(value as string)}</span>
      ),
    },
    {
      key: 'last_seen',
      header: 'Last Seen',
      render: (value: unknown) => (
        <span className="text-slate-500 dark:text-slate-400 text-sm">{formatTimeAgo(value as string)}</span>
      ),
    },
    {
      key: 'score',
      header: 'Threat Score',
      render: (value: unknown) => <AttackerScoreBar score={value as number} />,
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Attack Analysis</h1>
          <p className="text-slate-500 dark:text-slate-400 text-sm mt-1">
            Layer 3 ML attribution and dynamic signature management
          </p>
        </div>
        <div className="flex items-center gap-4">
          <StatusIndicator
            status={layer3Summary?.status === 'active' ? 'warning' : 'online'}
            label={layer3Summary?.status === 'active' ? 'Under Attack' : 'Normal'}
            showPulse={isUnderAttack}
          />
        </div>
      </div>

      {/* Attack Banner */}
      {isUnderAttack && (
        <div className="relative overflow-hidden rounded-xl p-4 border border-red-500/50 bg-gradient-to-r from-red-900/50 to-red-800/30 animate-pulse-slow">
          <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/5 to-transparent animate-shimmer" />
          <div className="relative flex items-center gap-4">
            <div className="p-3 bg-red-500/20 rounded-xl">
              <FireIcon className="h-8 w-8 text-red-400" />
            </div>
            <div className="flex-1">
              <div className="flex items-center gap-3">
                <h3 className="text-lg font-bold text-slate-900 dark:text-white">
                  {attackTargets.length} Active Attack{attackTargets.length > 1 ? 's' : ''} Detected
                </h3>
                <ThreatBadge level={Math.max(...attackTargets.map((a) => a.level)) as 0 | 1 | 2 | 3 | 4} />
              </div>
              <p className="text-sm text-slate-900 dark:text-white/70 mt-1">
                {attackTargets.map((a) => `${a.ip} (${a.attack_type})`).slice(0, 3).join(', ')}
                {attackTargets.length > 3 && ` +${attackTargets.length - 3} more`}
              </p>
            </div>
            <div className="text-right">
              <p className="text-xs text-slate-500 dark:text-slate-400">ML Confidence</p>
              <p className="text-2xl font-bold text-slate-900 dark:text-white">{mlConfidence.toFixed(0)}%</p>
            </div>
          </div>
        </div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Active Attacks"
          value={summaryLoading ? '...' : attackTargets.length.toString()}
          icon={FireIcon}
          color={attackTargets.length > 0 ? 'danger' : 'success'}
        />
        <MetricCard
          title="Total Attackers"
          value={summaryLoading ? '...' : formatNumber(layer3Summary?.total_attackers || 0)}
          icon={ExclamationTriangleIcon}
          color={layer3Summary?.total_attackers ? 'warning' : 'success'}
        />
        <MetricCard
          title="Active Signatures"
          value={summaryLoading ? '...' : formatNumber(layer3Summary?.total_signatures || 0)}
          icon={SparklesIcon}
          color="info"
        />
        <MetricCard
          title="Packet Ring Fill"
          value={
            summaryLoading
              ? '...'
              : `${((layer3Summary?.packet_ring_fill || 0) * 100).toFixed(1)}%`
          }
          icon={ChartBarIcon}
          color={
            (layer3Summary?.packet_ring_fill || 0) > 0.8
              ? 'warning'
              : 'success'
          }
        />
      </div>

      {/* Tabs */}
      <div className="border-b border-slate-300 dark:border-slate-700">
        <nav className="-mb-px flex space-x-3 sm:space-x-6 overflow-x-auto">
          {[
            { id: 'attacks', label: 'Attack Targets', icon: ShieldExclamationIcon, count: attackTargets.length },
            { id: 'analysis', label: 'ML Analysis', icon: CpuChipIcon },
            { id: 'signatures', label: 'Signatures', icon: SparklesIcon, count: layer3Summary?.total_signatures },
            { id: 'attackers', label: 'Top Attackers', icon: ExclamationTriangleIcon },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as TabType)}
              className={clsx(
                'flex items-center gap-2 py-4 px-1 border-b-2 font-medium text-sm transition-colors',
                activeTab === tab.id
                  ? 'border-brand-500 text-brand-400'
                  : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300 hover:border-slate-300 dark:border-slate-600'
              )}
            >
              <tab.icon className="h-5 w-5" />
              {tab.label}
              {tab.count !== undefined && tab.count > 0 && (
                <span
                  className={clsx(
                    'ml-1 px-2 py-0.5 rounded-full text-xs font-medium',
                    activeTab === tab.id
                      ? 'bg-brand-500/20 text-brand-400'
                      : 'bg-slate-200 dark:bg-slate-700 text-slate-500 dark:text-slate-400'
                  )}
                >
                  {tab.count}
                </span>
              )}
            </button>
          ))}
        </nav>
      </div>

      {/* Attack Targets Tab */}
      {activeTab === 'attacks' && (
        <div className="card">
          <div className="card-header flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-red-500/20 rounded-lg">
                <ShieldExclamationIcon className="h-5 w-5 text-red-400" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Attack Targets</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">Real-time attack detection with ML classification</p>
              </div>
            </div>
          </div>
          <div className="p-4">
            {summaryLoading ? (
              <LoadingSpinner />
            ) : attackTargets.length > 0 ? (
              <DataTable
                columns={attackColumns}
                data={attackTargets}
                emptyMessage="No active attacks"
              />
            ) : (
              <EmptyState
                icon={ShieldExclamationIcon}
                title="No Active Attacks"
                description="The system is operating normally with no detected threats"
              />
            )}
          </div>
        </div>
      )}

      {/* ML Analysis Tab */}
      {activeTab === 'analysis' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* ML Confidence Radar */}
          <div className="card">
            <div className="card-header flex items-center gap-3">
              <div className="p-2 bg-purple-500/20 rounded-lg">
                <CpuChipIcon className="h-5 w-5 text-purple-400" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-slate-900 dark:text-white">ML Confidence Analysis</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">Multi-dimensional threat assessment</p>
              </div>
            </div>
            <div className="p-4">
              <MLConfidenceChart attacks={attackTargets} />
            </div>
          </div>

          {/* Attack Type Distribution */}
          <div className="card">
            <div className="card-header flex items-center gap-3">
              <div className="p-2 bg-cyan-500/20 rounded-lg">
                <ChartBarIcon className="h-5 w-5 text-cyan-400" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Attack Type Distribution</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">Classification breakdown</p>
              </div>
            </div>
            <div className="p-4">
              {attackTargets.length > 0 ? (
                <AttackTypeBreakdown attacks={attackTargets} />
              ) : (
                <EmptyState
                  icon={ChartBarIcon}
                  title="No Data"
                  description="Attack distribution appears when threats are detected"
                />
              )}
            </div>
          </div>

          {/* ML Metrics */}
          <div className="card lg:col-span-2">
            <div className="card-header">
              <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Model Performance Metrics</h3>
            </div>
            <div className="p-6">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
                <div className="text-center">
                  <GaugeChart
                    value={mlConfidence}
                    max={100}
                    label="Confidence"
                    color="#6366f1"
                    size={120}
                  />
                  <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">Overall Confidence</p>
                </div>
                <div className="text-center">
                  <GaugeChart
                    value={
                      attackTargets.length > 0
                        ? (attackTargets.reduce((s, a) => s + a.tier_agreement, 0) / attackTargets.length / 3) * 100
                        : 100
                    }
                    max={100}
                    label="Agreement"
                    color="#22c55e"
                    size={120}
                  />
                  <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">Tier Agreement</p>
                </div>
                <div className="text-center">
                  <GaugeChart
                    value={(layer3Summary?.packet_ring_fill || 0) * 100}
                    max={100}
                    label="Buffer"
                    color="#f59e0b"
                    size={120}
                  />
                  <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">Ring Buffer</p>
                </div>
                <div className="text-center">
                  <GaugeChart
                    value={
                      attackTargets.length > 0
                        ? Math.min(100, attackTargets.reduce((s, a) => s + a.z_score, 0) / attackTargets.length * 10)
                        : 0
                    }
                    max={100}
                    label="Z-Score"
                    color="#ef4444"
                    size={120}
                  />
                  <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">Avg Z-Score</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Signatures Tab */}
      {activeTab === 'signatures' && (
        <div className="space-y-4">
          <div className="flex justify-end gap-3">
            <button
              onClick={() => generateMutation.mutate()}
              disabled={generateMutation.isPending || !isUnderAttack}
              className="btn btn-secondary flex items-center gap-2"
            >
              <ArrowPathIcon
                className={clsx('h-4 w-4', generateMutation.isPending && 'animate-spin')}
              />
              {generateMutation.isPending ? 'Generating...' : 'Auto-Generate'}
            </button>
            <button
              onClick={() => setShowAddSignature(true)}
              className="btn btn-primary flex items-center gap-2"
            >
              <PlusIcon className="h-4 w-4" />
              Add Signature
            </button>
          </div>

          <div className="card">
            <div className="card-header flex items-center gap-3">
              <div className="p-2 bg-purple-500/20 rounded-lg">
                <SparklesIcon className="h-5 w-5 text-purple-400" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Dynamic Signatures</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">ML-generated and custom attack signatures</p>
              </div>
            </div>
            <div className="p-4">
              {signaturesLoading ? (
                <LoadingSpinner />
              ) : signaturesData?.signatures && signaturesData.signatures.length > 0 ? (
                <DataTable
                  columns={signatureColumns}
                  data={signaturesData.signatures}
                  emptyMessage="No signatures"
                />
              ) : (
                <EmptyState
                  icon={SparklesIcon}
                  title="No Signatures Configured"
                  description="Add custom signatures or auto-generate from active attacks"
                  action={
                    <button
                      onClick={() => setShowAddSignature(true)}
                      className="btn btn-primary mt-4"
                    >
                      <PlusIcon className="h-4 w-4 mr-2" />
                      Add Signature
                    </button>
                  }
                />
              )}
            </div>
          </div>
        </div>
      )}

      {/* Attackers Tab */}
      {activeTab === 'attackers' && (
        <div className="card">
          <div className="card-header flex items-center gap-3">
            <div className="p-2 bg-orange-500/20 rounded-lg">
              <ExclamationTriangleIcon className="h-5 w-5 text-orange-400" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Top Attackers</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">Source IPs ranked by threat score</p>
            </div>
          </div>
          <div className="p-4">
            {attackersLoading ? (
              <LoadingSpinner />
            ) : attackersData?.attackers && attackersData.attackers.length > 0 ? (
              <DataTable
                columns={attackerColumns}
                data={attackersData.attackers}
                emptyMessage="No attackers"
              />
            ) : (
              <EmptyState
                icon={ExclamationTriangleIcon}
                title="No Attackers Recorded"
                description="Attacker data will appear when threats are detected"
              />
            )}
          </div>
        </div>
      )}

      {/* Attack Detail Modal */}
      {selectedAttack && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4">
            <div className="fixed inset-0 bg-black/70" onClick={() => setSelectedAttack(null)} />
            <div className="relative bg-white dark:bg-slate-900 rounded-xl shadow-2xl max-w-lg w-full border border-slate-300 dark:border-slate-700 animate-scale-in">
              <div className="p-6">
                <div className="flex items-center justify-between mb-6">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-red-500/20 rounded-lg">
                      <ShieldExclamationIcon className="h-6 w-6 text-red-400" />
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Attack Details</h3>
                      <p className="text-sm text-slate-500 dark:text-slate-400 font-mono">{selectedAttack.ip}</p>
                    </div>
                  </div>
                  <button
                    onClick={() => setSelectedAttack(null)}
                    className="p-2 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors"
                  >
                    <XMarkIcon className="h-5 w-5 text-slate-500 dark:text-slate-400" />
                  </button>
                </div>

                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-500 dark:text-slate-400">Severity Level</span>
                    <ThreatBadge level={selectedAttack.level as 0 | 1 | 2 | 3 | 4} />
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-3">
                      <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Attack Type</p>
                      <p className="text-slate-900 dark:text-white font-medium">{selectedAttack.attack_type}</p>
                    </div>
                    <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-3">
                      <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Protocol</p>
                      <p className="text-slate-900 dark:text-white font-medium uppercase">{selectedAttack.protocol}</p>
                    </div>
                    <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-3">
                      <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Z-Score</p>
                      <p className="text-red-600 dark:text-red-400 font-bold">{selectedAttack.z_score?.toFixed(2)}</p>
                    </div>
                    <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-3">
                      <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">Destination Port</p>
                      <p className="text-slate-900 dark:text-white font-medium">{selectedAttack.dst_port || 'N/A'}</p>
                    </div>
                  </div>

                  <div className="bg-slate-100 dark:bg-slate-800/50 rounded-lg p-4">
                    <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">ML Tier Agreement</p>
                    <div className="flex items-center justify-between">
                      <TierAgreementVisualization tierAgreement={selectedAttack.tier_agreement} />
                      <span className="text-lg font-bold text-slate-900 dark:text-white">
                        {selectedAttack.tier_agreement}/3 tiers
                      </span>
                    </div>
                  </div>
                </div>

                <div className="mt-6 flex gap-3">
                  <button
                    onClick={() => setSelectedAttack(null)}
                    className="flex-1 btn btn-ghost"
                  >
                    Close
                  </button>
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
                    <div className="p-2 bg-purple-500/20 rounded-lg">
                      <SparklesIcon className="h-6 w-6 text-purple-400" />
                    </div>
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Add Signature</h3>
                  </div>
                  <button
                    onClick={() => setShowAddSignature(false)}
                    className="p-2 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors"
                  >
                    <XMarkIcon className="h-5 w-5 text-slate-500 dark:text-slate-400" />
                  </button>
                </div>

                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    addSignatureMutation.mutate(signatureForm);
                  }}
                  className="space-y-4"
                >
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Name</label>
                    <input
                      type="text"
                      value={signatureForm.name}
                      onChange={(e) => setSignatureForm((f) => ({ ...f, name: e.target.value }))}
                      className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Protocol</label>
                    <select
                      value={signatureForm.protocol}
                      onChange={(e) => setSignatureForm((f) => ({ ...f, protocol: e.target.value }))}
                      className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
                    >
                      <option value="tcp">TCP</option>
                      <option value="udp">UDP</option>
                      <option value="icmp">ICMP</option>
                    </select>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                        Source IP
                      </label>
                      <input
                        type="text"
                        value={signatureForm.src_ip}
                        onChange={(e) => setSignatureForm((f) => ({ ...f, src_ip: e.target.value }))}
                        placeholder="Optional"
                        className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                        Dest IP
                      </label>
                      <input
                        type="text"
                        value={signatureForm.dst_ip}
                        onChange={(e) => setSignatureForm((f) => ({ ...f, dst_ip: e.target.value }))}
                        placeholder="Optional"
                        className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                        Source Port
                      </label>
                      <input
                        type="number"
                        value={signatureForm.src_port}
                        onChange={(e) =>
                          setSignatureForm((f) => ({ ...f, src_port: e.target.value }))
                        }
                        placeholder="Optional"
                        className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                        Dest Port
                      </label>
                      <input
                        type="number"
                        value={signatureForm.dst_port}
                        onChange={(e) =>
                          setSignatureForm((f) => ({ ...f, dst_port: e.target.value }))
                        }
                        placeholder="Optional"
                        className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
                      />
                    </div>
                  </div>

                  <div className="flex justify-end gap-3 pt-4">
                    <button
                      type="button"
                      onClick={() => setShowAddSignature(false)}
                      className="btn btn-ghost"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={addSignatureMutation.isPending}
                      className="btn btn-primary"
                    >
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

export default AttacksPage;
