/**
 * Configuration Page
 *
 * System configuration for Layer 1 (packet processing) parameters.
 * Uses instant-save per-field pattern with optimistic toggle updates
 * and animated collapsible sections.
 */

import { useState, useRef, useEffect, useMemo, useCallback } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Cog6ToothIcon,
  ArrowPathIcon,
  ClockIcon,
  GlobeAltIcon,
  UserIcon,
  ArrowTrendingUpIcon,
  ShieldExclamationIcon,
  FlagIcon,
  SignalIcon,
  WrenchScrewdriverIcon,
  ExclamationTriangleIcon,
  AdjustmentsHorizontalIcon,
} from '@heroicons/react/24/outline';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import api from '../services/api';
import { ConfigHistoryEntry, AnomalyStatus, SuppressedDetection } from '../types';
import { SkeletonCard } from '../components/ui/LoadingSpinner';
import {
  Toggle,
  NumberInput,
  SelectInput,
  SectionCard,
  FieldRow,
  InfoBanner,
  Modal,
} from '../components/ui/FormControls';
import { PageHeader } from '../components/ui';

// Section display names -- plain language for operators, not internal C struct names
const SECTION_NAMES: Record<string, string> = {
  flow_table: 'Connection Tracking',
  syn_proxy: 'TCP Flood Protection',
  connection_limits: 'Connection Limit Enforcement',
  udp_gatekeeper: 'UDP Flood Protection',
  rate_limits: 'Traffic Rate Limiting',
  tcp_flag_rate: 'TCP Flag Rate Limits',
  tcp_abuse: 'TCP Abuse Detection',
  telemetry: 'Statistics & Telemetry',
  ports: 'Network Port Configuration',
  maintenance: 'Background Maintenance',
  ip_lists: 'IP Access List Limits',
};

const RULES_MANAGED_SECTIONS = ['geo_blocking', 'signatures', 'other_protocols', 'validation'];

const SECTION_DESCRIPTIONS: Record<string, string> = {
  flow_table: 'Track active connections and manage flow state tables',
  syn_proxy: 'Protect against SYN floods using cryptographic cookie challenges',
  connection_limits: 'Limit how many simultaneous connections a single IP can hold',
  udp_gatekeeper: 'Protect against UDP floods by tracking per-source request volume',
  rate_limits: 'Control traffic rates per source, per destination, with progressive scaling',
  tcp_flag_rate: 'Set independent rate limits for each TCP flag type (SYN, ACK, RST, etc.)',
  tcp_abuse: 'Detect and respond to TCP protocol abuse patterns like duplicate sequences',
  telemetry: 'Configure statistics export intervals and flow sampling rates',
  ports: 'Map physical network interfaces for inbound and outbound traffic',
  maintenance: 'Set intervals for background cleanup and housekeeping tasks',
  ip_lists: 'Configure maximum entries for whitelist, blacklist, and greylist tables',
};

const LOG_LEVELS = [
  { value: 0, label: '0 - Emergency' }, { value: 1, label: '1 - Alert' },
  { value: 2, label: '2 - Critical' }, { value: 3, label: '3 - Error' },
  { value: 4, label: '4 - Warning' }, { value: 5, label: '5 - Notice' },
  { value: 6, label: '6 - Info' }, { value: 7, label: '7 - Debug' },
  { value: 8, label: '8 - Debug+' },
];

const ANOMALY_LEVELS = [
  { value: 1, label: '1 - Low' }, { value: 2, label: '2 - Medium' },
  { value: 3, label: '3 - High' }, { value: 4, label: '4 - Critical' },
];

// ==================== Sub-Grouped Section Types ====================

interface SubGroupField {
  key: string;
  label: string;
  desc: string;
}

interface SubGroup {
  id: string;
  title: string;
  description: string;
  icon: typeof GlobeAltIcon;
  accent: string;
  fields: SubGroupField[];
}

// ==================== Rate Limits Sub-Groups ====================

const RATE_LIMIT_GROUPS: SubGroup[] = [
  {
    id: 'global',
    title: 'Global Thresholds',
    description: 'System-wide rate caps applied to all traffic before per-source checks',
    icon: GlobeAltIcon,
    accent: 'text-blue-500 dark:text-blue-400',
    fields: [
      { key: 'global_pps_limit', label: 'Global PPS Limit', desc: 'Maximum packets/sec across all sources. 0 = unlimited.' },
      { key: 'global_bps_limit', label: 'Global BPS Limit', desc: 'Maximum bits/sec across all sources. 0 = unlimited.' },
    ],
  },
  {
    id: 'per-source',
    title: 'Per-Source IP',
    description: 'Individual rate limits applied to each source IP address',
    icon: UserIcon,
    accent: 'text-emerald-500 dark:text-emerald-400',
    fields: [
      { key: 'normal_pps_per_ip', label: 'Normal PPS / IP', desc: 'Packets/sec per source during normal operation' },
      { key: 'normal_bps_per_ip', label: 'Normal BPS / IP', desc: 'Bits/sec per source during normal operation' },
      { key: 'attack_pps_per_ip', label: 'Attack PPS / IP', desc: 'Reduced packets/sec per source when attack detected' },
      { key: 'attack_bps_per_ip', label: 'Attack BPS / IP', desc: 'Reduced bits/sec per source when attack detected' },
      { key: 'dynamic_enabled', label: 'Dynamic Switching', desc: 'Auto-switch between normal and attack limits based on anomaly detection' },
      { key: 'anomaly_detection_window', label: 'Detection Window (sec)', desc: 'Time window for anomaly detection before switching limits' },
    ],
  },
  {
    id: 'progressive',
    title: 'Progressive Scaling',
    description: 'Gradually tighten limits as attack severity increases through 4 levels',
    icon: ArrowTrendingUpIcon,
    accent: 'text-amber-500 dark:text-amber-400',
    fields: [
      { key: 'progressive_enabled', label: 'Progressive Mode', desc: 'Enable multi-level progressive rate limiting' },
      { key: 'level_low_percent', label: 'Low Severity (%)', desc: 'Rate limit as % of normal — mild anomaly detected' },
      { key: 'level_medium_percent', label: 'Medium Severity (%)', desc: 'Rate limit as % of normal — sustained anomaly' },
      { key: 'level_high_percent', label: 'High Severity (%)', desc: 'Rate limit as % of normal — active attack confirmed' },
      { key: 'level_critical_percent', label: 'Critical Severity (%)', desc: 'Rate limit as % of normal — severe volumetric attack' },
    ],
  },
  {
    id: 'spoofed',
    title: 'Spoofed Flood Protection',
    description: 'Per-destination aggregate limiting activated during spoofed source floods',
    icon: ShieldExclamationIcon,
    accent: 'text-red-500 dark:text-red-400',
    fields: [
      { key: 'spoofed_aggregate_enabled', label: 'Aggregate Mode', desc: 'Switch to per-destination aggregate limits during spoofed floods' },
      { key: 'spoofed_adaptive_limit_pct', label: 'Adaptive Limit (%)', desc: 'Threshold as % of learned baseline PPS per destination' },
      { key: 'spoofed_min_dst_pps', label: 'Min Destination PPS', desc: 'Floor PPS per destination — never limit below this rate' },
      { key: 'spoofed_syn_per_dst_limit', label: 'SYN / Destination Limit', desc: 'Max SYN packets/sec per destination before probabilistic drop' },
      { key: 'spoofed_packet_multiplier', label: 'Unvalidated Multiplier', desc: 'Packets from unvalidated sources count Nx toward threshold' },
      { key: 'legitimate_table_size', label: 'Legitimate Table Size', desc: 'Max entries in validated source IP table (SYN cookie passers)' },
      { key: 'legitimate_ttl_sec', label: 'Legitimate TTL (sec)', desc: 'Time before validated sources expire from fast-path table' },
    ],
  },
];

// ==================== TCP Flag Rate Sub-Groups ====================

const TCP_FLAG_RATE_GROUPS: SubGroup[] = [
  {
    id: 'general',
    title: 'General Settings',
    description: 'Module-level controls and table management',
    icon: WrenchScrewdriverIcon,
    accent: 'text-slate-500 dark:text-slate-400',
    fields: [
      { key: 'enabled', label: 'Enabled', desc: 'Enable per-TCP-flag rate limiting (Stage 9b)' },
      { key: 'max_entries', label: 'Max Tracked IPs', desc: 'Maximum source IPs to track concurrently' },
      { key: 'cleanup_interval_sec', label: 'Cleanup Interval (sec)', desc: 'How often expired entries are removed' },
      { key: 'report_violations', label: 'Report to Layer 4', desc: 'Send violation events for reputation updates' },
    ],
  },
  {
    id: 'flag-limits',
    title: 'Per-Flag PPS Limits',
    description: 'Independent rate limits for each TCP flag class per source IP. 0 = unlimited.',
    icon: FlagIcon,
    accent: 'text-indigo-500 dark:text-indigo-400',
    fields: [
      { key: 'syn_pps', label: 'SYN PPS', desc: 'SYN (no ACK) — connection initiation flood protection' },
      { key: 'syn_ack_pps', label: 'SYN+ACK PPS', desc: 'SYN+ACK responses — reflection attack protection' },
      { key: 'ack_pps', label: 'ACK PPS', desc: 'Pure ACK — high limit for bulk data transfers' },
      { key: 'rst_pps', label: 'RST PPS', desc: 'RST — connection reset flood protection' },
      { key: 'fin_pps', label: 'FIN PPS', desc: 'FIN — connection teardown flood protection' },
      { key: 'psh_pps', label: 'PSH PPS', desc: 'PSH — data push, needs higher limit for real traffic' },
      { key: 'urg_pps', label: 'URG PPS', desc: 'URG — rare in legitimate traffic, low limit recommended' },
      { key: 'other_pps', label: 'Other PPS', desc: 'Other flag combinations not matching above classes' },
    ],
  },
];

// ==================== TCP Abuse Detection Sub-Groups ====================

const TCP_ABUSE_GROUPS: SubGroup[] = [
  {
    id: 'general',
    title: 'General Settings',
    description: 'Module controls and feedback',
    icon: WrenchScrewdriverIcon,
    accent: 'text-slate-500 dark:text-slate-400',
    fields: [
      { key: 'enabled', label: 'Enabled', desc: 'Enable TCP protocol abuse detection' },
      { key: 'report_to_layer4', label: 'Report to Layer 4', desc: 'Send detections for reputation score updates' },
    ],
  },
  {
    id: 'thresholds',
    title: 'Detection Thresholds',
    description: 'Sensitivity tuning for each abuse pattern',
    icon: SignalIcon,
    accent: 'text-cyan-500 dark:text-cyan-400',
    fields: [
      { key: 'dup_seq_threshold', label: 'Dup SEQ Threshold', desc: 'Duplicate SEQ numbers per second to flag as flood' },
      { key: 'random_seq_threshold', label: 'Random SEQ Threshold', desc: 'Random SEQ jumps in 10s window to flag' },
      { key: 'random_ack_threshold', label: 'Random ACK Threshold', desc: 'Random ACK jumps in 10s window to flag' },
      { key: 'zero_window_threshold', label: 'Zero Window Threshold', desc: 'Zero window events in 10s to flag as attack' },
      { key: 'tiny_window_bytes', label: 'Tiny Window (bytes)', desc: 'Window size below this is considered tiny' },
      { key: 'small_window_bytes', label: 'Small Window (bytes)', desc: 'Window size below this is considered small' },
      { key: 'same_window_threshold', label: 'Same Window Threshold', desc: 'Same window value per second to flag as flood' },
      { key: 'same_ack_threshold', label: 'Same ACK Threshold', desc: 'Same ACK number per second to flag as flood' },
    ],
  },
  {
    id: 'actions',
    title: 'Response Actions',
    description: 'What to do when each abuse type is detected: 0 = Log only, 1 = Drop, 2 = Rate limit',
    icon: ExclamationTriangleIcon,
    accent: 'text-orange-500 dark:text-orange-400',
    fields: [
      { key: 'action_dup_seq', label: 'Dup SEQ Action', desc: 'Action for duplicate SEQ number floods' },
      { key: 'action_random_seq', label: 'Random SEQ Action', desc: 'Action for random SEQ jump floods' },
      { key: 'action_random_ack', label: 'Random ACK Action', desc: 'Action for random ACK jump floods' },
      { key: 'action_zero_window', label: 'Zero Window Action', desc: 'Action for zero window attacks' },
      { key: 'action_tiny_window', label: 'Tiny Window Action', desc: 'Action for tiny window attacks' },
      { key: 'action_small_window', label: 'Small Window Action', desc: 'Action for small window (may be legitimate)' },
      { key: 'action_same_window', label: 'Same Window Action', desc: 'Action for same window value floods' },
      { key: 'action_same_ack', label: 'Same ACK Action', desc: 'Action for same ACK value floods' },
    ],
  },
];

import {
  FEATURE_DISPLAY_NAMES,
  FEATURE_GROUP_ORDER,
  GROUP_DESCRIPTIONS,
  FEATURE_INFO,
  qualityColor,
  qualityLabel,
} from './featureConfig';

// ==================== Configuration Tabs ====================

interface ConfigTab {
  id: string;
  label: string;
  sections: string[];  // Section keys rendered under this tab
}

const CONFIG_TABS: ConfigTab[] = [
  {
    id: 'general',
    label: 'General',
    sections: ['ip_lists', 'ports', 'maintenance', 'telemetry'],
  },
  {
    id: 'tcp',
    label: 'TCP Protection',
    sections: ['syn_proxy', 'flow_table', 'connection_limits'],
  },
  {
    id: 'rate-limiting',
    label: 'Rate Limiting',
    sections: ['rate_limits', 'tcp_flag_rate', 'tcp_abuse'],
  },
  {
    id: 'udp',
    label: 'UDP Protection',
    sections: ['udp_gatekeeper'],
  },
  {
    id: 'anomaly-detection',
    label: 'Anomaly Detection',
    sections: [],  // Custom L2 rendering
  },
  {
    id: 'feature-selection',
    label: 'Feature Selection',
    sections: [],  // Custom feature enable/disable rendering
  },
  {
    id: 'attack-response',
    label: 'Attack Response',
    sections: [],  // Custom L1+L2 rendering
  },
  {
    id: 'adaptive',
    label: 'Adaptive',
    sections: [],  // Custom L2 adaptive rendering
  },
];

// ==================== Feature Selection Tab ====================

function FeatureSelectionTab() {
  const queryClient = useQueryClient();
  const [enabledFeatures, setEnabledFeatures] = useState<boolean[]>([]);
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [autoSelectSaving, setAutoSelectSaving] = useState(false);

  // IP scope selector: null = global, string = specific protected IP
  const [selectedScope, setSelectedScope] = useState<string | null>(null);

  // Feature weights state (global scope only)
  const [weights, setWeights] = useState<number[]>([]);
  const [weightsDirty, setWeightsDirty] = useState(false);
  const [weightsSaving, setWeightsSaving] = useState(false);

  const { data: l2Config } = useQuery({
    queryKey: ['layer2-config'],
    queryFn: () => api.getLayer2Config(),
  });

  const useFeatureWeights = !!(l2Config as Record<string, unknown>)?.use_feature_weights;
  const configWeights = ((l2Config as Record<string, unknown>)?.feature_weights as number[]) ?? [];

  // Sync weights from config (global only)
  useEffect(() => {
    if (configWeights.length > 0 && weights.length === 0) {
      setWeights([...configWeights]);
      setWeightsDirty(false);
    }
  }, [configWeights, weights.length]);

  // Global feature data (always loaded for quality info)
  const { data: featureData, isLoading } = useQuery({
    queryKey: ['layer2-features'],
    queryFn: () => api.getLayer2Features(),
    staleTime: 30 * 1000,
  });

  // Protected IPs for scope selector
  const { data: protectedIPsData } = useQuery({
    queryKey: ['rules-protected'],
    queryFn: () => api.getRulesProtected(),
  });

  // Per-IP features (only when a specific IP is selected)
  const { data: perIPFeatureData, isLoading: perIPLoading } = useQuery({
    queryKey: ['per-ip-features', selectedScope],
    queryFn: () => api.getPerIPFeatures(selectedScope!),
    enabled: selectedScope !== null,
    staleTime: 5000,
  });

  // Sync enabledFeatures when scope or underlying data changes
  useEffect(() => {
    if (selectedScope === null) {
      if (featureData?.features) {
        setEnabledFeatures(featureData.features.map(f => f.enabled));
        setDirty(false);
      }
    } else {
      if (perIPFeatureData?.features) {
        setEnabledFeatures(perIPFeatureData.features.map(f => f.enabled));
        setDirty(false);
      }
    }
  }, [selectedScope, featureData, perIPFeatureData]);

  const features = featureData?.features ?? [];
  const autoSelect = featureData?.auto_select ?? { enabled: false, min_quality: 0.05, min_samples: 300 };
  const perIPSource = perIPFeatureData?.source ?? 'global';

  // Group features by their group
  const grouped = useMemo(() => {
    const map = new Map<string, typeof features>();
    for (const feat of features) {
      const existing = map.get(feat.group) ?? [];
      existing.push(feat);
      map.set(feat.group, existing);
    }
    return FEATURE_GROUP_ORDER
      .filter(g => map.has(g))
      .map(g => ({ group: g, features: map.get(g)! }));
  }, [features]);

  const toggleFeature = useCallback((index: number) => {
    setEnabledFeatures(prev => {
      const next = [...prev];
      next[index] = !next[index];
      return next;
    });
    setDirty(true);
  }, []);

  const toggleGroup = useCallback((groupFeatures: typeof features, select: boolean) => {
    setEnabledFeatures(prev => {
      const next = [...prev];
      for (const f of groupFeatures) {
        next[f.index] = select;
      }
      return next;
    });
    setDirty(true);
  }, []);

  const selectAll = useCallback(() => {
    setEnabledFeatures(prev => prev.map(() => true));
    setDirty(true);
  }, []);

  const clearAll = useCallback(() => {
    setEnabledFeatures(prev => prev.map(() => false));
    setDirty(true);
  }, []);

  const save = useCallback(async () => {
    setSaving(true);
    try {
      if (selectedScope === null) {
        await api.setLayer2FeaturesEnabled(enabledFeatures);
        queryClient.invalidateQueries({ queryKey: ['layer2-features'] });
        toast.success('Feature selection saved');
      } else {
        await api.setPerIPFeatures(selectedScope, enabledFeatures);
        queryClient.invalidateQueries({ queryKey: ['per-ip-features', selectedScope] });
        toast.success(`Feature selection saved for ${selectedScope}`);
      }
      setDirty(false);
    } catch {
      toast.error('Failed to save feature selection');
    } finally {
      setSaving(false);
    }
  }, [enabledFeatures, queryClient, selectedScope]);

  const resetPerIP = useCallback(async () => {
    if (!selectedScope) return;
    setSaving(true);
    try {
      await api.resetPerIPFeatures(selectedScope);
      queryClient.invalidateQueries({ queryKey: ['per-ip-features', selectedScope] });
      setDirty(false);
      toast.success(`${selectedScope} reset to global feature defaults`);
    } catch {
      toast.error('Failed to reset per-IP features');
    } finally {
      setSaving(false);
    }
  }, [selectedScope, queryClient]);

  const toggleAutoSelect = useCallback(async () => {
    setAutoSelectSaving(true);
    try {
      await api.setLayer2AutoSelect(!autoSelect.enabled);
      queryClient.invalidateQueries({ queryKey: ['layer2-features'] });
      toast.success(autoSelect.enabled ? 'Auto-select disabled' : 'Auto-select enabled');
    } catch {
      toast.error('Failed to toggle auto-select');
    } finally {
      setAutoSelectSaving(false);
    }
  }, [autoSelect.enabled, queryClient]);

  const applyRecommendations = useCallback(async () => {
    // Disable all auto-downweighted features permanently
    const newEnabled = features.map((f, i) =>
      f.quality?.auto_disabled ? false : (enabledFeatures[i] ?? true)
    );
    setSaving(true);
    try {
      await api.setLayer2FeaturesEnabled(newEnabled);
      queryClient.invalidateQueries({ queryKey: ['layer2-features'] });
      setDirty(false);
      toast.success('Applied auto-select recommendations');
    } catch {
      toast.error('Failed to apply recommendations');
    } finally {
      setSaving(false);
    }
  }, [features, enabledFeatures, queryClient]);

  const enabledCount = enabledFeatures.filter(Boolean).length;
  const totalCount = enabledFeatures.length;
  const autoDisabledCount = features.filter(f => f.quality?.auto_disabled).length;
  const fullWeightCount = features.filter(f => !f.quality?.auto_disabled).length;

  if (isLoading) {
    return <SkeletonCard lines={6} />;
  }

  const protectedIPs = (protectedIPsData as { entries?: Array<{ ip: string }> } | undefined)?.entries ?? [];

  return (
    <div className="space-y-3 animate-fade-in">
      {/* IP Scope Selector */}
      <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-3 flex flex-wrap items-center gap-3">
        <span className="text-sm font-medium text-slate-700 dark:text-slate-200 flex-shrink-0">
          Editing for:
        </span>
        <select
          value={selectedScope ?? ''}
          onChange={(e) => {
            setSelectedScope(e.target.value === '' ? null : e.target.value);
            setDirty(false);
          }}
          className="flex-1 min-w-48 px-3 py-1.5 text-sm bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-600 rounded-lg text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
        >
          <option value="">Global (all IPs)</option>
          {protectedIPs.map(({ ip }) => (
            <option key={ip} value={ip}>{ip}</option>
          ))}
        </select>
        {selectedScope !== null && (
          <div className="flex items-center gap-2">
            {perIPSource === 'global' ? (
              <span className="text-xs px-2 py-1 rounded-full bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400">
                Inherits global
              </span>
            ) : (
              <span className="text-xs px-2 py-1 rounded-full bg-violet-100 dark:bg-violet-900/30 text-violet-700 dark:text-violet-300">
                Per-IP custom
              </span>
            )}
            {perIPSource === 'per_ip' && (
              <button
                onClick={resetPerIP}
                disabled={saving}
                className="text-xs px-3 py-1.5 rounded-lg border border-red-300 dark:border-red-700 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors disabled:opacity-50"
              >
                Reset to Global
              </button>
            )}
          </div>
        )}
        {perIPLoading && (
          <ArrowPathIcon className="h-4 w-4 animate-spin text-brand-500" />
        )}
      </div>

      {/* How Detection Works */}
      <div className="rounded-lg border border-blue-200 dark:border-blue-800 bg-blue-50/50 dark:bg-blue-950/20 p-4">
        <h3 className="text-sm font-semibold text-blue-800 dark:text-blue-300 mb-2 flex items-center gap-2">
          <ShieldExclamationIcon className="h-4 w-4" />
          How Feature-Based Anomaly Detection Works
        </h3>
        <div className="text-xs text-blue-700 dark:text-blue-400 space-y-2">
          <p>
            Layer 2 monitors <strong>{totalCount} traffic features</strong> in real time and compares each against learned baselines using Z-score analysis.
            When multiple features deviate significantly from their baselines simultaneously, an anomaly (potential attack) is detected.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-2">
            <div className="bg-white/60 dark:bg-slate-800/40 rounded p-2">
              <p className="font-semibold mb-0.5">1. Baseline Learning</p>
              <p>The system continuously learns normal traffic patterns using EWMA (Exponentially Weighted Moving Average) across three time tiers: immediate (1s/10s/60s), hourly (24 slots), and weekly (168 slots). Each feature builds a statistical profile of what "normal" looks like.</p>
            </div>
            <div className="bg-white/60 dark:bg-slate-800/40 rounded p-2">
              <p className="font-semibold mb-0.5">2. Z-Score Detection</p>
              <p>Every detection cycle (~1s), the current value of each enabled feature is compared to its baseline. The Z-score measures how many standard deviations the current value is from the mean. Scores above the threshold (default: 4.0) flag that feature as anomalous.</p>
            </div>
            <div className="bg-white/60 dark:bg-slate-800/40 rounded p-2">
              <p className="font-semibold mb-0.5">3. Multi-Tier Agreement</p>
              <p>To reduce false positives, at least 2 of the 3 tiers must agree on anomaly before an alert triggers. Each tier captures a different time scale, so agreement means the deviation is significant relative to both short-term and long-term patterns.</p>
            </div>
          </div>
          <p className="mt-1">
            <strong>Disabling a feature</strong> excludes it from both Z-score computation and baseline learning.
            <strong> Feature weights</strong> control how much each feature contributes to the combined anomaly score (0.1 = minimal, 1.0 = full weight).
            The quality indicators below each feature show how useful it is for detection based on observed traffic variance.
          </p>
        </div>
      </div>

      {/* Auto-Select Card -- global scope only */}
      {selectedScope === null && <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <ArrowTrendingUpIcon className="h-5 w-5 text-brand-500" />
            <div>
              <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">Auto-Select</h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Automatically downweight low-quality features based on learned traffic patterns
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {autoSelect.enabled && autoDisabledCount > 0 && (
              <button
                onClick={applyRecommendations}
                disabled={saving}
                className="btn btn-sm btn-secondary"
                title="Permanently disable all auto-downweighted features (sets feature_enabled to false)"
              >
                Apply Recommendations
              </button>
            )}
            <button
              onClick={toggleAutoSelect}
              disabled={autoSelectSaving}
              className={clsx(
                'relative inline-flex h-6 w-11 items-center rounded-full transition-colors',
                autoSelect.enabled ? 'bg-brand-500' : 'bg-slate-300 dark:bg-slate-600'
              )}
            >
              <span className={clsx(
                'inline-block h-4 w-4 transform rounded-full bg-white transition-transform',
                autoSelect.enabled ? 'translate-x-6' : 'translate-x-1'
              )} />
            </button>
          </div>
        </div>

        {/* Auto-select explanation */}
        <div className="mt-3 text-xs text-slate-500 dark:text-slate-400 space-y-2">
          <p>
            When enabled, auto-select evaluates each feature's <strong>quality score</strong> (0-100%) by analyzing the learned baselines.
            Features that never vary, are always zero, or have no dynamic range are automatically downweighted to 10% contribution
            instead of being fully disabled &mdash; this keeps them as a safety net while reducing noise.
          </p>
          {autoSelect.enabled && (
            <>
              <div className="flex flex-wrap items-center gap-4 py-1.5 px-3 rounded bg-slate-50 dark:bg-slate-700/50">
                <span><strong>{fullWeightCount}</strong>/{totalCount} features at full weight</span>
                {autoDisabledCount > 0 && (
                  <span className="text-amber-600 dark:text-amber-400">
                    <strong>{autoDisabledCount}</strong> downweighted to 0.1x
                  </span>
                )}
                <span className="border-l border-slate-300 dark:border-slate-600 pl-4">Quality threshold: {(autoSelect.min_quality * 100).toFixed(0)}%</span>
                <span>Requires: {autoSelect.min_samples}+ baseline samples (~{Math.ceil(autoSelect.min_samples / 60)} min)</span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                <div className="flex items-start gap-2">
                  <span className="mt-0.5 h-2.5 w-2.5 rounded-full bg-green-500 flex-shrink-0" />
                  <div>
                    <p className="font-medium text-slate-600 dark:text-slate-300">Strong signal (50-100%)</p>
                    <p>Feature varies meaningfully with traffic patterns. Full detection weight applied. Coefficient of Variation (CV) and dynamic range are both healthy.</p>
                  </div>
                </div>
                <div className="flex items-start gap-2">
                  <span className="mt-0.5 h-2.5 w-2.5 rounded-full bg-amber-500 flex-shrink-0" />
                  <div>
                    <p className="font-medium text-slate-600 dark:text-slate-300">Moderate signal (5-50%)</p>
                    <p>Feature has some variance but limited dynamic range. Weight is reduced proportionally. May become stronger as baselines mature or traffic patterns change.</p>
                  </div>
                </div>
                <div className="flex items-start gap-2">
                  <span className="mt-0.5 h-2.5 w-2.5 rounded-full bg-red-500 flex-shrink-0" />
                  <div>
                    <p className="font-medium text-slate-600 dark:text-slate-300">Low signal (&lt;5%)</p>
                    <p>Feature is constant, always zero, or has negligible variance. Downweighted to 0.1x. Common for protocol-specific features absent from your traffic (e.g., ICMP on TCP-only networks).</p>
                  </div>
                </div>
              </div>
              <p className="text-[11px] text-slate-400 dark:text-slate-500">
                <strong>Safety:</strong> Volume features (PPS, BPS, Flows/s) are never auto-downweighted. A minimum of 10 features always remain at full weight.
                Auto-selection adjusts weights at runtime only &mdash; it does not persist to the config file, so restarting the system resets to your manual settings.
                Quality is re-evaluated every ~1 hour to adapt to changing traffic profiles (e.g., UDP traffic appearing at night).
                <strong> "Apply Recommendations"</strong> permanently disables the low-quality features (sets them to off) &mdash; use this if you want the auto-select decisions to persist.
              </p>
            </>
          )}
          {!autoSelect.enabled && (
            <p className="text-[11px] text-slate-400 dark:text-slate-500">
              Quality scores are calculated from baseline data: <strong>CV</strong> (Coefficient of Variation = stddev / mean) measures how much a feature varies,
              and <strong>Range</strong> (dynamic range = (max - min) / mean) measures the observed spread.
              Both must be present for a high quality score. Features that are always zero score 0%.
              Enable auto-select to have the system automatically adjust weights based on these scores.
            </p>
          )}
        </div>
      </div>}

      {/* Per-Feature Weights -- global scope only */}
      {selectedScope === null && <SectionCard
        title="Per-Feature Weights"
        description="Fine-tune how much each feature contributes to the combined anomaly score. Requires 'use_feature_weights' to be enabled."
        collapsible
        defaultOpen={false}
      >
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm font-medium text-slate-700 dark:text-slate-200">Enable Feature Weights</div>
              <div className="text-xs text-slate-500 dark:text-slate-400">When disabled, all features contribute equally (weight 1.0)</div>
            </div>
            <Toggle
              enabled={useFeatureWeights}
              onChange={async (v) => {
                try {
                  await api.updateLayer2ConfigValue('use_feature_weights', v);
                  toast.success(v ? 'Feature weights enabled' : 'Feature weights disabled');
                } catch { toast.error('Failed to update'); }
                finally { queryClient.invalidateQueries({ queryKey: ['layer2-config'] }); }
              }}
              label="Use feature weights"
            />
          </div>

          {useFeatureWeights && weights.length > 0 && (
            <>
              <div className="flex items-center justify-between border-t border-slate-100 dark:border-slate-700 pt-3">
                <div className="text-xs text-slate-500 dark:text-slate-400">
                  Adjust individual weights (0.0 = ignored, 1.0 = full weight)
                </div>
                <div className="flex items-center gap-2">
                  {weightsDirty && (
                    <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400">
                      Unsaved
                    </span>
                  )}
                  <button
                    onClick={() => {
                      setWeights(weights.map(() => 1.0));
                      setWeightsDirty(true);
                    }}
                    className="btn btn-sm btn-ghost"
                  >
                    Reset All to 1.0
                  </button>
                  <button
                    onClick={async () => {
                      setWeightsSaving(true);
                      try {
                        await api.updateLayer2ConfigValue('feature_weights', weights);
                        queryClient.invalidateQueries({ queryKey: ['layer2-config'] });
                        setWeightsDirty(false);
                        toast.success('Feature weights saved');
                      } catch {
                        toast.error('Failed to save feature weights');
                      } finally {
                        setWeightsSaving(false);
                      }
                    }}
                    disabled={!weightsDirty || weightsSaving}
                    className={clsx('btn btn-sm', weightsDirty ? 'btn-primary' : 'btn-secondary opacity-50')}
                  >
                    {weightsSaving ? 'Saving...' : 'Save Weights'}
                  </button>
                </div>
              </div>

              <div className="space-y-4">
                {grouped.map(({ group, features: gFeatures }) => (
                  <div key={`weights-${group}`}>
                    <div className="border-b border-slate-100 dark:border-slate-800 pb-1 mb-2">
                      <span className="text-sm font-semibold text-slate-700 dark:text-slate-300">{group}</span>
                    </div>
                    <div className="space-y-1.5">
                      {gFeatures.map(feat => {
                        const w = weights[feat.index] ?? 1.0;
                        return (
                          <div key={`w-${feat.index}`} className="flex items-center gap-3 px-2 py-1 rounded hover:bg-slate-50 dark:hover:bg-slate-700/30">
                            <span className="text-sm text-slate-600 dark:text-slate-300 w-48 truncate flex-shrink-0">
                              {FEATURE_DISPLAY_NAMES[feat.name] ?? feat.name}
                            </span>
                            {feat.quality && (
                              <span className={clsx('h-2 w-2 rounded-full flex-shrink-0', qualityColor(feat.quality.score))} />
                            )}
                            <input
                              type="range"
                              min={0}
                              max={1}
                              step={0.05}
                              value={w}
                              onChange={(e) => {
                                const val = parseFloat(e.target.value);
                                setWeights(prev => {
                                  const next = [...prev];
                                  next[feat.index] = val;
                                  return next;
                                });
                                setWeightsDirty(true);
                              }}
                              className="flex-1 accent-brand-500 h-1.5 cursor-pointer"
                            />
                            <span className="text-xs font-mono text-slate-500 dark:text-slate-400 w-10 text-right flex-shrink-0">
                              {w.toFixed(2)}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </SectionCard>}

      {/* Summary + Actions */}
      <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <AdjustmentsHorizontalIcon className="h-5 w-5 text-brand-500" />
            <div>
              <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">Detection Features</h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                {enabledCount} of {totalCount} features enabled
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {dirty && (
              <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400">
                Unsaved changes
              </span>
            )}
            <button onClick={selectAll} className="btn btn-sm btn-secondary">Select All</button>
            <button onClick={clearAll} className="btn btn-sm btn-ghost">Clear All</button>
            <button
              onClick={save}
              disabled={!dirty || saving}
              className={clsx('btn btn-sm', dirty ? 'btn-primary' : 'btn-secondary opacity-50')}
            >
              {saving ? 'Saving...' : selectedScope ? `Save for ${selectedScope}` : 'Save'}
            </button>
          </div>
        </div>

        {/* Group chips */}
        <div className="flex flex-wrap gap-2 mb-4">
          {grouped.map(({ group, features: gFeatures }) => {
            const count = gFeatures.filter(f => enabledFeatures[f.index]).length;
            const total = gFeatures.length;
            const full = count === total;
            const partial = count > 0 && !full;
            return (
              <button
                key={group}
                onClick={() => toggleGroup(gFeatures, !full)}
                className={clsx(
                  'inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium border transition-all duration-200',
                  full
                    ? 'bg-brand-100 border-brand-300 text-brand-800 dark:bg-brand-900/30 dark:border-brand-700 dark:text-brand-300 shadow-sm'
                    : partial
                      ? 'bg-amber-50 border-amber-300 text-amber-800 dark:bg-amber-900/20 dark:border-amber-700 dark:text-amber-300'
                      : 'bg-white border-slate-200 text-slate-600 dark:bg-slate-800 dark:border-slate-600 dark:text-slate-400 hover:border-slate-300 dark:hover:border-slate-500 hover:shadow-sm'
                )}
              >
                {group}
                <span className={clsx(
                  'text-xs px-1.5 py-0.5 rounded-full font-semibold',
                  full ? 'bg-white/50 dark:bg-black/20' : 'bg-slate-100 dark:bg-slate-700'
                )}>{count}/{total}</span>
              </button>
            );
          })}
        </div>

        {/* Feature checkboxes by group */}
        <div className="space-y-4">
          {grouped.map(({ group, features: gFeatures }) => {
            const count = gFeatures.filter(f => enabledFeatures[f.index]).length;
            const total = gFeatures.length;
            return (
              <div key={group}>
                <div className="border-b border-slate-100 dark:border-slate-800 pb-1.5 mb-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-slate-700 dark:text-slate-300">{group}</span>
                      <span className={clsx(
                        'text-[10px] font-medium px-1.5 py-0.5 rounded-full',
                        count === total
                          ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                          : count > 0
                            ? 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400'
                            : 'bg-slate-100 text-slate-500 dark:bg-slate-700 dark:text-slate-400'
                      )}>
                        {count}/{total}
                      </span>
                    </div>
                    <button
                      onClick={() => toggleGroup(gFeatures, count < total)}
                      className="text-xs font-medium text-brand-600 hover:text-brand-700 dark:text-brand-400 dark:hover:text-brand-300 transition-colors"
                    >
                      {count === total ? 'Deselect all' : 'Select all'}
                    </button>
                  </div>
                  {GROUP_DESCRIPTIONS[group] && (
                    <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5">{GROUP_DESCRIPTIONS[group]}</p>
                  )}
                </div>
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-1.5">
                  {gFeatures.map(feat => {
                    const info = FEATURE_INFO[feat.name];
                    const q = feat.quality;
                    return (
                      <div key={feat.index} className="relative group/feat">
                        <label
                          className={clsx(
                            'flex items-center gap-2 px-2.5 py-2 rounded-lg cursor-pointer border transition-all duration-150 text-sm',
                            enabledFeatures[feat.index]
                              ? 'bg-brand-50 border-brand-200 text-brand-900 dark:bg-brand-900/15 dark:border-brand-800 dark:text-brand-200 shadow-sm'
                              : 'bg-white dark:bg-slate-800/50 border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400 hover:border-slate-300 dark:hover:border-slate-300 dark:border-slate-600 hover:shadow-sm'
                          )}
                        >
                          <input
                            type="checkbox"
                            checked={enabledFeatures[feat.index] ?? true}
                            onChange={() => toggleFeature(feat.index)}
                            className="rounded border-slate-300 text-brand-600 focus:ring-brand-500 dark:border-slate-600 dark:bg-slate-700"
                          />
                          <span className="truncate flex-1">
                            {FEATURE_DISPLAY_NAMES[feat.name] ?? feat.name}
                            {q?.auto_disabled && autoSelect.enabled && (
                              <span className="ml-1 text-[10px] text-amber-600 dark:text-amber-400 font-medium">(auto: 0.1x)</span>
                            )}
                          </span>
                          {/* Quality dot */}
                          {q && (
                            <span className={clsx('h-2 w-2 rounded-full flex-shrink-0', qualityColor(q.score))} title={qualityLabel(q.score)} />
                          )}
                          {info && (
                            <svg viewBox="0 0 20 20" fill="currentColor" className="h-3.5 w-3.5 flex-shrink-0 text-slate-400 dark:text-slate-500 group-hover/feat:text-brand-400 transition-colors">
                              <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a.75.75 0 000 1.5h.253a.25.25 0 01.244.304l-.459 2.066A1.75 1.75 0 0010.747 15H11a.75.75 0 000-1.5h-.253a.25.25 0 01-.244-.304l.459-2.066A1.75 1.75 0 009.253 9H9z" clipRule="evenodd" />
                            </svg>
                          )}
                        </label>
                        {info && (
                          <div className="hidden group-hover/feat:block absolute z-50 bottom-full left-0 mb-2 w-64 sm:w-80 p-3 rounded-lg shadow-xl border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-800 text-xs pointer-events-none">
                            <p className="text-slate-700 dark:text-slate-200 font-medium mb-1.5">{info.description}</p>
                            <div className="space-y-1.5 text-slate-500 dark:text-slate-400">
                              <div>
                                <span className="font-semibold text-slate-600 dark:text-slate-300">How it's calculated:</span>
                                <code className="ml-1 bg-slate-100 dark:bg-slate-700 px-1.5 py-0.5 rounded text-[11px] font-mono block mt-0.5">{info.calculation}</code>
                              </div>
                              <p><span className="font-semibold text-slate-600 dark:text-slate-300">Unit:</span> {info.unit}</p>
                              <p><span className="font-semibold text-slate-600 dark:text-slate-300">What to look for:</span> {info.insight}</p>
                              {q && (
                                <div className="mt-1.5 pt-1.5 border-t border-slate-100 dark:border-slate-700">
                                  <p className="font-semibold text-slate-600 dark:text-slate-300 mb-1">Signal Quality</p>
                                  <div className="flex items-center gap-2 mb-1">
                                    <span className={clsx('h-2.5 w-2.5 rounded-full', qualityColor(q.score))} />
                                    <span className="font-medium">{qualityLabel(q.score)}{q.score !== null ? ` — ${(q.score * 100).toFixed(0)}%` : ''}</span>
                                  </div>
                                  <div className="grid grid-cols-2 gap-x-3 gap-y-0.5 text-[11px]">
                                    <span title="Coefficient of Variation: how much the feature value fluctuates relative to its mean. Higher = more variable = better for detection.">
                                      Variability (CV): <strong>{q.cv < 0.001 ? 'None' : q.cv < 0.01 ? 'Very low' : q.cv < 0.1 ? 'Low' : q.cv < 0.5 ? 'Moderate' : 'High'}</strong> ({q.cv.toFixed(3)})
                                    </span>
                                    <span title="Dynamic Range: the observed spread (max - min) relative to the mean. Higher = more responsive to changes.">
                                      Range: <strong>{q.range_ratio < 0.01 ? 'None' : q.range_ratio < 0.05 ? 'Narrow' : q.range_ratio < 0.5 ? 'Moderate' : 'Wide'}</strong> ({q.range_ratio.toFixed(3)})
                                    </span>
                                  </div>
                                  {q.zero_dominant && (
                                    <p className="mt-1 text-red-500 dark:text-red-400 text-[11px]">
                                      This feature is always near zero in your traffic. It cannot distinguish normal from anomalous until the traffic profile changes.
                                    </p>
                                  )}
                                  {q.auto_disabled && autoSelect.enabled && (
                                    <p className="mt-1 text-amber-600 dark:text-amber-400 text-[11px]">
                                      Auto-downweighted to 0.1x. This feature still contributes minimally as a safety net. It will be re-evaluated hourly.
                                    </p>
                                  )}
                                  {!q.auto_disabled && q.score !== null && q.score < 0.5 && q.score > 0 && (
                                    <p className="mt-1 text-[11px]">
                                      This feature has some signal but limited variance. Its weight is scaled to {(0.1 + 0.9 * q.score).toFixed(2)}x when auto-select is active.
                                    </p>
                                  )}
                                </div>
                              )}
                            </div>
                            <div className="absolute top-full left-6 border-8 border-transparent border-t-white dark:border-t-slate-800" />
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ==================== Main Component ====================

export function ConfigPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState('general');
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Data queries
  const { data: layer1Config, isLoading: l1Loading } = useQuery({
    queryKey: ['layer1-config'],
    queryFn: () => api.getLayer1Config(),
  });

  const { data: layer2Config } = useQuery({
    queryKey: ['layer2-config'],
    queryFn: () => api.getLayer2Config(),
  });

  const { data: adaptiveConfig } = useQuery({
    queryKey: ['layer2-adaptive'],
    queryFn: () => api.getAdaptiveConfig(),
    enabled: activeTab === 'adaptive',
  });

  const { data: anomalyData } = useQuery<AnomalyStatus>({
    queryKey: ['realtime-anomaly'],
    queryFn: () => api.getRealtimeAnomaly(),
    enabled: activeTab === 'anomaly-detection',
    refetchInterval: 2000,
  });

  const { data: profilesData } = useQuery({
    queryKey: ['layer2-profiles'],
    queryFn: () => api.getLayer2Profiles(),
    enabled: activeTab === 'anomaly-detection',
  });

  const [selectedProfile, setSelectedProfile] = useState('');
  const [showApplyConfirm, setShowApplyConfirm] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);
  const [exportName, setExportName] = useState('');
  const [exportDesc, setExportDesc] = useState('');
  // Baseline management modals + suppressed detection tracking
  const [showSaveConfirm, setShowSaveConfirm] = useState(false);
  const [showResetConfirm, setShowResetConfirm] = useState(false);
  const [showForceConfirm, setShowForceConfirm] = useState(false);
  const suppressedRef = useRef<SuppressedDetection[]>([]);
  const [suppressedDetections, setSuppressedDetections] = useState<SuppressedDetection[]>([]);
  const lastSuppressedRef = useRef(0);

  const { data: configSchema } = useQuery<Record<string, Record<string, { type?: string; desc?: string; min?: number; max?: number }>> | null>({
    queryKey: ['layer1-config-schema'],
    queryFn: async () => {
      try {
        return await api.getLayer1ConfigSchema() as Record<string, Record<string, { type?: string; desc?: string; min?: number; max?: number }>>;
      } catch { return null; }
    },
  });

  // Track suppressed detections by watching count increments
  useEffect(() => {
    if (!anomalyData) return;
    const current = anomalyData.suppressed_count;
    if (current > lastSuppressedRef.current && lastSuppressedRef.current > 0) {
      const entry: SuppressedDetection = {
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        level_name: anomalyData.level_name,
        max_z_score: anomalyData.max_z_score,
        tier_agreement: anomalyData.tier_agreement,
        primary_feature_name: anomalyData.primary_feature_name,
        action: 'Would block',
      };
      const updated = [entry, ...suppressedRef.current].slice(0, 20);
      suppressedRef.current = updated;
      setSuppressedDetections(updated);
    }
    lastSuppressedRef.current = current;
  }, [anomalyData?.suppressed_count]);

  // Instant-save helpers -- show whether config was applied to running datapath
  const updateL1Value = async (section: string, key: string, value: unknown) => {
    try {
      const res = await api.updateLayer1ConfigValue(section, key, value);
      if (res.applied) {
        toast.success('Applied to datapath');
      } else {
        toast('Saved (dataplane offline)', { icon: '\u26A0\uFE0F' });
      }
    } catch {
      toast.error('Failed to update');
    } finally {
      queryClient.invalidateQueries({ queryKey: ['layer1-config'] });
    }
  };

  const updateL1TopLevel = async (key: string, value: unknown) => {
    try {
      const res = await api.updateLayer1TopLevel(key, value);
      if (res.applied) {
        toast.success('Applied to datapath');
      } else {
        toast('Saved (dataplane offline)', { icon: '\u26A0\uFE0F' });
      }
    } catch {
      toast.error('Failed to update');
    } finally {
      queryClient.invalidateQueries({ queryKey: ['layer1-config'] });
    }
  };

  const updateL2Value = async (key: string, value: unknown) => {
    try {
      const res = await api.updateLayer2ConfigValue(key, value);
      if (res.applied) {
        toast.success('Applied to datapath');
      } else {
        toast('Saved (dataplane offline)', { icon: '\u26A0\uFE0F' });
      }
    } catch {
      toast.error('Failed to update');
    } finally {
      queryClient.invalidateQueries({ queryKey: ['layer2-config'] });
    }
  };

  const updateAdaptiveValue = async (data: Record<string, unknown>) => {
    try {
      await api.updateAdaptiveConfig(data);
      toast.success('Updated');
    } catch {
      toast.error('Failed to update');
    } finally {
      queryClient.invalidateQueries({ queryKey: ['layer2-adaptive'] });
      queryClient.invalidateQueries({ queryKey: ['layer2-config'] });
    }
  };

  const toggleAdaptive = async (enabled: boolean) => {
    try {
      await api.setAdaptiveEnabled(enabled);
      toast.success('Updated');
    } catch {
      toast.error('Failed to update');
    } finally {
      queryClient.invalidateQueries({ queryKey: ['layer2-adaptive'] });
    }
  };

  const l1 = layer1Config as Record<string, unknown> | undefined;
  const l2 = layer2Config as Record<string, unknown> | undefined;
  const adaptive = adaptiveConfig as Record<string, unknown> | undefined;

  // Render a single field control (shared by generic and custom renderers)
  const renderField = (section: string, key: string, value: unknown, label: string, desc?: string, schema?: { type?: string; min?: number; max?: number }) => {
    const sch = schema || {};
    const type = sch.type || (typeof value === 'boolean' ? 'bool' : typeof value === 'number' ? (Number.isInteger(value) ? 'int' : 'float') : 'str');
    if (type === 'list' || Array.isArray(value) || type === 'str' || typeof value === 'string' || typeof value === 'object') return null;

    return (
      <FieldRow key={key} label={label} description={desc}>
        {type === 'bool' ? (
          <Toggle enabled={!!value} onChange={(v) => updateL1Value(section, key, v)} size="sm" label={label} />
        ) : (
          <NumberInput
            value={value as number}
            min={sch.min}
            max={sch.max}
            step={type === 'float' ? 0.01 : 1}
            onChange={(v) => updateL1Value(section, key, v)}
          />
        )}
      </FieldRow>
    );
  };

  // Shared sub-grouped section renderer
  const renderSubGroupedSection = (sectionKey: string, values: Record<string, unknown>, groups: SubGroup[]) => {
    const schema = (configSchema?.[sectionKey] || {}) as Record<string, { type?: string; desc?: string; min?: number; max?: number }>;

    return (
      <SectionCard
        key={sectionKey}
        title={SECTION_NAMES[sectionKey]}
        description={SECTION_DESCRIPTIONS[sectionKey]}
        collapsible
      >
        <div className="space-y-1">
          {groups.map((group) => {
            const Icon = group.icon;
            const hasToggle = group.fields.some(f => typeof values[f.key] === 'boolean');
            const toggleField = hasToggle ? group.fields.find(f => typeof values[f.key] === 'boolean') : null;

            return (
              <div key={group.id}>
                <div className="flex items-center gap-3 px-4 py-2.5 bg-slate-50 dark:bg-slate-800/50 border-b border-slate-100 dark:border-slate-800">
                  <Icon className={`h-4 w-4 ${group.accent} shrink-0`} />
                  <div className="flex-1 min-w-0">
                    <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                      {group.title}
                    </span>
                    <p className="text-[11px] text-slate-400 dark:text-slate-500 leading-tight mt-0.5">
                      {group.description}
                    </p>
                  </div>
                  {toggleField && (
                    <Toggle
                      enabled={!!values[toggleField.key]}
                      onChange={(v) => updateL1Value(sectionKey, toggleField.key, v)}
                      size="sm"
                      label={toggleField.label}
                    />
                  )}
                </div>
                <div className="divide-y divide-slate-100 dark:divide-slate-800">
                  {group.fields.map((field) => {
                    if (toggleField && field.key === toggleField.key) return null;
                    const value = values[field.key];
                    if (value === undefined) return null;
                    return renderField(sectionKey, field.key, value, field.label, field.desc, schema[field.key]);
                  })}
                </div>
              </div>
            );
          })}
        </div>
      </SectionCard>
    );
  };

  // Sections with custom sub-grouped rendering
  const SUB_GROUPED_SECTIONS: Record<string, SubGroup[]> = {
    rate_limits: RATE_LIMIT_GROUPS,
    tcp_flag_rate: TCP_FLAG_RATE_GROUPS,
    tcp_abuse: TCP_ABUSE_GROUPS,
  };

  // Schema-driven config section renderer
  const renderConfigSection = (sectionKey: string, values: unknown) => {
    if (typeof values !== 'object' || values === null || Array.isArray(values)) return null;
    if (RULES_MANAGED_SECTIONS.includes(sectionKey)) return null;
    if (!SECTION_NAMES[sectionKey]) return null;

    // Custom sub-grouped rendering for complex sections
    if (SUB_GROUPED_SECTIONS[sectionKey]) {
      return renderSubGroupedSection(sectionKey, values as Record<string, unknown>, SUB_GROUPED_SECTIONS[sectionKey]);
    }

    const sectionValues = values as Record<string, unknown>;
    const schema = (configSchema?.[sectionKey] || {}) as Record<string, { type?: string; desc?: string; min?: number; max?: number }>;

    return (
      <SectionCard
        key={sectionKey}
        title={SECTION_NAMES[sectionKey]}
        description={SECTION_DESCRIPTIONS[sectionKey]}
        collapsible
      >
        <div className="divide-y divide-slate-100 dark:divide-slate-800">
          {Object.entries(sectionValues).map(([key, value]) => {
            const sch = schema[key] || {};
            const label = key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
            return renderField(sectionKey, key, value, label, sch.desc, sch) as React.ReactNode;
          })}
          {/* Merge SYN Cookie fields into SYN Proxy section */}
          {sectionKey === 'syn_proxy' && !!l1?.syn_cookie && typeof l1.syn_cookie === 'object' && !Array.isArray(l1.syn_cookie) && (() => {
            const cookieValues = l1.syn_cookie as Record<string, unknown>;
            const cookieSchema = (configSchema?.syn_cookie || {}) as Record<string, { type?: string; desc?: string; min?: number; max?: number }>;
            const cookieLabels: Record<string, string> = {
              enabled: 'Cookie Validation',
              challenge_threshold: 'Challenge Threshold PPS',
            };
            const cookieDescs: Record<string, string> = {
              enabled: 'Use SYN cookies for stateless connection validation',
              challenge_threshold: 'Start challenging SYN packets when rate exceeds this PPS',
            };
            return (
              <>
                <div className="px-4 py-2 bg-slate-50 dark:bg-slate-800/50">
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                    Cookie Challenge
                  </span>
                </div>
                {Object.entries(cookieValues).map(([key, value]) => {
                  const sch = cookieSchema[key] || {};
                  const label = cookieLabels[key] || key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
                  const desc = cookieDescs[key] || sch.desc;
                  return renderField('syn_cookie', key, value, label, desc, sch);
                })}
              </>
            );
          })()}
        </div>
      </SectionCard>
    );
  };

  if (l1Loading) {
    return (
      <div className="space-y-6 animate-fade-in">
        <div className="flex items-center gap-3">
          <div className="skeleton h-7 w-7 rounded-lg" />
          <div className="skeleton h-8 w-64 rounded-lg" />
        </div>
        <div className="skeleton h-10 w-full rounded-lg" />
        <SkeletonCard />
        <SkeletonCard />
        <SkeletonCard />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="System Configuration"
        description="Protection presets and advanced packet processing parameters"
        icon={Cog6ToothIcon}
      />

      {l1 && (
        <div className="space-y-6 animate-fade-in">
          {/* Quick Presets */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <button
              onClick={() => {
                if (confirm('Apply Standard Protection preset? This will adjust SYN proxy, UDP gatekeeper, and rate limit settings for balanced day-to-day protection.')) {
                  Promise.all([
                    updateL1Value('syn_proxy', 'enabled', true),
                    updateL1Value('udp_gatekeeper', 'enabled', true),
                    updateL1Value('rate_limits', 'progressive_enabled', true),
                  ]).then(() => toast.success('Standard Protection preset applied'));
                }
              }}
              className="card-interactive p-4 text-left border-l-4 border-l-emerald-500"
            >
              <div className="flex items-center gap-2 mb-1">
                <div className="h-2 w-2 rounded-full bg-emerald-500" />
                <span className="text-sm font-semibold text-slate-900 dark:text-white">Standard Protection</span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">Balanced detection for normal operations. Recommended for day-to-day use.</p>
            </button>
            <button
              onClick={() => {
                if (confirm('Apply Under Attack preset? This enables aggressive filtering that may affect some legitimate traffic.')) {
                  Promise.all([
                    updateL1Value('syn_proxy', 'enabled', true),
                    updateL1Value('udp_gatekeeper', 'enabled', true),
                    updateL1Value('rate_limits', 'progressive_enabled', true),
                    updateL1Value('connection_limits', 'enabled', true),
                  ]).then(() => toast.success('Under Attack preset applied'));
                }
              }}
              className="card-interactive p-4 text-left border-l-4 border-l-red-500"
            >
              <div className="flex items-center gap-2 mb-1">
                <div className="h-2 w-2 rounded-full bg-red-500 animate-pulse" />
                <span className="text-sm font-semibold text-slate-900 dark:text-white">Under Attack</span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">Maximum protection. Aggressively filters traffic. May affect some legitimate users.</p>
            </button>
            <button
              onClick={() => {
                if (confirm('Apply Learning Mode preset? Detection will run in alert-only mode — no traffic will be blocked.')) {
                  Promise.all([
                    updateL1TopLevel('monitor_only', true),
                  ]).then(() => toast.success('Learning Mode preset applied'));
                }
              }}
              className="card-interactive p-4 text-left border-l-4 border-l-blue-500"
            >
              <div className="flex items-center gap-2 mb-1">
                <div className="h-2 w-2 rounded-full bg-blue-500" />
                <span className="text-sm font-semibold text-slate-900 dark:text-white">Learning Mode</span>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">Alert-only while baselines are being established. No traffic is blocked.</p>
            </button>
          </div>

          {/* Advanced Configuration Toggle */}
          <button
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="flex items-center gap-2 text-sm font-medium text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors"
          >
            <AdjustmentsHorizontalIcon className="h-4 w-4" />
            {showAdvanced ? 'Hide' : 'Show'} Advanced Configuration
            <svg className={clsx('h-4 w-4 transition-transform', showAdvanced && 'rotate-180')} fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>

          {showAdvanced && (<>
          <InfoBanner variant="warning">
            <strong>Advanced configuration.</strong> Incorrect settings may cause packet loss or reduced protection.
            Changes take effect immediately.
          </InfoBanner>

          {/* System Mode */}
          <SectionCard title="System Mode" description="Global operating mode, logging, and spoofed attack detection">
            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              <FieldRow label="Monitor Only Mode" description="Observe traffic without blocking. All protection stages run but no packets are dropped.">
                <Toggle enabled={!!(l1.monitor_only)} onChange={(v) => updateL1TopLevel('monitor_only', v)} label="Monitor only" />
              </FieldRow>
              <FieldRow label="Tap Mode" description="Receive a mirror copy of traffic on port 0 only. All detection and stats run but packets are not forwarded.">
                <Toggle enabled={!!(l1.tap_mode)} onChange={(v) => updateL1TopLevel('tap_mode', v)} label="Tap mode" />
              </FieldRow>
              <FieldRow label="Statistics Collection" description="Collect traffic metrics and counters for dashboard display">
                <Toggle enabled={l1.stats_enabled !== false} onChange={(v) => updateL1TopLevel('stats_enabled', v)} label="Statistics" />
              </FieldRow>
              <FieldRow label="Log Level" description="0=Emergency to 8=Debug+">
                <SelectInput
                  value={(l1.log_level as number) ?? 6}
                  onChange={(v) => updateL1TopLevel('log_level', parseInt(v))}
                  options={LOG_LEVELS}
                />
              </FieldRow>
            </div>
            {/* Spoofed Detection Threshold sub-section (from Layer 2 config) */}
            {l2 && (() => {
              return (
                <>
                  <div className="flex items-center gap-3 px-4 py-2.5 bg-slate-50 dark:bg-slate-800/50 border-t border-b border-slate-100 dark:border-slate-800">
                    <ExclamationTriangleIcon className="h-4 w-4 text-amber-500 dark:text-amber-400 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                        Spoofed Attack Detection
                      </span>
                      <p className="text-[11px] text-slate-400 dark:text-slate-500 leading-tight mt-0.5">
                        Thresholds for when Layer 2 activates spoofed flood mode (random source IPs)
                      </p>
                    </div>
                    <Toggle
                      enabled={!!l2.spoofed_require_anomaly}
                      onChange={(v) => updateL2Value('spoofed_require_anomaly', v)}
                      size="sm"
                      label="Require Anomaly"
                    />
                  </div>
                  <div className="divide-y divide-slate-100 dark:divide-slate-800">
                    <FieldRow label="Minimum PPS" description="Traffic must exceed this packet rate before spoofed detection evaluates source randomness">
                      <NumberInput value={l2.spoofed_min_pps as number ?? 1000} min={100} max={10000000} onChange={(v) => updateL2Value('spoofed_min_pps', v)} />
                    </FieldRow>
                    <FieldRow label="Randomness Threshold (%)" description="Percentage of unique source IPs relative to PPS. Above this = spoofed flood (e.g. 50 = half of packets from unique IPs)">
                      <NumberInput value={l2.spoofed_randomness_threshold as number ?? 50} min={1} max={100} onChange={(v) => updateL2Value('spoofed_randomness_threshold', v)} />
                    </FieldRow>
                  </div>
                </>
              );
            })()}
          </SectionCard>

          {/* Tab navigation + actions */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <nav className="flex gap-1 rounded-lg bg-slate-100 dark:bg-slate-800/60 p-1 overflow-x-auto max-w-full" role="tablist">
              {CONFIG_TABS.map((tab) => (
                <button
                  key={tab.id}
                  role="tab"
                  aria-selected={activeTab === tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`px-3 py-1.5 text-sm font-medium rounded-md transition-colors ${
                    activeTab === tab.id
                      ? 'bg-white dark:bg-slate-700 text-slate-900 dark:text-white shadow-sm'
                      : 'text-slate-500 dark:text-slate-300 hover:text-slate-700 dark:hover:text-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </nav>
            <div className="flex gap-2">
              <button
                onClick={async () => { await api.reloadLayer1Config(); queryClient.invalidateQueries({ queryKey: ['layer1-config'] }); toast.success('Config reloaded from disk'); }}
                className="btn btn-secondary btn-sm"
              >
                <ArrowPathIcon className="h-3.5 w-3.5" /> Reload
              </button>
              <button
                onClick={async () => { await api.resetLayer1Config(); queryClient.invalidateQueries({ queryKey: ['layer1-config'] }); toast.success('Config reset to defaults'); }}
                className="btn btn-danger btn-sm"
              >
                Reset Defaults
              </button>
            </div>
          </div>

          {/* Tab content -- only render sections belonging to active tab */}
          <div className="space-y-3">
            {(() => {
              const currentTab = CONFIG_TABS.find(t => t.id === activeTab);
              if (!currentTab) return null;

              // L1 config section tabs
              if (currentTab.sections.length > 0) {
                return currentTab.sections.map((sectionKey) => {
                  const val = l1[sectionKey];
                  return val !== undefined ? renderConfigSection(sectionKey, val) : null;
                });
              }

              // ==================== ANOMALY DETECTION TAB ====================
              if (activeTab === 'anomaly-detection' && l2) {
                return (
                  <div className="space-y-3 animate-fade-in">
                    <InfoBanner>
                      Layer 2 uses multi-tier Z-score anomaly detection with baseline learning.
                      Changes affect detection sensitivity and may require baseline re-learning.
                    </InfoBanner>

                    {/* Enhanced Learning Status Widget */}
                    {anomalyData && (
                      <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
                        {/* Header: Phase + Trust + Mode */}
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <SignalIcon className="h-4 w-4 text-blue-500" />
                            <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-200">Learning Status</h3>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${
                              anomalyData.learning_action === 0
                                ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                                : 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400'
                            }`}>
                              {anomalyData.learning_action === 0 ? 'BLOCK' : 'ALERT ONLY'}
                            </span>
                            <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${
                              anomalyData.learning_phase === 3 ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' :
                              anomalyData.learning_phase === 2 ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400' :
                              anomalyData.learning_phase === 1 ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400' :
                              'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
                            }`}>
                              {anomalyData.learning_phase_name}
                            </span>
                          </div>
                        </div>
                        <div className="text-xs text-slate-500 dark:text-slate-400 mb-3">
                          Trust: {anomalyData.trust_multiplier}x
                          {anomalyData.trust_multiplier > 1.0 && (
                            <span> (threshold: {(anomalyData.current_threshold * anomalyData.trust_multiplier).toFixed(1)})</span>
                          )}
                        </div>

                        {/* Tier Progress with slot counts */}
                        <div className="space-y-2 mb-3">
                          {[
                            { label: 'Tier 1 (10s)', progress: anomalyData.tier1_progress, eta: anomalyData.tier1_eta_sec, slots: null as string | null },
                            { label: 'Tier 2 (1h)', progress: anomalyData.tier2_progress, eta: anomalyData.tier2_eta_sec, slots: `${anomalyData.tier2_ready_count}/24 hourly slots ready` },
                            { label: 'Tier 3 (7d)', progress: anomalyData.tier3_progress, eta: anomalyData.tier3_eta_sec, slots: `${anomalyData.tier3_ready_count}/168 weekly slots ready` },
                          ].map(tier => (
                            <div key={tier.label}>
                              <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 mb-1">
                                <span>{tier.label}</span>
                                <span>{tier.progress}%{tier.eta > 0 && tier.progress < 100 ? ` — ~${tier.eta}s` : ''}</span>
                              </div>
                              <div className="h-1.5 bg-slate-100 dark:bg-slate-700 rounded-full overflow-hidden">
                                <div
                                  className={`h-full rounded-full transition-all duration-500 ${
                                    tier.progress >= 100 ? 'bg-green-500' : tier.progress > 50 ? 'bg-blue-500' : 'bg-yellow-500'
                                  }`}
                                  style={{ width: `${Math.min(tier.progress, 100)}%` }}
                                />
                              </div>
                              {tier.slots && (
                                <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-0.5">{tier.slots}</p>
                              )}
                            </div>
                          ))}
                        </div>

                        {/* Stats footer */}
                        <div className="flex items-center gap-4 text-xs text-slate-400 dark:text-slate-500 pt-2 border-t border-slate-100 dark:border-slate-800 mb-3">
                          <span>Updates: {anomalyData.baseline_updates.toLocaleString()}</span>
                          <span>Cycles: {anomalyData.detection_cycles.toLocaleString()}</span>
                          <span>Baseline: {anomalyData.baseline_age_sec > 0
                            ? `${anomalyData.baseline_age_sec < 60 ? `${anomalyData.baseline_age_sec}s` :
                                anomalyData.baseline_age_sec < 3600 ? `${Math.floor(anomalyData.baseline_age_sec / 60)}m` :
                                `${Math.floor(anomalyData.baseline_age_sec / 3600)}h ${Math.floor((anomalyData.baseline_age_sec % 3600) / 60)}m`} old`
                            : 'Cold start'}</span>
                        </div>

                        {/* Mitigation mode status */}
                        {anomalyData.learning_action === 1 && !anomalyData.mitigation_active && (
                          <p className="text-xs text-amber-600 dark:text-amber-400 mb-3">
                            Detections are logged but mitigations are suppressed until baselines mature.
                            {anomalyData.suppressed_count > 0 && ` (${anomalyData.suppressed_count} suppressed)`}
                          </p>
                        )}
                        {anomalyData.mitigation_active && (
                          <p className="text-xs text-green-600 dark:text-green-400 mb-3">
                            Mitigations are active — Layer 1 is enforcing rate limits.
                          </p>
                        )}

                        {/* Action buttons */}
                        <div className="flex flex-wrap gap-2 mb-3">
                          <button
                            className="px-3 py-1.5 text-xs font-medium rounded border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700"
                            onClick={() => setShowSaveConfirm(true)}
                          >
                            Save Baselines
                          </button>
                          <button
                            className="px-3 py-1.5 text-xs font-medium rounded border border-red-300 dark:border-red-800 text-red-700 dark:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/20"
                            onClick={() => setShowResetConfirm(true)}
                          >
                            Reset &amp; Re-learn
                          </button>
                          <button
                            className="px-3 py-1.5 text-xs font-medium rounded bg-green-600 text-white hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed"
                            disabled={anomalyData.learning_phase === 3}
                            onClick={() => setShowForceConfirm(true)}
                          >
                            Force Mature
                          </button>
                        </div>

                        {/* Suppressed Detections Table */}
                        {anomalyData.learning_action === 1 && (anomalyData.suppressed_count > 0 || suppressedDetections.length > 0) && (
                          <div className="pt-3 border-t border-slate-200 dark:border-slate-700">
                            <p className="text-xs font-medium text-slate-600 dark:text-slate-300 mb-2">
                              Suppressed Detections: {anomalyData.suppressed_count} total
                              {suppressedDetections.length > 0 && ` (${suppressedDetections.length} captured this session)`}
                            </p>
                            {suppressedDetections.length > 0 && (
                              <div className="overflow-x-auto">
                                <table className="w-full text-xs">
                                  <thead>
                                    <tr className="text-left text-slate-400 dark:text-slate-500 border-b border-slate-100 dark:border-slate-800">
                                      <th className="pb-1 pr-2">Time</th>
                                      <th className="pb-1 pr-2">Level</th>
                                      <th className="pb-1 pr-2">Z-Score</th>
                                      <th className="pb-1 pr-2">Tiers</th>
                                      <th className="pb-1 pr-2">Primary Feature</th>
                                      <th className="pb-1">Action</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {suppressedDetections.map((d, i) => (
                                      <tr key={i} className="text-slate-600 dark:text-slate-300 border-b border-slate-50 dark:border-slate-800/50">
                                        <td className="py-1 pr-2">{d.timestamp}</td>
                                        <td className="py-1 pr-2">{d.level_name}</td>
                                        <td className="py-1 pr-2">{d.max_z_score.toFixed(1)}</td>
                                        <td className="py-1 pr-2">{d.tier_agreement}/3</td>
                                        <td className="py-1 pr-2 font-mono">{d.primary_feature_name}</td>
                                        <td className="py-1">{d.action}</td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Baseline Profiles */}
                    <SectionCard title="Baseline Profiles" description="Load pre-built or exported baseline profiles to skip the learning period">
                      <div className="divide-y divide-slate-100 dark:divide-slate-800">
                        <FieldRow label="Apply Profile" description="Select a profile template to immediately populate all baselines. Current baselines will be replaced.">
                          <div className="flex items-center gap-2">
                            <SelectInput
                              value={selectedProfile}
                              options={[
                                { label: 'Select profile...', value: '' },
                                ...(profilesData?.profiles || []).map(p => ({
                                  label: `${p.name}${p.source === 'exported' ? ' (exported)' : ''}`,
                                  value: p.id,
                                })),
                              ]}
                              onChange={setSelectedProfile}
                            />
                            <button
                              className="px-3 py-1.5 text-xs font-medium rounded bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
                              disabled={!selectedProfile}
                              onClick={() => setShowApplyConfirm(true)}
                            >
                              Apply
                            </button>
                          </div>
                        </FieldRow>
                        {selectedProfile && profilesData?.profiles && (
                          <div className="px-4 py-2 text-xs text-slate-500 dark:text-slate-400">
                            {profilesData.profiles.find(p => p.id === selectedProfile)?.description || ''}
                          </div>
                        )}
                        <FieldRow label="Export Current Baselines" description="Save learned baselines as a reusable profile for future deployments.">
                          <button
                            className="px-3 py-1.5 text-xs font-medium rounded border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700"
                            onClick={() => { setExportName(''); setExportDesc(''); setShowExportModal(true); }}
                          >
                            Export Profile
                          </button>
                        </FieldRow>
                      </div>
                    </SectionCard>

                    {/* Apply Profile Confirmation Modal */}
                    <Modal open={showApplyConfirm} onClose={() => setShowApplyConfirm(false)} title="Apply Baseline Profile">
                      <p className="text-sm text-slate-600 dark:text-slate-300 mb-4">
                        This will <span className="font-semibold text-amber-600 dark:text-amber-400">replace all current baselines</span> with the selected profile.
                        The system will immediately jump to MATURE learning phase.
                      </p>
                      <p className="text-sm text-slate-500 dark:text-slate-400 mb-6">
                        Profile: <span className="font-medium text-slate-700 dark:text-slate-200">{profilesData?.profiles?.find(p => p.id === selectedProfile)?.name || selectedProfile}</span>
                      </p>
                      <div className="flex justify-end gap-2">
                        <button
                          className="px-3 py-1.5 text-sm rounded border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700"
                          onClick={() => setShowApplyConfirm(false)}
                        >
                          Cancel
                        </button>
                        <button
                          className="px-3 py-1.5 text-sm rounded bg-blue-600 text-white hover:bg-blue-700"
                          onClick={async () => {
                            setShowApplyConfirm(false);
                            try {
                              await api.applyLayer2Profile(selectedProfile);
                              toast.success('Profile applied successfully');
                              queryClient.invalidateQueries({ queryKey: ['realtime-anomaly'] });
                              queryClient.invalidateQueries({ queryKey: ['layer2-config'] });
                              setSelectedProfile('');
                            } catch {
                              toast.error('Failed to apply profile');
                            }
                          }}
                        >
                          Apply Profile
                        </button>
                      </div>
                    </Modal>

                    {/* Export Profile Modal */}
                    <Modal open={showExportModal} onClose={() => setShowExportModal(false)} title="Export Baselines as Profile">
                      <div className="space-y-3 mb-6">
                        <div>
                          <label className="block text-sm font-medium text-slate-700 dark:text-slate-200 mb-1">Profile Name</label>
                          <input
                            type="text"
                            className="w-full px-3 py-1.5 text-sm border rounded border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100"
                            placeholder="My Web Server Profile"
                            value={exportName}
                            onChange={(e) => setExportName(e.target.value)}
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-slate-700 dark:text-slate-200 mb-1">Description (optional)</label>
                          <input
                            type="text"
                            className="w-full px-3 py-1.5 text-sm border rounded border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100"
                            placeholder="Baselines from production web server"
                            value={exportDesc}
                            onChange={(e) => setExportDesc(e.target.value)}
                          />
                        </div>
                      </div>
                      <div className="flex justify-end gap-2">
                        <button
                          className="px-3 py-1.5 text-sm rounded border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700"
                          onClick={() => setShowExportModal(false)}
                        >
                          Cancel
                        </button>
                        <button
                          className="px-3 py-1.5 text-sm rounded bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50"
                          disabled={!exportName.trim()}
                          onClick={async () => {
                            setShowExportModal(false);
                            try {
                              await api.exportLayer2Profile(exportName.trim(), exportDesc.trim());
                              toast.success('Profile exported successfully');
                              queryClient.invalidateQueries({ queryKey: ['layer2-profiles'] });
                            } catch {
                              toast.error('Failed to export profile');
                            }
                          }}
                        >
                          Export
                        </button>
                      </div>
                    </Modal>

                    {/* Baseline Management Modals */}
                    <Modal open={showSaveConfirm} onClose={() => setShowSaveConfirm(false)} title="Save Baselines">
                      <p className="text-sm text-slate-600 dark:text-slate-300 mb-4">
                        Save current learned baselines to disk. This preserves your traffic
                        patterns for warm-start on next restart.
                      </p>
                      <div className="flex justify-end gap-2">
                        <button
                          className="px-3 py-1.5 text-sm rounded border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700"
                          onClick={() => setShowSaveConfirm(false)}
                        >
                          Cancel
                        </button>
                        <button
                          className="px-3 py-1.5 text-sm rounded bg-blue-600 text-white hover:bg-blue-700"
                          onClick={async () => {
                            setShowSaveConfirm(false);
                            try {
                              await api.saveLayer2Baselines();
                              toast.success('Baselines saved to disk');
                            } catch {
                              toast.error('Failed to save baselines');
                            }
                          }}
                        >
                          Save
                        </button>
                      </div>
                    </Modal>

                    <Modal open={showResetConfirm} onClose={() => setShowResetConfirm(false)} title="Reset Baselines">
                      <p className="text-sm text-slate-600 dark:text-slate-300 mb-4">
                        This will <span className="font-semibold text-red-600 dark:text-red-400">erase all learned baselines</span> and
                        return to COLD phase. The system must re-learn traffic patterns from scratch.
                      </p>
                      <p className="text-sm text-amber-600 dark:text-amber-400 mb-6">
                        Consider saving baselines first if you want to restore them later.
                      </p>
                      <div className="flex justify-end gap-2">
                        <button
                          className="px-3 py-1.5 text-sm rounded border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700"
                          onClick={() => setShowResetConfirm(false)}
                        >
                          Cancel
                        </button>
                        <button
                          className="px-3 py-1.5 text-sm rounded bg-red-600 text-white hover:bg-red-700"
                          onClick={async () => {
                            setShowResetConfirm(false);
                            try {
                              await api.resetLayer2Baselines();
                              toast.success('Baselines reset — re-learning from COLD');
                              queryClient.invalidateQueries({ queryKey: ['realtime-anomaly'] });
                              suppressedRef.current = [];
                              setSuppressedDetections([]);
                              lastSuppressedRef.current = 0;
                            } catch {
                              toast.error('Failed to reset baselines');
                            }
                          }}
                        >
                          Reset &amp; Re-learn
                        </button>
                      </div>
                    </Modal>

                    <Modal open={showForceConfirm} onClose={() => setShowForceConfirm(false)} title="Force Mature">
                      <p className="text-sm text-slate-600 dark:text-slate-300 mb-4">
                        This will override the learning phase to MATURE, enabling full-precision detection
                        immediately with whatever baselines currently exist.
                      </p>
                      <p className="text-sm text-amber-600 dark:text-amber-400 mb-6">
                        Detection may be less accurate if baselines have insufficient samples.
                        The override persists until baselines are reset.
                      </p>
                      <div className="flex justify-end gap-2">
                        <button
                          className="px-3 py-1.5 text-sm rounded border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700"
                          onClick={() => setShowForceConfirm(false)}
                        >
                          Cancel
                        </button>
                        <button
                          className="px-3 py-1.5 text-sm rounded bg-green-600 text-white hover:bg-green-700"
                          onClick={async () => {
                            setShowForceConfirm(false);
                            try {
                              await api.forceLayer2Mature();
                              toast.success('Learning phase forced to MATURE');
                              queryClient.invalidateQueries({ queryKey: ['realtime-anomaly'] });
                            } catch {
                              toast.error('Failed to force mature');
                            }
                          }}
                        >
                          Force Mature
                        </button>
                      </div>
                    </Modal>

                    {/* Alert-Only Mode Configuration */}
                    <SectionCard title="Learning Action Mode" description="Control whether detections trigger mitigation or alerts only during baseline learning">
                      <div className="divide-y divide-slate-100 dark:divide-slate-800">
                        <FieldRow label="Learning Action" description="BLOCK: enforce mitigations immediately. ALERT ONLY: detect anomalies but suppress mitigation until baselines mature.">
                          <SelectInput
                            value={String(l2.learning_action ?? 0)}
                            options={[
                              { label: 'Block (Enforce)', value: '0' },
                              { label: 'Alert Only', value: '1' },
                            ]}
                            onChange={(v) => updateL2Value('learning_action', Number(v))}
                          />
                        </FieldRow>
                        <FieldRow label="Auto-Promote on Mature" description="Automatically switch from Alert Only to Block when baselines reach MATURE phase.">
                          <Toggle enabled={!!(l2.auto_promote_on_mature ?? true)} onChange={(v) => updateL2Value('auto_promote_on_mature', v)} label="Auto-promote" />
                        </FieldRow>
                        <FieldRow label="Min Learning Duration (sec)" description="Minimum seconds before auto-promote can fire. Industry standard: 3600 (1h). Google uses 24h, Cloudflare 7d.">
                          <NumberInput value={(l2.min_learning_duration_sec as number) ?? 3600} min={0} max={604800} step={300} onChange={(v) => updateL2Value('min_learning_duration_sec', v)} />
                        </FieldRow>
                        <FieldRow label="Force Alert in Early Phases" description="Always suppress mitigation during COLD and WARMING phases regardless of learning action. Baselines are too young to enforce.">
                          <Toggle enabled={!!(l2.force_alert_early_phases ?? true)} onChange={(v) => updateL2Value('force_alert_early_phases', v)} label="Force alert early" />
                        </FieldRow>
                      </div>
                    </SectionCard>

                    <SectionCard title="Detection Parameters" description="Core detection thresholds and timing">
                      <div className="divide-y divide-slate-100 dark:divide-slate-800">
                        <FieldRow label="Z-Score Threshold" description="Base threshold for anomaly detection. Higher = less sensitive. Range: 3.0 - 12.0">
                          <NumberInput value={l2.z_score_threshold as number} step={0.5} min={3} max={12} onChange={(v) => updateL2Value('z_score_threshold', v)} />
                        </FieldRow>
                        <FieldRow label="Min Tier Agreement" description="Number of time tiers (immediate/hourly/weekly) that must agree. 1-3">
                          <NumberInput value={l2.min_tier_agreement as number} min={1} max={3} onChange={(v) => updateL2Value('min_tier_agreement', v)} />
                        </FieldRow>
                        <FieldRow label="Detection Interval (ms)" description="How often detection runs (milliseconds)">
                          <NumberInput value={l2.detection_interval_ms as number} min={100} max={10000} onChange={(v) => updateL2Value('detection_interval_ms', v)} />
                        </FieldRow>
                        <FieldRow label="Jitter (ms)" description="Random jitter added to interval to prevent synchronization">
                          <NumberInput value={l2.jitter_ms as number} min={0} max={1000} onChange={(v) => updateL2Value('jitter_ms', v)} />
                        </FieldRow>
                        <FieldRow label="Cool Down (sec)" description="Seconds after attack ends before declaring normal">
                          <NumberInput value={l2.cool_down_seconds as number} step={1} min={0} max={300} onChange={(v) => updateL2Value('cool_down_seconds', v)} />
                        </FieldRow>
                        <FieldRow label="Min PPS for Detection" description="Minimum packets/sec before anomaly detection runs. Prevents false positives during idle.">
                          <NumberInput value={l2.min_pps_for_detection as number ?? 100} min={0} max={100000} onChange={(v) => updateL2Value('min_pps_for_detection', v)} />
                        </FieldRow>
                        <FieldRow label="JSD Threshold" description="Jensen-Shannon divergence threshold for protocol mix anomaly (0.0-1.0). Lower = more sensitive.">
                          <NumberInput value={l2.jsd_threshold as number ?? 0.15} step={0.01} min={0.05} max={0.5} onChange={(v) => updateL2Value('jsd_threshold', v)} />
                        </FieldRow>
                      </div>
                    </SectionCard>

                    <SectionCard title="Severity Classification" description="Z-score thresholds for attack severity levels based on tier agreement">
                      <div className="space-y-5 p-4">
                        <div>
                          <h4 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-3">3-Tier Agreement (all tiers agree)</h4>
                          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                            {[
                              { key: 'z_critical_3tier', label: 'Critical' },
                              { key: 'z_high_3tier', label: 'High' },
                              { key: 'z_medium_3tier', label: 'Medium' },
                            ].map(item => (
                              <div key={item.key}>
                                <label className="block text-xs text-slate-500 dark:text-slate-400 mb-1">{item.label}</label>
                                <NumberInput value={l2[item.key] as number} step={0.5} onChange={(v) => updateL2Value(item.key, v)} />
                              </div>
                            ))}
                          </div>
                        </div>
                        <div>
                          <h4 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-3">2-Tier Agreement</h4>
                          <div className="grid grid-cols-2 gap-4">
                            {[
                              { key: 'z_high_2tier', label: 'High' },
                              { key: 'z_medium_2tier', label: 'Medium' },
                            ].map(item => (
                              <div key={item.key}>
                                <label className="block text-xs text-slate-500 dark:text-slate-400 mb-1">{item.label}</label>
                                <NumberInput value={l2[item.key] as number} step={0.5} onChange={(v) => updateL2Value(item.key, v)} />
                              </div>
                            ))}
                          </div>
                        </div>
                        <div>
                          <h4 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-3">1-Tier Agreement</h4>
                          <div className="max-w-xs">
                            <label className="block text-xs text-slate-500 dark:text-slate-400 mb-1">Medium</label>
                            <NumberInput value={l2.z_medium_1tier as number} step={0.5} onChange={(v) => updateL2Value('z_medium_1tier', v)} />
                          </div>
                        </div>
                      </div>
                    </SectionCard>

                    <SectionCard title="Warmup Thresholds" description="Minimum traffic before detection activates (prevents false positives on startup)">
                      <div className="divide-y divide-slate-100 dark:divide-slate-800">
                        <FieldRow label="PPS Threshold" description="Minimum packets/sec before detection starts">
                          <NumberInput value={l2.warmup_pps_threshold as number} min={0} onChange={(v) => updateL2Value('warmup_pps_threshold', v)} />
                        </FieldRow>
                        <FieldRow label="SYN Threshold" description="Minimum SYN packets/sec before SYN flood detection">
                          <NumberInput value={l2.warmup_syn_threshold as number} min={0} onChange={(v) => updateL2Value('warmup_syn_threshold', v)} />
                        </FieldRow>
                      </div>
                    </SectionCard>

                    <SectionCard title="Advanced Detection Internals" description="Expert tuning parameters for warmup behavior and feature scoring. Defaults are well-tested — change with caution." collapsible defaultOpen={false}>
                      <div className="divide-y divide-slate-100 dark:divide-slate-800">
                        <FieldRow label="Warmup Z Coefficient" description="Z-score multiplier during warmup phase (higher = less sensitive during warmup)">
                          <NumberInput value={l2.warmup_z_coefficient as number ?? 4.0} step={0.5} min={1.0} max={10.0} onChange={(v) => updateL2Value('warmup_z_coefficient', v)} />
                        </FieldRow>
                        <FieldRow label="Warmup Z Maximum" description="Maximum effective Z-threshold during warmup">
                          <NumberInput value={l2.warmup_z_max as number ?? 20.0} step={1.0} min={5.0} max={50.0} onChange={(v) => updateL2Value('warmup_z_max', v)} />
                        </FieldRow>
                        <FieldRow label="High Source Count Boost" description="Multiplier for anomaly score when many unique source IPs detected">
                          <NumberInput value={l2.warmup_high_src_boost as number ?? 1.2} step={0.1} min={1.0} max={3.0} onChange={(v) => updateL2Value('warmup_high_src_boost', v)} />
                        </FieldRow>
                        <FieldRow label="Min Features per Tier" description="Minimum anomalous features required per tier to flag anomaly">
                          <NumberInput value={l2.min_features_per_tier as number ?? 2} min={1} max={10} onChange={(v) => updateL2Value('min_features_per_tier', v)} />
                        </FieldRow>
                        <FieldRow label="Strong Z Multiplier" description="Multiplier for strongly-deviating features (boosts high-Z features in scoring)">
                          <NumberInput value={l2.strong_z_multiplier as number ?? 2.0} step={0.5} min={1.0} max={5.0} onChange={(v) => updateL2Value('strong_z_multiplier', v)} />
                        </FieldRow>
                      </div>
                    </SectionCard>

                    <SectionCard title="Flow Characterization" description="Weights and thresholds for attack traffic classification (SYN completion, response ratio, packet size, port concentration)" collapsible>
                      <div className="divide-y divide-slate-100 dark:divide-slate-800">
                        <FieldRow label="SYN Completion Weight" description="Weight for SYN handshake completion ratio in flow scoring">
                          <NumberInput value={l2.fc_weight_syn_completion as number ?? 0.4} step={0.05} min={0} max={1.0} onChange={(v) => updateL2Value('fc_weight_syn_completion', v)} />
                        </FieldRow>
                        <FieldRow label="Response Ratio Weight" description="Weight for response packet ratio in flow scoring">
                          <NumberInput value={l2.fc_weight_response_ratio as number ?? 0.3} step={0.05} min={0} max={1.0} onChange={(v) => updateL2Value('fc_weight_response_ratio', v)} />
                        </FieldRow>
                        <FieldRow label="BPP Diversity Weight" description="Weight for bytes-per-packet diversity in flow scoring">
                          <NumberInput value={l2.fc_weight_bpp_diversity as number ?? 0.15} step={0.05} min={0} max={1.0} onChange={(v) => updateL2Value('fc_weight_bpp_diversity', v)} />
                        </FieldRow>
                        <FieldRow label="Port Concentration Weight" description="Weight for destination port concentration in flow scoring">
                          <NumberInput value={l2.fc_weight_port_concentration as number ?? 0.15} step={0.05} min={0} max={1.0} onChange={(v) => updateL2Value('fc_weight_port_concentration', v)} />
                        </FieldRow>
                        <FieldRow label="BPP Low Threshold" description="Bytes-per-packet below this is 'small packet attack' territory">
                          <NumberInput value={l2.fc_bpp_low as number ?? 100} min={0} max={1500} onChange={(v) => updateL2Value('fc_bpp_low', v)} />
                        </FieldRow>
                        <FieldRow label="BPP High Threshold" description="Bytes-per-packet above this is 'amplification' territory">
                          <NumberInput value={l2.fc_bpp_high as number ?? 1000} min={0} max={9000} onChange={(v) => updateL2Value('fc_bpp_high', v)} />
                        </FieldRow>
                        <FieldRow label="Port Few Threshold" description="Fewer unique dst ports than this = single-service targeting">
                          <NumberInput value={l2.fc_port_few as number ?? 50} min={1} max={1000} onChange={(v) => updateL2Value('fc_port_few', v)} />
                        </FieldRow>
                        <FieldRow label="Port Moderate Threshold" description="More unique dst ports than this = scanning behavior">
                          <NumberInput value={l2.fc_port_moderate as number ?? 200} min={1} max={10000} onChange={(v) => updateL2Value('fc_port_moderate', v)} />
                        </FieldRow>
                      </div>
                    </SectionCard>

                    <SectionCard title="Fast Detection" description="100ms fast tier for catching sub-second pulse attacks that evade the 1Hz detection cycle" collapsible>
                      <div className="divide-y divide-slate-100 dark:divide-slate-800">
                        <FieldRow label="Enable Fast Detection" description="Run a 100ms detection tier alongside the standard 1Hz cycle">
                          <Toggle enabled={!!(l2.fast_detection_enabled)} onChange={(v) => updateL2Value('fast_detection_enabled', v)} label="Fast detection" />
                        </FieldRow>
                        <FieldRow label="Interval (ms)" description="Fast detection sampling interval (default: 100ms = 10 samples/sec)">
                          <NumberInput value={l2.fast_detection_interval_ms as number ?? 100} min={50} max={1000} onChange={(v) => updateL2Value('fast_detection_interval_ms', v)} />
                        </FieldRow>
                        <FieldRow label="Threshold Multiplier" description="Spike = multiplier x baseline. Lower = more sensitive.">
                          <NumberInput value={l2.fast_threshold_multiplier as number ?? 1.5} step={0.1} min={1.1} max={5.0} onChange={(v) => updateL2Value('fast_threshold_multiplier', v)} />
                        </FieldRow>
                        <FieldRow label="Min PPS Spike" description="Minimum packets/sec to consider a spike (absolute floor)">
                          <NumberInput value={l2.fast_min_pps_spike as number ?? 10000} min={100} max={10000000} onChange={(v) => updateL2Value('fast_min_pps_spike', v)} />
                        </FieldRow>
                        <FieldRow label="SYN Spike Threshold" description="SYN packets/sec spike threshold">
                          <NumberInput value={l2.fast_syn_spike_threshold as number ?? 5000} min={100} max={10000000} onChange={(v) => updateL2Value('fast_syn_spike_threshold', v)} />
                        </FieldRow>
                        <FieldRow label="Consecutive Required" description="Number of consecutive fast detections needed to confirm attack">
                          <NumberInput value={l2.fast_consecutive_required as number ?? 2} min={1} max={10} onChange={(v) => updateL2Value('fast_consecutive_required', v)} />
                        </FieldRow>
                        <FieldRow label="Warmup Samples" description="Number of 100ms samples to collect before fast detection activates (default: 30 = 3 seconds)">
                          <NumberInput value={l2.fast_warmup_samples as number ?? 30} min={5} max={300} onChange={(v) => updateL2Value('fast_warmup_samples', v)} />
                        </FieldRow>
                      </div>
                    </SectionCard>

                    <SectionCard title="Baseline Learning" description="Exponential moving average parameters for traffic baselines" collapsible>
                      <div className="divide-y divide-slate-100 dark:divide-slate-800">
                        <FieldRow label="Freeze During Attack" description="Pause baseline learning while attack is active to prevent poisoning">
                          <Toggle enabled={!!(l2.baseline_freeze_enabled)} onChange={(v) => updateL2Value('baseline_freeze_enabled', v)} label="Freeze baselines" />
                        </FieldRow>
                        <FieldRow label="Alpha 1s Window" description="Learning rate for 1-second burst baseline (higher = faster adaptation)">
                          <NumberInput value={l2.alpha_immediate_1s as number} step={0.01} min={0.01} max={1} onChange={(v) => updateL2Value('alpha_immediate_1s', v)} />
                        </FieldRow>
                        <FieldRow label="Alpha 10s Window" description="Learning rate for 10-second baseline">
                          <NumberInput value={l2.alpha_immediate_10s as number} step={0.01} min={0.01} max={1} onChange={(v) => updateL2Value('alpha_immediate_10s', v)} />
                        </FieldRow>
                        <FieldRow label="Alpha 60s Window" description="Learning rate for 60-second baseline">
                          <NumberInput value={l2.alpha_immediate_60s as number} step={0.01} min={0.01} max={1} onChange={(v) => updateL2Value('alpha_immediate_60s', v)} />
                        </FieldRow>
                        <FieldRow label="Alpha Hourly" description="Learning rate for ~1h window">
                          <NumberInput value={l2.alpha_hourly as number} step={0.01} min={0.01} max={1} onChange={(v) => updateL2Value('alpha_hourly', v)} />
                        </FieldRow>
                        <FieldRow label="Alpha Weekly" description="Learning rate for ~7d window">
                          <NumberInput value={l2.alpha_weekly as number} step={0.01} min={0.01} max={1} onChange={(v) => updateL2Value('alpha_weekly', v)} />
                        </FieldRow>
                        <FieldRow label="Min Samples (1s)" description="Samples needed before 1s baseline activates">
                          <NumberInput value={l2.min_samples_immediate_1s as number} min={1} onChange={(v) => updateL2Value('min_samples_immediate_1s', v)} />
                        </FieldRow>
                        <FieldRow label="Min Samples (10s)" description="Samples needed before 10s baseline activates">
                          <NumberInput value={l2.min_samples_immediate_10s as number} min={1} onChange={(v) => updateL2Value('min_samples_immediate_10s', v)} />
                        </FieldRow>
                        <FieldRow label="Min Samples (60s)" description="Samples needed before 60s baseline activates">
                          <NumberInput value={l2.min_samples_immediate_60s as number} min={1} onChange={(v) => updateL2Value('min_samples_immediate_60s', v)} />
                        </FieldRow>
                        <FieldRow label="Min Samples (Hourly)" description="Samples needed before hourly baseline activates">
                          <NumberInput value={l2.min_samples_hourly as number} min={1} onChange={(v) => updateL2Value('min_samples_hourly', v)} />
                        </FieldRow>
                        <FieldRow label="Min Samples (Weekly)" description="Samples needed before weekly baseline activates">
                          <NumberInput value={l2.min_samples_weekly as number} min={1} onChange={(v) => updateL2Value('min_samples_weekly', v)} />
                        </FieldRow>
                      </div>
                    </SectionCard>

                    <SectionCard title="Baseline Persistence" description="Control how saved baselines are trusted after restarts" collapsible>
                      <div className="divide-y divide-slate-100 dark:divide-slate-800">
                        <FieldRow label="Save Interval (sec)" description="How often baselines are persisted to disk (lower = less data loss on crash, higher = less disk I/O)">
                          <NumberInput value={l2.baseline_save_interval_sec as number ?? 300} min={30} max={3600} step={30} onChange={(v) => updateL2Value('baseline_save_interval_sec', v)} />
                        </FieldRow>
                        <FieldRow label="Fresh Threshold (sec)" description="Baselines younger than this get full trust (MATURE)">
                          <NumberInput value={l2.baseline_fresh_sec as number ?? 3600} min={60} max={86400} onChange={(v) => updateL2Value('baseline_fresh_sec', v)} />
                        </FieldRow>
                        <FieldRow label="Moderate Threshold (sec)" description="1.5x variance inflation (wider tolerance)">
                          <NumberInput value={l2.baseline_moderate_sec as number ?? 21600} min={3600} max={604800} onChange={(v) => updateL2Value('baseline_moderate_sec', v)} />
                        </FieldRow>
                        <FieldRow label="Stale Threshold (sec)" description="2.0x variance inflation">
                          <NumberInput value={l2.baseline_stale_sec as number ?? 86400} min={3600} max={604800} onChange={(v) => updateL2Value('baseline_stale_sec', v)} />
                        </FieldRow>
                        <FieldRow label="Expired Threshold (sec)" description="3.0x variance inflation. Older baselines are discarded.">
                          <NumberInput value={l2.baseline_expired_sec as number ?? 604800} min={86400} max={2592000} onChange={(v) => updateL2Value('baseline_expired_sec', v)} />
                        </FieldRow>
                      </div>
                    </SectionCard>

                    <SectionCard title="Progressive Trust" description="Scale detection sensitivity based on learning confidence" collapsible>
                      <div className="divide-y divide-slate-100 dark:divide-slate-800">
                        <FieldRow label="Cold Multiplier" description="Z-score × this during COLD phase (higher = less sensitive)">
                          <NumberInput value={l2.trust_multiplier_cold as number ?? 2.0} step={0.1} min={1.0} max={5.0} onChange={(v) => updateL2Value('trust_multiplier_cold', v)} />
                        </FieldRow>
                        <FieldRow label="Warming Multiplier" description="Z-score × this during WARMING phase">
                          <NumberInput value={l2.trust_multiplier_warming as number ?? 1.5} step={0.1} min={1.0} max={5.0} onChange={(v) => updateL2Value('trust_multiplier_warming', v)} />
                        </FieldRow>
                        <FieldRow label="Moderate Multiplier" description="Z-score × this during MODERATE phase">
                          <NumberInput value={l2.trust_multiplier_moderate as number ?? 1.2} step={0.1} min={1.0} max={5.0} onChange={(v) => updateL2Value('trust_multiplier_moderate', v)} />
                        </FieldRow>
                      </div>
                    </SectionCard>

                    <SectionCard title="Baseline Poison Protection" description="Detect and block attempts to gradually shift baselines" collapsible>
                      <div className="divide-y divide-slate-100 dark:divide-slate-800">
                        <FieldRow label="Enable Protection" description="Monitor for suspiciously consistent baseline shifts">
                          <Toggle enabled={!!(l2.baseline_poison_protection_enabled)} onChange={(v) => updateL2Value('baseline_poison_protection_enabled', v)} label="Poison protection" />
                        </FieldRow>
                        <FieldRow label="Change Rate Threshold" description="Max allowed baseline change rate before flagging">
                          <NumberInput value={l2.baseline_change_rate_threshold as number} step={0.1} min={0.1} onChange={(v) => updateL2Value('baseline_change_rate_threshold', v)} />
                        </FieldRow>
                        <FieldRow label="Window (sec)" description="Time window for poison detection">
                          <NumberInput value={l2.baseline_poison_window_sec as number} min={10} onChange={(v) => updateL2Value('baseline_poison_window_sec', v)} />
                        </FieldRow>
                        <FieldRow label="Count Threshold" description="Number of suspicious shifts to trigger protection">
                          <NumberInput value={l2.baseline_poison_count_threshold as number} min={1} onChange={(v) => updateL2Value('baseline_poison_count_threshold', v)} />
                        </FieldRow>
                      </div>
                    </SectionCard>

                    <SectionCard title="Layer 2 Logging" description="Logging verbosity for anomaly detection" collapsible>
                      <div className="divide-y divide-slate-100 dark:divide-slate-800">
                        <FieldRow label="Log Detections" description="Log each anomaly detection event with severity and feature details">
                          <Toggle enabled={!!(l2.log_detections ?? true)} onChange={(v) => updateL2Value('log_detections', v)} label="Log detections" />
                        </FieldRow>
                        <FieldRow label="Log Baseline Updates" description="Log each baseline value update">
                          <Toggle enabled={!!(l2.log_baseline_updates)} onChange={(v) => updateL2Value('log_baseline_updates', v)} label="Log baselines" />
                        </FieldRow>
                        <FieldRow label="Log Interval (sec)" description="Minimum interval between repeated log entries for the same event type">
                          <NumberInput value={l2.log_interval_sec as number ?? 60} min={1} max={3600} onChange={(v) => updateL2Value('log_interval_sec', v)} />
                        </FieldRow>
                        <FieldRow label="Log Level" description="0=Emergency to 7=Debug">
                          <SelectInput
                            value={(l2.log_level as number) ?? 2}
                            onChange={(v) => updateL2Value('log_level', parseInt(v))}
                            options={LOG_LEVELS.slice(0, 8)}
                          />
                        </FieldRow>
                      </div>
                    </SectionCard>

                    <div className="flex justify-end gap-2">
                      <button
                        onClick={async () => { await api.reloadLayer2Config(); queryClient.invalidateQueries({ queryKey: ['layer2-config'] }); toast.success('Layer 2 config reloaded'); }}
                        className="btn btn-secondary btn-sm"
                      >
                        <ArrowPathIcon className="h-3.5 w-3.5" /> Reload L2
                      </button>
                      <button
                        onClick={async () => { await api.resetLayer2Config(); queryClient.invalidateQueries({ queryKey: ['layer2-config'] }); toast.success('Layer 2 config reset'); }}
                        className="btn btn-danger btn-sm"
                      >
                        Reset L2 Defaults
                      </button>
                    </div>
                  </div>
                );
              }

              // ==================== FEATURE SELECTION TAB ====================
              if (activeTab === 'feature-selection') {
                return <FeatureSelectionTab />;
              }

              // ==================== ATTACK RESPONSE TAB ====================
              if (activeTab === 'attack-response') {
                return (
                  <div className="space-y-3 animate-fade-in">
                    <InfoBanner>
                      Controls how Layer 1 automatically responds when Layer 2 detects an anomaly.
                      These settings determine the speed and aggressiveness of automated countermeasures.
                    </InfoBanner>

                    {(() => {
                      const l2r = l1?.layer2_response as Record<string, unknown> | undefined;
                      if (!l2r) return (
                        <InfoBanner variant="warning">
                          Layer 2 response configuration not available. The backend may not expose this section yet.
                        </InfoBanner>
                      );
                      return (
                        <SectionCard title="Automated Response" description="Layer 1 reactions to Layer 2 anomaly detection">
                          <div className="divide-y divide-slate-100 dark:divide-slate-800">
                            <FieldRow label="Enable Automated Response" description="Allow Layer 1 to automatically engage countermeasures on attack detection">
                              <Toggle enabled={!!(l2r.enabled)} onChange={(v) => updateL1Value('layer2_response', 'enabled', v)} label="Automated response" />
                            </FieldRow>
                            <FieldRow label="Auto-Enable SYN Proxy" description="Automatically activate SYN proxy when attack detected">
                              <Toggle enabled={!!(l2r.auto_enable_syn_proxy_on_attack)} onChange={(v) => updateL1Value('layer2_response', 'auto_enable_syn_proxy_on_attack', v)} label="Auto SYN proxy" />
                            </FieldRow>
                            <FieldRow label="Auto-Reduce Rate Limits" description="Automatically tighten rate limits during attack">
                              <Toggle enabled={!!(l2r.auto_reduce_rate_limits_on_attack)} onChange={(v) => updateL1Value('layer2_response', 'auto_reduce_rate_limits_on_attack', v)} label="Auto rate limit" />
                            </FieldRow>
                            <FieldRow label="Rate Limit Divisor" description="Attack rate limits = normal / divisor. Higher = more aggressive.">
                              <NumberInput value={l2r.attack_rate_limit_divisor as number} min={1} max={100} onChange={(v) => updateL1Value('layer2_response', 'attack_rate_limit_divisor', v)} />
                            </FieldRow>
                            <FieldRow label="Min Anomaly Level" description="Minimum anomaly level to trigger response">
                              <SelectInput
                                value={(l2r.min_anomaly_level_for_response as number) ?? 2}
                                onChange={(v) => updateL1Value('layer2_response', 'min_anomaly_level_for_response', parseInt(v))}
                                options={ANOMALY_LEVELS}
                              />
                            </FieldRow>
                            <FieldRow label="Response Delay (sec)" description="Seconds to wait after detection before engaging countermeasures">
                              <NumberInput value={l2r.response_delay_sec as number} min={0} max={30} onChange={(v) => updateL1Value('layer2_response', 'response_delay_sec', v)} />
                            </FieldRow>
                          </div>
                        </SectionCard>
                      );
                    })()}

                    {l2 && (
                      <SectionCard title="Attack Classification" description="Duration thresholds for false positive / true positive classification">
                        <div className="divide-y divide-slate-100 dark:divide-slate-800">
                          <FieldRow label="FP Duration Threshold (sec)" description="Attacks shorter than this are classified as likely false positives">
                            <NumberInput value={l2.fp_duration_threshold_sec as number} step={1} min={0} onChange={(v) => updateL2Value('fp_duration_threshold_sec', v)} />
                          </FieldRow>
                          <FieldRow label="TP Duration Threshold (sec)" description="Attacks longer than this are classified as confirmed true positives">
                            <NumberInput value={l2.tp_duration_threshold_sec as number} step={1} min={0} onChange={(v) => updateL2Value('tp_duration_threshold_sec', v)} />
                          </FieldRow>
                          <FieldRow label="FP Z-Score Multiplier" description="Short detections with Z > threshold × this are NOT classified as FP (protects real flash attacks)">
                            <NumberInput value={l2.adaptive_fp_z_multiplier as number ?? 1.5} step={0.1} min={1.0} max={3.0} onChange={(v) => updateL2Value('adaptive_fp_z_multiplier', v)} />
                          </FieldRow>
                        </div>
                      </SectionCard>
                    )}
                  </div>
                );
              }

              // ==================== ADAPTIVE THRESHOLD TAB ====================
              if (activeTab === 'adaptive' && adaptive) {
                return (
                  <div className="space-y-3 animate-fade-in">
                    <InfoBanner>
                      The adaptive threshold system automatically adjusts the Z-score detection threshold
                      based on false positive and true positive feedback from attack classifications.
                    </InfoBanner>

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      {[
                        { label: 'Status', value: adaptive.enabled ? 'Active' : 'Disabled', color: adaptive.enabled ? 'text-green-600 dark:text-green-400' : 'text-slate-500' },
                        { label: 'Current Threshold', value: typeof adaptive.current_threshold === 'number' ? (adaptive.current_threshold as number).toFixed(2) : 'N/A', color: 'text-blue-600 dark:text-blue-400' },
                        { label: 'Threshold Range', value: `${adaptive.min_threshold ?? '?'} - ${adaptive.max_threshold ?? '?'}`, color: 'text-slate-900 dark:text-white' },
                        { label: 'Eval Interval', value: `${adaptive.eval_interval_sec ?? '?'}s`, color: 'text-slate-900 dark:text-white' },
                      ].map(item => (
                        <div key={item.label} className="card p-4 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800">
                          <p className="text-xs text-slate-500 dark:text-slate-400">{item.label}</p>
                          <p className={`text-lg font-semibold mt-1 ${item.color}`}>{item.value}</p>
                        </div>
                      ))}
                    </div>

                    <SectionCard title="Adaptive Tuning Settings" description="Configure how the threshold auto-adjusts">
                      <div className="divide-y divide-slate-100 dark:divide-slate-800">
                        <FieldRow label="Enable Adaptive Tuning" description="Automatically adjust Z-score threshold based on FP/TP feedback">
                          <Toggle enabled={!!(adaptive.enabled)} onChange={toggleAdaptive} label="Adaptive tuning" />
                        </FieldRow>
                        <FieldRow label="Min Threshold" description="Lower bound for adaptive adjustment">
                          <NumberInput value={adaptive.min_threshold as number} step={0.5} min={3} max={8} onChange={(v) => updateAdaptiveValue({ min_threshold: v })} />
                        </FieldRow>
                        <FieldRow label="Max Threshold" description="Upper bound for adaptive adjustment">
                          <NumberInput value={adaptive.max_threshold as number} step={0.5} min={6} max={15} onChange={(v) => updateAdaptiveValue({ max_threshold: v })} />
                        </FieldRow>
                        <FieldRow label="Step Size" description="How much to adjust threshold per evaluation">
                          <NumberInput value={adaptive.step as number} step={0.01} min={0.1} max={1} onChange={(v) => updateAdaptiveValue({ step: v })} />
                        </FieldRow>
                        <FieldRow label="Eval Interval (sec)" description="Seconds between evaluations">
                          <NumberInput value={adaptive.eval_interval_sec as number} min={60} max={3600} onChange={(v) => updateAdaptiveValue({ eval_interval_sec: v })} />
                        </FieldRow>
                        <FieldRow label="FP Threshold" description="FP rate above this triggers threshold increase">
                          <NumberInput value={adaptive.fp_threshold as number} step={0.01} min={0.1} max={0.8} onChange={(v) => updateAdaptiveValue({ fp_threshold: v })} />
                        </FieldRow>
                        <FieldRow label="TP Min" description="Minimum TP rate before allowing threshold decrease">
                          <NumberInput value={adaptive.tp_min as number} step={0.01} min={0.2} max={0.9} onChange={(v) => updateAdaptiveValue({ tp_min: v })} />
                        </FieldRow>
                        <FieldRow label="Min Samples" description="Minimum attack samples needed before adjusting">
                          <NumberInput value={adaptive.min_samples as number} min={5} max={100} onChange={(v) => updateAdaptiveValue({ min_samples: v })} />
                        </FieldRow>
                        <FieldRow label="Daily Max Increase" description="Max Z-score increase per 24h window (anti-gaming ratchet)">
                          <NumberInput value={adaptive.daily_max_increase as number ?? 2.0} step={0.5} min={0.5} max={5} onChange={(v) => updateAdaptiveValue({ daily_max_increase: v })} />
                        </FieldRow>
                        <FieldRow label="FP Z-Score Guard" description="Short attacks with Z > threshold × this are NOT classified as FP">
                          <NumberInput value={adaptive.fp_z_multiplier as number ?? 1.5} step={0.1} min={1.0} max={3.0} onChange={(v) => updateAdaptiveValue({ fp_z_multiplier: v })} />
                        </FieldRow>
                      </div>
                    </SectionCard>
                  </div>
                );
              }

              return null;
            })()}
          </div>

          {/* Config History */}
          <ConfigHistory />
          </>)}
        </div>
      )}
    </div>
  );
}

function ConfigHistory() {
  const queryClient = useQueryClient();
  const [restoring, setRestoring] = useState<number | null>(null);

  const { data: historyData } = useQuery({
    queryKey: ['config-history'],
    queryFn: () => api.getLayer1ConfigHistory(20),
    refetchInterval: 30000,
  });

  const history = historyData?.history || [];

  const handleRestore = async (entry: ConfigHistoryEntry) => {
    if (!confirm(`Restore config to version ${entry.version}?`)) return;
    setRestoring(entry.id);
    try {
      await api.restoreLayer1Snapshot(entry.id);
      queryClient.invalidateQueries({ queryKey: ['layer1-config'] });
      queryClient.invalidateQueries({ queryKey: ['config-history'] });
      toast.success(`Restored to version ${entry.version}`);
    } catch {
      toast.error('Restore failed');
    } finally {
      setRestoring(null);
    }
  };

  const formatTime = (iso: string | null) => {
    if (!iso) return '—';
    const d = new Date(iso);
    const now = new Date();
    const diffMs = now.getTime() - d.getTime();
    const diffMin = Math.floor(diffMs / 60000);
    if (diffMin < 1) return 'Just now';
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHr = Math.floor(diffMin / 60);
    if (diffHr < 24) return `${diffHr}h ago`;
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  return (
    <SectionCard
      title="Config History"
      description="Version snapshots for rollback. Each config change is automatically saved."
      collapsible
    >
      {history.length === 0 ? (
        <p className="text-sm text-slate-400 dark:text-slate-500 py-4 text-center">No history yet. Changes will appear here after your first config update.</p>
      ) : (
        <div className="divide-y divide-slate-100 dark:divide-slate-800">
          {history.map((entry, idx) => (
            <div key={entry.id} className="flex items-center justify-between py-2.5 px-1">
              <div className="flex items-center gap-3 min-w-0">
                <div className="flex items-center gap-1.5 text-xs text-slate-400 dark:text-slate-500 shrink-0">
                  <ClockIcon className="h-3.5 w-3.5" />
                  <span className="font-mono">v{entry.version}</span>
                </div>
                <span className="text-sm text-slate-600 dark:text-slate-300 truncate">
                  {entry.description || (idx === 0 ? 'Current' : 'Config change')}
                </span>
                <span className="text-xs text-slate-400 dark:text-slate-500 shrink-0">
                  {formatTime(entry.created_at)}
                </span>
              </div>
              {idx > 0 && (
                <button
                  onClick={() => handleRestore(entry)}
                  disabled={restoring !== null}
                  className="btn btn-secondary btn-xs shrink-0 ml-2"
                >
                  {restoring === entry.id ? 'Restoring...' : 'Restore'}
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </SectionCard>
  );
}

export default ConfigPage;
