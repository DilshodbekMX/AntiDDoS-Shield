/**
 * Asset Detail Page
 *
 * Detailed view of a single protected IP address showing:
 * - Real-time traffic metrics
 * - Anomaly detection status
 * - Protocol breakdown
 * - Historical data
 * - Quick actions (block, whitelist, etc.)
 */

import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { clsx } from 'clsx';
import {
  ArrowLeftIcon,
  ArrowPathIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  ChartBarIcon,
  SignalIcon,
  BoltIcon,
  FireIcon,
  ArrowTrendingUpIcon,
  FingerPrintIcon,
  AdjustmentsHorizontalIcon,
  ChevronDownIcon,
  BeakerIcon,
} from '@heroicons/react/24/outline';
import {
  MetricCard,
  GaugeChart,
  ThreatBadge,
  ThreatLevelBar,
  StatusIndicator,
  EmptyState,
} from '../components/ui';
import api from '../services/api';
import { useState, useCallback, useMemo } from 'react';
import { formatBytes, formatNumber } from '../utils/formatting';
import toast from 'react-hot-toast';
import {
  FEATURE_DISPLAY_NAMES,
  FEATURE_GROUP_ORDER,
  GROUP_DESCRIPTIONS,
  FEATURE_INFO,
  qualityColor,
  qualityLabel,
} from './featureConfig';

interface AssetStats {
  dst_ip: string;
  dst_ip_str: string;
  has_traffic_data: boolean;
  packets_per_sec: number;
  bytes_per_sec: number;
  flows_per_sec: number;
  total_packets: number;
  active_flows: number;
  syn_per_sec: number;
  syn_ack_per_sec: number;
  ack_per_sec: number;
  rst_per_sec: number;
  fin_per_sec: number;
  tcp_ratio: number;
  udp_ratio: number;
  icmp_ratio: number;
  other_ratio: number;
  unique_src_ips: number;
  unique_flows: number;
  max_flow_fraction: number;
  topk_flow_share: number;
  heavy_hitter_count: number;
  avg_packets_per_flow: number;
  flow_duration_avg_ms: number;
  anomaly_active: boolean;
  anomaly_level: number;
  anomaly_level_name: string;
  max_z_score: number;
  tier_agreement: number;
  anomalous_feature_count: number;
  anomaly_protocol: number;
  anomaly_protocol_name: string;
  attack_type: number;
  attack_type_name: string;
  anomaly_dst_port: number;
}

// ==================== Detection Config Section ====================

const OVERRIDE_FIELDS = [
  { key: 'z_score_threshold', label: 'Z-Score Threshold', type: 'number', min: 3, max: 12, step: 0.5, group: 'detection', description: 'Anomaly detection sensitivity (lower = more sensitive)' },
  { key: 'min_tier_agreement', label: 'Min Tier Agreement', type: 'select', options: [1, 2, 3], group: 'detection', description: 'Number of baseline tiers that must agree' },
  { key: 'min_features_per_tier', label: 'Min Features/Tier', type: 'number', min: 1, max: 24, step: 1, group: 'detection', description: 'Features above threshold to trigger a tier' },
  { key: 'cool_down_seconds', label: 'Cool-Down (sec)', type: 'number', min: 0, max: 300, step: 5, group: 'handling', description: 'Wait time after anomaly clears' },
  { key: 'baseline_freeze_enabled', label: 'Freeze Baselines', type: 'toggle', group: 'handling', description: 'Freeze baselines during attack' },
  { key: 'alpha_immediate_1s', label: 'Alpha 1s', type: 'number', min: 0.01, max: 1, step: 0.01, group: 'learning', description: 'EWMA smoothing for 1s sub-tier' },
  { key: 'alpha_immediate_10s', label: 'Alpha 10s', type: 'number', min: 0.01, max: 1, step: 0.01, group: 'learning', description: 'EWMA smoothing for 10s sub-tier' },
  { key: 'alpha_immediate_60s', label: 'Alpha 60s', type: 'number', min: 0.001, max: 1, step: 0.001, group: 'learning', description: 'EWMA smoothing for 60s sub-tier' },
  { key: 'min_samples_immediate_1s', label: 'Min Samples 1s', type: 'number', min: 1, max: 1000, step: 1, group: 'learning' },
  { key: 'min_samples_immediate_10s', label: 'Min Samples 10s', type: 'number', min: 1, max: 1000, step: 1, group: 'learning' },
  { key: 'min_samples_immediate_60s', label: 'Min Samples 60s', type: 'number', min: 1, max: 1000, step: 1, group: 'learning' },
  { key: 'warmup_pps_threshold', label: 'Warmup PPS', type: 'number', min: 1000, max: 10000000, step: 1000, group: 'warmup', description: 'PPS threshold during warmup' },
  { key: 'warmup_syn_threshold', label: 'Warmup SYN/s', type: 'number', min: 100, max: 1000000, step: 100, group: 'warmup', description: 'SYN/s threshold during warmup' },
] as const;

function DetectionConfigSection({ ip }: { ip: string }) {
  const queryClient = useQueryClient();
  const [expanded, setExpanded] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [formData, setFormData] = useState<Record<string, number | boolean | null>>({});
  const [dirty, setDirty] = useState(false);

  const { data: configData, isLoading } = useQuery({
    queryKey: ['per-ip-l2-config', ip],
    queryFn: async () => {
      const res = await api.getPerIPL2Config(ip) as { success: boolean; data: {
        is_active: boolean;
        version: number;
        overrides: Record<string, number | boolean>;
        effective: Record<string, number | boolean>;
        global_defaults?: Record<string, number | boolean>;
        updated_at: string | null;
        updated_by: string | null;
      }};
      return res.data;
    },
    refetchInterval: false,
  });

  const saveMutation = useMutation({
    mutationFn: async (data: Record<string, unknown>) => {
      return api.updatePerIPL2Config(ip, data);
    },
    onSuccess: () => {
      toast.success('Detection config saved');
      queryClient.invalidateQueries({ queryKey: ['per-ip-l2-config', ip] });
      setDirty(false);
    },
    onError: (err: Error) => {
      toast.error(`Failed to save: ${err.message}`);
    },
  });

  const resetMutation = useMutation({
    mutationFn: async () => {
      return api.deletePerIPL2Config(ip);
    },
    onSuccess: () => {
      toast.success('Reverted to global defaults');
      queryClient.invalidateQueries({ queryKey: ['per-ip-l2-config', ip] });
      setFormData({});
      setDirty(false);
    },
    onError: (err: Error) => {
      toast.error(`Failed to reset: ${err.message}`);
    },
  });

  const handleFieldChange = useCallback((key: string, value: number | boolean | null) => {
    setFormData(prev => ({ ...prev, [key]: value }));
    setDirty(true);
  }, []);

  const handleSave = () => {
    // Build payload: only include fields that have been changed
    const payload: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(formData)) {
      if (value !== undefined) {
        payload[key] = value;
      }
    }
    if (Object.keys(payload).length > 0) {
      saveMutation.mutate(payload);
    }
  };

  const getEffectiveValue = (key: string): number | boolean | undefined => {
    if (formData[key] !== undefined && formData[key] !== null) {
      return formData[key] as number | boolean;
    }
    return configData?.effective[key] as number | boolean | undefined;
  };

  const isOverridden = (key: string): boolean => {
    if (formData[key] !== undefined && formData[key] !== null) return true;
    return configData?.overrides[key] !== undefined;
  };

  const handleRevertField = (key: string) => {
    // Setting to null in the payload will revert to global on next save
    setFormData(prev => ({ ...prev, [key]: null }));
    setDirty(true);
  };

  const renderField = (field: typeof OVERRIDE_FIELDS[number]) => {
    const effectiveValue = getEffectiveValue(field.key);
    const overridden = isOverridden(field.key);
    const globalValue = configData?.global_defaults?.[field.key];

    return (
      <div key={field.key} className="flex items-center justify-between py-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm text-slate-700 dark:text-slate-300">{field.label}</span>
            {overridden && (
              <span className="px-1.5 py-0.5 text-[10px] font-medium bg-indigo-500/20 text-indigo-300 rounded">
                Custom
              </span>
            )}
            {!overridden && (
              <span className="px-1.5 py-0.5 text-[10px] font-medium bg-slate-200 dark:bg-slate-700 text-slate-500 dark:text-slate-400 rounded">
                Global
              </span>
            )}
          </div>
          {'description' in field && field.description && (
            <div className="text-xs text-slate-500 mt-0.5">{field.description}</div>
          )}
        </div>
        <div className="flex items-center gap-2 ml-4">
          {field.type === 'number' && (
            <input
              type="number"
              min={field.min}
              max={field.max}
              step={field.step}
              value={formData[field.key] !== undefined && formData[field.key] !== null
                ? formData[field.key] as number
                : (effectiveValue as number) ?? ''}
              onChange={(e) => {
                const val = e.target.value === '' ? null : Number(e.target.value);
                handleFieldChange(field.key, val);
              }}
              className="w-28 px-2 py-1 text-sm bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded text-slate-900 dark:text-white text-right focus:outline-none focus:ring-1 focus:ring-indigo-500"
            />
          )}
          {field.type === 'select' && (
            <select
              value={formData[field.key] !== undefined && formData[field.key] !== null
                ? String(formData[field.key])
                : String(effectiveValue ?? '')}
              onChange={(e) => handleFieldChange(field.key, Number(e.target.value))}
              className="w-28 px-2 py-1 text-sm bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded text-slate-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-indigo-500"
            >
              {field.options.map(opt => (
                <option key={opt} value={opt}>{opt}</option>
              ))}
            </select>
          )}
          {field.type === 'toggle' && (
            <button
              onClick={() => handleFieldChange(field.key, !effectiveValue)}
              className={clsx(
                'relative inline-flex h-6 w-11 items-center rounded-full transition-colors',
                effectiveValue ? 'bg-indigo-600' : 'bg-slate-200 dark:bg-slate-700'
              )}
            >
              <span
                className={clsx(
                  'inline-block h-4 w-4 transform rounded-full bg-white transition-transform',
                  effectiveValue ? 'translate-x-6' : 'translate-x-1'
                )}
              />
            </button>
          )}
          {overridden && (
            <button
              onClick={() => handleRevertField(field.key)}
              className="text-xs text-slate-500 hover:text-slate-700 dark:hover:text-slate-300"
              title={`Revert to global (${globalValue})`}
            >
              Revert
            </button>
          )}
        </div>
      </div>
    );
  };

  const detectionFields = OVERRIDE_FIELDS.filter(f => f.group === 'detection');
  const handlingFields = OVERRIDE_FIELDS.filter(f => f.group === 'handling');
  const learningFields = OVERRIDE_FIELDS.filter(f => f.group === 'learning');
  const warmupFields = OVERRIDE_FIELDS.filter(f => f.group === 'warmup');

  return (
    <div className="card">
      <button
        onClick={() => setExpanded(!expanded)}
        className="card-header w-full flex items-center justify-between cursor-pointer hover:bg-slate-200 dark:hover:bg-slate-800/50 transition-colors"
      >
        <div className="flex items-center gap-2">
          <AdjustmentsHorizontalIcon className="h-5 w-5 text-indigo-400" />
          <h3 className="card-title">Detection Config</h3>
          {configData?.is_active && (
            <span className="px-2 py-0.5 text-xs font-medium bg-indigo-500/20 text-indigo-300 rounded-full">
              Custom v{configData.version}
            </span>
          )}
          {configData && !configData.is_active && (
            <span className="px-2 py-0.5 text-xs font-medium bg-slate-200 dark:bg-slate-700 text-slate-500 dark:text-slate-400 rounded-full">
              Using Global Defaults
            </span>
          )}
        </div>
        <ChevronDownIcon className={clsx('h-5 w-5 text-slate-500 dark:text-slate-400 transition-transform', expanded && 'rotate-180')} />
      </button>

      {expanded && (
        <div className="p-6 border-t border-slate-200 dark:border-slate-800">
          {isLoading ? (
            <div className="text-center py-8 text-slate-500 dark:text-slate-400">Loading config...</div>
          ) : (
            <>
              {/* Detection Sensitivity */}
              <div className="mb-6">
                <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3 uppercase tracking-wider">
                  Detection Sensitivity
                </h4>
                <div className="divide-y divide-slate-200 dark:divide-slate-800">
                  {detectionFields.map(renderField)}
                </div>
              </div>

              {/* Attack Handling */}
              <div className="mb-6">
                <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3 uppercase tracking-wider">
                  Attack Handling
                </h4>
                <div className="divide-y divide-slate-200 dark:divide-slate-800">
                  {handlingFields.map(renderField)}
                </div>
              </div>

              {/* Advanced: Learning Speed */}
              <div className="mb-6">
                <button
                  onClick={() => setShowAdvanced(!showAdvanced)}
                  className="flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300 transition-colors"
                >
                  <ChevronDownIcon className={clsx('h-4 w-4 transition-transform', showAdvanced && 'rotate-180')} />
                  Advanced: Learning Speed & Warmup
                </button>
                {showAdvanced && (
                  <div className="mt-3 space-y-6">
                    <div>
                      <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3 uppercase tracking-wider">
                        Learning Speed (EWMA)
                      </h4>
                      <div className="divide-y divide-slate-200 dark:divide-slate-800">
                        {learningFields.map(renderField)}
                      </div>
                    </div>
                    <div>
                      <h4 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3 uppercase tracking-wider">
                        Warmup Thresholds
                      </h4>
                      <div className="divide-y divide-slate-200 dark:divide-slate-800">
                        {warmupFields.map(renderField)}
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Actions */}
              <div className="flex items-center justify-between pt-4 border-t border-slate-200 dark:border-slate-800">
                <div className="text-xs text-slate-500">
                  {configData?.updated_at && (
                    <>Last updated: {new Date(configData.updated_at).toLocaleString()}</>
                  )}
                </div>
                <div className="flex items-center gap-3">
                  {configData?.is_active && (
                    <button
                      onClick={() => resetMutation.mutate()}
                      disabled={resetMutation.isPending}
                      className="px-4 py-2 text-sm text-red-400 hover:text-red-300 border border-red-500/30 hover:border-red-500/50 rounded-lg transition-colors disabled:opacity-50"
                    >
                      {resetMutation.isPending ? 'Resetting...' : 'Reset to Global'}
                    </button>
                  )}
                  <button
                    onClick={handleSave}
                    disabled={!dirty || saveMutation.isPending}
                    className="px-4 py-2 text-sm bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-800 disabled:text-slate-500 text-white rounded-lg transition-colors"
                  >
                    {saveMutation.isPending ? 'Saving...' : 'Save Config'}
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

// ==================== Feature Selection Section ====================

function FeatureSelectionSection({ ip }: { ip: string }) {
  const queryClient = useQueryClient();
  const [expanded, setExpanded] = useState(false);
  // null = not yet edited; mirrors the server state
  const [pending, setPending] = useState<boolean[] | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ['per-ip-features', ip],
    queryFn: () => api.getPerIPFeatures(ip),
    refetchInterval: false,
  });

  // Global feature data for quality indicators
  const { data: globalFeatureData } = useQuery({
    queryKey: ['layer2-features'],
    queryFn: () => api.getLayer2Features(),
    staleTime: 60 * 1000,
  });

  const saveMutation = useMutation({
    mutationFn: (enabled: boolean[]) => api.setPerIPFeatures(ip, enabled),
    onSuccess: () => {
      toast.success('Feature selection saved');
      queryClient.invalidateQueries({ queryKey: ['per-ip-features', ip] });
      setPending(null);
    },
    onError: (err: Error) => toast.error(`Failed to save: ${err.message}`),
  });

  const resetMutation = useMutation({
    mutationFn: () => api.resetPerIPFeatures(ip),
    onSuccess: () => {
      toast.success('Feature selection reset to global defaults');
      queryClient.invalidateQueries({ queryKey: ['per-ip-features', ip] });
      setPending(null);
    },
    onError: (err: Error) => toast.error(`Failed to reset: ${err.message}`),
  });

  // Current working state: pending edits override server state
  const serverEnabled = data?.features.map(f => f.enabled) ?? [];
  const enabled = pending ?? serverEnabled;
  const isPerIp = data?.source === 'per_ip';
  const dirty = pending !== null;

  // Quality map from global feature data
  const qualityMap = useMemo(() => {
    const map = new Map<string, { score: number | null; auto_disabled: boolean; cv: number; range_ratio: number; zero_dominant: boolean }>();
    for (const f of globalFeatureData?.features ?? []) {
      if (f.quality) map.set(f.name, f.quality);
    }
    return map;
  }, [globalFeatureData]);

  // Group features using FEATURE_GROUP_ORDER
  const grouped = useMemo(() => {
    const feats = data?.features ?? [];
    const map = new Map<string, typeof feats>();
    for (const feat of feats) {
      const existing = map.get(feat.group) ?? [];
      existing.push(feat);
      map.set(feat.group, existing);
    }
    return FEATURE_GROUP_ORDER
      .filter(g => map.has(g))
      .map(g => ({ group: g, features: map.get(g)! }));
  }, [data]);

  const toggleFeature = useCallback((index: number) => {
    const base = pending ?? serverEnabled;
    const next = [...base];
    next[index] = !next[index];
    setPending(next);
  }, [pending, serverEnabled]);

  const toggleGroup = useCallback((groupFeatures: NonNullable<typeof data>['features'], select: boolean) => {
    const base = pending ?? serverEnabled;
    const next = [...base];
    for (const f of groupFeatures) {
      next[f.index] = select;
    }
    setPending(next);
  }, [pending, serverEnabled]);

  const disabledCount = enabled.filter(e => !e).length;
  const totalCount = enabled.length;

  return (
    <div className="card">
      <button
        onClick={() => setExpanded(!expanded)}
        className="card-header w-full flex items-center justify-between cursor-pointer hover:bg-slate-200 dark:hover:bg-slate-800/50 transition-colors"
      >
        <div className="flex items-center gap-2">
          <BeakerIcon className="h-5 w-5 text-violet-400" />
          <h3 className="card-title">Feature Selection</h3>
          {isPerIp && !dirty && (
            <span className="px-2 py-0.5 text-xs font-medium bg-violet-500/20 text-violet-300 rounded-full">
              Per-IP Custom
            </span>
          )}
          {!isPerIp && !dirty && (
            <span className="px-2 py-0.5 text-xs font-medium bg-slate-200 dark:bg-slate-700 text-slate-500 dark:text-slate-400 rounded-full">
              Global Defaults
            </span>
          )}
          {dirty && (
            <span className="px-2 py-0.5 text-xs font-medium bg-amber-500/20 text-amber-300 rounded-full">
              Unsaved Changes
            </span>
          )}
          {disabledCount > 0 && !dirty && (
            <span className="px-2 py-0.5 text-xs font-medium bg-red-500/15 text-red-400 rounded-full">
              {disabledCount} disabled
            </span>
          )}
        </div>
        <ChevronDownIcon className={clsx('h-5 w-5 text-slate-500 dark:text-slate-400 transition-transform', expanded && 'rotate-180')} />
      </button>

      {expanded && (
        <div className="p-6 border-t border-slate-200 dark:border-slate-800">
          {isLoading ? (
            <div className="text-center py-8 text-slate-500 dark:text-slate-400">Loading features...</div>
          ) : (
            <>
              <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
                Customise which of the {totalCount} detection features are active for this IP.
                Disabled features are excluded from anomaly scoring — the C engine reloads immediately on save.
                Quality dots indicate signal strength based on observed traffic variance.
              </p>

              {/* Group chips */}
              <div className="flex flex-wrap gap-2 mb-4">
                {grouped.map(({ group, features: gFeatures }) => {
                  const count = gFeatures.filter(f => enabled[f.index]).length;
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
                          ? 'bg-violet-100 border-violet-300 text-violet-800 dark:bg-violet-900/30 dark:border-violet-700 dark:text-violet-300 shadow-sm'
                          : partial
                            ? 'bg-amber-50 border-amber-300 text-amber-800 dark:bg-amber-900/20 dark:border-amber-700 dark:text-amber-300'
                            : 'bg-white border-slate-200 text-slate-600 dark:bg-slate-800 dark:border-slate-600 dark:text-slate-400 hover:border-slate-300 hover:shadow-sm'
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
                  const count = gFeatures.filter(f => enabled[f.index]).length;
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
                            className="text-xs font-medium text-violet-600 hover:text-violet-700 dark:text-violet-400 dark:hover:text-violet-300 transition-colors"
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
                          const q = qualityMap.get(feat.name);
                          return (
                            <div key={feat.index} className="relative group/feat">
                              <label
                                className={clsx(
                                  'flex items-center gap-2 px-2.5 py-2 rounded-lg cursor-pointer border transition-all duration-150 text-sm',
                                  enabled[feat.index]
                                    ? 'bg-violet-50 border-violet-200 text-violet-900 dark:bg-violet-900/15 dark:border-violet-800 dark:text-violet-200 shadow-sm'
                                    : 'bg-white dark:bg-slate-800/50 border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400 hover:border-slate-300 hover:shadow-sm'
                                )}
                              >
                                <input
                                  type="checkbox"
                                  checked={enabled[feat.index] ?? true}
                                  onChange={() => toggleFeature(feat.index)}
                                  className="rounded border-slate-300 text-violet-600 focus:ring-violet-500 dark:border-slate-600 dark:bg-slate-700"
                                />
                                <span className="truncate flex-1">
                                  {FEATURE_DISPLAY_NAMES[feat.name] ?? feat.name}
                                </span>
                                {q && (
                                  <span className={clsx('h-2 w-2 rounded-full flex-shrink-0', qualityColor(q.score))} title={qualityLabel(q.score)} />
                                )}
                                {info && (
                                  <svg viewBox="0 0 20 20" fill="currentColor" className="h-3.5 w-3.5 flex-shrink-0 text-slate-400 dark:text-slate-500 group-hover/feat:text-violet-400 transition-colors">
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
                                        <div className="flex items-center gap-2 mb-1">
                                          <span className={clsx('h-2.5 w-2.5 rounded-full', qualityColor(q.score))} />
                                          <span className="font-medium">{qualityLabel(q.score)}{q.score !== null ? ` — ${(q.score * 100).toFixed(0)}%` : ''}</span>
                                        </div>
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

              {/* Actions */}
              <div className="flex items-center justify-between pt-5 mt-5 border-t border-slate-200 dark:border-slate-800">
                <div className="text-xs text-slate-500">
                  {enabled.filter(Boolean).length} / {totalCount} features active
                </div>
                <div className="flex items-center gap-3">
                  {dirty && (
                    <button
                      onClick={() => setPending(null)}
                      className="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 transition-colors"
                    >
                      Discard
                    </button>
                  )}
                  {isPerIp && !dirty && (
                    <button
                      onClick={() => resetMutation.mutate()}
                      disabled={resetMutation.isPending}
                      className="px-4 py-2 text-sm text-red-400 hover:text-red-300 border border-red-500/30 hover:border-red-500/50 rounded-lg transition-colors disabled:opacity-50"
                    >
                      {resetMutation.isPending ? 'Resetting...' : 'Reset to Global'}
                    </button>
                  )}
                  <button
                    onClick={() => saveMutation.mutate(enabled)}
                    disabled={!dirty || saveMutation.isPending}
                    className="px-4 py-2 text-sm bg-violet-600 hover:bg-violet-500 disabled:bg-violet-900 disabled:text-slate-500 text-white rounded-lg transition-colors"
                  >
                    {saveMutation.isPending ? 'Saving...' : 'Apply to IP'}
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

// ==================== Main Page ====================

export function AssetDetailPage() {
  const { ip } = useParams<{ ip: string }>();
  const navigate = useNavigate();
  const [refreshing, setRefreshing] = useState(false);

  const decodedIP = ip ? decodeURIComponent(ip) : '';

  // Fetch asset stats
  const { data: assetStats, refetch, isLoading, error } = useQuery({
    queryKey: ['asset-detail', decodedIP],
    queryFn: async () => {
      const response = await api.getPerIPStats();
      const data = response as unknown as { protected_ips: AssetStats[] };
      const asset = data.protected_ips.find((a) => a.dst_ip_str === decodedIP);
      if (!asset) {
        throw new Error('Asset not found');
      }
      return asset;
    },
    refetchInterval: 2000,
    enabled: !!decodedIP,
  });

  const handleRefresh = async () => {
    setRefreshing(true);
    await refetch();
    setRefreshing(false);
  };

  const getThreatLevel = (level: number): 'critical' | 'high' | 'medium' | 'low' | 'none' => {
    if (level >= 4) return 'critical';
    if (level >= 3) return 'high';
    if (level >= 2) return 'medium';
    if (level >= 1) return 'low';
    return 'none';
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <ArrowPathIcon className="h-8 w-8 animate-spin text-brand-500" />
      </div>
    );
  }

  if (error || !assetStats) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <button onClick={() => navigate('/assets')} className="btn-ghost p-2">
            <ArrowLeftIcon className="h-5 w-5" />
          </button>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Asset Not Found</h1>
        </div>
        <EmptyState
          icon={ExclamationTriangleIcon}
          title="Asset Not Found"
          description={`Protected IP ${decodedIP} was not found or has no active traffic.`}
          action={
            <Link to="/assets" className="btn-primary">
              Back to Assets
            </Link>
          }
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-4">
          <button onClick={() => navigate('/assets')} className="btn-ghost p-2">
            <ArrowLeftIcon className="h-5 w-5" />
          </button>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold font-mono text-slate-900 dark:text-white">{decodedIP}</h1>
              {assetStats.anomaly_active ? (
                <ThreatBadge level={getThreatLevel(assetStats.anomaly_level)} animated size="lg" />
              ) : (
                <StatusIndicator status="online" label="Healthy" size="lg" />
              )}
            </div>
            <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">Protected Asset Details</p>
          </div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="btn-ghost inline-flex items-center gap-2"
          >
            <ArrowPathIcon className={clsx('h-4 w-4', refreshing && 'animate-spin')} />
            Refresh
          </button>
          <Link
            to={`/threat-center?tab=investigate&ip=${encodeURIComponent(decodedIP)}`}
            className="btn-primary inline-flex items-center gap-2"
          >
            <ShieldCheckIcon className="h-4 w-4" />
            <span className="hidden sm:inline">Investigate in Threat Center</span>
            <span className="sm:hidden">Investigate</span>
          </Link>
        </div>
      </div>

      {/* Attack Alert Banner */}
      {assetStats.anomaly_active && (
        <div className="card border-red-500/50 bg-gradient-to-r from-red-500/10 to-orange-500/10">
          <div className="p-6">
            <div className="flex items-start gap-4">
              <div className="flex-shrink-0">
                <div className="h-12 w-12 rounded-full bg-red-500/20 flex items-center justify-center">
                  <FireIcon className="h-6 w-6 text-red-500" />
                </div>
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-2">
                  <h3 className="text-lg font-semibold text-red-600 dark:text-red-400">
                    Active Attack Detected
                  </h3>
                  <ThreatBadge level={getThreatLevel(assetStats.anomaly_level)} animated />
                </div>
                <ThreatLevelBar level={assetStats.anomaly_level} max={4} />
                <div className="mt-4 grid grid-cols-2 gap-4 sm:grid-cols-4">
                  <div>
                    <div className="text-sm text-red-300/70">Attack Type</div>
                    <div className="text-lg font-bold text-red-200">
                      {assetStats.attack_type_name}
                    </div>
                  </div>
                  <div>
                    <div className="text-sm text-red-300/70">Protocol</div>
                    <div className="text-lg font-bold text-red-200">
                      {assetStats.anomaly_protocol_name}
                    </div>
                  </div>
                  <div>
                    <div className="text-sm text-red-300/70">Target Port</div>
                    <div className="text-lg font-bold text-red-200">
                      {assetStats.anomaly_dst_port || 'Any'}
                    </div>
                  </div>
                  <div>
                    <div className="text-sm text-red-300/70">Z-Score</div>
                    <div className="text-lg font-bold text-red-200">
                      {assetStats.max_z_score.toFixed(2)}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Traffic Metrics */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          title="Packets/Second"
          value={formatNumber(assetStats.packets_per_sec)}
          unit="pps"
          icon={BoltIcon}
          color="brand"
        />
        <MetricCard
          title="Bandwidth"
          value={formatBytes(assetStats.bytes_per_sec)}
          unit="/s"
          icon={ArrowTrendingUpIcon}
          color="info"
        />
        <MetricCard
          title="Active Flows"
          value={formatNumber(assetStats.active_flows)}
          icon={SignalIcon}
          color="success"
        />
        <MetricCard
          title="Unique Sources"
          value={formatNumber(assetStats.unique_src_ips)}
          icon={FingerPrintIcon}
          color="neutral"
        />
      </div>

      {/* Protocol Breakdown & TCP Flags */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Protocol Distribution */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Protocol Distribution</h3>
          </div>
          <div className="p-6">
            <div className="grid grid-cols-2 gap-6 sm:grid-cols-4">
              <div className="flex flex-col items-center">
                <GaugeChart
                  value={assetStats.tcp_ratio}
                  size="md"
                  label="TCP"
                  color="blue"
                />
              </div>
              <div className="flex flex-col items-center">
                <GaugeChart
                  value={assetStats.udp_ratio}
                  size="md"
                  label="UDP"
                  color="green"
                />
              </div>
              <div className="flex flex-col items-center">
                <GaugeChart
                  value={assetStats.icmp_ratio}
                  size="md"
                  label="ICMP"
                  color="yellow"
                />
              </div>
              <div className="flex flex-col items-center">
                <GaugeChart
                  value={assetStats.other_ratio}
                  size="md"
                  label="Other"
                  color="gray"
                />
              </div>
            </div>
          </div>
        </div>

        {/* TCP Flag Rates */}
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">TCP Flag Rates</h3>
          </div>
          <div className="p-6">
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-500 dark:text-slate-400">SYN</span>
                <span className="font-mono text-sm text-slate-900 dark:text-white">
                  {formatNumber(assetStats.syn_per_sec)}/s
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-500 dark:text-slate-400">SYN-ACK</span>
                <span className="font-mono text-sm text-slate-900 dark:text-white">
                  {formatNumber(assetStats.syn_ack_per_sec)}/s
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-500 dark:text-slate-400">ACK</span>
                <span className="font-mono text-sm text-slate-900 dark:text-white">
                  {formatNumber(assetStats.ack_per_sec)}/s
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-500 dark:text-slate-400">RST</span>
                <span className="font-mono text-sm text-slate-900 dark:text-white">
                  {formatNumber(assetStats.rst_per_sec)}/s
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-500 dark:text-slate-400">FIN</span>
                <span className="font-mono text-sm text-slate-900 dark:text-white">
                  {formatNumber(assetStats.fin_per_sec)}/s
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Flow Analysis */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Flow Analysis</h3>
        </div>
        <div className="p-6">
          <div className="grid grid-cols-2 gap-6 sm:grid-cols-4 lg:grid-cols-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-slate-900 dark:text-white">
                {formatNumber(assetStats.unique_flows)}
              </div>
              <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">Unique Flows</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-slate-900 dark:text-white">
                {formatNumber(assetStats.flows_per_sec)}
              </div>
              <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">Flows/Second</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-slate-900 dark:text-white">
                {assetStats.avg_packets_per_flow.toFixed(1)}
              </div>
              <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">Avg Packets/Flow</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-slate-900 dark:text-white">
                {assetStats.flow_duration_avg_ms.toFixed(0)}ms
              </div>
              <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">Avg Flow Duration</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-slate-900 dark:text-white">
                {assetStats.heavy_hitter_count}
              </div>
              <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">Heavy Hitters</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-slate-900 dark:text-white">
                {assetStats.topk_flow_share.toFixed(1)}%
              </div>
              <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">Top-K Flow Share</div>
            </div>
          </div>
        </div>
      </div>

      {/* Anomaly Detection Details */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Anomaly Detection</h3>
          <StatusIndicator
            status={assetStats.anomaly_active ? 'error' : 'online'}
            label={assetStats.anomaly_active ? 'Anomaly Detected' : 'Normal'}
          />
        </div>
        <div className="p-6">
          <div className="grid grid-cols-2 gap-6 sm:grid-cols-4">
            <div>
              <div className="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider">Status</div>
              <div
                className={clsx(
                  'text-lg font-semibold mt-1',
                  assetStats.anomaly_active ? 'text-red-400' : 'text-emerald-400'
                )}
              >
                {assetStats.anomaly_active ? 'ACTIVE' : 'NORMAL'}
              </div>
            </div>
            <div>
              <div className="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider">Level</div>
              <div className="text-lg font-semibold text-slate-900 dark:text-white mt-1">
                {assetStats.anomaly_level_name}
              </div>
            </div>
            <div>
              <div className="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider">Max Z-Score</div>
              <div className="text-lg font-semibold font-mono text-slate-900 dark:text-white mt-1">
                {assetStats.max_z_score.toFixed(3)}
              </div>
            </div>
            <div>
              <div className="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider">Tier Agreement</div>
              <div className="text-lg font-semibold text-slate-900 dark:text-white mt-1">
                {assetStats.tier_agreement}/3
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Detection Config (Per-IP Overrides) */}
      <DetectionConfigSection ip={decodedIP} />

      {/* Feature Selection (Per-IP) */}
      <FeatureSelectionSection ip={decodedIP} />

      {/* Total Packets Summary */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Session Statistics</h3>
        </div>
        <div className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                Total Packets Processed
              </div>
              <div className="text-3xl font-bold text-slate-900 dark:text-white mt-1">
                {formatNumber(assetStats.total_packets)}
              </div>
            </div>
            <ChartBarIcon className="h-16 w-16 text-slate-700" />
          </div>
        </div>
      </div>
    </div>
  );
}

export default AssetDetailPage;
