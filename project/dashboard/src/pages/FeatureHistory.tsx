/**
 * Feature History Page
 *
 * Browse historical per-IP feature data from SQLite telemetry.
 * Same tier/chart layout as the real-time Feature Monitor, but over longer time ranges.
 */

import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ClockIcon, ExclamationTriangleIcon } from '@heroicons/react/24/outline';
import { IPScopeSelector } from '../components/IPScopeSelector';
import { HistoryTimeRangeSelector } from '../components/Features/HistoryTimeRangeSelector';
import { BaselineTierSelector } from '../components/Features/BaselineTierSelector';
import { FeatureChart } from '../components/Features/FeatureChart';
import { useIPScopeStore, useBaselineTierStore } from '../store';
import api from '../services/api';
import { TIERS, L2_FEATURE_NAMES } from './featureTiers';
import type { FeatureSample } from '../hooks/useFeatureHistory';

type LabelFilter = 'all' | 'normal' | 'attack';

/** Baseline tier names matching the JSON keys from baselines_all column */
const BL_TIER_NAMES = ['1s', '10s', '60s', 'hourly', 'weekly'] as const;

/** All 39 L2 feature names (the ones C exports baselines for) */
const BL_FEATURE_NAMES = L2_FEATURE_NAMES;

/** Convert a telemetry DB row into a FeatureSample for FeatureChart */
function toFeatureSample(row: {
  timestamp: number;
  feat_values: string;
  baselines_all?: string | null;
  anomaly_active: number;
}): FeatureSample {
  const values: number[] = JSON.parse(row.feat_values);
  const sample: Record<string, unknown> = {
    timestamp: row.timestamp * 1000,
    timestamp_str: new Date(row.timestamp * 1000).toLocaleTimeString(),
  };

  L2_FEATURE_NAMES.forEach((name, i) => {
    sample[name] = values[i] ?? 0;
  });

  // Key mismatch: DB stores flow_duration_avg, chart expects flow_duration_avg_ms
  sample['flow_duration_avg_ms'] = (sample['flow_duration_avg'] as number) || 0;

  // Parse all 5 baseline tiers into bl_{tier}_{feature} keys
  if (row.baselines_all) {
    try {
      const tiers = JSON.parse(row.baselines_all) as Record<
        string,
        { means: number[]; stds: number[]; ready?: boolean; samples?: number }
      >;
      for (const tierName of BL_TIER_NAMES) {
        const tierData = tiers[tierName];
        if (!tierData?.means) continue;
        BL_FEATURE_NAMES.forEach((name, i) => {
          const mean = tierData.means[i];
          if (typeof mean === 'number' && mean > 0) {
            sample[`bl_${tierName}_${name}`] = mean;
          }
        });
        // Map flow_duration_avg -> flow_duration_avg_ms for chart compatibility
        const durIdx = 23; // flow_duration_avg index
        const durMean = tierData.means[durIdx];
        if (typeof durMean === 'number' && durMean > 0) {
          sample[`bl_${tierName}_flow_duration_avg_ms`] = durMean;
        }
      }
    } catch {
      // Corrupted baselines_all -- skip silently
    }
  }

  // Mark anomaly periods for chart background
  sample['_anomaly'] = row.anomaly_active === 1;

  return sample as unknown as FeatureSample;
}

export function FeatureHistoryPage() {
  const { selectedIP } = useIPScopeStore();
  const { enabledTiers } = useBaselineTierStore();
  const [sinceMinutes, setSinceMinutes] = useState(60);
  const [labelFilter, setLabelFilter] = useState<LabelFilter>('all');

  const { data, isLoading, error } = useQuery({
    queryKey: ['telemetry-features', selectedIP, sinceMinutes, labelFilter],
    queryFn: () =>
      api.getTelemetryFeatures({
        dst_ip: selectedIP || undefined,
        since_minutes: sinceMinutes,
        limit: 5000,
        label: labelFilter === 'all' ? undefined : labelFilter,
      }),
    refetchInterval: 30_000,
    enabled: !!selectedIP,
  });

  const history = useMemo(() => {
    if (!data?.samples) return [];
    return data.samples.map(toFeatureSample);
  }, [data]);

  const attackCount = useMemo(
    () => data?.samples?.filter((s) => s.anomaly_active === 1).length ?? 0,
    [data],
  );

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <ClockIcon className="h-5 w-5 text-brand-400" />
          <h1 className="text-lg font-semibold text-slate-900 dark:text-white">
            Feature History
          </h1>
          {data && (
            <span className="text-xs text-slate-500">
              {data.count.toLocaleString()} samples
            </span>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <IPScopeSelector />
          <HistoryTimeRangeSelector value={sinceMinutes} onChange={setSinceMinutes} />
          <BaselineTierSelector />
        </div>
      </div>

      {/* Label filter chips */}
      <div className="flex items-center gap-2">
        <span className="text-xs text-slate-500">Filter:</span>
        {(['all', 'normal', 'attack'] as const).map((f) => (
          <button
            key={f}
            onClick={() => setLabelFilter(f)}
            className={`px-2.5 py-0.5 rounded text-xs font-medium border transition-all ${
              labelFilter === f
                ? f === 'attack'
                  ? 'border-red-500 bg-red-500/20 text-red-300'
                  : 'border-brand-500 bg-brand-500/20 text-brand-300'
                : 'border-slate-300 dark:border-slate-600 text-slate-500 bg-slate-100 dark:bg-slate-800/50 hover:bg-slate-200 dark:hover:bg-slate-700/50'
            }`}
          >
            {f.charAt(0).toUpperCase() + f.slice(1)}
            {f === 'attack' && attackCount > 0 && labelFilter === 'all' && (
              <span className="ml-1 text-red-400">({attackCount})</span>
            )}
          </button>
        ))}
      </div>

      {/* State messages */}
      {!selectedIP && (
        <div className="flex items-center gap-2 p-4 rounded-lg bg-slate-100 dark:bg-slate-800/50 text-slate-500 text-sm">
          <ExclamationTriangleIcon className="h-5 w-5" />
          Select a protected IP to view historical features.
        </div>
      )}

      {selectedIP && isLoading && (
        <div className="flex items-center justify-center h-32">
          <div className="w-6 h-6 border-2 border-brand-500 border-t-transparent rounded-full animate-spin" />
        </div>
      )}

      {selectedIP && error && (
        <div className="p-4 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 text-sm">
          Failed to load feature history. Check API connection.
        </div>
      )}

      {selectedIP && !isLoading && history.length === 0 && !error && (
        <div className="p-4 rounded-lg bg-slate-100 dark:bg-slate-800/50 text-slate-500 text-sm">
          No feature samples found for this IP in the selected time range.
        </div>
      )}

      {/* Tier charts */}
      {history.length > 0 &&
        TIERS.map((tier) => (
          <div key={tier.id} className="space-y-2">
            <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 border-b border-slate-200 dark:border-slate-700 pb-1">
              {tier.name}
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4 gap-3">
              {tier.features.map((feat) => (
                <FeatureChart
                  key={feat.key}
                  featureKey={feat.key}
                  label={feat.label}
                  color={feat.color}
                  format={feat.format}
                  history={history}
                  height={140}
                  enabledTiers={enabledTiers}
                  viewMode="ewma"
                />
              ))}
            </div>
          </div>
        ))}
    </div>
  );
}

export default FeatureHistoryPage;
