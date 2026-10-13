/**
 * Feature Monitor Page
 *
 * Real-time per-IP detection feature monitoring with dual view modes:
 *  - EWMA mode: Feature values with C Layer 2 EWMA baseline overlays (5 tiers)
 *  - Detection mode: Post-EWMA detection metrics (z-score, CUSUM, JSD, log z-score, threshold)
 *
 * Shows all 39 C Layer 2 detection features + dashboard extras, organized by tier.
 * Each chart shows the detection method appropriate to its feature (matching C exactly).
 */

import { useEffect, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  ChartBarSquareIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';
import { IPScopeSelector } from '../components/IPScopeSelector';
import { BaselineTierSelector } from '../components/Features/BaselineTierSelector';
import { TimeWindowSelector } from '../components/Features/TimeWindowSelector';
import { ViewModeSelector } from '../components/Features/ViewModeSelector';
import { useIPScopeStore, useBaselineTierStore, useTimeWindowStore, useViewModeStore } from '../store';
import { useFeatureHistory } from '../hooks/useFeatureHistory';
import { FeatureChart } from '../components/Features/FeatureChart';
import { formatPPS, formatNumber, formatBPS } from '../utils/formatting';
import api from '../services/api';
import { TIERS } from './featureTiers';

// ==================== Page ====================

const POLL_INTERVAL_SEC = 1;  // Match C Layer 1's 1 Hz export rate

export function FeaturesPage() {
  const { selectedIP } = useIPScopeStore();
  const { enabledTiers } = useBaselineTierStore();
  const { windowSeconds } = useTimeWindowStore();
  const { viewMode } = useViewModeStore();
  const { addSample, getHistory, getSampleCount, tick } = useFeatureHistory();

  // Poll per-IP stats every 1s (includes C baseline means in response)
  const { data: ipData } = useQuery({
    queryKey: ['features-per-ip', selectedIP],
    queryFn: () => api.getPerIPStatsSingle(selectedIP!),
    refetchInterval: 1000,
    enabled: !!selectedIP,
  });

  const anomalyActive = ipData?.anomaly_active ?? false;

  // Accumulate into ring buffer on each new sample
  useEffect(() => {
    if (selectedIP && ipData) {
      // PerIPStatsEntry is structurally compatible with PerIPAPIResponse
      addSample(selectedIP, ipData as unknown as Parameters<typeof addSample>[1]);
    }
  }, [selectedIP, ipData, addSample]);

  const fullHistory = getHistory(selectedIP);
  const sampleCount = getSampleCount(selectedIP);

  // Slice history to the selected time window
  const maxSamples = Math.ceil(windowSeconds / POLL_INTERVAL_SEC);
  const history = useMemo(
    () => fullHistory.slice(-maxSamples),
    // eslint-disable-next-line react-hooks/exhaustive-deps -- fullHistory is a mutable ref; tick always increments
    [fullHistory, maxSamples, tick]
  );

  // Latest values for info bar and summary (always from full history)
  const latest = useMemo(() => {
    if (fullHistory.length === 0) return null;
    return fullHistory[fullHistory.length - 1];
    // eslint-disable-next-line react-hooks/exhaustive-deps -- fullHistory is a mutable ref; tick always increments
  }, [fullHistory, tick]);

  const anomalyLevel = ipData?.anomaly_level_name ?? 'NONE';
  const maxZScore = ipData?.max_z_score ?? 0;
  const tierAgreement = ipData?.tier_agreement ?? 0;

  // Sparkline data for summary cards (last 60 samples = 1 min)
  const sparkSlice = useMemo(() => history.slice(-60), [history]);

  // ==================== Empty state ====================
  if (!selectedIP) {
    return (
      <div className="space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <ChartBarSquareIcon className="h-7 w-7 text-brand-400" />
            <div>
              <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Feature Monitor</h1>
              <p className="text-sm text-slate-500 dark:text-slate-400">
                Real-time detection features with C Layer 2 baseline and detection overlays
              </p>
            </div>
          </div>
          <IPScopeSelector />
        </div>
        <div className="flex flex-col items-center justify-center py-24 text-slate-500">
          <ChartBarSquareIcon className="h-12 w-12 mb-3 text-slate-600" />
          <p className="text-lg font-medium">Select a protected IP</p>
          <p className="text-sm">Choose an IP from the dropdown to start monitoring features</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <ChartBarSquareIcon className="h-7 w-7 text-brand-400" />
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Feature Monitor</h1>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              {viewMode === 'detection'
                ? 'Post-EWMA detection metrics: Z-Score, CUSUM, JSD, Log Z-Score, Threshold'
                : 'Real-time detection features with C Layer 2 EWMA baseline overlays'}
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2 sm:gap-4">
          <ViewModeSelector />
          <TimeWindowSelector />
          {viewMode === 'ewma' && <BaselineTierSelector />}
          <IPScopeSelector />
        </div>
      </div>

      {/* Info bar */}
      <div className="bg-slate-100 dark:bg-slate-800/60 rounded-lg px-4 py-2.5 border border-slate-300 dark:border-slate-700 flex items-center gap-6 text-sm flex-wrap">
        <span className="text-slate-500">
          Samples: <span className="text-slate-900 dark:text-white font-mono">{sampleCount}</span>
        </span>
        <span className="text-slate-500">
          IP: <span className="text-cyan-600 dark:text-cyan-400 font-mono">{selectedIP}</span>
        </span>
        <span className="text-slate-500">
          PPS: <span className="text-slate-900 dark:text-white font-mono">
            {latest ? formatPPS(latest.packets_per_sec) : '--'}
          </span>
        </span>
        {anomalyActive ? (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-bold bg-red-500/20 text-red-400 border border-red-500/30">
            <ExclamationTriangleIcon className="h-3.5 w-3.5" />
            {anomalyLevel} (Z={maxZScore.toFixed(1)}, {tierAgreement}T)
          </span>
        ) : (
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
            NORMAL
          </span>
        )}
        <span className="text-slate-600 ml-auto font-mono text-xs">
          {latest ? latest.timestamp_str : ''}
        </span>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <SummaryCard
          label="PACKETS/SEC"
          value={latest ? formatPPS(latest.packets_per_sec) : '--'}
          color="text-emerald-600 dark:text-emerald-400"
          sparkline={sparkSlice.map((s) => s.packets_per_sec)}
        />
        <SummaryCard
          label="BITS/SEC"
          value={latest ? formatBPS(latest.bytes_per_sec * 8) : '--'}
          color="text-blue-600 dark:text-blue-400"
          sparkline={sparkSlice.map((s) => s.bytes_per_sec * 8)}
        />
        <SummaryCard
          label="FLOWS/SEC (HLL)"
          value={latest ? formatNumber(latest.flows_per_sec) : '--'}
          color="text-indigo-600 dark:text-indigo-400"
          sparkline={sparkSlice.map((s) => s.flows_per_sec)}
        />
      </div>

      {/* Feature tiers */}
      {TIERS.map((tier) => (
        <div key={tier.id}>
          <div className="flex items-center gap-2 mb-3">
            <span className="h-2 w-2 rounded-full bg-brand-500" />
            <h2 className="text-sm font-semibold text-brand-400 uppercase tracking-wider">
              {tier.name}
            </h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
            {tier.features.map((feat) => (
              <FeatureChart
                key={feat.key}
                featureKey={feat.key}
                label={feat.label}
                color={feat.color}
                format={feat.format}
                history={history}
                enabledTiers={enabledTiers}
                viewMode={viewMode}
              />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

// ==================== Summary Card ====================

function SummaryCard({
  label,
  value,
  color,
  sparkline,
}: {
  label: string;
  value: string;
  color: string;
  sparkline: number[];
}) {
  // Mini inline sparkline (last 60 values)
  const points = useMemo(() => {
    if (sparkline.length < 2) return '';
    const max = Math.max(...sparkline, 1);
    const h = 24;
    const w = 100;
    return sparkline
      .map((v, i) => {
        const x = (i / (sparkline.length - 1)) * w;
        const y = h - (v / max) * h;
        return `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(' ');
  }, [sparkline]);

  return (
    <div className="bg-white dark:bg-slate-800/50 rounded-lg p-4 border border-slate-300 dark:border-slate-700">
      <span className="text-xs text-slate-500 uppercase tracking-wider">{label}</span>
      <div className="flex items-end justify-between mt-1">
        <span className={`text-2xl font-bold font-mono ${color}`}>{value}</span>
        {points && (
          <svg width={100} height={24} className="opacity-60">
            <path d={points} fill="none" stroke="currentColor" strokeWidth={1.5} className={color} />
          </svg>
        )}
      </div>
    </div>
  );
}

export default FeaturesPage;
