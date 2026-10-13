/**
 * FeatureChart -- small real-time time-series chart for one detection feature.
 *
 * Supports two view modes:
 *  EWMA mode: Recharts LineChart with real-time values + dashed EWMA baseline lines
 *  Detection mode: Shows post-EWMA detection metrics (z-score, CUSUM, JSD, etc.)
 *    with horizontal threshold reference lines and color-coded background
 */

import { useMemo, memo } from 'react';
import { useUIStore } from '../../store';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts';
import type { FeatureSample } from '../../hooks/useFeatureHistory';
import {
  BASELINE_TIERS,
  BASELINE_FEATURE_KEYS,
  FEATURE_DETECTION,
  getBaselineAPIKey,
} from '../../hooks/useFeatureHistory';
import type { DetectionMethod } from '../../hooks/useFeatureHistory';
import type { ViewMode } from '../../store';

interface FeatureChartProps {
  featureKey: string;
  label: string;
  color: string;
  format: (v: number) => string;
  history: FeatureSample[];
  height?: number;
  /** Which baseline tier IDs to show (from store). Empty = no baselines. */
  enabledTiers?: string[];
  /** View mode: 'ewma' for baselines, 'detection' for z-score/CUSUM/JSD/etc */
  viewMode?: ViewMode;
}

// Round to 2 decimal places
function roundVal(v: number): number {
  return Math.round(v * 100) / 100;
}

/** Check whether this feature has baselines exported from C */
const BASELINE_FEATURE_SET = new Set<string>(BASELINE_FEATURE_KEYS);

/** Friendly tooltip name for each data key */
function tooltipName(name: string): string {
  if (name === 'value') return 'Real-time';
  if (name === 'det') return 'Z-Score';
  if (name === 'cusum') return 'CUSUM';
  for (const tier of BASELINE_TIERS) {
    if (name.startsWith(`bl_${tier.id}_`)) return tier.label;
  }
  return name;
}

/** Detection method display config */
const DET_METHOD_CONFIG: Record<DetectionMethod, {
  label: string;
  color: string;
  unit: string;
  warningThreshold: number;
  alarmThreshold: number;
}> = {
  zscore: { label: 'Z-Score', color: '#f59e0b', unit: 'σ', warningThreshold: 3, alarmThreshold: 6 },
  cusum: { label: 'Z-Score + CUSUM', color: '#f59e0b', unit: 'σ', warningThreshold: 3, alarmThreshold: 6 },
  log_zscore: { label: 'Log Z-Score', color: '#a78bfa', unit: 'σ', warningThreshold: 3, alarmThreshold: 6 },
  jsd: { label: 'JSD', color: '#22d3ee', unit: '', warningThreshold: 1.5, alarmThreshold: 3 },
  threshold: { label: 'Threshold', color: '#fb923c', unit: '', warningThreshold: 4, alarmThreshold: 6 },
};

/** Format detection score */
function fmtDet(v: number): string {
  if (v < 0.01) return '0';
  if (v < 10) return v.toFixed(2);
  return v.toFixed(1);
}

export const FeatureChart = memo(function FeatureChart({
  featureKey,
  label,
  color,
  format,
  history,
  height = 140,
  enabledTiers,
  viewMode = 'ewma',
}: FeatureChartProps) {
  const { darkMode } = useUIStore();
  const hasBaselines = BASELINE_FEATURE_SET.has(featureKey);
  const detConfig = FEATURE_DETECTION[featureKey];
  const methodConfig = detConfig ? DET_METHOD_CONFIG[detConfig.method] : null;
  const isDetectionMode = viewMode === 'detection' && detConfig;

  // Build baseline data keys only for enabled tiers (EWMA mode)
  const tierKeys = useMemo(() => {
    if (!hasBaselines || isDetectionMode) return [];
    const enabled = enabledTiers ? new Set(enabledTiers) : null;
    return BASELINE_TIERS
      .filter((tier) => !enabled || enabled.has(tier.id))
      .map((tier) => ({
        dataKey: getBaselineAPIKey(tier.id, featureKey),
        color: tier.color,
        dash: tier.dash,
        label: tier.label,
      }));
  }, [featureKey, hasBaselines, enabledTiers, isDetectionMode]);

  const chartData = useMemo(() => {
    return history.map((sample) => {
      const rec = sample as unknown as Record<string, number>;

      if (isDetectionMode) {
        // Detection mode: show detection score + CUSUM if applicable
        const entry: Record<string, unknown> = {
          time: sample.timestamp_str,
          det: roundVal(rec[`det_${featureKey}`] ?? 0),
        };
        if (detConfig?.method === 'cusum') {
          entry.cusum = roundVal(rec[`cusum_${featureKey}`] ?? 0);
        }
        return entry;
      }

      // EWMA mode: show feature value + baseline lines
      const entry: Record<string, unknown> = {
        time: sample.timestamp_str,
        value: roundVal(rec[featureKey] ?? 0),
      };
      for (const tk of tierKeys) {
        const bl = rec[tk.dataKey];
        if (typeof bl === 'number' && bl > 0) {
          entry[tk.dataKey] = roundVal(bl);
        }
      }
      return entry;
    });
  }, [history, featureKey, tierKeys, isDetectionMode, detConfig]);

  const latest = chartData.length > 0 ? chartData[chartData.length - 1] : null;

  // Compute tick interval to show ~5 labels
  const tickInterval = Math.max(1, Math.floor(chartData.length / 5));

  // Y domain
  const yDomain = useMemo(() => {
    if (chartData.length === 0) return undefined;
    let min = Infinity;
    let max = -Infinity;

    if (isDetectionMode) {
      for (const d of chartData) {
        const det = d.det as number;
        if (det < min) min = det;
        if (det > max) max = det;
        if (detConfig?.method === 'cusum') {
          const c = d.cusum as number;
          if (typeof c === 'number') {
            if (c < min) min = c;
            if (c > max) max = c;
          }
        }
      }
      if (!isFinite(min)) return [0, 10] as [number, number];
      // Always show at least up to alarm threshold
      const alarm = methodConfig?.alarmThreshold ?? 6;
      max = Math.max(max, alarm + 1);
      return [0, max + 1] as [number, number];
    }

    // EWMA mode
    for (const d of chartData) {
      const v = d.value as number;
      if (v < min) min = v;
      if (v > max) max = v;
      for (const tk of tierKeys) {
        const bl = d[tk.dataKey];
        if (typeof bl === 'number') {
          if (bl < min) min = bl;
          if (bl > max) max = bl;
        }
      }
    }
    if (!isFinite(min)) return undefined;
    const pad = (max - min) * 0.1 || 1;
    return [Math.max(0, min - pad), max + pad] as [number, number];
  }, [chartData, tierKeys, isDetectionMode, detConfig, methodConfig]);

  // Determine which tiers have at least one data point (EWMA mode)
  const activeTiers = useMemo(() => {
    if (tierKeys.length === 0) return [];
    return tierKeys.filter((tk) =>
      chartData.some((d) => typeof d[tk.dataKey] === 'number')
    );
  }, [chartData, tierKeys]);

  // Current detection score for header badge
  const latestDet = isDetectionMode && latest ? (latest.det as number) : 0;
  const detBadgeColor = latestDet >= (methodConfig?.alarmThreshold ?? 6)
    ? 'text-red-400 bg-red-500/15 border-red-500/30'
    : latestDet >= (methodConfig?.warningThreshold ?? 3)
      ? 'text-amber-400 bg-amber-500/15 border-amber-500/30'
      : 'text-emerald-400 bg-emerald-500/15 border-emerald-500/30';

  // Background tint based on latest detection score
  const bgTint = isDetectionMode
    ? latestDet >= (methodConfig?.alarmThreshold ?? 6)
      ? 'bg-red-50 dark:bg-red-950/30 border-red-200 dark:border-red-900/40'
      : latestDet >= (methodConfig?.warningThreshold ?? 3)
        ? 'bg-amber-50 dark:bg-amber-950/20 border-amber-200 dark:border-amber-900/30'
        : 'bg-white dark:bg-slate-800/50 border-slate-300 dark:border-slate-700'
    : 'bg-white dark:bg-slate-800/50 border-slate-300 dark:border-slate-700';

  return (
    <div className={`rounded-lg p-3 border ${bgTint}`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-medium text-slate-500 dark:text-slate-400">{label}</span>
        {isDetectionMode ? (
          <div className="flex items-center gap-1.5">
            <span className="text-2xs text-slate-500">{methodConfig?.label}</span>
            <span className={`text-xs font-bold font-mono px-1.5 py-0.5 rounded border ${detBadgeColor}`}>
              {fmtDet(latestDet)}{methodConfig?.unit}
            </span>
          </div>
        ) : (
          <span className="text-sm font-bold text-slate-900 dark:text-white font-mono">
            {latest ? format(latest.value as number) : '--'}
          </span>
        )}
      </div>

      {/* Chart */}
      {chartData.length < 2 ? (
        <div
          className="flex items-center justify-center text-xs text-slate-600"
          style={{ height }}
        >
          Collecting data...
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={height}>
          <LineChart
            data={chartData}
            margin={{ top: 4, right: 4, left: 0, bottom: 0 }}
          >
            <CartesianGrid
              strokeDasharray="3 3"
              stroke={darkMode ? '#374151' : '#e2e8f0'}
              strokeOpacity={0.3}
            />
            <XAxis
              dataKey="time"
              tick={{ fill: darkMode ? '#6b7280' : '#94a3b8', fontSize: 9 }}
              interval={tickInterval}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              tick={{ fill: darkMode ? '#6b7280' : '#94a3b8', fontSize: 9 }}
              width={52}
              tickFormatter={isDetectionMode ? fmtDet : (v: number) => format(v)}
              tickLine={false}
              axisLine={false}
              domain={yDomain}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: darkMode ? '#1F2937' : '#ffffff',
                border: `1px solid ${darkMode ? '#374151' : '#e2e8f0'}`,
                borderRadius: '0.5rem',
                color: darkMode ? '#F9FAFB' : '#1e293b',
                fontSize: '12px',
              }}
              formatter={(value: number, name: string) => [
                isDetectionMode ? fmtDet(value) : format(value),
                tooltipName(name),
              ]}
              labelFormatter={(l: string) => l}
            />

            {isDetectionMode ? (
              <>
                {/* Detection threshold reference lines */}
                <ReferenceLine
                  y={methodConfig?.warningThreshold ?? 3}
                  stroke="#facc15"
                  strokeDasharray="4 4"
                  strokeOpacity={0.5}
                />
                <ReferenceLine
                  y={methodConfig?.alarmThreshold ?? 6}
                  stroke="#ef4444"
                  strokeDasharray="4 4"
                  strokeOpacity={0.5}
                />
                {/* CUSUM line (if applicable) */}
                {detConfig?.method === 'cusum' && (
                  <Line
                    type="linear"
                    dataKey="cusum"
                    name="cusum"
                    stroke="#22d3ee"
                    strokeWidth={1}
                    strokeDasharray="4 3"
                    dot={false}
                    isAnimationActive={false}
                    connectNulls
                  />
                )}
                {/* Detection score line */}
                <Line
                  type="linear"
                  dataKey="det"
                  name="det"
                  stroke={methodConfig?.color ?? '#f59e0b'}
                  strokeWidth={1.5}
                  dot={false}
                  isAnimationActive={false}
                />
              </>
            ) : (
              <>
                {/* C Layer 2 EWMA baseline lines -- one per tier */}
                {activeTiers.map((tk) => (
                  <Line
                    key={tk.dataKey}
                    type="linear"
                    dataKey={tk.dataKey}
                    name={tk.dataKey}
                    stroke={tk.color}
                    strokeWidth={1}
                    strokeDasharray={tk.dash}
                    dot={false}
                    isAnimationActive={false}
                    connectNulls
                  />
                ))}
                {/* Real-time line (on top) */}
                <Line
                  type="linear"
                  dataKey="value"
                  name="value"
                  stroke={color}
                  strokeWidth={1.5}
                  dot={false}
                  isAnimationActive={false}
                />
              </>
            )}
          </LineChart>
        </ResponsiveContainer>
      )}

      {/* Legend */}
      <div className="flex items-center gap-2 mt-1.5 text-2xs text-slate-500 flex-wrap">
        {isDetectionMode ? (
          <>
            <div className="flex items-center gap-1">
              <span
                className="inline-block w-3 h-0.5 rounded"
                style={{ backgroundColor: methodConfig?.color ?? '#f59e0b' }}
              />
              <span>{methodConfig?.label ?? 'Score'}</span>
            </div>
            {detConfig?.method === 'cusum' && (
              <div className="flex items-center gap-1">
                <span className="inline-block w-3 h-0.5 rounded" style={{ backgroundColor: '#22d3ee' }} />
                <span>CUSUM</span>
              </div>
            )}
            <div className="flex items-center gap-1">
              <span className="inline-block w-3 h-0.5 rounded" style={{ backgroundColor: '#facc15' }} />
              <span>Warning ({methodConfig?.warningThreshold})</span>
            </div>
            <div className="flex items-center gap-1">
              <span className="inline-block w-3 h-0.5 rounded" style={{ backgroundColor: '#ef4444' }} />
              <span>Alarm ({methodConfig?.alarmThreshold})</span>
            </div>
          </>
        ) : (
          <>
            {/* Real-time swatch */}
            <div className="flex items-center gap-1">
              <span
                className="inline-block w-3 h-0.5 rounded"
                style={{ backgroundColor: color }}
              />
              <span>Real-time</span>
            </div>
            {/* Baseline tier swatches */}
            {activeTiers.map((tk) => (
              <div key={tk.dataKey} className="flex items-center gap-1">
                <span
                  className="inline-block w-3 h-0.5 rounded"
                  style={{ backgroundColor: tk.color }}
                />
                <span>{tk.label}</span>
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  );
});
