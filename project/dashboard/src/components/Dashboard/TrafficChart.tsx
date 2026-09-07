/**
 * Traffic Chart Component -- Two charts with Size/Number toggle
 * Top: Inbound vs Outbound
 * Bottom: Received, Sent, Dropped
 *
 * Premium aesthetics: custom HTML tooltips, subtle grids, smooth curves,
 * crosshair cursor, restrained 5-color palette.
 */

import { useState, useMemo, memo } from 'react';
import type { RechartsTooltipProps, RechartsPayloadEntry } from '../../types/api';
import { useUIStore } from '../../store';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceLine,
  ReferenceArea,
  ResponsiveContainer,
} from 'recharts';
import { StatsHistoryPoint } from '../../types';
import { formatBytes, formatNumber } from '../../utils/formatting';

export interface AttackEvent {
  timestamp: string;
  label: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface BaselineBand {
  /** Mean baseline value */
  mean: number;
  /** Upper bound of normal range */
  upper: number;
  /** Label for the baseline line */
  label?: string;
}

interface TrafficChartProps {
  data: StatsHistoryPoint[];
  loading?: boolean;
  height?: number;
  attackEvents?: AttackEvent[];
  /** Optional baseline band for the inbound chart */
  baselineBand?: BaselineBand;
}

type ChartMode = 'size' | 'number';

function parseTimeLabel(timestamp: string | number): string {
  if (typeof timestamp === 'number') {
    const d = new Date(timestamp);
    if (!isNaN(d.getTime())) {
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }
  }
  if (typeof timestamp === 'string') {
    if (/^\d{1,2}:\d{2}(:\d{2})?$/.test(timestamp)) {
      return timestamp;
    }
    const d = new Date(timestamp);
    if (!isNaN(d.getTime())) {
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }
  }
  return '';
}

/**
 * Restrained 5-color data palette
 * 1. Indigo  -- primary (inbound)
 * 2. Emerald -- positive/safe (outbound, forwarded)
 * 3. Blue    -- informational (received)
 * 4. Red     -- danger (dropped)
 * 5. Amber   -- warning (attack markers)
 */
const COLORS = {
  inbound:  '#6366F1', // Indigo
  outbound: '#10B981', // Emerald
  received: '#6366F1', // Indigo (same as inbound for consistency)
  sent:     '#10B981', // Emerald (forwarded = safe)
  dropped:  '#EF4444', // Red
};

const GRID_STYLE_DARK = {
  strokeDasharray: '3 3',
  stroke: '#374151',
  strokeOpacity: 0.15,
};

const GRID_STYLE_LIGHT = {
  strokeDasharray: '3 3',
  stroke: '#e2e8f0',
  strokeOpacity: 0.5,
};

function ModeToggle({ mode, onChange }: { mode: ChartMode; onChange: (m: ChartMode) => void }) {
  return (
    <div className="inline-flex rounded-md border border-slate-300 dark:border-slate-600 overflow-hidden">
      <button
        onClick={() => onChange('size')}
        className={`px-2.5 py-0.5 text-2xs font-medium transition-colors ${
          mode === 'size'
            ? 'bg-indigo-600 text-white'
            : 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 hover:text-slate-200'
        }`}
      >
        B/s
      </button>
      <button
        onClick={() => onChange('number')}
        className={`px-2.5 py-0.5 text-2xs font-medium transition-colors border-l border-slate-300 dark:border-slate-600 ${
          mode === 'number'
            ? 'bg-indigo-600 text-white'
            : 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 hover:text-slate-200'
        }`}
      >
        pps
      </button>
    </div>
  );
}

function ColorDot({ color }: { color: string }) {
  return <span className="inline-block w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: color }} />;
}

/**
 * Custom HTML tooltip for premium look
 */
function createCustomTooltip(fmtValue: (v: number) => string) {
  return function CustomChartTooltip({ active, payload, label }: RechartsTooltipProps) {
    if (!active || !payload || payload.length === 0) return null;

    return (
      <div className="chart-tooltip">
        <div className="chart-tooltip-title">{label}</div>
        {payload.map((entry: RechartsPayloadEntry, i: number) => (
          <div key={i} className="chart-tooltip-row">
            <span className="chart-tooltip-label">
              <span className="chart-tooltip-dot" style={{ backgroundColor: entry.color }} />
              {entry.name}
            </span>
            <span className="chart-tooltip-value">{fmtValue(entry.value)}</span>
          </div>
        ))}
      </div>
    );
  };
}

export const TrafficChart = memo(function TrafficChart({
  data,
  loading = false,
  height = 400,
  attackEvents,
  baselineBand,
}: TrafficChartProps) {
  const [mode, setMode] = useState<ChartMode>('size');
  const { darkMode } = useUIStore();

  const isSize = mode === 'size';
  const fmtValue = isSize ? (v: number) => formatBytes(v) + '/s' : (v: number) => formatNumber(v) + ' pps';

  // All hooks must be called before any early returns (React rules of hooks)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const TooltipContent = useMemo(() => createCustomTooltip(fmtValue), [mode]);

  if (loading) {
    return (
      <div className="flex items-center justify-center rounded-lg" style={{ height }}>
        <div className="animate-pulse text-slate-500">Loading chart...</div>
      </div>
    );
  }

  if (!data || data.length === 0) {
    return (
      <div className="flex items-center justify-center rounded-lg" style={{ height }}>
        <div className="text-slate-500">No data available</div>
      </div>
    );
  }

  const formattedData = data
    .filter((point) => point.timestamp)
    .map((point) => ({
      ...point,
      time: parseTimeLabel(point.timestamp),
    }));

  const tickInterval = Math.max(1, Math.floor(formattedData.length / 7));
  const chartHeight = Math.floor((height - 40) / 2);

  const fmtAxis = isSize ? (v: number) => formatBytes(v) : (v: number) => formatNumber(v);

  const inboundKey = isSize ? 'rx_bps' : 'rx_pps';
  const outboundKey = isSize ? 'tx_bps' : 'tx_pps';
  const receivedKey = isSize ? 'rx_bps' : 'rx_pps';
  const sentKey = isSize ? 'fwd_bps' : 'fwd_pps';
  const droppedKey = isSize ? 'drop_bps' : 'drop_pps';

  const GRID_STYLE = darkMode ? GRID_STYLE_DARK : GRID_STYLE_LIGHT;
  const tickFill = darkMode ? '#64748B' : '#94a3b8';

  const xAxisProps = {
    dataKey: 'time' as const,
    tick: { fill: tickFill, fontSize: 10 },
    interval: tickInterval,
    tickMargin: 4,
    axisLine: { stroke: darkMode ? '#334155' : '#cbd5e1' },
    tickLine: false,
  };

  const yAxisProps = {
    tick: { fill: tickFill, fontSize: 10 },
    width: 72,
    axisLine: false,
    tickLine: false,
  };

  return (
    <div className="space-y-3">
      {/* Mode toggle */}
      <div className="flex items-center justify-between px-1">
        <div />
        <ModeToggle mode={mode} onChange={setMode} />
      </div>

      {/* Chart 1: Inbound vs Outbound */}
      <div>
        <div className="flex items-center gap-4 mb-1 px-1">
          <h4 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wide">Inbound / Outbound</h4>
          <div className="flex items-center gap-3 text-2xs text-slate-500">
            <span className="flex items-center gap-1"><ColorDot color={COLORS.inbound} /> Inbound</span>
            <span className="flex items-center gap-1"><ColorDot color={COLORS.outbound} /> Outbound</span>
          </div>
        </div>
        <ResponsiveContainer width="100%" height={chartHeight}>
          <AreaChart data={formattedData} margin={{ top: 4, right: 12, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="gradIn" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={COLORS.inbound} stopOpacity={0.2} />
                <stop offset="95%" stopColor={COLORS.inbound} stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gradOut" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={COLORS.outbound} stopOpacity={0.15} />
                <stop offset="95%" stopColor={COLORS.outbound} stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid {...GRID_STYLE} />
            <XAxis {...xAxisProps} />
            <YAxis {...yAxisProps} tickFormatter={fmtAxis} />
            <Tooltip
              content={<TooltipContent />}
              cursor={{ stroke: '#475569', strokeWidth: 1, strokeDasharray: '4 4' }}
            />
            <Area
              type="linear"
              dataKey={inboundKey}
              name="Inbound"
              stroke={COLORS.inbound}
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#gradIn)"
              isAnimationActive={false}
  
            />
            <Area
              type="linear"
              dataKey={outboundKey}
              name="Outbound"
              stroke={COLORS.outbound}
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#gradOut)"
              isAnimationActive={false}
  
            />
            {/* Baseline normal range band */}
            {baselineBand && (
              <ReferenceArea
                y1={0}
                y2={baselineBand.upper}
                fill="#10B981"
                fillOpacity={0.04}
                stroke="none"
              />
            )}
            {/* Baseline threshold line */}
            {baselineBand && (
              <ReferenceLine
                y={baselineBand.upper}
                stroke="#10B981"
                strokeDasharray="6 4"
                strokeWidth={1}
                strokeOpacity={0.5}
                label={{ value: baselineBand.label || 'Baseline', position: 'insideTopRight', fontSize: 9, fill: '#6ee7b7' }}
              />
            )}
            {attackEvents?.map((event, i) => (
              <ReferenceLine
                key={`attack-1-${i}`}
                x={event.timestamp}
                stroke={event.severity === 'critical' || event.severity === 'high' ? '#ef4444' : '#f59e0b'}
                strokeDasharray="4 2"
                strokeWidth={1.5}
                label={{ value: event.label, position: 'insideTopLeft', fontSize: 9, fill: event.severity === 'critical' || event.severity === 'high' ? '#fca5a5' : '#fcd34d' }}
              />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Chart 2: Received / Forwarded / Dropped */}
      <div>
        <div className="flex items-center gap-4 mb-1 px-1">
          <h4 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wide">Received / Forwarded / Dropped</h4>
          <div className="flex items-center gap-3 text-2xs text-slate-500">
            <span className="flex items-center gap-1"><ColorDot color={COLORS.received} /> Received</span>
            <span className="flex items-center gap-1"><ColorDot color={COLORS.sent} /> Forwarded</span>
            <span className="flex items-center gap-1"><ColorDot color={COLORS.dropped} /> Dropped</span>
          </div>
        </div>
        <ResponsiveContainer width="100%" height={chartHeight}>
          <AreaChart data={formattedData} margin={{ top: 4, right: 12, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="gradRecv" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={COLORS.received} stopOpacity={0.15} />
                <stop offset="95%" stopColor={COLORS.received} stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gradSent" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={COLORS.sent} stopOpacity={0.15} />
                <stop offset="95%" stopColor={COLORS.sent} stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gradDrop" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={COLORS.dropped} stopOpacity={0.2} />
                <stop offset="95%" stopColor={COLORS.dropped} stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid {...GRID_STYLE} />
            <XAxis {...xAxisProps} />
            <YAxis {...yAxisProps} tickFormatter={fmtAxis} />
            <Tooltip
              content={<TooltipContent />}
              cursor={{ stroke: '#475569', strokeWidth: 1, strokeDasharray: '4 4' }}
            />
            <Area
              type="linear"
              dataKey={receivedKey}
              name="Received"
              stroke={COLORS.received}
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#gradRecv)"
              isAnimationActive={false}
  
            />
            <Area
              type="linear"
              dataKey={sentKey}
              name="Forwarded"
              stroke={COLORS.sent}
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#gradSent)"
              isAnimationActive={false}
  
            />
            <Area
              type="linear"
              dataKey={droppedKey}
              name="Dropped"
              stroke={COLORS.dropped}
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#gradDrop)"
              isAnimationActive={false}
  
            />
            {attackEvents?.map((event, i) => (
              <ReferenceLine
                key={`attack-2-${i}`}
                x={event.timestamp}
                stroke={event.severity === 'critical' || event.severity === 'high' ? '#ef4444' : '#f59e0b'}
                strokeDasharray="4 2"
                strokeWidth={1.5}
              />
            ))}
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
});

export default TrafficChart;
