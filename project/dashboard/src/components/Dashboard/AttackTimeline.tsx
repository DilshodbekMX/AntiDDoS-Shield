/**
 * Attack Timeline Visualization
 *
 * Horizontal timeline showing attack duration bars on a time axis.
 * Severity encoded as color intensity. Click to select and expand.
 */

import { useMemo, useState } from 'react';
import { clsx } from 'clsx';
import { AttackSummary } from '../../types';

interface AttackTimelineProps {
  attacks: AttackSummary[];
  onSelectAttack?: (id: string) => void;
  selectedId?: string | null;
}

const SEVERITY_COLORS: Record<string, { bar: string; bg: string; border: string }> = {
  critical: { bar: 'bg-red-500', bg: 'bg-red-500/20', border: 'border-red-500/50' },
  high:     { bar: 'bg-orange-500', bg: 'bg-orange-500/20', border: 'border-orange-500/50' },
  medium:   { bar: 'bg-yellow-500', bg: 'bg-yellow-500/20', border: 'border-yellow-500/50' },
  low:      { bar: 'bg-emerald-500', bg: 'bg-emerald-500/20', border: 'border-emerald-500/50' },
};

const ATTACK_TYPE_LABELS: Record<string, string> = {
  syn_flood: 'SYN',
  udp_flood: 'UDP',
  icmp_flood: 'ICMP',
  http_flood: 'HTTP',
  dns_amplification: 'DNS Amp',
  ntp_amplification: 'NTP Amp',
  slowloris: 'Slowloris',
  volumetric: 'Volumetric',
  unknown: 'Unknown',
};

function formatTime(dateStr: string): string {
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return '';
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatDurationShort(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  const hours = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  return `${hours}h${mins > 0 ? ` ${mins}m` : ''}`;
}

export function AttackTimeline({ attacks, onSelectAttack, selectedId }: AttackTimelineProps) {
  const [hoveredId, setHoveredId] = useState<string | null>(null);

  // Compute time range and layout
  const { rows, ticks } = useMemo(() => {
    if (attacks.length === 0) return { rows: [], timeRange: { start: 0, end: 0, span: 0 }, ticks: [] };

    const now = Date.now();
    const items = attacks.map((a) => {
      const start = new Date(a.started_at).getTime();
      const end = a.ended_at ? new Date(a.ended_at).getTime() : now;
      return { ...a, startMs: isNaN(start) ? now : start, endMs: isNaN(end) ? now : end };
    });

    const minTime = Math.min(...items.map((a) => a.startMs));
    const maxTime = Math.max(...items.map((a) => a.endMs));
    // Add 5% padding on each side
    const span = maxTime - minTime || 60000; // at least 1 minute
    const paddedStart = minTime - span * 0.05;
    const paddedEnd = maxTime + span * 0.05;
    const paddedSpan = paddedEnd - paddedStart;

    // Generate ~5 evenly spaced time ticks
    const tickCount = 5;
    const tickArr = [];
    for (let i = 0; i <= tickCount; i++) {
      const t = paddedStart + (paddedSpan * i) / tickCount;
      tickArr.push({ time: t, label: formatTime(new Date(t).toISOString()), pct: (i / tickCount) * 100 });
    }

    // Layout rows to avoid overlapping bars (lane allocation)
    const lanes: { endMs: number }[] = [];
    const sorted = [...items].sort((a, b) => a.startMs - b.startMs);
    const rowData = sorted.map((item) => {
      let lane = lanes.findIndex((l) => l.endMs <= item.startMs);
      if (lane === -1) {
        lane = lanes.length;
        lanes.push({ endMs: item.endMs });
      } else {
        lanes[lane].endMs = item.endMs;
      }
      const leftPct = ((item.startMs - paddedStart) / paddedSpan) * 100;
      const widthPct = ((item.endMs - item.startMs) / paddedSpan) * 100;
      return { ...item, lane, leftPct, widthPct: Math.max(widthPct, 0.5) }; // min 0.5% width for visibility
    });

    return {
      rows: rowData,
      timeRange: { start: paddedStart, end: paddedEnd, span: paddedSpan },
      ticks: tickArr,
    };
  }, [attacks]);

  if (attacks.length === 0) return null;

  const laneCount = Math.max(1, ...rows.map((r) => r.lane + 1));
  const laneHeight = 32;
  const timelineHeight = laneCount * laneHeight + 28; // +28 for axis

  return (
    <div className="card">
      <div className="card-header flex items-center justify-between">
        <h3 className="card-title">Attack Timeline</h3>
        <div className="flex items-center gap-4 text-2xs text-slate-500">
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-6 rounded-sm bg-red-500" /> Critical
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-6 rounded-sm bg-orange-500" /> High
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-6 rounded-sm bg-yellow-500" /> Medium
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-6 rounded-sm bg-emerald-500" /> Low
          </span>
        </div>
      </div>
      <div className="p-4">
        <div className="relative" style={{ height: timelineHeight }}>
          {/* Time axis ticks */}
          <div className="absolute bottom-0 left-0 right-0 h-6 border-t border-slate-200 dark:border-slate-700">
            {ticks.map((tick, i) => (
              <div
                key={i}
                className="absolute -top-1 flex flex-col items-center"
                style={{ left: `${tick.pct}%` }}
              >
                <div className="w-px h-2 bg-slate-300 dark:bg-slate-600" />
                <span className="text-2xs text-slate-500 mt-0.5 whitespace-nowrap">
                  {tick.label}
                </span>
              </div>
            ))}
          </div>

          {/* Attack bars */}
          {rows.map((attack) => {
            const colors = SEVERITY_COLORS[attack.severity] ?? SEVERITY_COLORS.low;
            const isSelected = selectedId === attack.id;
            const isHovered = hoveredId === attack.id;
            const durationMs = attack.endMs - attack.startMs;

            return (
              <div
                key={attack.id}
                className="absolute group"
                style={{
                  left: `${attack.leftPct}%`,
                  width: `${attack.widthPct}%`,
                  top: attack.lane * laneHeight,
                  height: laneHeight - 4,
                }}
              >
                {/* Bar */}
                <button
                  className={clsx(
                    'w-full h-full rounded-md border transition-all duration-200 flex items-center overflow-hidden cursor-pointer',
                    colors.bg,
                    colors.border,
                    isSelected && 'ring-2 ring-white/30 shadow-lg',
                    isHovered && 'brightness-125 shadow-md',
                  )}
                  onClick={() => onSelectAttack?.(attack.id)}
                  onMouseEnter={() => setHoveredId(attack.id)}
                  onMouseLeave={() => setHoveredId(null)}
                  aria-label={`${attack.attack_type} attack on ${attack.target_ip}, ${attack.severity} severity, duration ${formatDurationShort(durationMs)}`}
                >
                  {/* Fill bar showing relative intensity */}
                  <div
                    className={clsx('h-full rounded-md opacity-60', colors.bar)}
                    style={{ width: '100%' }}
                  />
                  {/* Label (only if bar is wide enough) */}
                  {attack.widthPct > 4 && (
                    <span className="absolute inset-0 flex items-center px-2 text-2xs font-medium text-white truncate">
                      {ATTACK_TYPE_LABELS[attack.attack_type] ?? attack.attack_type}
                      {attack.widthPct > 8 && ` · ${attack.target_ip}`}
                    </span>
                  )}
                </button>

                {/* Tooltip on hover */}
                {isHovered && (
                  <div className="absolute z-20 bottom-full left-1/2 -translate-x-1/2 mb-2 pointer-events-none">
                    <div className="bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-600 rounded-lg shadow-xl px-3 py-2 text-xs whitespace-nowrap">
                      <div className="font-semibold text-slate-900 dark:text-white">
                        {ATTACK_TYPE_LABELS[attack.attack_type] ?? attack.attack_type}
                      </div>
                      <div className="text-slate-500 dark:text-slate-400 mt-0.5">
                        <span className="font-mono text-indigo-600 dark:text-indigo-300">{attack.target_ip}</span>
                        {' · '}{attack.severity.toUpperCase()}
                        {' · '}{formatDurationShort(durationMs)}
                      </div>
                      <div className="text-slate-500 mt-0.5">
                        {formatTime(attack.started_at)}
                        {attack.ended_at ? ` → ${formatTime(attack.ended_at)}` : ' → ongoing'}
                      </div>
                      {attack.is_active && (
                        <div className="text-red-600 dark:text-red-400 font-medium mt-0.5 flex items-center gap-1">
                          <span className="h-1.5 w-1.5 rounded-full bg-red-500 animate-pulse" />
                          Active
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export default AttackTimeline;
