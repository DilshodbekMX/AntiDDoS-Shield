/**
 * Baselines Visualization Page
 *
 * Displays Layer 2 three-tier baseline data:
 * - Tier 1 (Immediate): Single global EWMA baseline
 * - Tier 2 (Hourly): 24 time-of-day baselines with daily traffic pattern chart
 * - Tier 3 (Weekly): 168 day-hour baselines heatmap
 */

import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  ChartBarIcon,
  ClockIcon,
  CalendarDaysIcon,
  SignalIcon,
  ArrowPathIcon,
} from '@heroicons/react/24/outline';
import { InformationCircleIcon } from '@heroicons/react/24/outline';
import api from '../services/api';
import { BaselinesData, BaselineTierSlot } from '../types';
import { SkeletonCard } from '../components/ui/LoadingSpinner';
import { SectionCard, SelectInput } from '../components/ui/FormControls';
import { PageHeader } from '../components/ui';
import { IPScopeSelector } from '../components/IPScopeSelector';
import { useUIStore } from '../store';
import { useIPScopeStore } from '../store';
import { useTimezoneStore, TIMEZONE_OPTIONS } from '../store/timezoneStore';
import { clsx } from 'clsx';

// Feature display names
const FEATURE_LABELS: Record<string, string> = {
  packets_per_sec: 'Packets/sec',
  bytes_per_sec: 'Bytes/sec',
  flows_per_sec: 'Flows/sec',
  syn_per_sec: 'SYN/sec',
  syn_ack_per_sec: 'SYN-ACK/sec',
  ack_per_sec: 'ACK/sec',
  rst_per_sec: 'RST/sec',
  fin_per_sec: 'FIN/sec',
  tcp_ratio: 'TCP %',
  udp_ratio: 'UDP %',
  icmp_ratio: 'ICMP %',
  other_ratio: 'Other %',
  syn_ack_ratio: 'SYN/ACK Ratio',
  rst_syn_ratio: 'RST/SYN Ratio',
  bytes_per_packet: 'Bytes/Packet',
  unique_src_ips: 'Unique Src IPs',
  unique_dst_ports: 'Unique Dst Ports',
  unique_flows: 'Unique Flows',
  new_srcip_rate: 'New SrcIP Rate',
  max_flow_fraction: 'Max Flow %',
  topk_flow_share: 'Top-K Flow Share',
  heavy_hitter_count: 'Heavy Hitters',
  avg_packets_per_flow: 'Avg Pkts/Flow',
  flow_duration_avg: 'Flow Duration (ms)',
  syn_tcp_ratio: 'SYN/TCP %',
  synack_tcp_ratio: 'SYNACK/TCP %',
  ack_tcp_ratio: 'ACK/TCP %',
  rst_tcp_ratio: 'RST/TCP %',
  fin_tcp_ratio: 'FIN/TCP %',
  burst_factor: 'Burst Factor',
  udp_flow_ratio: 'UDP Flow Ratio',
  icmp_echo_ratio: 'ICMP Echo %',
  dst_port_density: 'Dst Port Density',
  src_ip_entropy: 'Src IP Entropy',
};

const DAY_NAMES = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

/**
 * Get the display timezone offset in hours from the timezone store.
 * Falls back to browser timezone if set to "auto".
 */
function getTimezoneOffsetHours(): number {
  return useTimezoneStore.getState().getOffsetHours();
}

/**
 * Get the current hour (0-23) in the selected timezone.
 * Used for "Now" markers on charts that display rotated (local) data.
 */
function getCurrentHourInSelectedTz(): number {
  const offsetHours = getTimezoneOffsetHours();
  const nowUTC = new Date();
  const utcHour = nowUTC.getUTCHours();
  const utcMinutes = nowUTC.getUTCMinutes();
  return Math.floor(((utcHour + utcMinutes / 60 + offsetHours) % 24 + 24) % 24);
}

/**
 * Get the current day (Monday=0) and hour (0-23) in the selected timezone.
 */
function getCurrentDayHourInSelectedTz(): { currentDay: number; currentHour: number } {
  const offsetHours = getTimezoneOffsetHours();
  const nowUTC = new Date();
  // Compute total hours since epoch in the selected timezone
  const totalMs = nowUTC.getTime() + offsetHours * 3600000;
  const localDate = new Date(totalMs);
  const currentDay = (localDate.getUTCDay() + 6) % 7; // Monday=0
  const currentHour = localDate.getUTCHours();
  return { currentDay, currentHour };
}

/**
 * Rotate a UTC-indexed array to local time.
 * E.g., for UTC+5: slot 0 (UTC midnight) moves to slot 5 (local midnight was UTC 19:00).
 */
function rotateToLocalTime<T>(arr: T[], offsetHours: number): T[] {
  const len = arr.length;
  const shift = ((offsetHours % len) + len) % len; // handle negative offsets
  return [...arr.slice(len - shift), ...arr.slice(0, len - shift)];
}

function formatNumber(n: number): string {
  if (n >= 1_000_000_000) return (n / 1_000_000_000).toFixed(1) + 'B';
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 10_000) return (n / 1_000).toFixed(1) + 'K';
  if (n >= 1_000) return (n / 1_000).toFixed(2) + 'K';
  if (n >= 100) return Math.round(n).toString();
  if (n >= 1) return n.toFixed(1);
  if (n > 0) return n.toFixed(2);
  return '0';
}

// ==================== Tier 1: Immediate Sub-Tiers ====================

const SUBTIER_NAMES = ['1-Second', '10-Second', '60-Second'];
const SUBTIER_DESCS = ['\u03B1=0.8, flash spike detection', '\u03B1=0.18, short attack detection', '\u03B1=0.033, slow ramp detection'];
const SUBTIER_COLORS = ['text-rose-400', 'text-indigo-400', 'text-teal-400'];
const SUBTIER_MIN_SAMPLES = [3, 10, 30];

function ImmediateCard({ data }: { data: BaselineTierSlot[] }) {
  const readyCount = data.filter(s => s.ready).length;
  return (
    <SectionCard
      title="Tier 1: Immediate Sub-Tiers"
      description={`3 EWMA sub-tiers with different smoothing windows (${readyCount}/3 ready)`}
    >
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {data.map((sub, i) => (
          <div key={i} className="bg-white dark:bg-slate-800/50 rounded-lg p-3 border border-slate-300 dark:border-slate-700">
            <div className={clsx('text-xs font-medium mb-1', SUBTIER_COLORS[i])}>{SUBTIER_NAMES[i]}</div>
            <div className="text-2xs text-slate-500 mb-2">{SUBTIER_DESCS[i]}</div>
            <div className="space-y-1">
              <div className="flex justify-between text-xs">
                <span className="text-slate-500">Mean</span>
                <span className="text-slate-900 dark:text-white font-medium">{formatNumber(sub.mean)}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-slate-500">StdDev</span>
                <span className="text-amber-600 dark:text-amber-400 font-medium">{formatNumber(sub.stddev)}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-slate-500">Samples</span>
                <span className="text-cyan-600 dark:text-cyan-400 font-medium">{formatNumber(sub.samples)}</span>
              </div>
            </div>
            <div className="mt-2">
              <span className={clsx(
                'inline-flex items-center rounded-full px-2 py-0.5 text-2xs font-medium',
                sub.ready ? 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-400' : 'bg-yellow-500/20 text-yellow-700 dark:text-yellow-400'
              )}>
                {sub.ready ? 'Ready' : `Learning (min ${SUBTIER_MIN_SAMPLES[i]})`}
              </span>
            </div>
          </div>
        ))}
      </div>
    </SectionCard>
  );
}

// ==================== Tier 2: Hourly Baselines ====================

function HourlyGrid({ hourly }: { hourly: BaselineTierSlot[] }) {
  const currentHour = getCurrentHourInSelectedTz();

  return (
    <SectionCard title="Tier 2: Hourly Baselines" description="24 time-of-day baselines (alpha=0.1). Each hour learns its own traffic pattern.">
      <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
        {hourly.map((slot, i) => (
          <div
            key={i}
            className={clsx(
              'rounded-lg p-2 text-center border transition-colors',
              i === currentHour
                ? 'border-brand-500 bg-brand-500/10'
                : slot.ready
                ? 'border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800/60'
                : 'border-slate-200 dark:border-slate-800 bg-slate-100 dark:bg-slate-900/50'
            )}
          >
            <div className={clsx(
              'text-xs font-mono mb-1',
              i === currentHour ? 'text-brand-400 font-bold' : 'text-slate-500'
            )}>
              {String(i).padStart(2, '0')}:00
              {i === currentHour && <span className="ml-1 text-brand-300">*</span>}
            </div>
            <div className="text-sm font-semibold text-slate-900 dark:text-white leading-tight">
              {formatNumber(slot.mean)}
            </div>
            <div className="text-2xs text-slate-500 mt-0.5">
              &plusmn;{formatNumber(slot.stddev)}
            </div>
            <div className={clsx(
              'text-2xs mt-0.5',
              slot.samples > 0 ? 'text-cyan-500' : 'text-slate-600'
            )}>
              {slot.samples} smp
            </div>
            {!slot.ready && (
              <div className="text-2xs text-yellow-600 mt-0.5">learning</div>
            )}
          </div>
        ))}
      </div>
    </SectionCard>
  );
}

// ==================== Daily Pattern Chart (SVG) ====================

function DailyPatternChart({ hourly, featureLabel }: { hourly: BaselineTierSlot[]; featureLabel: string }) {
  const { darkMode } = useUIStore();
  const gridColor = darkMode ? '#334155' : '#cbd5e1';
  const textColor = darkMode ? '#64748b' : '#64748b';
  const periodColor = darkMode ? '#475569' : '#94a3b8';
  const chartData = useMemo(() => {
    const means = hourly.map(h => h.mean);
    const stddevs = hourly.map(h => h.stddev);
    const maxVal = Math.max(...means.map((m, i) => m + stddevs[i]), 1);

    const width = 720;
    const height = 200;
    const padX = 40;
    const padY = 20;
    const chartW = width - padX * 2;
    const chartH = height - padY * 2;

    const points = means.map((m, i) => ({
      x: padX + (i / 23) * chartW,
      y: padY + chartH - (m / maxVal) * chartH,
      mean: m,
      stddev: stddevs[i],
      upper: padY + chartH - (Math.min(m + stddevs[i], maxVal) / maxVal) * chartH,
      lower: padY + chartH - (Math.max(m - stddevs[i], 0) / maxVal) * chartH,
    }));

    // Build SVG paths
    const linePath = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ');
    const areaUpperPath = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.upper}`).join(' ');
    const areaLowerPath = [...points].reverse().map((p, i) => `${i === 0 ? 'L' : 'L'} ${p.x} ${p.lower}`).join(' ');
    const areaPath = areaUpperPath + ' ' + areaLowerPath + ' Z';

    return { points, linePath, areaPath, maxVal, width, height, padX, padY, chartW, chartH };
  }, [hourly]);

  const { points, linePath, areaPath, maxVal, width, height, padX, padY, chartH } = chartData;

  return (
    <SectionCard title="Daily Traffic Pattern" description={`${featureLabel} baseline over 24 hours. Shaded area shows ±1 standard deviation.`}>
      <div className="bg-white dark:bg-slate-900 rounded-lg p-3 overflow-x-auto">
        <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-auto min-w-[500px]" preserveAspectRatio="xMidYMid meet">
          {/* Grid lines */}
          {[0, 0.25, 0.5, 0.75, 1].map(frac => {
            const y = padY + chartH * (1 - frac);
            return (
              <g key={frac}>
                <line x1={padX} y1={y} x2={width - padX} y2={y} stroke={gridColor} strokeWidth="0.5" strokeDasharray="4 2" />
                <text x={padX - 4} y={y + 3} textAnchor="end" fill={textColor} fontSize="8">
                  {formatNumber(maxVal * frac)}
                </text>
              </g>
            );
          })}

          {/* Hour labels */}
          {[0, 3, 6, 9, 12, 15, 18, 21].map(h => (
            <text
              key={h}
              x={points[h].x}
              y={height - 4}
              textAnchor="middle"
              fill={textColor}
              fontSize="8"
            >
              {String(h).padStart(2, '0')}
            </text>
          ))}

          {/* StdDev band */}
          <path d={areaPath} fill="#6366f1" opacity="0.15" />

          {/* Mean line */}
          <path d={linePath} fill="none" stroke="#6366f1" strokeWidth="2" />

          {/* Data points */}
          {points.map((p, i) => (
            <circle key={i} cx={p.x} cy={p.y} r="3" fill="#6366f1" stroke="#1e1b4b" strokeWidth="1">
              <title>{`${String(i).padStart(2, '0')}:00 — Mean: ${formatNumber(p.mean)}, StdDev: ${formatNumber(p.stddev)}`}</title>
            </circle>
          ))}

          {/* Current hour marker */}
          {(() => {
            const h = getCurrentHourInSelectedTz();
            const p = points[h];
            return (
              <g>
                <line x1={p.x} y1={padY} x2={p.x} y2={padY + chartH} stroke="#22d3ee" strokeWidth="1" strokeDasharray="3 2" opacity="0.5" />
                <circle cx={p.x} cy={p.y} r="5" fill="#22d3ee" stroke="#0e7490" strokeWidth="1.5" />
                <text x={p.x} y={padY - 4} textAnchor="middle" fill="#22d3ee" fontSize="8" fontWeight="bold">Now</text>
              </g>
            );
          })()}

          {/* Time period labels */}
          <text x={padX + 20} y={padY + 12} fill={periodColor} fontSize="7">Night</text>
          <text x={padX + 160} y={padY + 12} fill={periodColor} fontSize="7">Morning</text>
          <text x={padX + 340} y={padY + 12} fill={periodColor} fontSize="7">Afternoon</text>
          <text x={padX + 530} y={padY + 12} fill={periodColor} fontSize="7">Evening</text>
        </svg>
      </div>
    </SectionCard>
  );
}

// ==================== Tier 3: Weekly Heatmap ====================

function WeeklyHeatmap({ weekly }: { weekly: BaselineTierSlot[] }) {
  const [selectedSlot, setSelectedSlot] = useState<{ day: number; hour: number } | null>(null);
  const { darkMode } = useUIStore();

  const maxMean = useMemo(() => Math.max(...weekly.map(w => w.mean), 1), [weekly]);

  const { currentDay, currentHour } = getCurrentDayHourInSelectedTz();

  const getSlot = (day: number, hour: number) => weekly[day * 24 + hour];

  const getIntensity = (mean: number) => {
    if (mean <= 0) return 0;
    return Math.min(mean / maxMean, 1);
  };

  const selectedData = selectedSlot ? getSlot(selectedSlot.day, selectedSlot.hour) : null;

  return (
    <SectionCard title="Tier 3: Weekly Baselines" description="168 day-hour baselines (alpha=0.05). Each cell represents a unique day + hour combination.">
      {/* Heatmap grid */}
      <div className="overflow-x-auto">
        <div className="min-w-[600px]">
          {/* Hour labels */}
          <div className="flex ml-10 mb-1">
            {Array.from({ length: 24 }, (_, h) => (
              <div key={h} className="flex-1 text-center text-2xs text-slate-600 font-mono">
                {h % 3 === 0 ? String(h).padStart(2, '0') : ''}
              </div>
            ))}
          </div>

          {/* Grid rows */}
          {DAY_NAMES.map((day, d) => (
            <div key={d} className="flex items-center gap-1 mb-0.5">
              <div className={clsx(
                'w-9 text-right text-xs font-medium pr-1',
                d === currentDay ? 'text-brand-400' : 'text-slate-500'
              )}>
                {day}
              </div>
              <div className="flex flex-1 gap-px">
                {Array.from({ length: 24 }, (_, h) => {
                  const slot = getSlot(d, h);
                  const intensity = getIntensity(slot.mean);
                  const isCurrent = d === currentDay && h === currentHour;
                  const isSelected = selectedSlot?.day === d && selectedSlot?.hour === h;

                  return (
                    <button
                      key={h}
                      onClick={() => setSelectedSlot(isSelected ? null : { day: d, hour: h })}
                      className={clsx(
                        'flex-1 aspect-square rounded-sm transition-all cursor-pointer',
                        isCurrent && 'ring-1 ring-cyan-400',
                        isSelected && 'ring-2 ring-white'
                      )}
                      style={{
                        backgroundColor: slot.ready
                          ? darkMode
                            ? `rgba(99, 102, 241, ${0.1 + intensity * 0.8})`
                            : `rgba(99, 102, 241, ${0.08 + intensity * 0.5})`
                          : darkMode ? '#0f172a' : '#f1f5f9',
                      }}
                      title={`${day} ${String(h).padStart(2, '0')}:00 — Mean: ${formatNumber(slot.mean)}, StdDev: ${formatNumber(slot.stddev)}, Samples: ${slot.samples}`}
                    />
                  );
                })}
              </div>
            </div>
          ))}

          {/* Legend */}
          <div className="flex items-center gap-2 mt-3 ml-10">
            <span className="text-2xs text-slate-500">Low</span>
            <div className="flex gap-px">
              {[0.1, 0.25, 0.4, 0.55, 0.7, 0.85, 1.0].map(v => (
                <div
                  key={v}
                  className="w-4 h-3 rounded-sm"
                  style={{ backgroundColor: `rgba(99, 102, 241, ${0.1 + v * 0.8})` }}
                />
              ))}
            </div>
            <span className="text-2xs text-slate-500">High</span>
            <span className="text-2xs text-slate-600 ml-2">|</span>
            <div className="w-4 h-3 rounded-sm bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800" />
            <span className="text-2xs text-slate-500">Not ready</span>
          </div>
        </div>
      </div>

      {/* Selected slot detail */}
      {selectedData && selectedSlot && (
        <div className="mt-3 bg-slate-100 dark:bg-slate-800/50 rounded-lg p-3 border border-slate-300 dark:border-slate-700">
          <div className="flex items-center gap-4">
            <div className="text-sm font-medium text-slate-900 dark:text-white">
              {DAY_NAMES[selectedSlot.day]} {String(selectedSlot.hour).padStart(2, '0')}:00
            </div>
            <div className="flex gap-4 text-xs">
              <span className="text-slate-500 dark:text-slate-400">Mean: <span className="text-slate-900 dark:text-white font-medium">{formatNumber(selectedData.mean)}</span></span>
              <span className="text-slate-500 dark:text-slate-400">StdDev: <span className="text-amber-600 dark:text-amber-400 font-medium">{formatNumber(selectedData.stddev)}</span></span>
              <span className="text-slate-500 dark:text-slate-400">Samples: <span className="text-cyan-600 dark:text-cyan-400 font-medium">{selectedData.samples}</span></span>
              <span className={selectedData.ready ? 'text-emerald-600 dark:text-emerald-400' : 'text-yellow-600 dark:text-yellow-400'}>
                {selectedData.ready ? 'Ready' : 'Learning'}
              </span>
            </div>
          </div>
        </div>
      )}
    </SectionCard>
  );
}

// ==================== Readiness Summary ====================

function ReadinessSummary({ data, localHourly, localWeekly }: { data: BaselinesData; localHourly: BaselineTierSlot[]; localWeekly: BaselineTierSlot[] }) {
  const hourlyReady = localHourly.filter(h => h.ready).length;
  const weeklyReady = localWeekly.filter(w => w.ready).length;
  const totalSamples = localHourly.reduce((sum, h) => sum + h.samples, 0);

  return (
    <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
      <div className="bg-white dark:bg-slate-800/60 rounded-lg p-3 border border-slate-300 dark:border-slate-700">
        <div className="flex items-center gap-2 mb-1">
          <SignalIcon className="h-4 w-4 text-emerald-400" />
          <span className="text-xs text-slate-500">Tier 1</span>
        </div>
        {(() => {
          const t1Ready = data.immediate.filter(s => s.ready).length;
          const allReady = t1Ready === data.immediate.length;
          return (
            <>
              <div className={clsx('text-lg font-bold', allReady ? 'text-emerald-600 dark:text-emerald-400' : 'text-yellow-600 dark:text-yellow-400')}>
                {t1Ready}<span className="text-sm text-slate-500">/{data.immediate.length}</span>
              </div>
              <div className="mt-1 h-1.5 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden">
                <div className="h-full rounded-full bg-emerald-500 transition-all" style={{ width: `${(t1Ready / data.immediate.length) * 100}%` }} />
              </div>
            </>
          );
        })()}
      </div>

      <div className="bg-white dark:bg-slate-800/60 rounded-lg p-3 border border-slate-300 dark:border-slate-700">
        <div className="flex items-center gap-2 mb-1">
          <ClockIcon className="h-4 w-4 text-indigo-400" />
          <span className="text-xs text-slate-500">Tier 2 (Hourly)</span>
        </div>
        <div className="text-lg font-bold text-slate-900 dark:text-white">{hourlyReady}<span className="text-sm text-slate-500">/24</span></div>
        <div className="mt-1 h-1.5 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden">
          <div className="h-full rounded-full bg-indigo-500 transition-all" style={{ width: `${(hourlyReady / 24) * 100}%` }} />
        </div>
      </div>

      <div className="bg-white dark:bg-slate-800/60 rounded-lg p-3 border border-slate-300 dark:border-slate-700">
        <div className="flex items-center gap-2 mb-1">
          <CalendarDaysIcon className="h-4 w-4 text-purple-400" />
          <span className="text-xs text-slate-500">Tier 3 (Weekly)</span>
        </div>
        <div className="text-lg font-bold text-slate-900 dark:text-white">{weeklyReady}<span className="text-sm text-slate-500">/168</span></div>
        <div className="mt-1 h-1.5 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden">
          <div className="h-full rounded-full bg-purple-500 transition-all" style={{ width: `${(weeklyReady / 168) * 100}%` }} />
        </div>
      </div>

      <div className="bg-white dark:bg-slate-800/60 rounded-lg p-3 border border-slate-300 dark:border-slate-700">
        <div className="flex items-center gap-2 mb-1">
          <ArrowPathIcon className="h-4 w-4 text-cyan-400" />
          <span className="text-xs text-slate-500">Total Updates</span>
        </div>
        <div className="text-lg font-bold text-slate-900 dark:text-white">{formatNumber(data.total_updates)}</div>
        <div className="text-2xs text-slate-500">across all tiers</div>
      </div>

      <div className="bg-white dark:bg-slate-800/60 rounded-lg p-3 border border-slate-300 dark:border-slate-700">
        <div className="flex items-center gap-2 mb-1">
          <ChartBarIcon className="h-4 w-4 text-amber-400" />
          <span className="text-xs text-slate-500">Hourly Samples</span>
        </div>
        <div className="text-lg font-bold text-slate-900 dark:text-white">{formatNumber(totalSamples)}</div>
        <div className="text-2xs text-slate-500">total across 24 hours</div>
      </div>
    </div>
  );
}

// ==================== Main Page ====================

export function BaselinesPage() {
  const [selectedFeature, setSelectedFeature] = useState('packets_per_sec');
  const { selectedIP } = useIPScopeStore();

  const { data, isLoading, error } = useQuery<BaselinesData>({
    queryKey: ['baselines-data', selectedFeature, selectedIP || 'global'],
    queryFn: () => api.getLayer2BaselinesData(selectedFeature, selectedIP || undefined),
    refetchInterval: 30000,
  });

  const featureOptions = data?.features_available
    ? data.features_available.map(f => ({ value: f, label: FEATURE_LABELS[f] || f }))
    : Object.entries(FEATURE_LABELS).map(([value, label]) => ({ value, label }));

  const featureLabel = FEATURE_LABELS[selectedFeature] || selectedFeature;

  // Subscribe to timezone value so component re-renders when timezone changes
  const selectedTz = useTimezoneStore((s) => s.timezone);
  const tzOffset = selectedTz === 'auto'
    ? -new Date().getTimezoneOffset() / 60
    : (TIMEZONE_OPTIONS.find((o) => o.value === selectedTz)?.offsetHours ?? -new Date().getTimezoneOffset() / 60);
  const localHourly = data ? rotateToLocalTime(data.hourly, tzOffset) : [];
  const localWeekly = data ? rotateToLocalTime(data.weekly, tzOffset) : [];

  if (isLoading) {
    return (
      <div className="space-y-4">
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Baseline Explorer</h1>
        <SkeletonCard lines={4} />
        <SkeletonCard lines={6} />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="space-y-4">
        <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Baseline Explorer</h1>
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 text-yellow-700 dark:text-yellow-400 text-sm">
          {error instanceof Error ? error.message : 'No baseline data available. Save baselines from the Configuration page first.'}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Baseline Explorer"
        description="Three-tier EWMA baselines across 193 time slots (1 + 24 + 168)"
        actions={
          <>
            <IPScopeSelector />
            <label className="text-xs text-slate-500">Feature:</label>
            <SelectInput
              value={selectedFeature}
              onChange={setSelectedFeature}
              options={featureOptions}
              className="w-48"
            />
          </>
        }
      />

      {/* Per-IP info banner */}
      {selectedIP && data.fallback === 'no_data' && (
        <div className="flex items-center gap-2 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 px-4 py-2.5 text-sm text-amber-700 dark:text-amber-300">
          <InformationCircleIcon className="h-4 w-4 flex-shrink-0" />
          <span>No per-IP baseline data for {selectedIP} yet — the IP may not be receiving traffic or baselines are still learning. Data will appear automatically once traffic is detected.</span>
        </div>
      )}
      {selectedIP && data.per_ip && !data.fallback && data.learning_status && data.learning_status.phase !== 'mature' && (
        <div className="rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 px-4 py-3 text-sm text-amber-700 dark:text-amber-300">
          <div className="flex items-center gap-2 mb-2">
            <InformationCircleIcon className="h-4 w-4 flex-shrink-0" />
            <span className="font-medium">Learning in progress — {data.learning_status.phase_label}</span>
            {data.learning_status.eta && (
              <span className="text-xs opacity-75">({data.learning_status.eta})</span>
            )}
          </div>
          <div className="flex gap-4 text-xs">
            <span>Immediate: <span className="font-mono font-medium">{data.learning_status.tier1_progress}</span></span>
            <span>Hourly: <span className="font-mono font-medium">{data.learning_status.tier2_progress}</span></span>
            <span>Weekly: <span className="font-mono font-medium">{data.learning_status.tier3_progress}</span></span>
          </div>
          <div className="mt-2 h-1.5 bg-amber-200 dark:bg-amber-800 rounded-full overflow-hidden">
            <div
              className="h-full bg-amber-500 dark:bg-amber-400 rounded-full transition-all duration-500"
              style={{ width: `${Math.round(((data.immediate.filter(t => t.ready).length + localHourly.filter(t => t.ready).length + localWeekly.filter(t => t.ready).length) / (3 + 24 + 168)) * 100)}%` }}
            />
          </div>
        </div>
      )}
      {selectedIP && data.per_ip && !data.fallback && data.learning_status?.phase === 'mature' && (
        <div className="flex items-center gap-2 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 px-4 py-2.5 text-sm text-emerald-700 dark:text-emerald-300">
          <InformationCircleIcon className="h-4 w-4 flex-shrink-0" />
          <span>Baselines mature for {selectedIP}. All tiers fully learned — anomaly detection is at full accuracy.</span>
        </div>
      )}

      {/* Last saved */}
      {data.save_timestamp > 0 && (
        <div className="text-xs text-slate-500">
          Last saved: {new Date(data.save_timestamp * 1000).toLocaleString()}
        </div>
      )}

      {/* Readiness summary */}
      <ReadinessSummary data={data} localHourly={localHourly} localWeekly={localWeekly} />

      {/* Tier 1 */}
      <ImmediateCard data={data.immediate} />

      {/* Daily Pattern Chart */}
      <DailyPatternChart hourly={localHourly} featureLabel={featureLabel} />

      {/* Tier 2: Hourly Grid */}
      <HourlyGrid hourly={localHourly} />

      {/* Tier 3: Weekly Heatmap */}
      <WeeklyHeatmap weekly={localWeekly} />
    </div>
  );
}

export default BaselinesPage;
