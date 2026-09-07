/**
 * LearningStatus -- Layer 2 baseline learning progress widget
 *
 * Displays the current learning phase (cold_start -> warmup -> moderate -> mature),
 * per-tier progress bars, ETA countdown, and alert-only mode indicator.
 * Collapses to a badge when fully mature.
 *
 * Connected to: GET /api/v2/layer2/learning-status (polled every 5s)
 * Updated via: 'learning_state_change' WebSocket events
 */

import { useQuery } from '@tanstack/react-query';
import { clsx } from 'clsx';
import {
  CheckCircleIcon,
  ClockIcon,
  ExclamationTriangleIcon,
  BeakerIcon,
} from '@heroicons/react/24/outline';
import api from '../../services/api';

// ============================================================================
// Types
// ============================================================================

interface LearningStatusData {
  state: string;
  phase: number;
  progress_pct: number;
  tier1_ready: boolean;
  tier2_ready: boolean;
  tier3_ready: boolean;
  tier1_progress: number;
  tier2_progress: number;
  tier3_progress: number;
  tier1_eta_sec: number;
  tier2_eta_sec: number;
  tier3_eta_sec: number;
  tier2_slots_ready: number;
  tier3_slots_ready: number;
  baseline_age_sec: number;
  eta_mature_seconds: number;
  total_updates: number;
  mitigation_active: boolean;
  learning_action: number;
  suppressed_count: number;
  trust_multiplier: number;
}

// ============================================================================
// Helpers
// ============================================================================

function formatEta(seconds: number): string {
  if (seconds <= 0) return 'Ready';
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.ceil(seconds / 60)}m`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`;
  return `${(seconds / 86400).toFixed(1)}d`;
}

function formatBaselineAge(seconds: number): string {
  if (seconds === 0) return 'Cold start';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m old`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h old`;
  return `${(seconds / 86400).toFixed(1)}d old`;
}

// ============================================================================
// Sub-components
// ============================================================================

interface TierBarProps {
  label: string;
  sublabel: string;
  progress: number;
  eta: number;
  ready: boolean;
  slotsReady?: number;
  totalSlots?: number;
}

function TierBar({ label, sublabel, progress, eta, ready, slotsReady, totalSlots }: TierBarProps) {
  const barColor = ready
    ? 'bg-emerald-500'
    : progress > 50
    ? 'bg-amber-500'
    : 'bg-brand-500';

  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {ready ? (
            <CheckCircleIcon className="h-4 w-4 text-emerald-400 flex-shrink-0" />
          ) : (
            <ClockIcon className="h-4 w-4 text-slate-400 flex-shrink-0" />
          )}
          <span className="text-sm font-medium text-slate-900 dark:text-white">
            {label}
          </span>
          <span className="text-xs text-slate-500 dark:text-slate-400">{sublabel}</span>
          {totalSlots !== undefined && slotsReady !== undefined && (
            <span className="text-xs text-slate-500 dark:text-slate-400">
              {slotsReady}/{totalSlots} slots
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {!ready && (
            <span className="text-xs text-slate-500 dark:text-slate-400">
              ETA: {formatEta(eta)}
            </span>
          )}
          <span className={clsx(
            'text-xs font-semibold tabular-nums',
            ready ? 'text-emerald-400' : 'text-slate-700 dark:text-slate-300'
          )}>
            {progress}%
          </span>
        </div>
      </div>
      <div className="h-1.5 w-full bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
        <div
          className={clsx('h-full rounded-full transition-all duration-500', barColor)}
          style={{ width: `${Math.min(100, progress)}%` }}
        />
      </div>
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export interface LearningStatusProps {
  /** Collapse to a single badge when mature (default: true) */
  collapseWhenMature?: boolean;
  /** Show suppressed detections counter */
  showSuppressed?: boolean;
  className?: string;
}

const PHASE_CONFIG = {
  cold_start: {
    label: 'Cold Start',
    color: 'text-red-400',
    bg: 'bg-red-500/10 border-red-500/30',
    dot: 'bg-red-400',
    description: 'No behavioral baselines — absolute thresholds only',
  },
  warmup: {
    label: 'Warmup',
    color: 'text-amber-400',
    bg: 'bg-amber-500/10 border-amber-500/30',
    dot: 'bg-amber-400',
    description: 'Tier 1 ready — basic behavioral detection active',
  },
  moderate: {
    label: 'Moderate',
    color: 'text-blue-400',
    bg: 'bg-blue-500/10 border-blue-500/30',
    dot: 'bg-blue-400',
    description: 'Tier 1 + hourly slot ready — time-aware detection',
  },
  mature: {
    label: 'Mature',
    color: 'text-emerald-400',
    bg: 'bg-emerald-500/10 border-emerald-500/30',
    dot: 'bg-emerald-400',
    description: 'All tiers ready — full 3-tier precision',
  },
};

export function LearningStatus({
  collapseWhenMature = true,
  showSuppressed = true,
  className,
}: LearningStatusProps) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['learning-status'],
    queryFn: () => api.getLearningStatus(),
    refetchInterval: 5000,
    staleTime: 4000,
  });

  if (isLoading) {
    return (
      <div className={clsx('h-20 bg-slate-100 dark:bg-slate-800 rounded-xl border border-slate-300 dark:border-slate-700 animate-pulse', className)} />
    );
  }

  if (isError || !data) {
    return null;
  }

  const status = data as LearningStatusData;
  const phaseKey = (status.state in PHASE_CONFIG ? status.state : 'cold_start') as keyof typeof PHASE_CONFIG;
  const phase = PHASE_CONFIG[phaseKey];
  const isMature = status.state === 'mature';

  // Collapsed badge for mature state
  if (isMature && collapseWhenMature) {
    return (
      <div className={clsx(
        'flex items-center gap-2 px-3 py-1.5 rounded-lg border text-sm',
        phase.bg,
        className
      )}>
        <CheckCircleIcon className={clsx('h-4 w-4', phase.color)} />
        <span className={clsx('font-medium', phase.color)}>Baseline Mature</span>
        <span className="text-xs text-slate-500 dark:text-slate-400">
          · {status.total_updates.toLocaleString()} updates
          {status.baseline_age_sec > 0 && ` · ${formatBaselineAge(status.baseline_age_sec)}`}
        </span>
      </div>
    );
  }

  return (
    <div className={clsx(
      'rounded-xl border overflow-hidden',
      phase.bg,
      className
    )}>
      {/* Header */}
      <div className="px-4 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className={clsx('h-2.5 w-2.5 rounded-full', phase.dot, !isMature && 'animate-pulse')} />
          <div>
            <div className="flex items-center gap-2">
              <span className={clsx('text-sm font-semibold', phase.color)}>
                {phase.label}
              </span>
              <span className="text-xs text-slate-500 dark:text-slate-400">
                — {phase.description}
              </span>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {status.learning_action === 1 && !status.mitigation_active && (
            <span className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-orange-500/20 border border-orange-500/30 text-xs font-medium text-orange-400">
              <ExclamationTriangleIcon className="h-3.5 w-3.5" />
              Alert Only
            </span>
          )}
          {status.trust_multiplier > 1.0 && (
            <span className="text-xs text-slate-500 dark:text-slate-400">
              Trust: {status.trust_multiplier.toFixed(1)}x
            </span>
          )}
          {status.eta_mature_seconds > 0 && (
            <span className="text-xs text-slate-500 dark:text-slate-400">
              Ready in ~{formatEta(status.eta_mature_seconds)}
            </span>
          )}
        </div>
      </div>

      {/* Overall Progress Bar */}
      <div className="px-4 pb-1">
        <div className="h-1 w-full bg-slate-200 dark:bg-slate-700/60 rounded-full overflow-hidden">
          <div
            className={clsx(
              'h-full rounded-full transition-all duration-700',
              isMature ? 'bg-emerald-500' : 'bg-brand-500'
            )}
            style={{ width: `${status.progress_pct}%` }}
          />
        </div>
      </div>

      {/* Tier Progress */}
      <div className="px-4 pb-3 pt-3 space-y-3">
        <TierBar
          label="Tier 1"
          sublabel="(Immediate ~10s)"
          progress={status.tier1_progress}
          eta={status.tier1_eta_sec}
          ready={status.tier1_ready}
        />
        <TierBar
          label="Tier 2"
          sublabel="(Hourly ~24h)"
          progress={status.tier2_progress}
          eta={status.tier2_eta_sec}
          ready={status.tier2_ready}
          slotsReady={status.tier2_slots_ready}
          totalSlots={24}
        />
        <TierBar
          label="Tier 3"
          sublabel="(Weekly ~7d)"
          progress={status.tier3_progress}
          eta={status.tier3_eta_sec}
          ready={status.tier3_ready}
          slotsReady={status.tier3_slots_ready}
          totalSlots={168}
        />
      </div>

      {/* Footer Stats */}
      <div className="px-4 py-2 border-t border-slate-300/50 dark:border-slate-600/50 flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1">
            <BeakerIcon className="h-3.5 w-3.5" />
            {status.total_updates.toLocaleString()} updates
          </span>
          <span>{formatBaselineAge(status.baseline_age_sec)}</span>
        </div>
        {showSuppressed && status.suppressed_count > 0 && (
          <span className="text-orange-400 font-medium">
            {status.suppressed_count} suppressed detection{status.suppressed_count !== 1 ? 's' : ''}
          </span>
        )}
      </div>
    </div>
  );
}

export default LearningStatus;
