/**
 * HeroStatusBanner -- Primary dashboard status indicator
 *
 * Single dominant element at the top of the dashboard.
 * Green when safe, red when under attack.
 * Both states are always rendered; crossfade via opacity for smooth transitions.
 */

import { clsx } from 'clsx';
import {
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  ArrowPathIcon,
} from '@heroicons/react/24/outline';
import {
  StatusIndicator,
  ThreatBadge,
  ThreatLevelBar,
} from '../ui';
import { formatBytes } from '../../utils/formatting';
import { useUIStore } from '../../store';
import type { AnomalyStatus, PerIPAnomalyEntry } from '../../types';

interface HeroStatusBannerProps {
  isConnected: boolean;
  hasActiveAnomaly: boolean;
  anomalyLevel: number;
  anomalyLevelName: string;
  anomalyData: AnomalyStatus | undefined;
  totalRxBps: number;
  protectedAssetCount: number;
  anomalousIpCount: number;
  selectedIP: string | null;
  selectedIPAnomaly: PerIPAnomalyEntry | null;
  onRefresh: () => void;
  refreshing: boolean;
  children?: React.ReactNode;
}

function getThreatLevel(level: number): 'critical' | 'high' | 'medium' | 'low' | 'none' {
  if (level >= 4) return 'critical';
  if (level >= 3) return 'high';
  if (level >= 2) return 'medium';
  if (level >= 1) return 'low';
  return 'none';
}

export function HeroStatusBanner({
  isConnected,
  hasActiveAnomaly,
  anomalyLevel,
  anomalyLevelName,
  anomalyData,
  totalRxBps,
  protectedAssetCount,
  anomalousIpCount,
  selectedIP,
  selectedIPAnomaly,
  onRefresh,
  refreshing,
  children,
}: HeroStatusBannerProps) {
  const { darkMode } = useUIStore();
  const threatLevel = getThreatLevel(anomalyLevel);
  const isAttack = !!hasActiveAnomaly;

  // Attack-state derived values (always computed for crossfade rendering)
  const featureName = selectedIP && selectedIPAnomaly
    ? selectedIPAnomaly.anomaly_protocol_name || 'Unknown'
    : anomalyData?.primary_feature_name || 'Unknown';
  const attackType = selectedIP && selectedIPAnomaly
    ? selectedIPAnomaly.attack_type_name || 'Anomaly'
    : 'Anomaly';
  const zScore = selectedIP && selectedIPAnomaly
    ? selectedIPAnomaly.max_z_score
    : anomalyData?.max_z_score || 0;
  const rateLimitPct = selectedIP && selectedIPAnomaly
    ? selectedIPAnomaly.rate_limit_pct ?? 100
    : anomalyData?.rate_limit_pct || 0;

  return (
    <div
      className={clsx(
        'card border-l-4 transition-all duration-700 ease-in-out',
        isAttack
          ? 'border-l-red-500 border-red-500/50'
          : 'border-l-emerald-500 border-emerald-500/30',
      )}
      style={{
        background: isAttack
          ? darkMode
            ? 'linear-gradient(to right, rgba(69, 10, 10, 0.50), rgba(67, 20, 7, 0.30))'
            : 'linear-gradient(to right, rgba(254, 202, 202, 0.50), rgba(254, 226, 226, 0.30))'
          : darkMode
            ? 'linear-gradient(to right, rgba(6, 78, 59, 0.40), rgb(15, 23, 42))'
            : 'linear-gradient(to right, rgba(209, 250, 229, 0.60), rgba(255, 255, 255, 1))',
        boxShadow: isAttack ? '0 0 20px rgba(239, 68, 68, 0.15)' : 'none',
      }}
    >
      <div className="p-5 relative overflow-hidden">
        {/* Shared controls -- always visible */}
        <div className="absolute top-3 right-3 sm:top-5 sm:right-5 flex items-center gap-2 sm:gap-3 z-10">
          {children}
          <button
            onClick={onRefresh}
            disabled={refreshing}
            className="btn-primary inline-flex items-center gap-2"
            aria-label="Refresh dashboard data"
          >
            <ArrowPathIcon className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {/* Icon -- transitions between shield/warning */}
        <div className="flex items-start gap-4">
          <div
            className={clsx(
              'flex-shrink-0 h-12 w-12 rounded-full flex items-center justify-center transition-colors duration-700',
              isAttack ? 'bg-red-500/20' : 'bg-emerald-500/15',
            )}
          >
            {isAttack ? (
              <ExclamationTriangleIcon className="h-6 w-6 text-red-400 animate-pulse" />
            ) : (
              <ShieldCheckIcon className="h-6 w-6 text-emerald-400" />
            )}
          </div>

          {/* Content area -- both states rendered, crossfade via opacity */}
          <div className="flex-1 min-w-0 relative">
            {/* -- Attack content -- */}
            <div
              className={clsx(
                'transition-all duration-500 ease-in-out',
                isAttack
                  ? 'opacity-100 relative'
                  : 'opacity-0 absolute inset-0 pointer-events-none',
              )}
              aria-hidden={!isAttack}
            >
              <div className="flex items-center gap-3 mb-1 pr-40">
                <h1 className="text-lg font-bold text-red-700 dark:text-red-200">
                  {selectedIP ? `Attack on ${selectedIP}` : 'ATTACK IN PROGRESS'}
                </h1>
                <ThreatBadge level={threatLevel} animated size="lg" />
                <StatusIndicator
                  status={isConnected ? 'online' : 'offline'}
                  label={isConnected ? 'DPDK' : 'Disconnected'}
                  size="sm"
                />
              </div>

              <p className="text-sm text-red-600 dark:text-red-300/80 mb-3">
                {anomalousIpCount} asset{anomalousIpCount !== 1 ? 's' : ''} targeted
                {' '}&middot; {attackType}
                {' '}&middot; Auto-mitigating at {rateLimitPct}%
              </p>

              <ThreatLevelBar level={anomalyLevel} max={4} />

              <div className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 sm:grid-cols-4">
                <div>
                  <div className="text-xs text-red-500 dark:text-red-400/70">Severity</div>
                  <div className="text-sm font-semibold text-red-700 dark:text-red-200">{anomalyLevelName}</div>
                </div>
                <div>
                  <div className="text-xs text-red-500 dark:text-red-400/70">
                    {selectedIP ? 'Protocol' : 'Primary Feature'}
                  </div>
                  <div className="text-sm font-semibold text-red-700 dark:text-red-200">{featureName}</div>
                </div>
                <div>
                  <div className="text-xs text-red-500 dark:text-red-400/70">Max Z-Score</div>
                  <div className="text-sm font-semibold text-red-700 dark:text-red-200">{zScore.toFixed(2)}</div>
                </div>
                <div>
                  <div className="text-xs text-red-500 dark:text-red-400/70">Rate Limit</div>
                  <div className="text-sm font-semibold text-red-700 dark:text-red-200">{rateLimitPct}%</div>
                </div>
              </div>

              {/* Detection methods & accuracy (global view only) */}
              {!selectedIP && anomalyData && (
                <div className="mt-2 flex items-center gap-3 text-xs">
                  {anomalyData.current_threshold > 0 && (
                    <span className="text-red-600 dark:text-red-300/80">Z&ge;{anomalyData.current_threshold.toFixed(1)}</span>
                  )}
                  {anomalyData.cusum_active && (
                    <span className="inline-flex items-center rounded-full bg-amber-500/15 px-2 py-0.5 text-amber-600 dark:text-amber-400 font-medium">CUSUM</span>
                  )}
                  {anomalyData.jsd_active && (
                    <span className="inline-flex items-center rounded-full bg-amber-500/15 px-2 py-0.5 text-amber-600 dark:text-amber-400 font-medium">JSD</span>
                  )}
                  {anomalyData.fast_active && (
                    <span className="inline-flex items-center rounded-full bg-amber-500/15 px-2 py-0.5 text-amber-600 dark:text-amber-400 font-medium">Fast</span>
                  )}
                  {anomalyData.tp_rate > 0 && (
                    <span className="text-red-600 dark:text-red-300/80">TP: {anomalyData.tp_rate}%</span>
                  )}
                  {anomalyData.fp_rate > 0 && (
                    <span className="text-red-600 dark:text-red-300/80">FP: {anomalyData.fp_rate}%</span>
                  )}
                  {anomalyData.adaptive_adjustments > 0 && (
                    <span className="text-red-600 dark:text-red-300/80">{anomalyData.adaptive_adjustments} adj</span>
                  )}
                  {anomalyData.sensitivity_preset != null && anomalyData.sensitivity_preset > 0 && (
                    <span className="inline-flex items-center rounded-full bg-slate-500/15 px-2 py-0.5 text-slate-600 dark:text-slate-300 font-medium">
                      {anomalyData.sensitivity_preset === 1 ? 'Strict' : anomalyData.sensitivity_preset === 2 ? 'Moderate' : 'Conservative'}
                    </span>
                  )}
                </div>
              )}
            </div>

            {/* -- Safe content -- */}
            <div
              className={clsx(
                'transition-all duration-500 ease-in-out',
                !isAttack
                  ? 'opacity-100 relative'
                  : 'opacity-0 absolute inset-0 pointer-events-none',
              )}
              aria-hidden={isAttack}
            >
              <div className="flex items-center gap-3 mb-1 pr-40">
                <h1 className="text-lg font-bold text-slate-900 dark:text-white">Protected</h1>
                <StatusIndicator
                  status={isConnected ? 'online' : 'offline'}
                  label={isConnected ? 'DPDK Connected' : 'Disconnected'}
                  size="sm"
                />
              </div>
              <p className="text-sm text-slate-600 dark:text-slate-400">
                {protectedAssetCount > 0
                  ? `All ${protectedAssetCount} assets protected`
                  : 'System operational'}
                {' '}&middot; No active threats
                {' '}&middot; {formatBytes(totalRxBps)}/s clean traffic
                {anomalyData?.current_threshold != null && anomalyData.current_threshold > 0 && (
                  <>{' '}&middot; Z&ge;{anomalyData.current_threshold.toFixed(1)}</>
                )}
              </p>
              {anomalyData?.active && !anomalyData?.mitigation_active && (
                <p className="text-xs text-amber-600 dark:text-amber-400 mt-1">
                  Alert-only: anomaly detected (Z={anomalyData.max_z_score?.toFixed(1)}, {anomalyData.primary_feature_name}) — mitigation suppressed during learning
                </p>
              )}
              {anomalyData && anomalyData.learning_phase_name && anomalyData.learning_phase_name !== 'MATURE' && (
                <p className="text-xs text-amber-600 dark:text-amber-400 mt-1">
                  Learning: {anomalyData.learning_phase_name}
                  {anomalyData.tier1_progress > 0 && anomalyData.tier1_progress < 100 && (
                    <> &middot; Tier 1: {anomalyData.tier1_progress}%</>
                  )}
                  {anomalyData.baseline_age_sec > 0 && (
                    <> &middot; Age: {anomalyData.baseline_age_sec >= 3600
                      ? `${Math.floor(anomalyData.baseline_age_sec / 3600)}h`
                      : `${Math.floor(anomalyData.baseline_age_sec / 60)}m`}</>
                  )}
                </p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default HeroStatusBanner;
