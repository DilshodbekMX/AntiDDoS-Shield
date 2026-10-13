/**
 * Attack Status Component
 */

import { memo } from 'react';
import { clsx } from 'clsx';
import { format } from 'date-fns';
import {
  ExclamationTriangleIcon,
  ShieldCheckIcon,
  ClockIcon,
} from '@heroicons/react/24/outline';
import { Attack, AttackSeverity, AttackType } from '../../types';
import { formatBytes, formatNumber } from '../../utils/formatting';

interface AttackStatusProps {
  attacks: Attack[];
  loading?: boolean;
  /** Number of protected assets for the current view */
  protectedAssetCount?: number;
}

const attackTypeLabels: Record<AttackType, string> = {
  [AttackType.UNKNOWN]: 'Unknown',
  [AttackType.SYN_FLOOD]: 'SYN Flood',
  [AttackType.UDP_FLOOD]: 'UDP Flood',
  [AttackType.ICMP_FLOOD]: 'ICMP Flood',
  [AttackType.DNS_AMPLIFICATION]: 'DNS Amplification',
  [AttackType.NTP_AMPLIFICATION]: 'NTP Amplification',
  [AttackType.MEMCACHED_AMPLIFICATION]: 'Memcached Amplification',
  [AttackType.HTTP_FLOOD]: 'HTTP Flood',
  [AttackType.SLOWLORIS]: 'Slowloris',
  [AttackType.ACK_FLOOD]: 'ACK Flood',
  [AttackType.RST_FLOOD]: 'RST Flood',
  [AttackType.FIN_FLOOD]: 'FIN Flood',
  [AttackType.FRAGMENT_FLOOD]: 'Fragment Flood',
  [AttackType.CARPET_BOMB]: 'Carpet Bombing',
  [AttackType.VOLUMETRIC]: 'Volumetric Attack',
  [AttackType.APPLICATION]: 'Application Layer',
};

export const AttackStatus = memo(function AttackStatus({ attacks, loading = false, protectedAssetCount = 0 }: AttackStatusProps) {
  if (loading) {
    return (
      <div className="card h-full">
        <div className="card-header">
          <h3 className="card-title">Attack Status</h3>
        </div>
        <div className="p-6">
          <div className="animate-pulse space-y-4">
            <div className="h-4 bg-slate-200 dark:bg-slate-700 rounded w-1/4"></div>
            <div className="h-20 bg-slate-200 dark:bg-slate-700 rounded"></div>
          </div>
        </div>
      </div>
    );
  }

  const activeAttacks = attacks.filter((a) => a.is_active);

  if (activeAttacks.length === 0) {
    return (
      <div className="card h-full">
        <div className="card-header">
          <h3 className="card-title">Attack Status</h3>
          <span className="badge-success text-2xs">Protected</span>
        </div>
        <div className="flex flex-col items-center justify-center py-12 px-6 text-center">
          <div className="h-14 w-14 rounded-full bg-emerald-500/10 flex items-center justify-center mb-4">
            <ShieldCheckIcon className="h-8 w-8 text-emerald-400" />
          </div>
          <h4 className="text-base font-semibold text-slate-900 dark:text-white mb-1">All Clear</h4>
          <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
            {protectedAssetCount > 0
              ? `No active attacks detected. All ${protectedAssetCount} protected assets are operating normally.`
              : 'No active attacks detected. Your system is monitoring for threats.'}
          </p>
          <a href="/attack-history" className="text-xs text-brand-400 hover:text-brand-300 transition-colors">
            View attack history &rarr;
          </a>
        </div>
      </div>
    );
  }

  return (
    <div className="card h-full">
      <div className="card-header">
        <div className="flex items-center gap-2">
          <ExclamationTriangleIcon className="h-5 w-5 text-red-400" />
          <h3 className="card-title">
            Active Attacks ({activeAttacks.length})
          </h3>
        </div>
      </div>

      <ul className="divide-y divide-slate-200 dark:divide-slate-800">
        {activeAttacks.map((attack) => (
          <li key={attack.id} className="p-4">
            <div className="flex items-start justify-between">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span
                    className={clsx(
                      'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium',
                      attack.severity === AttackSeverity.CRITICAL && 'badge-critical',
                      attack.severity === AttackSeverity.HIGH && 'badge-danger',
                      attack.severity === AttackSeverity.MEDIUM && 'badge-warning',
                      attack.severity === AttackSeverity.LOW && 'badge-info',
                    )}
                  >
                    {attack.severity.toUpperCase()}
                  </span>
                  <span className="text-sm font-medium text-slate-900 dark:text-white">
                    {attackTypeLabels[attack.attack_type] || attack.attack_type}
                  </span>
                  {attack.spoofed_mode && (
                    <span className="badge-neutral text-2xs">Spoofed</span>
                  )}
                  {attack.rate_limit_pct != null && attack.rate_limit_pct < 100 && (
                    <span className="badge-info text-2xs">Rate {attack.rate_limit_pct}%</span>
                  )}
                  {attack.cusum_triggered && (
                    <span className="badge-warning text-2xs">CUSUM</span>
                  )}
                  {attack.jsd_triggered && (
                    <span className="badge-warning text-2xs">JSD</span>
                  )}
                  {attack.fast_triggered && (
                    <span className="badge-warning text-2xs">Fast</span>
                  )}
                  {attack.sensitivity_preset != null && attack.sensitivity_preset > 0 && (
                    <span className="badge-neutral text-2xs">
                      {attack.sensitivity_preset === 1 ? 'Strict' : attack.sensitivity_preset === 2 ? 'Moderate' : 'Conservative'}
                    </span>
                  )}
                </div>

                <div className="mt-2 space-y-1.5 text-sm">
                  <div className="flex items-center gap-4">
                    <div>
                      <span className="text-slate-500">Target: </span>
                      <span className="font-mono text-slate-900 dark:text-white">
                        {attack.target_ip}
                        {attack.target_port ? `:${attack.target_port}` : ''}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500">Sources: </span>
                      <span className="text-slate-900 dark:text-white">
                        {formatNumber(attack.source_ips_count)} IPs
                      </span>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-x-4 gap-y-1">
                    <div>
                      <span className="text-slate-500">Peak: </span>
                      <span className="text-slate-900 dark:text-white">{formatBytes(attack.peak_bps)}/s</span>
                    </div>
                    <div>
                      <span className="text-slate-500">PPS: </span>
                      <span className="text-slate-900 dark:text-white">{formatNumber(attack.peak_pps)} pps</span>
                    </div>
                  </div>
                </div>

                <div className="mt-2 flex items-center gap-3 text-xs text-slate-500">
                  <div className="flex items-center gap-1">
                    <ClockIcon className="h-3.5 w-3.5" />
                    {(() => {
                      try {
                        const date = new Date(attack.started_at);
                        if (!isNaN(date.getTime())) {
                          return `Started ${format(date, 'HH:mm:ss')}`;
                        }
                      } catch {
                        // Fall through
                      }
                      return 'Started --:--:--';
                    })()}
                  </div>
                  {attack.duration_seconds != null && attack.duration_seconds > 0 && (
                    <span>
                      Duration: {attack.duration_seconds >= 3600
                        ? `${Math.floor(attack.duration_seconds / 3600)}h ${Math.floor((attack.duration_seconds % 3600) / 60)}m`
                        : attack.duration_seconds >= 60
                          ? `${Math.floor(attack.duration_seconds / 60)}m ${Math.floor(attack.duration_seconds % 60)}s`
                          : `${Math.floor(attack.duration_seconds)}s`}
                    </span>
                  )}
                  {attack.confidence_pct != null && attack.confidence_pct > 0 ? (
                    <span>Confidence: {attack.confidence_pct}%</span>
                  ) : attack.ml_confidence != null ? (
                    <span>Confidence: {attack.ml_confidence}%</span>
                  ) : null}
                  {attack.spoofed_mode && attack.randomness_pct != null && attack.randomness_pct > 0 && (
                    <span>Randomness: {attack.randomness_pct}%</span>
                  )}
                  {attack.peak_z_feature_name && (
                    <span>Peak: {attack.peak_z_feature_name}</span>
                  )}
                  {attack.cool_down_remaining_sec != null && attack.cool_down_remaining_sec > 0 && (
                    <span>Cool-down: {attack.cool_down_remaining_sec}s</span>
                  )}
                  {attack.learning_phase != null && attack.learning_phase < 3 && (
                    <span className="text-amber-500">
                      {attack.learning_phase === 0 ? 'Cold' : attack.learning_phase === 1 ? 'Warming' : 'Moderate'}
                    </span>
                  )}
                </div>
              </div>

              <div className="ml-4 flex-shrink-0">
                {attack.mitigated ? (
                  <span className="badge-success text-2xs">Mitigated</span>
                ) : (
                  <span className="badge-danger text-2xs animate-pulse">Active</span>
                )}
              </div>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
});

export default AttackStatus;
