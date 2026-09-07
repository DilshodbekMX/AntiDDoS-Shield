/**
 * Running Configuration Page (Read-Only)
 *
 * Displays the current active configuration for Layer 1 and Layer 2
 * in a read-only format. Allows operators to verify what values are
 * currently applied without accidentally changing anything.
 */

import { useQuery } from '@tanstack/react-query';
import {
  EyeIcon,
  Cog6ToothIcon,
  ArrowTrendingUpIcon,
  ClipboardDocumentIcon,
} from '@heroicons/react/24/outline';
import toast from 'react-hot-toast';
import api from '../services/api';
import { SkeletonCard } from '../components/ui/LoadingSpinner';
import { PageHeader } from '../components/ui';

// ==================== Section metadata ====================

const L1_SECTION_NAMES: Record<string, string> = {
  ip_lists: 'IP List Limits',
  flow_table: 'Flow Table',
  syn_proxy: 'SYN Proxy',
  syn_cookie: 'SYN Cookie',
  connection_limits: 'Connection Limits',
  udp_gatekeeper: 'UDP Gatekeeper',
  rate_limits: 'Rate Limits',
  tcp_flag_rate: 'TCP Flag Rate Limiting',
  tcp_abuse: 'TCP Abuse Detection',
  geo_blocking: 'Geo-Blocking',
  signatures: 'Signatures',
  other_protocols: 'Other Protocols',
  validation: 'Protocol Validation',
  telemetry: 'Telemetry',
  ports: 'Network Ports',
  maintenance: 'Maintenance',
};

// ==================== Helpers ====================

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'boolean') return value ? 'Enabled' : 'Disabled';
  if (typeof value === 'number') return value.toLocaleString();
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) {
    if (value.length === 0) return '(empty)';
    return value.join(', ');
  }
  return JSON.stringify(value);
}

function copyAllToClipboard(l1Config: Record<string, unknown>, l2Config: Record<string, unknown>) {
  const text = [
    '=== Layer 1 Configuration ===',
    JSON.stringify(l1Config, null, 2),
    '',
    '=== Layer 2 Configuration ===',
    JSON.stringify(l2Config, null, 2),
  ].join('\n');

  navigator.clipboard.writeText(text).then(
    () => toast.success('Configuration copied to clipboard'),
    () => toast.error('Failed to copy')
  );
}

// ==================== Sub-Components ====================

function ValueCell({ value }: { value: unknown }) {
  if (typeof value === 'boolean') {
    return (
      <span
        className={
          value
            ? 'inline-flex items-center rounded-full bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-400'
            : 'inline-flex items-center rounded-full bg-slate-500/10 px-2 py-0.5 text-xs font-medium text-slate-500 dark:text-slate-400'
        }
      >
        {value ? 'Enabled' : 'Disabled'}
      </span>
    );
  }
  return <span className="text-sm text-slate-900 dark:text-white font-mono">{formatValue(value)}</span>;
}

interface ConfigSectionProps {
  title: string;
  data: Record<string, unknown>;
}

function ConfigSection({ title, data }: ConfigSectionProps) {
  const entries = Object.entries(data);
  if (entries.length === 0) return null;

  // Separate nested objects from simple values
  const simpleEntries = entries.filter(([, v]) => typeof v !== 'object' || v === null || Array.isArray(v));
  const nestedEntries = entries.filter(([, v]) => typeof v === 'object' && v !== null && !Array.isArray(v));

  return (
    <div className="card overflow-hidden">
      <div className="card-header">
        <h3 className="text-base font-semibold text-slate-900 dark:text-white">{title}</h3>
        <span className="text-xs text-slate-500">{entries.length} fields</span>
      </div>
      <div className="divide-y divide-slate-200 dark:divide-slate-800">
        {simpleEntries.map(([key, value]) => (
          <div key={key} className="flex items-center justify-between px-4 py-2.5">
            <span className="text-sm text-slate-500 dark:text-slate-400">{key}</span>
            <ValueCell value={value} />
          </div>
        ))}
        {nestedEntries.map(([key, value]) => (
          <div key={key} className="px-4 py-2.5">
            <span className="text-sm text-slate-500 dark:text-slate-400 font-medium">{key}</span>
            <div className="mt-1.5 ml-3 space-y-1 border-l border-slate-300 dark:border-slate-700 pl-3">
              {Object.entries(value as Record<string, unknown>).map(([subKey, subValue]) => (
                <div key={subKey} className="flex items-center justify-between">
                  <span className="text-xs text-slate-500">{subKey}</span>
                  <ValueCell value={subValue} />
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ==================== Main Component ====================

export function RunningConfigPage() {
  const { data: l1Config, isLoading: l1Loading } = useQuery({
    queryKey: ['layer1-config-readonly'],
    queryFn: () => api.getLayer1Config(),
    refetchInterval: 30000,
  });

  const { data: l2Config, isLoading: l2Loading } = useQuery({
    queryKey: ['layer2-config-readonly'],
    queryFn: () => api.getLayer2Config(),
    refetchInterval: 30000,
  });

  const isLoading = l1Loading || l2Loading;

  // Organize L1 config by known sections, with fallback for unknown keys
  const l1Sections: { title: string; data: Record<string, unknown> }[] = [];
  const l1TopLevel: Record<string, unknown> = {};

  if (l1Config) {
    for (const [key, value] of Object.entries(l1Config)) {
      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        l1Sections.push({
          title: L1_SECTION_NAMES[key] || key,
          data: value as Record<string, unknown>,
        });
      } else {
        l1TopLevel[key] = value;
      }
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Running Configuration"
        description="Current active values — read-only view"
        icon={EyeIcon}
        iconClassName="text-brand-400"
        actions={
          !isLoading && l1Config && l2Config ? (
            <button onClick={() => copyAllToClipboard(l1Config, l2Config)} className="btn-secondary btn-sm inline-flex items-center gap-2">
              <ClipboardDocumentIcon className="h-4 w-4" />
              Copy All
            </button>
          ) : undefined
        }
      />

      {isLoading ? (
        <div className="grid gap-4 md:grid-cols-2">
          {Array.from({ length: 6 }).map((_, i) => (
            <SkeletonCard key={i} />
          ))}
        </div>
      ) : (
        <>
          {/* Layer 1 */}
          <div>
            <div className="flex items-center gap-2 mb-4">
              <Cog6ToothIcon className="h-5 w-5 text-indigo-400" />
              <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Layer 1 — Packet Processing</h2>
            </div>

            {/* Top-level L1 values (log_level, stats_enabled, etc.) */}
            {Object.keys(l1TopLevel).length > 0 && (
              <div className="mb-4">
                <ConfigSection title="General" data={l1TopLevel} />
              </div>
            )}

            <div className="grid gap-4 md:grid-cols-2">
              {l1Sections.map(({ title, data }) => (
                <ConfigSection key={title} title={title} data={data} />
              ))}
            </div>
          </div>

          {/* Layer 2 */}
          <div>
            <div className="flex items-center gap-2 mb-4">
              <ArrowTrendingUpIcon className="h-5 w-5 text-amber-400" />
              <h2 className="text-lg font-semibold text-slate-900 dark:text-white">Layer 2 — Anomaly Detection</h2>
            </div>

            {l2Config && (
              <div className="grid gap-4 md:grid-cols-2">
                <ConfigSection
                  title="Detection Parameters"
                  data={l2Config as Record<string, unknown>}
                />
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

export default RunningConfigPage;
