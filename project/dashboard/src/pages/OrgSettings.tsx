/**
 * Organization Settings Page
 *
 * Organization info, protected networks, alerting, and infrastructure config.
 * Reads/writes config/single_org_config.json via the /org/settings API.
 */

import { useState, useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  BuildingOfficeIcon,
  GlobeAltIcon,
  BellAlertIcon,
  ClockIcon,
  PlusIcon,
  TrashIcon,
} from '@heroicons/react/24/outline';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import api from '../services/api';
import { SkeletonCard } from '../components/ui/LoadingSpinner';
import {
  Toggle,
  NumberInput,
  SelectInput,
  SectionCard,
  FieldRow,
} from '../components/ui/FormControls';
import { useTimezoneStore, TIMEZONE_OPTIONS } from '../store/timezoneStore';

type TabKey = 'organization' | 'networks' | 'infrastructure';

export function OrgSettingsPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabKey>('organization');

  const { data: settings, isLoading } = useQuery({
    queryKey: ['org-settings'],
    queryFn: () => api.getOrgSettings(),
  });

  const org = (settings?.organization ?? {}) as Record<string, string>;
  const telemetry = (settings?.telemetry ?? {}) as Record<string, Record<string, unknown>>;
  const alerting = (settings?.alerting ?? {}) as Record<string, unknown>;

  const tabs = [
    { key: 'organization' as TabKey, label: 'Organization', icon: BuildingOfficeIcon },
    { key: 'networks' as TabKey, label: 'Protected Networks', icon: GlobeAltIcon },
    { key: 'infrastructure' as TabKey, label: 'Infrastructure', icon: BellAlertIcon },
  ];

  if (isLoading) {
    return (
      <div className="space-y-4">
        <SkeletonCard lines={4} />
        <SkeletonCard lines={6} />
      </div>
    );
  }

  return (
    <div className="space-y-4 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Organization Settings</h1>
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
          Configure organization info, protected networks, alerting, and telemetry
        </p>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="-mb-px flex space-x-4 sm:space-x-8 overflow-x-auto">
          {tabs.map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={clsx(
                'flex items-center gap-2 py-4 px-1 border-b-2 font-medium text-sm whitespace-nowrap',
                activeTab === tab.key
                  ? 'border-brand-500 text-brand-600 dark:text-brand-400'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              )}
            >
              <tab.icon className="h-5 w-5" />
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {activeTab === 'organization' && (
        <OrganizationTab org={org} queryClient={queryClient} />
      )}
      {activeTab === 'networks' && (
        <NetworksTab queryClient={queryClient} />
      )}
      {activeTab === 'infrastructure' && (
        <InfrastructureTab
          alerting={alerting}
          telemetry={telemetry}
          queryClient={queryClient}
        />
      )}
    </div>
  );
}

// ==================== Organization Tab ====================

function OrganizationTab({
  org,
  queryClient,
}: {
  org: Record<string, string>;
  queryClient: ReturnType<typeof useQueryClient>;
}) {
  const [name, setName] = useState(org.name ?? '');
  const [email, setEmail] = useState(org.contact_email ?? '');
  const [webhook, setWebhook] = useState(org.alert_webhook ?? '');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setName(org.name ?? '');
    setEmail(org.contact_email ?? '');
    setWebhook(org.alert_webhook ?? '');
  }, [org.name, org.contact_email, org.alert_webhook]);

  const isDirty =
    name !== (org.name ?? '') ||
    email !== (org.contact_email ?? '') ||
    webhook !== (org.alert_webhook ?? '');

  const save = async () => {
    setSaving(true);
    try {
      await api.updateOrganization({ name, contact_email: email, alert_webhook: webhook });
      queryClient.invalidateQueries({ queryKey: ['org-settings'] });
      toast.success('Organization info saved');
    } catch {
      toast.error('Failed to save organization info');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4">
      <SectionCard title="Organization Info" description="Basic organization details used in alerts and reports">
        <div className="space-y-4">
          <FieldRow label="Organization Name" description="Display name for this deployment">
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full max-w-md px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-md text-sm"
              placeholder="Your Organization"
            />
          </FieldRow>
          <FieldRow label="Contact Email" description="Primary contact for security alerts">
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full max-w-md px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-md text-sm"
              placeholder="security@example.com"
            />
          </FieldRow>
          <FieldRow label="Alert Webhook URL" description="URL to receive attack notifications via HTTP POST">
            <input
              type="url"
              value={webhook}
              onChange={(e) => setWebhook(e.target.value)}
              className="w-full max-w-md px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-md text-sm"
              placeholder="https://hooks.slack.com/services/..."
            />
          </FieldRow>
          <div className="flex items-center gap-3 pt-2">
            {isDirty && (
              <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400">
                Unsaved changes
              </span>
            )}
            <button
              onClick={save}
              disabled={!isDirty || saving}
              className={clsx('btn btn-sm', isDirty ? 'btn-primary' : 'btn-secondary opacity-50')}
            >
              {saving ? 'Saving...' : 'Save'}
            </button>
          </div>
        </div>
      </SectionCard>

      <TimezoneCard />
    </div>
  );
}

// ==================== Timezone Card ====================

function TimezoneCard() {
  const { timezone, setTimezone, getOffsetHours } = useTimezoneStore();
  const browserOffset = -new Date().getTimezoneOffset() / 60;
  const effectiveOffset = getOffsetHours();
  const sign = effectiveOffset >= 0 ? '+' : '';

  return (
    <SectionCard
      title="Timezone"
      description="Timezone used for baseline charts, hourly grids, and weekly heatmaps. Stored locally in your browser."
    >
      <div className="space-y-4">
        <FieldRow label="Display Timezone" description="Controls how UTC-indexed baseline data is displayed on charts">
          <div className="flex items-center gap-3">
            <ClockIcon className="h-5 w-5 text-slate-400 flex-shrink-0" />
            <select
              value={timezone}
              onChange={(e) => setTimezone(e.target.value)}
              className="w-full max-w-xs px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-md text-sm"
            >
              {TIMEZONE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.value === 'auto'
                    ? `Auto (browser: UTC${browserOffset >= 0 ? '+' : ''}${browserOffset})`
                    : opt.label}
                </option>
              ))}
            </select>
          </div>
        </FieldRow>
        <div className="text-xs text-slate-500 dark:text-slate-400">
          Effective offset: <span className="font-mono font-medium text-slate-700 dark:text-slate-300">UTC{sign}{effectiveOffset}</span>
          {' '}&mdash; baseline hour 0 on charts = midnight in this timezone
        </div>
      </div>
    </SectionCard>
  );
}

// ==================== Networks Tab ====================

function NetworksTab({ queryClient }: { queryClient: ReturnType<typeof useQueryClient> }) {
  const { data, isLoading } = useQuery({
    queryKey: ['org-networks'],
    queryFn: () => api.getProtectedNetworks(),
  });

  const [networks, setNetworks] = useState<Array<{ network: string; description: string }>>([]);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (data?.networks) {
      setNetworks([...data.networks]);
      setDirty(false);
    }
  }, [data]);

  const addNetwork = () => {
    setNetworks([...networks, { network: '', description: '' }]);
    setDirty(true);
  };

  const removeNetwork = (index: number) => {
    setNetworks(networks.filter((_, i) => i !== index));
    setDirty(true);
  };

  const updateNetwork = (index: number, field: 'network' | 'description', value: string) => {
    setNetworks(networks.map((n, i) => i === index ? { ...n, [field]: value } : n));
    setDirty(true);
  };

  const save = async () => {
    // Validate CIDR format
    const cidrPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/;
    const invalid = networks.filter(n => n.network && !cidrPattern.test(n.network));
    if (invalid.length > 0) {
      toast.error('Invalid CIDR format. Use format like 192.168.1.0/24');
      return;
    }

    const validNetworks = networks.filter(n => n.network.trim());
    setSaving(true);
    try {
      await api.updateProtectedNetworks(validNetworks);
      queryClient.invalidateQueries({ queryKey: ['org-networks'] });
      queryClient.invalidateQueries({ queryKey: ['org-settings'] });
      toast.success(`Saved ${validNetworks.length} protected networks`);
      setDirty(false);
    } catch {
      toast.error('Failed to save networks');
    } finally {
      setSaving(false);
    }
  };

  if (isLoading) return <SkeletonCard lines={4} />;

  return (
    <SectionCard title="Protected Networks" description="CIDR ranges to protect from DDoS attacks">
      <div className="space-y-3">
        {networks.map((net, i) => (
          <div key={i} className="flex items-center gap-3">
            <input
              type="text"
              value={net.network}
              onChange={(e) => updateNetwork(i, 'network', e.target.value)}
              placeholder="203.0.113.0/24"
              className="w-48 px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-md text-sm font-mono"
            />
            <input
              type="text"
              value={net.description}
              onChange={(e) => updateNetwork(i, 'description', e.target.value)}
              placeholder="Description"
              className="flex-1 px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-md text-sm"
            />
            <button
              onClick={() => removeNetwork(i)}
              className="p-2 text-red-500 hover:text-red-700 hover:bg-red-50 dark:hover:bg-red-900/20 rounded"
            >
              <TrashIcon className="h-4 w-4" />
            </button>
          </div>
        ))}

        <div className="flex items-center gap-3 pt-2">
          <button onClick={addNetwork} className="btn btn-sm btn-secondary inline-flex items-center gap-1">
            <PlusIcon className="h-4 w-4" />
            Add Network
          </button>
          {dirty && (
            <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400">
              Unsaved changes
            </span>
          )}
          <button
            onClick={save}
            disabled={!dirty || saving}
            className={clsx('btn btn-sm', dirty ? 'btn-primary' : 'btn-secondary opacity-50')}
          >
            {saving ? 'Saving...' : 'Save Networks'}
          </button>
        </div>
      </div>
    </SectionCard>
  );
}

// ==================== Infrastructure Tab ====================

function InfrastructureTab({
  alerting,
  telemetry,
  queryClient,
}: {
  alerting: Record<string, unknown>;
  telemetry: Record<string, Record<string, unknown>>;
  queryClient: ReturnType<typeof useQueryClient>;
}) {
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['org-settings'] });

  const saveAlerting = async (key: string, value: unknown) => {
    try {
      const updated = { ...alerting, [key]: value };
      await api.updateAlertingConfig(updated);
      invalidate();
      toast.success('Alerting updated');
    } catch {
      toast.error('Failed to update alerting');
    }
  };

  const prom = (telemetry?.prometheus ?? {}) as Record<string, unknown>;
  const logging = (telemetry?.logging ?? {}) as Record<string, unknown>;

  const savePrometheus = async (key: string, value: unknown) => {
    try {
      const updated = {
        enabled: prom.enabled ?? true,
        port: prom.port ?? 9090,
        path: prom.path ?? '/metrics',
        [key]: value,
      } as { enabled: boolean; port: number; path: string };
      await api.updatePrometheusConfig(updated);
      invalidate();
      toast.success('Prometheus config updated');
    } catch {
      toast.error('Failed to update Prometheus config');
    }
  };

  const saveLogging = async (key: string, value: unknown) => {
    try {
      const updated = {
        level: logging.level ?? 'info',
        path: logging.path ?? 'logs/antiddos.log',
        max_size_mb: logging.max_size_mb ?? 100,
        max_files: logging.max_files ?? 10,
        [key]: value,
      } as { level: string; path: string; max_size_mb: number; max_files: number };
      await api.updateLoggingConfig(updated);
      invalidate();
      toast.success('Logging config updated');
    } catch {
      toast.error('Failed to update logging config');
    }
  };

  return (
    <div className="space-y-4">
      {/* Alerting */}
      <SectionCard title="Alerting" description="Attack alert notification settings" collapsible>
        <div className="space-y-3">
          <FieldRow label="Alerting Enabled" description="Send alert notifications for detected attacks">
            <Toggle
              enabled={!!(alerting.enabled ?? true)}
              onChange={(v) => saveAlerting('enabled', v)}
              label="Enable alerting"
            />
          </FieldRow>
          <FieldRow label="Throttle (seconds)" description="Minimum interval between repeat alerts for the same attack">
            <NumberInput
              value={(alerting.throttle_sec as number) ?? 60}
              min={1}
              max={3600}
              onChange={(v) => saveAlerting('throttle_sec', v)}
            />
          </FieldRow>
          <FieldRow label="Alert on Attack Start" description="Send notification when a new attack is detected">
            <Toggle
              enabled={!!(alerting.attack_start ?? true)}
              onChange={(v) => saveAlerting('attack_start', v)}
              label="Attack start alerts"
            />
          </FieldRow>
          <FieldRow label="Alert on Attack End" description="Send notification when an attack subsides">
            <Toggle
              enabled={!!(alerting.attack_end ?? true)}
              onChange={(v) => saveAlerting('attack_end', v)}
              label="Attack end alerts"
            />
          </FieldRow>
          <FieldRow label="Severity Threshold" description="Minimum anomaly level to trigger alerts">
            <SelectInput
              value={String(alerting.severity_threshold ?? 2)}
              options={[
                { value: '0', label: 'None (all events)' },
                { value: '1', label: 'Low' },
                { value: '2', label: 'Medium' },
                { value: '3', label: 'High' },
                { value: '4', label: 'Critical' },
              ]}
              onChange={(v) => saveAlerting('severity_threshold', Number(v))}
            />
          </FieldRow>
        </div>
      </SectionCard>

      {/* Prometheus */}
      <SectionCard title="Prometheus" description="Metrics exporter configuration" collapsible>
        <div className="space-y-3">
          <FieldRow label="Enabled" description="Export metrics for Prometheus scraping">
            <Toggle
              enabled={!!(prom.enabled ?? true)}
              onChange={(v) => savePrometheus('enabled', v)}
              label="Enable Prometheus"
            />
          </FieldRow>
          <FieldRow label="Port" description="TCP port for the metrics endpoint">
            <NumberInput
              value={(prom.port as number) ?? 9090}
              min={1024}
              max={65535}
              onChange={(v) => savePrometheus('port', v)}
            />
          </FieldRow>
          <FieldRow label="Path" description="HTTP path for the metrics endpoint">
            <input
              type="text"
              value={(prom.path as string) ?? '/metrics'}
              onChange={(e) => savePrometheus('path', e.target.value)}
              className="w-48 px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-md text-sm font-mono"
            />
          </FieldRow>
        </div>
      </SectionCard>

      {/* Logging */}
      <SectionCard title="Logging" description="Application log settings" collapsible>
        <div className="space-y-3">
          <FieldRow label="Log Level" description="Minimum severity level to log">
            <SelectInput
              value={(logging.level as string) ?? 'info'}
              options={[
                { value: 'debug', label: 'Debug' },
                { value: 'info', label: 'Info' },
                { value: 'warn', label: 'Warning' },
                { value: 'error', label: 'Error' },
              ]}
              onChange={(v) => saveLogging('level', v)}
            />
          </FieldRow>
          <FieldRow label="Log Path" description="File path for log output">
            <input
              type="text"
              value={(logging.path as string) ?? 'logs/antiddos.log'}
              onChange={(e) => saveLogging('path', e.target.value)}
              className="w-full max-w-md px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-md text-sm font-mono"
            />
          </FieldRow>
          <FieldRow label="Max Log Size (MB)" description="Maximum size per log file before rotation">
            <NumberInput
              value={(logging.max_size_mb as number) ?? 100}
              min={1}
              max={10000}
              onChange={(v) => saveLogging('max_size_mb', v)}
            />
          </FieldRow>
          <FieldRow label="Max Log Files" description="Number of rotated log files to keep">
            <NumberInput
              value={(logging.max_files as number) ?? 10}
              min={1}
              max={100}
              onChange={(v) => saveLogging('max_files', v)}
            />
          </FieldRow>
        </div>
      </SectionCard>

      {/* Telemetry Forwarding */}
      <TelemetryForwardingCard queryClient={queryClient} />
    </div>
  );
}

// ==================== Telemetry Forwarding Card ====================

function TelemetryForwardingCard({ queryClient }: { queryClient: ReturnType<typeof useQueryClient> }) {
  const { data: fwdConfig, isLoading: fwdLoading } = useQuery({
    queryKey: ['forwarding-config'],
    queryFn: () => api.getForwardingConfig(),
  });

  const { data: ifacesData } = useQuery({
    queryKey: ['network-interfaces'],
    queryFn: () => api.getNetworkInterfaces(),
  });

  const [enabled, setEnabled] = useState(false);
  const [bindIp, setBindIp] = useState('');
  const [destIp, setDestIp] = useState('');
  const [destPort, setDestPort] = useState(9999);
  const [protocol, setProtocol] = useState('tcp');
  const [intervalMs, setIntervalMs] = useState(500);
  const [streams, setStreams] = useState({
    stats: true,
    traffic: true,
    anomaly: true,
    per_ip_features: true,
    sysmon: false,
  });
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);

  const { data: fwdStatus } = useQuery({
    queryKey: ['forwarding-status'],
    queryFn: () => api.getForwardingStatus(),
    refetchInterval: enabled ? 2000 : false,
  });

  useEffect(() => {
    if (fwdConfig) {
      setEnabled(fwdConfig.enabled ?? false);
      setBindIp(fwdConfig.bind_ip ?? '');
      setDestIp(fwdConfig.dest_ip ?? '');
      setDestPort(fwdConfig.dest_port ?? 9999);
      setProtocol(fwdConfig.protocol ?? 'tcp');
      setIntervalMs(fwdConfig.interval_ms ?? 500);
      setStreams(fwdConfig.streams ?? { stats: true, traffic: true, anomaly: true, per_ip_features: true, sysmon: false });
      setDirty(false);
    }
  }, [fwdConfig]);

  const interfaces = ifacesData?.interfaces ?? [];

  const update = <T,>(setter: (v: T) => void) => (v: T) => {
    setter(v);
    setDirty(true);
  };

  const updateStream = (key: string, value: boolean) => {
    setStreams((prev) => ({ ...prev, [key]: value }));
    setDirty(true);
  };

  const save = async () => {
    if (!destIp && enabled) {
      toast.error('Destination IP is required when forwarding is enabled');
      return;
    }
    setSaving(true);
    try {
      await api.updateForwardingConfig({
        enabled,
        bind_ip: bindIp,
        dest_ip: destIp,
        dest_port: destPort,
        protocol,
        streams,
        interval_ms: intervalMs,
      });
      queryClient.invalidateQueries({ queryKey: ['forwarding-config'] });
      queryClient.invalidateQueries({ queryKey: ['org-settings'] });
      toast.success(enabled ? 'Telemetry forwarding enabled' : 'Telemetry forwarding saved');
      setDirty(false);
    } catch {
      toast.error('Failed to save forwarding config');
    } finally {
      setSaving(false);
    }
  };

  if (fwdLoading) return <SkeletonCard lines={6} />;

  return (
    <SectionCard
      title="Telemetry Forwarding"
      description="Forward real-time telemetry data to a remote receiver over TCP or UDP"
      collapsible
    >
      <div className="space-y-4">
        <FieldRow label="Enable Forwarding" description="Start sending telemetry to the configured remote destination">
          <Toggle enabled={enabled} onChange={update(setEnabled)} label="Enable forwarding" />
        </FieldRow>

        {/* Live forwarding status */}
        {enabled && fwdStatus && (
          <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50 p-4">
            <div className="flex items-center gap-2 mb-3">
              <span className={clsx(
                'h-2.5 w-2.5 rounded-full',
                fwdStatus.connected_to_remote ? 'bg-emerald-500 animate-pulse' : fwdStatus.enabled ? 'bg-amber-500' : 'bg-slate-400'
              )} />
              <span className="text-sm font-medium text-gray-800 dark:text-gray-200">
                {fwdStatus.connected_to_remote ? 'Connected' : fwdStatus.enabled ? 'Connecting...' : 'Inactive'}
              </span>
              {fwdStatus.dest_ip && (
                <span className="text-xs text-gray-500 dark:text-gray-400 font-mono">
                  → {fwdStatus.dest_ip}:{fwdStatus.dest_port}/{fwdStatus.protocol}
                </span>
              )}
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div>
                <div className="text-[10px] uppercase tracking-wider text-gray-500 dark:text-gray-400">Packets Sent</div>
                <div className="text-sm font-mono font-semibold text-gray-900 dark:text-gray-100">
                  {(fwdStatus.packets_sent ?? 0).toLocaleString()}
                </div>
              </div>
              <div>
                <div className="text-[10px] uppercase tracking-wider text-gray-500 dark:text-gray-400">Bytes Sent</div>
                <div className="text-sm font-mono font-semibold text-gray-900 dark:text-gray-100">
                  {fwdStatus.bytes_sent != null && fwdStatus.bytes_sent > 1048576
                    ? `${(fwdStatus.bytes_sent / 1048576).toFixed(1)} MB`
                    : fwdStatus.bytes_sent != null && fwdStatus.bytes_sent > 1024
                      ? `${(fwdStatus.bytes_sent / 1024).toFixed(1)} KB`
                      : `${fwdStatus.bytes_sent ?? 0} B`}
                </div>
              </div>
              <div>
                <div className="text-[10px] uppercase tracking-wider text-gray-500 dark:text-gray-400">Last Send</div>
                <div className="text-sm font-mono font-semibold text-gray-900 dark:text-gray-100">
                  {fwdStatus.last_send_ago_sec != null ? `${fwdStatus.last_send_ago_sec}s ago` : '—'}
                </div>
              </div>
              <div>
                <div className="text-[10px] uppercase tracking-wider text-gray-500 dark:text-gray-400">Errors</div>
                <div className={clsx(
                  'text-sm font-mono font-semibold',
                  (fwdStatus.send_errors ?? 0) > 0 ? 'text-red-600 dark:text-red-400' : 'text-gray-900 dark:text-gray-100'
                )}>
                  {(fwdStatus.send_errors ?? 0).toLocaleString()}
                </div>
              </div>
            </div>

            {/* Socket connection indicators */}
            <div className="flex items-center gap-4 mt-3 pt-3 border-t border-slate-200 dark:border-slate-700">
              <div className="flex items-center gap-1.5">
                <span className={clsx('h-1.5 w-1.5 rounded-full', fwdStatus.connected_to_remote ? 'bg-emerald-500' : 'bg-red-400')} />
                <span className="text-[11px] text-gray-600 dark:text-gray-400">Remote</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className={clsx('h-1.5 w-1.5 rounded-full', fwdStatus.connected_to_stats ? 'bg-emerald-500' : 'bg-red-400')} />
                <span className="text-[11px] text-gray-600 dark:text-gray-400">Stats socket</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className={clsx('h-1.5 w-1.5 rounded-full', fwdStatus.connected_to_traffic ? 'bg-emerald-500' : 'bg-red-400')} />
                <span className="text-[11px] text-gray-600 dark:text-gray-400">Traffic socket</span>
              </div>
            </div>

            {/* Last error */}
            {fwdStatus.last_error && (
              <div className="mt-2 text-xs text-red-600 dark:text-red-400 font-mono truncate" title={fwdStatus.last_error}>
                {fwdStatus.last_error}
              </div>
            )}
          </div>
        )}

        <FieldRow label="Bind Interface" description="Local network interface to send from (use 'all' for 0.0.0.0)">
          <SelectInput
            value={bindIp}
            options={[
              { value: '', label: 'Auto (OS default)' },
              ...interfaces.map((iface) => ({
                value: iface.ip,
                label: `${iface.name} (${iface.ip})`,
              })),
            ]}
            onChange={update(setBindIp)}
          />
        </FieldRow>

        <FieldRow label="Destination IP" description="Remote IP address to forward telemetry to">
          <input
            type="text"
            value={destIp}
            onChange={(e) => { setDestIp(e.target.value); setDirty(true); }}
            placeholder="192.168.1.100"
            className="w-48 px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-md text-sm font-mono"
          />
        </FieldRow>

        <FieldRow label="Destination Port" description="Remote port number">
          <NumberInput
            value={destPort}
            min={1}
            max={65535}
            onChange={update(setDestPort)}
          />
        </FieldRow>

        <FieldRow label="Protocol" description="Transport protocol for forwarding">
          <SelectInput
            value={protocol}
            options={[
              { value: 'tcp', label: 'TCP (reliable, ordered)' },
              { value: 'udp', label: 'UDP (low latency, fire-and-forget)' },
            ]}
            onChange={update(setProtocol)}
          />
        </FieldRow>

        <FieldRow label="Interval (ms)" description="How often to forward data (100-10000ms)">
          <NumberInput
            value={intervalMs}
            min={100}
            max={10000}
            onChange={update(setIntervalMs)}
          />
        </FieldRow>

        {/* Stream selection */}
        <div className="border-t border-gray-200 dark:border-gray-700 pt-4">
          <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">Data Streams</h4>
          <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">
            Select which telemetry streams to forward. Each stream sends binary packed structs at the configured interval.
          </p>
          <div className="grid grid-cols-1 gap-3">
            {([
              {
                key: 'stats',
                label: 'Port Statistics',
                magic: '0x44504B53 (DPKS)',
                size: '~720 bytes',
                interval: '500ms',
                mode: 'Aggregated snapshot',
                desc: 'Aggregated NIC counters summed across all DPDK lcores. NOT per-packet — one snapshot every 500ms with cumulative totals and computed PPS/BPS rates from delta since last send.',
                fields: [
                  'rx_packets / tx_packets — cumulative packet counters (all lcores summed)',
                  'rx_bytes / tx_bytes — cumulative byte counters',
                  'rx_pps / tx_pps — computed rate: (current - previous) * 1000 / delta_ms',
                  'rx_bps / tx_bps — computed rate: (byte_diff * 8 * 1000) / delta_ms',
                  'dropped — cumulative drops across all lcores',
                  'drops_by_reason[13] — cumulative per-reason: Validation, Blacklist, RateLimit, SynFlood, Reputation, Policy, ProxyError, GeoBlocked, Signature, OtherProto, SpoofedTCP, ProtoBlocked, ProtoRateLimit',
                ],
              },
              {
                key: 'traffic',
                label: 'Traffic Samples',
                magic: '0x5452464B (TRFK)',
                size: '~3,216 bytes',
                interval: '100ms',
                mode: 'Sampled (ring buffer)',
                desc: 'Sampled packet headers from the DPDK fast path. Every processed packet enqueues into a lock-free ring buffer (size 400). Every 100ms, up to 100 entries are drained and sent. At high PPS the ring overflows — this is best-effort sampling, NOT a full packet capture. Overflow count tracked via drop_count atomic counter.',
                fields: [
                  'src_ip / dst_ip — source and destination IPv4 (host byte order)',
                  'src_port / dst_port — transport layer ports (TCP/UDP only)',
                  'protocol — IP next_proto_id (TCP=6, UDP=17, ICMP=1)',
                  'flags — TCP flags byte (SYN=0x02, ACK=0x10, RST=0x04, FIN=0x01, PSH=0x08)',
                  'pkt_len — total packet length from rte_mbuf.pkt_len',
                  'port_id — DPDK NIC port index (0-based)',
                  'direction — 0=RX (ingress from wire), 1=TX (egress forwarded)',
                  'timestamp_ms — gettimeofday() at capture time',
                  'Ring overflow: at >4,000 pps the 400-slot ring may overflow; excess packets are silently dropped (tracked in drop_count)',
                ],
              },
              {
                key: 'anomaly',
                label: 'Anomaly Detection',
                magic: '0x414E4F4D (ANOM)',
                size: '~280 bytes',
                interval: '1s',
                mode: 'Snapshot (global singleton)',
                desc: 'Global Layer 2 detection engine state — single struct, NOT per-packet. Reads the L2 anomaly state machine, baseline readiness, adaptive threshold, learning phase, and detection method status. Sent every 1s (every 2 stats loops).',
                fields: [
                  'active / level — current anomaly state (0=none, 1=low, 2=medium, 3=high, 4=critical)',
                  'max_z_score — peak Z-score across all features and tiers',
                  'confidence — detection confidence (0.0-1.0) from multi-tier agreement',
                  'tier_agreement — number of baseline tiers (1s/10s/60s) that agree on anomaly',
                  'primary_feature — feature index with highest Z-score deviation',
                  'start_time_ns / duration_sec — when anomaly started, how long active',
                  'cool_down_remaining — seconds remaining before re-detection allowed',
                  'baselines_frozen / tier1_ready / tier2_ready_count / tier3_ready_count — baseline maturity',
                  'baseline_updates / detection_cycles / detection_count — lifetime counters',
                  'packets_per_sec / bytes_per_sec / syn_per_sec — current global traffic rates (seqlock-protected)',
                  'unique_src_ips / unique_flows / heavy_hitters — cardinality from HyperLogLog/CMS',
                  'rate_limit_pct — Layer 1 rate limit enforcement level (100=normal, 50=half, 0=block)',
                  'current_threshold — adaptive Z-score threshold (auto-tuned between 4.0-10.0)',
                  'learning_phase — COLD→WARMING→MODERATE→MATURE + per-tier progress 0-100%',
                  'tier1_eta_sec / tier2_eta_sec / tier3_eta_sec — estimated time until tier ready',
                  'mitigation_active / learning_action — 0=BLOCK (enforce), 1=ALERT_ONLY (detect only)',
                  'suppressed_count — detections suppressed during alert-only mode',
                  'trust_multiplier — progressive trust (1.0 at MATURE, higher during learning)',
                  'sensitivity_preset — STRICT/MODERATE/CONSERVATIVE/custom',
                  'cusum_active / jsd_active / fast_active — which detection methods triggered',
                  'fp_rate / tp_rate — estimated false/true positive rates from adaptive threshold',
                  'adaptive_adjustments — number of threshold auto-adjustments made',
                ],
              },
              {
                key: 'per_ip_features',
                label: 'Per-IP Features & Anomalies',
                magic: '0x50495046 / 0x50455250 / 0x5049424C',
                size: '~7-65 KB per packet type',
                interval: '1s',
                mode: 'Snapshot (shared memory seqlock)',
                desc: 'Three separate packet types sent together every 1s. Reads per-destination-IP data from POSIX shared memory using seqlock for consistency (skips if write-in-progress). Up to 64 protected IPs. All values are pre-aggregated rates computed by Layer 2, NOT raw packets.',
                fields: [
                  '── Features packet (PIPF) ──',
                  'dst_ip — protected destination IP (network byte order)',
                  'Volume: packets_per_sec, bytes_per_sec, flows_per_sec (pre-computed rates)',
                  'TCP flags: syn/syn_ack/ack/rst/fin per second',
                  'Protocol mix: tcp_ratio, udp_ratio, icmp_ratio (0-100%)',
                  'Cardinality: unique_src_ips (HyperLogLog), unique_flows, unique_dst_ports',
                  'Concentration: max_flow_fraction, topk_flow_share, heavy_hitter_count (Count-Min Sketch)',
                  'Flow behavior: avg_packets_per_flow, flow_duration_avg_ms, active_flows',
                  'L2 detection: burst_factor (pps/ewma*100), rst_syn_ratio, new_srcip_rate (churn)',
                  'Advanced: ttl_mean, tcp_completion_rate, src_port_entropy, dst_port_density',
                  '── Anomaly packet (PERP) ──',
                  'anomaly_active / anomaly_level / anomaly_protocol / attack_type per IP',
                  'max_z_score / tier_agreement / anomalous_feature_count per IP',
                  'flash_crowd_score (0=attack, 100=legitimate) / spoofed_mode / randomness_pct',
                  'detection_method bitmask (zscore|cusum|jsd|fast) / confidence / severity per IP',
                  'learning_phase / tier1_progress / cool_down_remaining per IP',
                  '── Baseline packet (PIBL) ──',
                  'means[5 tiers][39 features] — EWMA baseline means (1s, 10s, 60s, hourly, weekly)',
                  'variances[5 tiers][39 features] — EWMA baseline variances',
                  'tier_ready[5] / tier_samples[5] — per-tier maturity status',
                ],
              },
              {
                key: 'sysmon',
                label: 'System Monitor',
                magic: '0x53595354 (SYST)',
                size: '~5.2 KB',
                interval: '1s',
                mode: 'Snapshot (polled)',
                desc: 'Host system and DPDK runtime resource usage. Polled every 1s (every 2 stats loops). Reads /proc/stat, /proc/meminfo, and DPDK lcore/mempool APIs. NOT per-packet — purely infrastructure health.',
                fields: [
                  'DPDK lcores (up to 64): lcore_id, is_active, busy/idle cycles, utilization %',
                  'DPDK mempools (up to 8): name, total size, available/in-use count, usage %',
                  'DPDK hugepages: total_bytes, used_bytes, usage %',
                  'System CPUs (up to 64): per-core usage_pct, user_pct, system_pct, idle_pct, iowait_pct',
                  'System memory: total_bytes, free_bytes, available_bytes, used_bytes, usage %',
                  'Load average: 1min, 5min, 15min (from /proc/loadavg)',
                ],
              },
            ] as Array<{ key: keyof typeof streams; label: string; magic: string; size: string; interval: string; mode: string; desc: string; fields: string[] }>).map(({ key, label, magic, size, interval, mode, desc, fields }) => (
              <label
                key={key}
                className={clsx(
                  'flex items-start gap-3 p-4 rounded-lg border cursor-pointer transition-colors',
                  streams[key]
                    ? 'border-brand-400 bg-brand-50 text-gray-900 dark:border-brand-400 dark:bg-slate-800 dark:ring-1 dark:ring-brand-500/30'
                    : 'border-gray-200 bg-white dark:border-gray-700 dark:bg-slate-900 hover:bg-gray-50 dark:hover:bg-slate-800'
                )}
              >
                <input
                  type="checkbox"
                  checked={streams[key]}
                  onChange={(e) => updateStream(key, e.target.checked)}
                  className="mt-1 h-4 w-4 rounded border-gray-300 text-brand-600 focus:ring-brand-500"
                />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-semibold text-gray-900 dark:text-gray-100">{label}</span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-gray-200 dark:bg-slate-700/80 text-gray-600 dark:text-gray-300">
                      {magic}
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 dark:bg-slate-700/80 text-gray-500 dark:text-gray-400">
                      ~{size}
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 dark:bg-slate-700/80 text-gray-500 dark:text-gray-400">
                      every {interval}
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5 mt-1.5">
                    <span className={clsx(
                      'text-[10px] font-medium px-1.5 py-0.5 rounded',
                      mode.includes('Sampled') ? 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300' :
                      mode.includes('Aggregated') ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300' :
                      'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300'
                    )}>
                      {mode}
                    </span>
                  </div>
                  <p className="text-xs text-gray-600 dark:text-gray-400 mt-1.5">{desc}</p>
                  <details className="mt-2">
                    <summary className="text-xs font-medium text-brand-600 dark:text-brand-400 cursor-pointer hover:underline">
                      View fields ({fields.length})
                    </summary>
                    <ul className="mt-1.5 space-y-0.5 text-[11px] text-gray-600 dark:text-gray-400 font-mono leading-relaxed">
                      {fields.map((f, i) => (
                        <li key={i} className="flex gap-1.5">
                          <span className="text-gray-400 dark:text-gray-500 select-none">-</span>
                          <span>{f}</span>
                        </li>
                      ))}
                    </ul>
                  </details>
                </div>
              </label>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-3 pt-2">
          {dirty && (
            <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400">
              Unsaved changes
            </span>
          )}
          <button
            onClick={save}
            disabled={!dirty || saving}
            className={clsx('btn btn-sm', dirty ? 'btn-primary' : 'btn-secondary opacity-50')}
          >
            {saving ? 'Saving...' : 'Save Forwarding'}
          </button>
        </div>
      </div>
    </SectionCard>
  );
}

export default OrgSettingsPage;
