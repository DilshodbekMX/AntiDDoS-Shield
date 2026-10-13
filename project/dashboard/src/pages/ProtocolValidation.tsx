/**
 * Protocol Validation Page
 *
 * Tabbed interface for L3/L4 packet validation and L7 application-layer validation.
 * L3/L4 tab: checksum, attack detection (sub-grouped), ICMP filtering, forwarding.
 * L7 tab: DNS, NTP, HTTP protocol validation (enabled via master toggles on L3/L4 tab).
 *
 * Each check has a severity tag (critical/recommended/caution) so operators
 * can quickly see which toggles are safe to disable.
 */

import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  ShieldExclamationIcon,
  BeakerIcon,
  ShieldCheckIcon,
  BoltIcon,
  SignalIcon,
  CubeIcon,
} from '@heroicons/react/24/outline';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import api from '../services/api';
import { SkeletonCard } from '../components/ui/LoadingSpinner';
import { Toggle, SectionCard, NumberInput } from '../components/ui/FormControls';
import { PageHeader } from '../components/ui';

// ==================== Types ====================

type Severity = 'critical' | 'recommended' | 'caution';

interface FieldDef {
  key: string;
  label: string;
  desc: string;
  severity: Severity;
}

// ==================== Severity Badge ====================

const SEVERITY_STYLES: Record<Severity, { bg: string; label: string }> = {
  critical: {
    bg: 'bg-red-100 text-red-700 dark:bg-red-500/15 dark:text-red-400',
    label: 'Critical',
  },
  recommended: {
    bg: 'bg-blue-100 text-blue-700 dark:bg-blue-500/15 dark:text-blue-400',
    label: 'Recommended',
  },
  caution: {
    bg: 'bg-orange-100 text-orange-700 dark:bg-orange-500/15 dark:text-orange-400',
    label: 'Caution',
  },
};

function SeverityBadge({ severity }: { severity: Severity }) {
  const s = SEVERITY_STYLES[severity];
  return (
    <span className={clsx('inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide leading-none', s.bg)}>
      {s.label}
    </span>
  );
}

// ==================== ValidationRow ====================

/** Row with label + severity badge + description + control (toggle/number). */
function ValidationRow({
  label,
  desc,
  severity,
  children,
}: {
  label: string;
  desc: string;
  severity: Severity;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between py-3 first:pt-0 last:pb-0">
      <div className="flex-1 min-w-0 mr-4">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-slate-900 dark:text-white">{label}</span>
          <SeverityBadge severity={severity} />
        </div>
        <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{desc}</div>
      </div>
      <div className="flex-shrink-0">{children}</div>
    </div>
  );
}

// ==================== Sub-group Header ====================

function SubGroupHeader({ title }: { title: string }) {
  return (
    <div className="pt-4 pb-1 first:pt-0">
      <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
        {title}
      </div>
    </div>
  );
}

// ==================== Summary Card ====================

function SummaryCard({
  icon: Icon,
  title,
  enabled,
  total,
  subtitle,
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  enabled: number;
  total: number;
  subtitle?: string;
}) {
  const ratio = total > 0 ? enabled / total : 0;
  const color =
    ratio >= 1 ? 'border-emerald-500' :
    ratio > 0  ? 'border-amber-500' :
                  'border-red-500';
  const textColor =
    ratio >= 1 ? 'text-emerald-600 dark:text-emerald-400' :
    ratio > 0  ? 'text-amber-600 dark:text-amber-400' :
                  'text-red-600 dark:text-red-400';
  const barColor =
    ratio >= 1 ? 'bg-emerald-500' :
    ratio > 0  ? 'bg-amber-500' :
                  'bg-red-500';

  return (
    <div className={clsx(
      'rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800/50 p-3',
      'border-l-[3px]', color
    )}>
      <div className="flex items-center gap-2 mb-1">
        <Icon className="h-4 w-4 text-slate-400 dark:text-slate-500" />
        <span className="text-xs font-medium text-slate-600 dark:text-slate-300 truncate">{title}</span>
      </div>
      <div className={clsx('text-lg font-bold leading-tight', textColor)}>
        {enabled}/{total}
        <span className="text-xs font-normal text-slate-400 dark:text-slate-500 ml-1">enabled</span>
      </div>
      {subtitle && (
        <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5 truncate">{subtitle}</div>
      )}
      {/* Mini progress bar */}
      <div className="mt-2 h-1 rounded-full bg-slate-100 dark:bg-slate-700 overflow-hidden">
        <div
          className={clsx('h-full rounded-full transition-all duration-300', barColor)}
          style={{ width: `${Math.round(ratio * 100)}%` }}
        />
      </div>
    </div>
  );
}

// ==================== Enabled-count badge (for SectionCard headers) ====================

function EnabledBadge({ enabled, total }: { enabled: number; total: number }) {
  const ratio = total > 0 ? enabled / total : 0;
  const bg =
    ratio >= 1 ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-400' :
    ratio > 0  ? 'bg-amber-100 text-amber-700 dark:bg-amber-500/20 dark:text-amber-400' :
                  'bg-red-100 text-red-700 dark:bg-red-500/20 dark:text-red-400';
  return (
    <span className={clsx('px-2 py-0.5 rounded-full text-xs font-semibold', bg)}>
      {enabled}/{total}
    </span>
  );
}

// ==================== Helpers ====================

function countEnabled(config: Record<string, unknown> | undefined, fields: FieldDef[]): number {
  if (!config) return 0;
  return fields.filter(f => !!config[f.key]).length;
}

// ==================== L3/L4 Field Definitions ====================

const CHECKSUM_FIELDS: FieldDef[] = [
  { key: 'validate_ip_checksum', label: 'IP Header Checksum', desc: 'Verify IPv4 header checksum. Hardware-accelerated when NIC supports it.', severity: 'critical' },
  { key: 'validate_tcp_checksum', label: 'TCP Checksum', desc: 'Verify TCP pseudo-header + data checksum. Higher CPU cost in software mode.', severity: 'recommended' },
  { key: 'validate_udp_checksum', label: 'UDP Checksum', desc: 'Verify UDP pseudo-header + data checksum. Zero checksum is valid per RFC 768.', severity: 'recommended' },
  { key: 'validate_icmp_checksum', label: 'ICMP Checksum', desc: 'Verify ICMP message checksum. Always invalid if checksum fails (corruption).', severity: 'recommended' },
];

// Attack Detection -- sub-grouped
const ATTACK_PROTOCOL_FIELDS: FieldDef[] = [
  { key: 'drop_invalid_src_ip', label: 'Invalid Source IP', desc: 'Drop packets with bogus source IPs: 0.0.0.0, broadcast, loopback, multicast, reserved, link-local (RFC 5735).', severity: 'critical' },
  { key: 'drop_land_attack', label: 'LAND Attack', desc: 'Drop packets where source IP equals destination IP (CVE-1999-0016).', severity: 'critical' },
  { key: 'drop_zero_ttl', label: 'Zero TTL', desc: 'Drop packets with TTL=0. These should never reach a host and indicate crafted packets.', severity: 'critical' },
  { key: 'drop_port_zero', label: 'L4 Port Zero', desc: 'Drop TCP/UDP with source or destination port 0. Reserved per RFC, never legitimate traffic.', severity: 'critical' },
  { key: 'drop_ip_reserved_flag', label: 'IP Reserved Flag', desc: 'Drop packets with IP flags bit 0 set. Must be zero per RFC 791 — always malformed.', severity: 'critical' },
  { key: 'drop_tcp_data_offset', label: 'Invalid TCP Header Length', desc: 'Drop TCP with data offset < 5 (header < 20 bytes). Always malformed per RFC 793.', severity: 'critical' },
];

const ATTACK_SCAN_FIELDS: FieldDef[] = [
  { key: 'drop_tcp_null', label: 'TCP NULL Scan', desc: 'Drop TCP packets with no flags set. Used by port scanners (nmap -sN).', severity: 'recommended' },
  { key: 'drop_tcp_xmas', label: 'TCP XMAS Scan', desc: 'Drop TCP packets with FIN+PSH+URG flags set simultaneously (nmap -sX).', severity: 'recommended' },
];

const ATTACK_FRAGMENT_FIELDS: FieldDef[] = [
  { key: 'drop_syn_fragment', label: 'Fragmented TCP SYN', desc: 'Drop TCP SYN on fragmented packets. SYN is 40-60 bytes and fits in any MTU — always crafted.', severity: 'critical' },
  { key: 'drop_teardrop', label: 'Teardrop Attack', desc: 'Drop fragments where offset + length exceeds 65535 bytes. Violates IP spec (CVE-1999-0015).', severity: 'critical' },
  { key: 'drop_fragment_fin_rst', label: 'Fragmented FIN/RST', desc: 'Drop FIN or RST on fragmented packets. Like SYN, these are tiny and never need fragmenting — always crafted.', severity: 'recommended' },
  { key: 'drop_all_fragments', label: 'Drop All Fragments', desc: 'Drop ALL IP fragments unconditionally. Modern best practice — PMTUD eliminates legitimate fragmentation. Overrides other fragment checks when enabled.', severity: 'caution' },
  { key: 'drop_fragments', label: 'Suspicious Fragments', desc: 'Drop IP fragments smaller than minimum size (400B default). Heuristic — may flag legitimate small fragments.', severity: 'caution' },
];

const ALL_ATTACK_FIELDS: FieldDef[] = [
  ...ATTACK_PROTOCOL_FIELDS,
  ...ATTACK_SCAN_FIELDS,
  ...ATTACK_FRAGMENT_FIELDS,
];

const BEHAVIOR_FIELDS: FieldDef[] = [
  { key: 'decrement_ttl', label: 'Decrement TTL', desc: 'Decrease TTL by 1 on forwarded packets. Disable for L2 bridge mode, enable for L3 router mode.', severity: 'recommended' },
];

// ==================== ICMP Field Definitions ====================

const ICMP_FIELDS: FieldDef[] = [
  { key: 'icmp_drop_redirect', label: 'Redirect (Type 5)', desc: 'ICMP Redirect messages can be used for route injection attacks. Rarely needed from external sources.', severity: 'critical' },
  { key: 'icmp_drop_router_advert', label: 'Router Advertisement (Type 9)', desc: 'Easily spoofed to redirect traffic. Should be blocked from untrusted networks.', severity: 'critical' },
  { key: 'icmp_drop_router_solicit', label: 'Router Solicitation (Type 10)', desc: 'Can be used to trigger Router Advertisements. Block from external sources.', severity: 'recommended' },
  { key: 'icmp_drop_timestamp', label: 'Timestamp (Type 13/14)', desc: 'Timestamp request/reply used for OS fingerprinting and reconnaissance.', severity: 'recommended' },
  { key: 'icmp_drop_address_mask', label: 'Address Mask (Type 17/18)', desc: 'Address Mask request/reply used for network reconnaissance. Obsolete.', severity: 'recommended' },
  { key: 'icmp_drop_info', label: 'Information (Type 15/16)', desc: 'Information request/reply — obsolete protocol, no legitimate modern use.', severity: 'recommended' },
  { key: 'icmp_drop_source_quench', label: 'Source Quench (Type 4)', desc: 'Obsolete per RFC 6633. Was used for congestion notification but deprecated in favor of ECN.', severity: 'recommended' },
];

// ==================== L7 Master Toggle Definitions ====================

const L7_MASTER_TOGGLES: FieldDef[] = [
  { key: 'dns_enabled', label: 'DNS Validation', desc: 'Validate DNS protocol headers on UDP port 53. Catches malformed queries, amplification vectors, and RFC violations.', severity: 'recommended' },
  { key: 'ntp_enabled', label: 'NTP Validation', desc: 'Validate NTP protocol headers on UDP port 123. Blocks monlist amplification (CVE-2013-5211) and malformed packets.', severity: 'recommended' },
  { key: 'http_enabled', label: 'HTTP Inspection', desc: 'Validate HTTP request line on first data packet (TCP 80/8080). No TLS inspection. Limited to unencrypted traffic.', severity: 'recommended' },
];

// ==================== L7 Detail Field Definitions ====================

const DNS_FIELDS: FieldDef[] = [
  { key: 'dns_drop_too_short', label: 'Too Short', desc: 'Drop DNS packets shorter than 12 bytes (minimum DNS header size).', severity: 'critical' },
  { key: 'dns_drop_invalid_opcode', label: 'Invalid Opcode', desc: 'Drop DNS with opcode > 5. Standard: 0=Query, 1=IQuery, 2=Status, 4=Notify, 5=Update.', severity: 'critical' },
  { key: 'dns_drop_qr_mismatch', label: 'QR Direction Mismatch', desc: 'Drop queries from server port or responses from client port (QR bit vs direction).', severity: 'recommended' },
  { key: 'dns_drop_qdcount_invalid', label: 'Invalid Question Count', desc: 'Drop standard queries (opcode 0) with QDCOUNT != 1.', severity: 'recommended' },
  { key: 'dns_drop_both_port53', label: 'Both Ports 53', desc: 'Drop packets where both source and destination port are 53. Never legitimate.', severity: 'critical' },
  { key: 'dns_drop_zone_transfer', label: 'Zone Transfer over UDP', desc: 'Drop AXFR (QTYPE=252) zone transfer requests over UDP. AXFR requires TCP.', severity: 'recommended' },
  { key: 'dns_drop_label_too_long', label: 'Label Too Long', desc: 'Drop DNS with any label exceeding 63 bytes (RFC 1035 limit).', severity: 'critical' },
  { key: 'dns_drop_name_too_long', label: 'Name Too Long', desc: 'Drop DNS with FQDN exceeding 255 bytes (RFC 1035 limit).', severity: 'critical' },
  { key: 'dns_drop_pointer_loop', label: 'Compression Pointer Loop', desc: 'Drop DNS with circular compression pointers (depth > 16). Prevents infinite loops.', severity: 'critical' },
];

const NTP_FIELDS: FieldDef[] = [
  { key: 'ntp_drop_too_short', label: 'Too Short', desc: 'Drop NTP packets shorter than minimum size (48 bytes for standard, 4 for control).', severity: 'critical' },
  { key: 'ntp_drop_invalid_version', label: 'Invalid Version', desc: 'Drop NTP with version 0 or > 4. Valid versions: 1-4.', severity: 'critical' },
  { key: 'ntp_drop_invalid_mode', label: 'Invalid Mode', desc: 'Drop NTP with mode > 7. Valid modes: 0-7.', severity: 'recommended' },
  { key: 'ntp_drop_monlist', label: 'Block Monlist (Mode 7)', desc: 'Drop NTP Mode 7 private messages. Primary amplification vector (CVE-2013-5211).', severity: 'critical' },
  { key: 'ntp_drop_control', label: 'Block Control (Mode 6)', desc: 'Drop NTP Mode 6 control messages. Used by ntpq — disable only if you use NTP management.', severity: 'caution' },
  { key: 'ntp_drop_invalid_stratum', label: 'Invalid Stratum', desc: 'Drop NTP with stratum > 15. Values 16-255 are reserved.', severity: 'recommended' },
  { key: 'ntp_drop_size_mismatch', label: 'Size Mismatch', desc: 'Drop NTP packets with incorrect size for their version and mode.', severity: 'recommended' },
];

const HTTP_FIELDS: FieldDef[] = [
  { key: 'http_drop_invalid_method', label: 'Invalid Method', desc: 'Drop HTTP with unrecognized request method. Valid: GET, POST, HEAD, PUT, DELETE, PATCH, OPTIONS, CONNECT, TRACE.', severity: 'critical' },
  { key: 'http_drop_invalid_version', label: 'Invalid Version', desc: 'Drop HTTP with unrecognized version string. Valid: HTTP/0.9, HTTP/1.0, HTTP/1.1.', severity: 'recommended' },
  { key: 'http_drop_line_too_long', label: 'Request Line Too Long', desc: 'Drop HTTP where request line exceeds configured maximum length.', severity: 'recommended' },
  { key: 'http_drop_non_ascii', label: 'Non-ASCII Characters', desc: 'Drop HTTP with non-printable characters in request line. Indicates binary garbage or exploit attempt.', severity: 'critical' },
];

// ==================== Component ====================

export function ProtocolValidationPage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'l3l4' | 'l7'>('l3l4');

  const { data: layer1Config, isLoading } = useQuery({
    queryKey: ['layer1-config'],
    queryFn: () => api.getLayer1Config(),
  });

  const updateValidation = async (key: string, value: boolean) => {
    try {
      await api.updateLayer1ConfigValue('validation', key, value);
      toast.success('Updated');
    } catch {
      toast.error('Failed to update');
    } finally {
      queryClient.invalidateQueries({ queryKey: ['layer1-config'] });
    }
  };

  const updateL7 = async (key: string, value: boolean | number) => {
    try {
      await api.updateLayer1ConfigValue('l7_validation', key, value);
      toast.success('Updated');
    } catch {
      toast.error('Failed to update');
    } finally {
      queryClient.invalidateQueries({ queryKey: ['layer1-config'] });
    }
  };

  const config = layer1Config as Record<string, unknown> | undefined;
  const validation = config?.validation as Record<string, unknown> | undefined;
  const l7 = config?.l7_validation as Record<string, unknown> | undefined;

  const l7AnyEnabled = !!(l7?.dns_enabled || l7?.ntp_enabled || l7?.http_enabled);

  // Counts for summary
  const checksumEnabled = countEnabled(validation, CHECKSUM_FIELDS);
  const attackEnabled = countEnabled(validation, ALL_ATTACK_FIELDS);
  const icmpEnabled = countEnabled(l7, ICMP_FIELDS);
  const l7MasterEnabled = countEnabled(l7, L7_MASTER_TOGGLES);

  if (isLoading) {
    return (
      <div className="space-y-6 animate-fade-in">
        <div className="flex items-center gap-3">
          <div className="skeleton h-7 w-7 rounded-lg" />
          <div className="skeleton h-8 w-64 rounded-lg" />
        </div>
        <SkeletonCard />
        <SkeletonCard />
        <SkeletonCard />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Protocol Validation"
        description="Packet validation checks running in the datapath pipeline. Each check shows a severity tag to help you decide what to enable."
        icon={ShieldExclamationIcon}
      />

      {/* Tabs */}
      <div className="border-b border-slate-200 dark:border-slate-700">
        <nav className="-mb-px flex space-x-4 sm:space-x-8 overflow-x-auto">
          <button
            onClick={() => setActiveTab('l3l4')}
            className={clsx(
              'flex items-center gap-2 py-3 px-1 border-b-2 font-medium text-sm transition-colors',
              activeTab === 'l3l4'
                ? 'border-indigo-500 text-indigo-600 dark:text-indigo-400'
                : 'border-transparent text-slate-500 hover:text-slate-700 dark:hover:text-slate-200 dark:text-slate-300 hover:border-slate-300'
            )}
          >
            <ShieldExclamationIcon className="h-5 w-5" />
            Packet Validation
          </button>
          <button
            onClick={() => l7AnyEnabled && setActiveTab('l7')}
            className={clsx(
              'flex items-center gap-2 py-3 px-1 border-b-2 font-medium text-sm transition-colors',
              activeTab === 'l7'
                ? 'border-indigo-500 text-indigo-600 dark:text-indigo-400'
                : l7AnyEnabled
                  ? 'border-transparent text-slate-500 hover:text-slate-700 dark:hover:text-slate-200 dark:text-slate-300 hover:border-slate-300'
                  : 'border-transparent text-slate-400 dark:text-slate-600 opacity-50 cursor-not-allowed'
            )}
            title={l7AnyEnabled ? undefined : 'Enable at least one L7 protocol below to configure'}
          >
            <BeakerIcon className="h-5 w-5" />
            Application Validation
            {!l7AnyEnabled && (
              <span className="text-2xs bg-slate-200 dark:bg-slate-700 text-slate-500 dark:text-slate-400 px-1.5 py-0.5 rounded-full">Off</span>
            )}
          </button>
        </nav>
      </div>

      {/* ==================== L3/L4 Tab ==================== */}
      {activeTab === 'l3l4' && validation && (
        <div className="space-y-6 animate-fade-in">

          {/* Summary Bar */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <SummaryCard
              icon={ShieldCheckIcon}
              title="Checksums"
              enabled={checksumEnabled}
              total={CHECKSUM_FIELDS.length}
            />
            <SummaryCard
              icon={BoltIcon}
              title="Attack Detection"
              enabled={attackEnabled}
              total={ALL_ATTACK_FIELDS.length}
            />
            <SummaryCard
              icon={SignalIcon}
              title="ICMP Filtering"
              enabled={l7?.icmp_enabled ? icmpEnabled : 0}
              total={ICMP_FIELDS.length}
              subtitle={l7?.icmp_enabled ? `Rate: ${l7?.icmp_rate_limit_pps ?? 1000} pps` : 'Disabled'}
            />
            <SummaryCard
              icon={CubeIcon}
              title="L7 Protocols"
              enabled={l7MasterEnabled}
              total={L7_MASTER_TOGGLES.length}
              subtitle={
                L7_MASTER_TOGGLES.filter(t => l7?.[t.key]).map(t => t.label.split(' ')[0]).join(', ') || 'None'
              }
            />
          </div>

          {/* Severity Legend */}
          <div className="flex items-center gap-4 text-[11px] text-slate-500 dark:text-slate-400">
            <span className="font-medium text-slate-600 dark:text-slate-300">Severity:</span>
            <span className="flex items-center gap-1">
              <span className="inline-block w-2 h-2 rounded-full bg-red-500" />
              Critical — always invalid, no false positives
            </span>
            <span className="flex items-center gap-1">
              <span className="inline-block w-2 h-2 rounded-full bg-blue-500" />
              Recommended — safe for most deployments
            </span>
            <span className="flex items-center gap-1">
              <span className="inline-block w-2 h-2 rounded-full bg-orange-500" />
              Caution — may affect legitimate traffic
            </span>
          </div>

          {/* Checksum Verification */}
          <SectionCard
            title="Checksum Verification"
            description="Header integrity checks. Hardware-accelerated on supported NICs."
            badge={<EnabledBadge enabled={checksumEnabled} total={CHECKSUM_FIELDS.length} />}
            collapsible
            defaultOpen
          >
            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {CHECKSUM_FIELDS.map((f) => (
                <ValidationRow key={f.key} label={f.label} desc={f.desc} severity={f.severity}>
                  <Toggle enabled={!!validation[f.key]} onChange={(v) => updateValidation(f.key, v)} size="sm" label={f.label} />
                </ValidationRow>
              ))}
            </div>
          </SectionCard>

          {/* Attack Detection -- sub-grouped */}
          <SectionCard
            title="Attack Detection"
            description="Drop packets matching known attack patterns and scanning techniques."
            badge={<EnabledBadge enabled={attackEnabled} total={ALL_ATTACK_FIELDS.length} />}
            collapsible
            defaultOpen
          >
            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {/* Protocol Violations */}
              <SubGroupHeader title="Protocol Violations" />
              {ATTACK_PROTOCOL_FIELDS.map((f) => (
                <ValidationRow key={f.key} label={f.label} desc={f.desc} severity={f.severity}>
                  <Toggle enabled={!!validation[f.key]} onChange={(v) => updateValidation(f.key, v)} size="sm" label={f.label} />
                </ValidationRow>
              ))}
              {/* Scan Detection */}
              <SubGroupHeader title="Scan Detection" />
              {ATTACK_SCAN_FIELDS.map((f) => (
                <ValidationRow key={f.key} label={f.label} desc={f.desc} severity={f.severity}>
                  <Toggle enabled={!!validation[f.key]} onChange={(v) => updateValidation(f.key, v)} size="sm" label={f.label} />
                </ValidationRow>
              ))}
              {/* Fragment Attacks */}
              <SubGroupHeader title="Fragment Attacks" />
              {ATTACK_FRAGMENT_FIELDS.map((f) => (
                <ValidationRow key={f.key} label={f.label} desc={f.desc} severity={f.severity}>
                  <Toggle enabled={!!validation[f.key]} onChange={(v) => updateValidation(f.key, v)} size="sm" label={f.label} />
                </ValidationRow>
              ))}
            </div>
          </SectionCard>

          {/* Forwarding Behavior */}
          <SectionCard
            title="Forwarding Behavior"
            description="Controls how packets are modified before forwarding."
            collapsible
            defaultOpen
          >
            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {BEHAVIOR_FIELDS.map((f) => (
                <ValidationRow key={f.key} label={f.label} desc={f.desc} severity={f.severity}>
                  <Toggle enabled={!!validation[f.key]} onChange={(v) => updateValidation(f.key, v)} size="sm" label={f.label} />
                </ValidationRow>
              ))}
            </div>
          </SectionCard>

          {/* ICMP Filtering */}
          {l7 && (
            <SectionCard
              title="ICMP Filtering"
              description="Block dangerous ICMP message types and apply global rate limiting."
              badge={l7.icmp_enabled ? <EnabledBadge enabled={icmpEnabled} total={ICMP_FIELDS.length} /> : (
                <span className="px-2 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-500 dark:bg-slate-700 dark:text-slate-400">Off</span>
              )}
              collapsible
              defaultOpen
            >
              <div className="divide-y divide-slate-100 dark:divide-slate-800">
                <div className="flex items-center justify-between py-3 first:pt-0 last:pb-0">
                  <div className="flex-1 min-w-0 mr-4">
                    <div className="text-sm font-medium text-slate-900 dark:text-white">Enable ICMP Filtering</div>
                    <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                      Filter dangerous ICMP types (redirect, timestamp, address mask) and apply global rate limiting.
                    </div>
                  </div>
                  <div className="flex-shrink-0">
                    <Toggle enabled={!!l7.icmp_enabled} onChange={(v) => updateL7('icmp_enabled', v)} size="sm" label="ICMP Filtering" />
                  </div>
                </div>
                {!!l7.icmp_enabled && (
                  <>
                    {ICMP_FIELDS.map((f) => (
                      <ValidationRow key={f.key} label={f.label} desc={f.desc} severity={f.severity}>
                        <Toggle enabled={!!l7[f.key]} onChange={(v) => updateL7(f.key, v)} size="sm" label={f.label} />
                      </ValidationRow>
                    ))}
                    <div className="flex items-center justify-between py-3">
                      <div className="flex-1 min-w-0 mr-4">
                        <div className="text-sm font-medium text-slate-900 dark:text-white">Rate Limit (PPS)</div>
                        <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                          Global ICMP rate limit in packets per second. 0 = unlimited.
                        </div>
                      </div>
                      <div className="flex-shrink-0">
                        <NumberInput
                          value={l7.icmp_rate_limit_pps as number ?? 1000}
                          onChange={(v) => updateL7('icmp_rate_limit_pps', v)}
                          min={0}
                          max={1000000}
                          step={100}
                        />
                      </div>
                    </div>
                  </>
                )}
              </div>
            </SectionCard>
          )}

          {/* L7 Protocol Validation Master Toggles */}
          {l7 && (
            <SectionCard
              title="Application-Layer Validation"
              description="Enable L7 protocol validation (Stage 4f). Toggle protocols here, configure details in the Application Validation tab."
              badge={<EnabledBadge enabled={l7MasterEnabled} total={L7_MASTER_TOGGLES.length} />}
              collapsible
              defaultOpen
            >
              <div className="divide-y divide-slate-100 dark:divide-slate-800">
                {L7_MASTER_TOGGLES.map((f) => (
                  <ValidationRow key={f.key} label={f.label} desc={f.desc} severity={f.severity}>
                    <Toggle enabled={!!l7[f.key]} onChange={(v) => updateL7(f.key, v)} size="sm" label={f.label} />
                  </ValidationRow>
                ))}
              </div>
            </SectionCard>
          )}
        </div>
      )}

      {/* ==================== L7 Tab ==================== */}
      {activeTab === 'l7' && l7 && (
        <div className="space-y-6 animate-fade-in">
          {/* DNS */}
          {!!l7.dns_enabled && (
            <SectionCard
              title="DNS Validation"
              description="UDP port 53 — full header and question section validation."
              badge={<EnabledBadge enabled={countEnabled(l7, DNS_FIELDS)} total={DNS_FIELDS.length} />}
              collapsible
              defaultOpen
            >
              <div className="divide-y divide-slate-100 dark:divide-slate-800">
                {DNS_FIELDS.map((f) => (
                  <ValidationRow key={f.key} label={f.label} desc={f.desc} severity={f.severity}>
                    <Toggle enabled={!!l7[f.key]} onChange={(v) => updateL7(f.key, v)} size="sm" label={f.label} />
                  </ValidationRow>
                ))}
                <div className="flex items-center justify-between py-3">
                  <div className="flex-1 min-w-0 mr-4">
                    <div className="text-sm font-medium text-slate-900 dark:text-white">Max UDP Message Size</div>
                    <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                      Maximum DNS UDP message size in bytes. Standard is 512; set higher (4096) if EDNS0 is used.
                    </div>
                  </div>
                  <div className="flex-shrink-0">
                    <NumberInput
                      value={l7.dns_max_udp_size as number ?? 512}
                      onChange={(v) => updateL7('dns_max_udp_size', v)}
                      min={512}
                      max={65535}
                      step={512}
                    />
                  </div>
                </div>
              </div>
            </SectionCard>
          )}

          {/* NTP */}
          {!!l7.ntp_enabled && (
            <SectionCard
              title="NTP Validation"
              description="UDP port 123 — header validation and amplification protection."
              badge={<EnabledBadge enabled={countEnabled(l7, NTP_FIELDS)} total={NTP_FIELDS.length} />}
              collapsible
              defaultOpen
            >
              <div className="divide-y divide-slate-100 dark:divide-slate-800">
                {NTP_FIELDS.map((f) => (
                  <ValidationRow key={f.key} label={f.label} desc={f.desc} severity={f.severity}>
                    <Toggle enabled={!!l7[f.key]} onChange={(v) => updateL7(f.key, v)} size="sm" label={f.label} />
                  </ValidationRow>
                ))}
              </div>
            </SectionCard>
          )}

          {/* HTTP */}
          {!!l7.http_enabled && (
            <SectionCard
              title="HTTP Validation"
              description="TCP ports 80/8080 — first data packet inspection only. No TLS. No TCP reassembly."
              badge={<EnabledBadge enabled={countEnabled(l7, HTTP_FIELDS)} total={HTTP_FIELDS.length} />}
              collapsible
              defaultOpen
            >
              <div className="divide-y divide-slate-100 dark:divide-slate-800">
                {HTTP_FIELDS.map((f) => (
                  <ValidationRow key={f.key} label={f.label} desc={f.desc} severity={f.severity}>
                    <Toggle enabled={!!l7[f.key]} onChange={(v) => updateL7(f.key, v)} size="sm" label={f.label} />
                  </ValidationRow>
                ))}
                <div className="flex items-center justify-between py-3">
                  <div className="flex-1 min-w-0 mr-4">
                    <div className="text-sm font-medium text-slate-900 dark:text-white">Max Request Line Length</div>
                    <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                      Maximum HTTP request line length in bytes before dropping.
                    </div>
                  </div>
                  <div className="flex-shrink-0">
                    <NumberInput
                      value={l7.http_max_request_line as number ?? 8192}
                      onChange={(v) => updateL7('http_max_request_line', v)}
                      min={256}
                      max={65535}
                      step={1024}
                    />
                  </div>
                </div>
              </div>
            </SectionCard>
          )}

          {/* Empty state */}
          {!l7.dns_enabled && !l7.ntp_enabled && !l7.http_enabled && (
            <div className="text-center py-12 text-slate-400 dark:text-slate-500">
              <BeakerIcon className="h-12 w-12 mx-auto mb-3 opacity-50" />
              <p className="text-sm">No L7 protocols enabled.</p>
              <p className="text-xs mt-1">Go to the Packet Validation tab to enable DNS, NTP, or HTTP validation.</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default ProtocolValidationPage;
