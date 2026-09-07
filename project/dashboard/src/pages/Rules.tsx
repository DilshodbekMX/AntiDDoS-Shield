/**
 * Access Rules Page
 *
 * IP Access Lists management:
 * - Whitelist (trusted IPs that bypass all checks)
 * - Blacklist (blocked IPs dropped immediately)
 * - Protected Servers (with per-IP protection profiles)
 */

import React, { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ShieldCheckIcon,
  ShieldExclamationIcon,
  ServerStackIcon,
  PlusIcon,
  TrashIcon,
  MagnifyingGlassIcon,
  XMarkIcon,
  CheckIcon,
  PencilSquareIcon,
  ChevronDownIcon,
  GlobeAltIcon,
  BoltIcon,
  LockClosedIcon,
  SignalIcon,
} from '@heroicons/react/24/outline';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import api from '../services/api';
import { Modal, Toggle, InfoBanner } from '../components/ui/FormControls';
import { EmptyState, SkeletonCard } from '../components/ui';

type MainCategory = 'access-control' | 'attack-protection';
type ProtectionTab = 'signatures' | 'protocols' | 'stages';
type IPListTab = 'whitelist' | 'blacklist' | 'protected';

interface StageInfo {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  category: string;
}

const STAGE_CATEGORY_NAMES: Record<string, string> = {
  mode: 'Operating Mode',
  tcp_protection: 'TCP Protection',
  udp_protection: 'UDP Protection',
  validation: 'Packet Validation',
  rate_limiting: 'Rate Limiting',
  access_control: 'Access Control',
  forwarding: 'Forwarding',
  telemetry: 'Telemetry',
  monitoring: 'Monitoring',
};

// 'mode' (monitor_only, tap_mode) excluded -- lives in Config > System Mode
const STAGE_ORDER = ['tcp_protection', 'udp_protection', 'validation', 'rate_limiting', 'access_control', 'forwarding', 'telemetry', 'monitoring'];

// Stages that have dedicated controls elsewhere -- hide from Protection Stages to avoid confusion
const STAGES_HIDDEN_FROM_LIST = new Set([
  'enforce_protected_ips',  // Config > General > IP Access List Limits
  'geo_blocking',           // Dedicated Geo-Blocking page
  'stats_enabled',          // Config > System Mode
]);

const STAGE_COLORS: Record<string, string> = {
  mode: 'bg-red-500',
  tcp_protection: 'bg-blue-500',
  udp_protection: 'bg-pink-500',
  validation: 'bg-yellow-500',
  rate_limiting: 'bg-purple-500',
  access_control: 'bg-rose-500',
  forwarding: 'bg-teal-500',
  telemetry: 'bg-cyan-500',
  monitoring: 'bg-indigo-500',
};

interface Signature {
  id: number;
  name: string;
  description?: string;
  category: string;
  enabled: boolean;
  port?: number;
}

interface SignaturesData {
  config: { enabled: boolean; log_matches?: boolean; block_amplification?: boolean; block_scans?: boolean };
  categories: Record<string, Signature[]>;
}

interface ProtocolEntry {
  number: number;
  name: string;
}

interface ProtocolsData {
  enabled: boolean;
  default_action: string;
  allowed_protocols: ProtocolEntry[];
  all_protocols: ProtocolEntry[];
  rate_limit_pps?: number;
  log_unknown?: boolean;
}

const SIGNATURE_CATEGORY_LABELS: Record<string, { label: string; description: string }> = {
  amplification: { label: 'Amplification Attacks', description: 'DNS, NTP, SSDP reflection attacks' },
  port_scan: { label: 'Port Scans', description: 'TCP/UDP scanning detection' },
  protocol_anomaly: { label: 'Protocol Anomalies', description: 'Invalid TCP flags, malformed headers' },
  attack_tools: { label: 'Attack Tools', description: 'LOIC, HOIC, Mirai signatures' },
};

const SIGNATURE_CATEGORY_ORDER = ['amplification', 'port_scan', 'protocol_anomaly', 'attack_tools'];

interface IPEntry {
  ip: string;
  description: string;
  added?: string;
  created?: string;
  expires?: string | null;
  profile_name?: string;
  profile_overrides?: Record<string, unknown>;
  mode?: string;
}

interface ProfileTemplate {
  name: string;
  description?: string;
  pps_limit?: number;
  bps_limit?: number;
  attack_pps_limit?: number;
  attack_bps_limit?: number;
  max_conn_per_src?: number;
  max_conn_total?: number;
  syn_proxy_mode?: string;
  syn_challenge_threshold?: number;
  tcp_ports?: number[];
  udp_ports?: number[];
}

// Profile visual config
const PROFILE_THEME: Record<string, { bg: string; text: string; border: string; icon: string; dot: string }> = {
  web_server: {
    bg: 'bg-blue-50 dark:bg-blue-900/20',
    text: 'text-blue-700 dark:text-blue-300',
    border: 'border-blue-200 dark:border-blue-800',
    icon: '',
    dot: 'bg-blue-500',
  },
  email_server: {
    bg: 'bg-purple-50 dark:bg-purple-900/20',
    text: 'text-purple-700 dark:text-purple-300',
    border: 'border-purple-200 dark:border-purple-800',
    icon: '',
    dot: 'bg-purple-500',
  },
  dns_server: {
    bg: 'bg-emerald-50 dark:bg-emerald-900/20',
    text: 'text-emerald-700 dark:text-emerald-300',
    border: 'border-emerald-200 dark:border-emerald-800',
    icon: '',
    dot: 'bg-emerald-500',
  },
  api_server: {
    bg: 'bg-orange-50 dark:bg-orange-900/20',
    text: 'text-orange-700 dark:text-orange-300',
    border: 'border-orange-200 dark:border-orange-800',
    icon: '',
    dot: 'bg-orange-500',
  },
  generic: {
    bg: 'bg-slate-50 dark:bg-slate-800/50',
    text: 'text-slate-600 dark:text-slate-300',
    border: 'border-slate-200 dark:border-slate-700',
    icon: '',
    dot: 'bg-slate-400',
  },
  custom: {
    bg: 'bg-rose-50 dark:bg-rose-900/20',
    text: 'text-rose-700 dark:text-rose-300',
    border: 'border-rose-200 dark:border-rose-800',
    icon: '',
    dot: 'bg-rose-500',
  },
};

const SYN_MODE_LABELS: Record<string, { label: string; color: string }> = {
  global: { label: 'Global', color: 'text-slate-500' },
  disabled: { label: 'Off', color: 'text-red-500' },
  always: { label: 'Always', color: 'text-emerald-600' },
  threshold: { label: 'Threshold', color: 'text-amber-600' },
};

function getTheme(profileName: string | undefined) {
  return PROFILE_THEME[profileName || 'generic'] || PROFILE_THEME.generic;
}

function getProfileLabel(profileName: string | undefined) {
  const labels: Record<string, string> = {
    web_server: 'Web Server',
    email_server: 'Email Server',
    dns_server: 'DNS Server',
    api_server: 'API Server',
    generic: 'Generic',
    custom: 'Custom',
  };
  return labels[profileName || 'generic'] || profileName || 'Generic';
}

function formatPorts(ports: number[] | undefined): string {
  if (!ports || ports.length === 0) return 'All';
  return ports.join(', ');
}

function formatPPS(pps: number | undefined): string {
  if (!pps) return '-';
  if (pps >= 1000000) return `${(pps / 1000000).toFixed(1)}M`;
  if (pps >= 1000) return `${(pps / 1000).toFixed(0)}K`;
  return String(pps);
}

// Compute effective profile: merge template defaults with overrides
function getEffectiveProfile(
  templateName: string | undefined,
  overrides: Record<string, unknown> | undefined,
  templates: Record<string, ProfileTemplate>
): Record<string, unknown> {
  const base = templates[templateName || 'generic'] || {};
  return { ...base, ...(overrides || {}) };
}

export function RulesPage() {
  const queryClient = useQueryClient();

  // Navigation
  const [mainCategory, setMainCategory] = useState<MainCategory>('access-control');
  const [protectionTab, setProtectionTab] = useState<ProtectionTab>('stages');
  const [ipListTab, setIPListTab] = useState<IPListTab>('protected');
  const [newProtocol, setNewProtocol] = useState('');

  // Form state
  const [search, setSearch] = useState('');
  const [showAddModal, setShowAddModal] = useState(false);
  const [newIP, setNewIP] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newDuration, setNewDuration] = useState('');
  const [newProfile, setNewProfile] = useState('generic');
  const [newMode, setNewMode] = useState<'bypass' | 'track'>('bypass');
  const [checkIpValue, setCheckIpValue] = useState('');
  const [checkResult, setCheckResult] = useState<Record<string, unknown> | null>(null);

  // Bulk import
  const [showBulkModal, setShowBulkModal] = useState(false);
  const [bulkIPs, setBulkIPs] = useState('');

  // Profile edit
  const [showEditModal, setShowEditModal] = useState(false);
  const [editingIP, setEditingIP] = useState<IPEntry | null>(null);
  const [editProfile, setEditProfile] = useState('generic');
  const [editOverrides, setEditOverrides] = useState<Record<string, string>>({});

  // Expanded rows
  const [expandedIP, setExpandedIP] = useState<string | null>(null);

  // Confirm clear
  const [confirmClear, setConfirmClear] = useState(false);

  // Fetch profile templates from backend
  const { data: profileTemplatesData } = useQuery({
    queryKey: ['profile-templates'],
    queryFn: async () => {
      try {
        const data = await api.getProfileTemplates();
        return data.templates as unknown as ProfileTemplate[];
      } catch {
        return null;
      }
    },
    staleTime: 60000,
  });

  // Build templates map
  const templates = useMemo(() => {
    const map: Record<string, ProfileTemplate> = {};
    if (profileTemplatesData) {
      for (const t of profileTemplatesData) {
        map[t.name] = t;
      }
    }
    // Ensure generic always exists
    if (!map.generic) {
      map.generic = { name: 'generic', description: 'Use global defaults' };
    }
    return map;
  }, [profileTemplatesData]);

  const templateList = useMemo(() => {
    const order = ['web_server', 'email_server', 'dns_server', 'api_server', 'generic', 'custom'];
    const result = order
      .filter(name => name === 'custom' || templates[name])
      .map(name => name === 'custom'
        ? { name: 'custom', description: 'Define all settings manually' } as ProfileTemplate
        : templates[name]
      );
    return result;
  }, [templates]);

  // Fetch data
  const { data: rulesStats } = useQuery({
    queryKey: ['rules-stats'],
    queryFn: () => api.getRulesStats(),
    refetchInterval: 5000,
  });

  const { data: whitelistData, isLoading: whitelistLoading } = useQuery({
    queryKey: ['rules-whitelist'],
    queryFn: () => api.getRulesWhitelist() as Promise<{ entries: IPEntry[]; count: number }>,
  });

  const { data: blacklistData, isLoading: blacklistLoading } = useQuery({
    queryKey: ['rules-blacklist'],
    queryFn: () => api.getRulesBlacklist() as Promise<{ entries: IPEntry[]; count: number }>,
  });

  const { data: protectedData, isLoading: protectedLoading } = useQuery({
    queryKey: ['rules-protected'],
    queryFn: () => api.getRulesProtected() as Promise<{ entries: IPEntry[]; count: number }>,
  });

  // Protection Stages
  const { data: stagesData, isLoading: stagesLoading } = useQuery<Record<string, StageInfo[]> | null>({
    queryKey: ['stages-categories'],
    queryFn: async () => {
      try {
        return await api.getLayer1StagesByCategory() as Record<string, StageInfo[]>;
      } catch {
        return null;
      }
    },
    enabled: mainCategory === 'attack-protection',
  });

  // Signatures
  const { data: signaturesData, isLoading: signaturesLoading } = useQuery<SignaturesData | null>({
    queryKey: ['signatures'],
    queryFn: async () => {
      try {
        return await api.getSignatures() as unknown as SignaturesData;
      } catch {
        return null;
      }
    },
    enabled: mainCategory === 'attack-protection' && protectionTab === 'signatures',
  });

  // Protocols
  const { data: protocolsData, isLoading: protocolsLoading } = useQuery<ProtocolsData | null>({
    queryKey: ['protocols'],
    queryFn: async () => {
      try {
        return await api.getProtocols() as unknown as ProtocolsData;
      } catch {
        return null;
      }
    },
    enabled: mainCategory === 'attack-protection' && protectionTab === 'protocols',
  });

  // Exclude 'mode' category and stages with dedicated controls elsewhere
  const filteredStages = stagesData
    ? STAGE_ORDER.flatMap(cat => (stagesData[cat] || []).filter(s => !STAGES_HIDDEN_FROM_LIST.has(s.id)))
    : [];
  const activeStagesCount = filteredStages.filter(s => s.enabled).length;
  const totalStagesCount = filteredStages.length;

  // Signature functions
  const toggleSignature = async (sigId: number, enabled: boolean) => {
    try {
      await api.setSignatureEnabled(sigId, enabled);
      toast.success(`Signature ${enabled ? 'enabled' : 'disabled'}`);
    } catch {
      toast.error('Failed');
    } finally {
      queryClient.invalidateQueries({ queryKey: ['signatures'] });
    }
  };

  const toggleSignaturesEnabled = async (enabled: boolean) => {
    try {
      await api.setSignaturesEnabled(enabled);
      toast.success(`Signatures ${enabled ? 'enabled' : 'disabled'}`);
    } catch {
      toast.error('Failed');
    } finally {
      queryClient.invalidateQueries({ queryKey: ['signatures'] });
    }
  };

  // Protocol functions
  const toggleProtocolsEnabled = async (enabled: boolean) => {
    try {
      await api.setProtocolsEnabled(enabled);
      toast.success(`Protocol filter ${enabled ? 'enabled' : 'disabled'}`);
    } catch {
      toast.error('Failed');
    } finally {
      queryClient.invalidateQueries({ queryKey: ['protocols'] });
    }
  };

  const setProtocolAction = async (action: 'drop' | 'accept' | 'rate_limit') => {
    try {
      await api.setProtocolsAction(action);
      toast.success('Default action updated');
    } catch {
      toast.error('Failed');
    } finally {
      queryClient.invalidateQueries({ queryKey: ['protocols'] });
    }
  };

  const addProtocol = async () => {
    if (!newProtocol) return;
    try {
      await api.addProtocol(newProtocol);
      toast.success('Protocol added');
      setNewProtocol('');
    } catch {
      toast.error('Failed to add protocol');
    } finally {
      queryClient.invalidateQueries({ queryKey: ['protocols'] });
    }
  };

  const removeProtocol = async (protoNum: number) => {
    try {
      await api.removeProtocol(protoNum);
      toast.success('Protocol removed');
    } catch {
      toast.error('Failed');
    } finally {
      queryClient.invalidateQueries({ queryKey: ['protocols'] });
    }
  };

  const toggleStage = async (stageId: string, enabled: boolean) => {
    try {
      if (enabled) {
        await api.enableLayer1Stage(stageId);
      } else {
        await api.disableLayer1Stage(stageId);
      }
      toast.success(`Stage ${enabled ? 'enabled' : 'disabled'}`);
    } catch {
      toast.error('Failed to toggle stage');
    } finally {
      queryClient.invalidateQueries({ queryKey: ['stages-categories'] });
    }
  };

  // Mutations
  const addIPMutation = useMutation({
    mutationFn: async (data: { ip: string; description?: string; expires_hours?: number; profile?: string; mode?: string }) => {
      if (ipListTab === 'whitelist') return api.addRulesWhitelist(data.ip, data.description, data.expires_hours, data.mode);
      if (ipListTab === 'blacklist') return api.addRulesBlacklist(data.ip, data.description, data.expires_hours);
      return api.addRulesProtected({ ip: data.ip, description: data.description, profile: data.profile || 'generic' });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`rules-${ipListTab}`] });
      queryClient.invalidateQueries({ queryKey: ['rules-protected'] });
      queryClient.invalidateQueries({ queryKey: ['rules-stats'] });
      toast.success(`Added to ${ipListTab}`);
      setShowAddModal(false);
      setNewIP(''); setNewDescription(''); setNewDuration(''); setNewProfile('generic'); setNewMode('bypass');
    },
    onError: (error: Error) => toast.error(error.message || 'Failed'),
  });

  const removeIPMutation = useMutation({
    mutationFn: (data: { ip: string }) => {
      if (ipListTab === 'whitelist') return api.removeRulesWhitelist(data.ip);
      if (ipListTab === 'blacklist') return api.removeRulesBlacklist(data.ip);
      return api.removeRulesProtected(data.ip);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`rules-${ipListTab}`] });
      queryClient.invalidateQueries({ queryKey: ['rules-protected'] });
      queryClient.invalidateQueries({ queryKey: ['rules-stats'] });
      toast.success('Removed');
    },
  });

  const clearListMutation = useMutation({
    mutationFn: () => {
      if (ipListTab === 'whitelist') return api.clearRulesWhitelist();
      if (ipListTab === 'blacklist') return api.clearRulesBlacklist();
      return api.clearRulesProtected();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`rules-${ipListTab}`] });
      queryClient.invalidateQueries({ queryKey: ['rules-stats'] });
      toast.success('Cleared');
    },
  });

  const updateProfileMutation = useMutation({
    mutationFn: async (data: { ip: string; profile: string; overrides: Record<string, unknown> }) => {
      return api.updateProtectedProfile(data.ip, data.profile, data.overrides);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules-protected'] });
      toast.success('Profile updated');
      setShowEditModal(false);
      setEditingIP(null);
    },
    onError: (error: Error) => toast.error(error.message || 'Failed to update profile'),
  });

  // Check IP
  const handleCheckIP = async () => {
    if (!checkIpValue) return;
    try {
      const result = await api.checkIP(checkIpValue);
      setCheckResult(result);
    } catch { toast.error('Failed to check IP'); }
  };

  // Bulk import
  const handleBulkImport = async () => {
    if (!bulkIPs.trim()) return;
    const lines = bulkIPs.split('\n').filter(l => l.trim());
    let ok = 0, fail = 0;
    for (const line of lines) {
      const parts = line.split(/[,\t]/).map(s => s.trim());
      const ip = parts[0]; const desc = parts[1] || '';
      if (!ip) continue;
      try {
        if (ipListTab === 'whitelist') await api.addRulesWhitelist(ip, desc);
        else if (ipListTab === 'blacklist') await api.addRulesBlacklist(ip, desc);
        else await api.addRulesProtected({ ip, description: desc, profile: 'generic' });
        ok++;
      } catch { fail++; }
    }
    queryClient.invalidateQueries({ queryKey: [`rules-${ipListTab}`] });
    queryClient.invalidateQueries({ queryKey: ['rules-protected'] });
    queryClient.invalidateQueries({ queryKey: ['rules-stats'] });
    if (ok > 0) toast.success(`Imported ${ok} IPs`);
    if (fail > 0) toast.error(`Failed: ${fail} IPs`);
    setShowBulkModal(false); setBulkIPs('');
  };

  const handleClearList = () => {
    if (confirmClear) { clearListMutation.mutate(); setConfirmClear(false); }
    else { setConfirmClear(true); setTimeout(() => setConfirmClear(false), 3000); }
  };

  // Open edit modal - populate from entry + template
  const openEditProfile = (entry: IPEntry) => {
    setEditingIP(entry);
    const profName = entry.profile_name || 'generic';
    setEditProfile(profName);

    // Pre-populate overrides from existing entry
    const ov = entry.profile_overrides || {};
    const fields: Record<string, string> = {};
    const numFields = ['pps_limit', 'bps_limit', 'attack_pps_limit', 'attack_bps_limit', 'max_conn_per_src', 'syn_challenge_threshold'];
    for (const f of numFields) {
      fields[f] = ov[f] !== undefined && ov[f] !== null ? String(ov[f]) : '';
    }
    fields.syn_proxy_mode = (ov.syn_proxy_mode as string) || '';
    fields.tcp_ports = Array.isArray(ov.tcp_ports) ? (ov.tcp_ports as number[]).join(', ') : '';
    fields.udp_ports = Array.isArray(ov.udp_ports) ? (ov.udp_ports as number[]).join(', ') : '';
    fields.other_allowed_protos = Array.isArray(ov.other_allowed_protos) ? (ov.other_allowed_protos as number[]).join(', ') : '';
    // Pre-populate per-protocol actions and rate limits
    for (const f of ['tcp_action', 'udp_action', 'icmp_action', 'other_action',
                      'tcp_rate_limit_pps', 'udp_rate_limit_pps', 'icmp_rate_limit_pps', 'other_rate_limit_pps']) {
      fields[f] = ov[f] !== undefined && ov[f] !== null ? String(ov[f]) : '';
    }
    setEditOverrides(fields);
    setShowEditModal(true);
  };

  // When template changes in edit modal, reset overrides
  const handleTemplateChange = (newTemplate: string) => {
    setEditProfile(newTemplate);
    // Clear overrides when switching template (user starts fresh)
    setEditOverrides({
      pps_limit: '', bps_limit: '', attack_pps_limit: '', attack_bps_limit: '',
      max_conn_per_src: '', syn_proxy_mode: '', syn_challenge_threshold: '',
      tcp_ports: '', udp_ports: '', other_allowed_protos: '',
      tcp_action: '', udp_action: '', icmp_action: '', other_action: '',
      tcp_rate_limit_pps: '', udp_rate_limit_pps: '', icmp_rate_limit_pps: '', other_rate_limit_pps: '',
    });
  };

  // Get template default for a field (for placeholder display)
  const getTemplateDefault = (field: string): string => {
    const tmpl = templates[editProfile];
    if (!tmpl) return '';
    const val = (tmpl as unknown as Record<string, unknown>)[field];
    if (val === undefined || val === null) return '';
    if (Array.isArray(val)) return val.join(', ');
    return String(val);
  };

  // Save profile
  const handleSaveProfile = () => {
    if (!editingIP) return;
    const overrides: Record<string, unknown> = {};
    const numFields = ['pps_limit', 'bps_limit', 'attack_pps_limit', 'attack_bps_limit', 'max_conn_per_src', 'syn_challenge_threshold',
      'tcp_rate_limit_pps', 'udp_rate_limit_pps', 'icmp_rate_limit_pps', 'other_rate_limit_pps'];
    for (const f of numFields) {
      if (editOverrides[f]?.trim()) overrides[f] = parseInt(editOverrides[f]);
    }
    if (editOverrides.syn_proxy_mode?.trim()) overrides.syn_proxy_mode = editOverrides.syn_proxy_mode;
    if (editOverrides.tcp_ports?.trim()) overrides.tcp_ports = editOverrides.tcp_ports.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
    if (editOverrides.udp_ports?.trim()) overrides.udp_ports = editOverrides.udp_ports.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
    if (editOverrides.other_allowed_protos?.trim()) overrides.other_allowed_protos = editOverrides.other_allowed_protos.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p) && p >= 0 && p <= 255);
    // Per-protocol actions
    for (const f of ['tcp_action', 'udp_action', 'icmp_action', 'other_action']) {
      if (editOverrides[f]?.trim()) overrides[f] = editOverrides[f];
    }
    updateProfileMutation.mutate({ ip: editingIP.ip, profile: editProfile, overrides });
  };

  // Effective profile for edit modal preview
  const editEffective = useMemo(() => {
    const base = templates[editProfile] || {};
    const result: Record<string, unknown> = { ...base };
    const numFields = ['pps_limit', 'bps_limit', 'attack_pps_limit', 'attack_bps_limit', 'max_conn_per_src', 'syn_challenge_threshold',
      'tcp_rate_limit_pps', 'udp_rate_limit_pps', 'icmp_rate_limit_pps', 'other_rate_limit_pps'];
    for (const f of numFields) {
      if (editOverrides[f]?.trim()) result[f] = parseInt(editOverrides[f]);
    }
    if (editOverrides.syn_proxy_mode?.trim()) result.syn_proxy_mode = editOverrides.syn_proxy_mode;
    if (editOverrides.tcp_ports?.trim()) result.tcp_ports = editOverrides.tcp_ports.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
    if (editOverrides.udp_ports?.trim()) result.udp_ports = editOverrides.udp_ports.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
    if (editOverrides.other_allowed_protos?.trim()) result.other_allowed_protos = editOverrides.other_allowed_protos.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p) && p >= 0 && p <= 255);
    // Per-protocol actions
    for (const f of ['tcp_action', 'udp_action', 'icmp_action', 'other_action']) {
      if (editOverrides[f]?.trim()) result[f] = editOverrides[f];
    }
    return result;
  }, [editProfile, editOverrides, templates]);

  // IP list helpers
  const getCurrentIPList = () => {
    switch (ipListTab) {
      case 'whitelist': return whitelistData;
      case 'blacklist': return blacklistData;
      case 'protected': return protectedData;
    }
  };
  const isIPListLoading = () => {
    switch (ipListTab) {
      case 'whitelist': return whitelistLoading;
      case 'blacklist': return blacklistLoading;
      case 'protected': return protectedLoading;
    }
  };

  const currentIPData = getCurrentIPList();
  const filteredEntries = currentIPData?.entries.filter(entry =>
    entry.ip.includes(search) || (entry.description || '').toLowerCase().includes(search.toLowerCase()) ||
    (entry.profile_name || '').toLowerCase().includes(search.toLowerCase())
  ) || [];

  // Override field rendered inline (not a sub-component, to preserve input focus)
  const renderOverrideField = (label: string, field: string, placeholder?: string, type: string = 'number') => {
    const templateVal = getTemplateDefault(field);
    const ph = placeholder || (templateVal ? `${templateVal} (from template)` : 'Not set');
    return (
      <div>
        <label className="block text-xs font-medium text-slate-500 dark:text-slate-400 mb-1">{label}</label>
        <input
          type={type}
          value={editOverrides[field] || ''}
          onChange={(e) => setEditOverrides(prev => ({ ...prev, [field]: e.target.value }))}
          placeholder={ph}
          className={clsx(
            'input w-full text-sm',
            editOverrides[field]?.trim() && 'ring-1 ring-blue-300 dark:ring-blue-700'
          )}
          min={type === 'number' ? 0 : undefined}
        />
        {editOverrides[field]?.trim() && templateVal && (
          <p className="text-[10px] text-blue-500 mt-0.5">Override (template: {templateVal})</p>
        )}
      </div>
    );
  };

  // Effective settings badge for table rows
  const ProfileBadge = ({ entry }: { entry: IPEntry }) => {
    const profName = entry.profile_name || 'generic';
    const theme = getTheme(profName);
    const eff = getEffectiveProfile(profName, entry.profile_overrides, templates);
    const overrideCount = Object.keys(entry.profile_overrides || {}).length;

    return (
      <div className="flex items-center gap-2">
        <span className={clsx('inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold border', theme.bg, theme.text, theme.border)}>
          <span className={clsx('w-2 h-2 rounded-full', theme.dot)} />
          {getProfileLabel(profName)}
        </span>
        {overrideCount > 0 && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400 font-medium">
            +{overrideCount}
          </span>
        )}
        {/* Quick info pills */}
        <div className="hidden lg:flex items-center gap-1">
          {(eff.tcp_ports as number[] | undefined)?.length ? (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-500 font-mono">
              TCP:{formatPorts(eff.tcp_ports as number[])}
            </span>
          ) : null}
          {(eff.syn_proxy_mode as string) && (eff.syn_proxy_mode as string) !== 'global' && (
            <span className={clsx('text-[10px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 font-medium',
              SYN_MODE_LABELS[eff.syn_proxy_mode as string]?.color || 'text-slate-500')}>
              SYN:{SYN_MODE_LABELS[eff.syn_proxy_mode as string]?.label || eff.syn_proxy_mode as string}
            </span>
          )}
        </div>
      </div>
    );
  };

  // Expanded row detail
  const ProfileDetail = ({ entry }: { entry: IPEntry }) => {
    const eff = getEffectiveProfile(entry.profile_name, entry.profile_overrides, templates);
    const synMode = SYN_MODE_LABELS[(eff.syn_proxy_mode as string) || 'global'] || SYN_MODE_LABELS.global;

    return (
      <tr className="bg-slate-50/50 dark:bg-slate-800/30">
        <td colSpan={6} className="px-4 py-3">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider flex items-center gap-1">
                <SignalIcon className="h-3 w-3" /> Rate Limits
              </h4>
              <div className="space-y-1">
                <div className="flex justify-between"><span className="text-slate-500">Normal PPS</span><span className="font-mono font-medium text-slate-900 dark:text-white">{formatPPS(eff.pps_limit as number)}</span></div>
                <div className="flex justify-between"><span className="text-slate-500">Attack PPS</span><span className="font-mono font-medium text-red-600">{formatPPS(eff.attack_pps_limit as number)}</span></div>
                {(eff.bps_limit as number) ? <div className="flex justify-between"><span className="text-slate-500">Normal BPS</span><span className="font-mono font-medium text-slate-900 dark:text-white">{formatPPS(eff.bps_limit as number)}</span></div> : null}
              </div>
            </div>
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider flex items-center gap-1">
                <LockClosedIcon className="h-3 w-3" /> SYN Proxy
              </h4>
              <div className="space-y-1">
                <div className="flex justify-between"><span className="text-slate-500">Mode</span><span className={clsx('font-medium', synMode.color)}>{synMode.label}</span></div>
                {(eff.syn_proxy_mode as string) === 'threshold' && (
                  <div className="flex justify-between"><span className="text-slate-500">Threshold</span><span className="font-mono font-medium text-slate-900 dark:text-white">{formatPPS(eff.syn_challenge_threshold as number)} PPS</span></div>
                )}
              </div>
            </div>
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider flex items-center gap-1">
                <BoltIcon className="h-3 w-3" /> Connections
              </h4>
              <div className="space-y-1">
                <div className="flex justify-between"><span className="text-slate-500">Max/Src</span><span className="font-mono font-medium text-slate-900 dark:text-white">{(eff.max_conn_per_src as number) ? formatPPS(eff.max_conn_per_src as number) : '-'}</span></div>
              </div>
            </div>
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider flex items-center gap-1">
                <GlobeAltIcon className="h-3 w-3" /> Allowed Ports
              </h4>
              <div className="space-y-1">
                <div className="flex justify-between"><span className="text-slate-500">TCP</span><span className="font-mono font-medium text-slate-900 dark:text-white">{formatPorts(eff.tcp_ports as number[])}</span></div>
                <div className="flex justify-between"><span className="text-slate-500">UDP</span><span className="font-mono font-medium text-slate-900 dark:text-white">{formatPorts(eff.udp_ports as number[])}</span></div>
              </div>
            </div>
          </div>
        </td>
      </tr>
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Rules & Configuration</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Manage IP lists, geo-blocking, attack signatures, and protection settings
          </p>
        </div>
        <span className={clsx(
          'inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium',
          (rulesStats as Record<string, unknown>)?.datapath_connected
            ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-500/10 dark:text-emerald-400'
            : 'bg-red-100 text-red-800 dark:bg-red-500/10 dark:text-red-400'
        )}>
          <span className={clsx('h-1.5 w-1.5 rounded-full', (rulesStats as Record<string, unknown>)?.datapath_connected ? 'bg-emerald-500' : 'bg-red-500')} />
          {(rulesStats as Record<string, unknown>)?.datapath_connected ? 'Datapath Connected' : 'Disconnected'}
        </span>
      </div>

      {/* Main Category Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <button
          onClick={() => setMainCategory('access-control')}
          className={clsx(
            'card text-left transition-all',
            mainCategory === 'access-control' ? 'ring-2 ring-emerald-500/50' : 'hover:shadow-md'
          )}
        >
          <div className="card-body">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-emerald-100 dark:bg-emerald-900/40">
                <ShieldCheckIcon className="h-5 w-5 text-emerald-600" />
              </div>
              <div>
                <div className="font-semibold text-slate-900 dark:text-white">Access Control</div>
                <div className="text-sm text-slate-500">IP lists, geo-blocking</div>
              </div>
            </div>
          </div>
        </button>
        <button
          onClick={() => setMainCategory('attack-protection')}
          className={clsx(
            'card text-left transition-all',
            mainCategory === 'attack-protection' ? 'ring-2 ring-red-500/50' : 'hover:shadow-md'
          )}
        >
          <div className="card-body">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-red-100 dark:bg-red-900/40">
                <ShieldExclamationIcon className="h-5 w-5 text-red-600" />
              </div>
              <div>
                <div className="font-semibold text-slate-900 dark:text-white">Attack Protection</div>
                <div className="text-sm text-slate-500">Signatures, protocols, stages</div>
              </div>
            </div>
          </div>
        </button>
      </div>

      {/* ==================== ACCESS CONTROL SECTION ==================== */}
      {mainCategory === 'access-control' && (
        <div className="space-y-6 animate-fade-in">

      {/* Quick Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {[
          { tab: 'whitelist' as IPListTab, label: 'Whitelisted', count: (rulesStats as Record<string, number>)?.whitelist_count || 0, icon: CheckIcon, color: 'emerald' },
          { tab: 'blacklist' as IPListTab, label: 'Blacklisted', count: (rulesStats as Record<string, number>)?.blacklist_count || 0, icon: XMarkIcon, color: 'red' },
          { tab: 'protected' as IPListTab, label: 'Protected', count: (rulesStats as Record<string, number>)?.protected_count || 0, icon: ServerStackIcon, color: 'amber' },
        ].map(({ tab, label, count, icon: Icon, color }) => (
          <button
            key={tab}
            onClick={() => setIPListTab(tab)}
            className={clsx(
              'card text-left transition-all',
              ipListTab === tab ? `ring-2 ring-${color}-500/50` : 'hover:shadow-md'
            )}
          >
            <div className="card-body">
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg bg-${color}-100 dark:bg-${color}-900/40`}><Icon className={`h-5 w-5 text-${color}-600`} /></div>
                <div>
                  <div className="text-2xl font-bold text-slate-900 dark:text-white">{count}</div>
                  <div className="text-sm text-slate-500">{label}</div>
                </div>
              </div>
            </div>
          </button>
        ))}
      </div>

      {/* IP Check */}
      <div className="card">
        <div className="card-body">
          <h3 className="font-medium text-slate-900 dark:text-white mb-3">Check IP Status</h3>
          <div className="flex gap-2">
            <input type="text" value={checkIpValue} onChange={(e) => setCheckIpValue(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && handleCheckIP()} placeholder="Enter IP address" className="input flex-1" />
            <button onClick={handleCheckIP} className="btn btn-primary">Check</button>
          </div>
          {checkResult && (
            <div className={clsx('mt-3 p-3 rounded-lg border', checkResult.blacklisted ? 'bg-red-50 border-red-200 dark:bg-red-900/10 dark:border-red-800' : checkResult.whitelisted ? 'bg-emerald-50 border-emerald-200 dark:bg-emerald-900/10 dark:border-emerald-800' : checkResult.protected ? 'bg-amber-50 border-amber-200 dark:bg-amber-900/10 dark:border-amber-800' : 'bg-slate-50 border-slate-200 dark:bg-slate-800 dark:border-slate-700')}>
              <span className="font-mono text-sm">{checkResult.ip as string}</span>
              {!!checkResult.blacklisted && <span className="ml-2 badge bg-red-500 text-white text-xs">BLACKLISTED</span>}
              {!!checkResult.whitelisted && <span className="ml-2 badge bg-emerald-500 text-white text-xs">WHITELISTED</span>}
              {!!checkResult.protected && <span className="ml-2 badge bg-amber-500 text-white text-xs">PROTECTED</span>}
              {!checkResult.blacklisted && !checkResult.whitelisted && !checkResult.protected && <span className="ml-2 badge bg-slate-500 text-slate-900 dark:text-white text-xs">NOT IN LISTS</span>}
            </div>
          )}
        </div>
      </div>

      {/* Tab bar */}
      <div className="flex flex-wrap items-center gap-4">
        <div className="flex gap-2">
          {[
            { tab: 'whitelist' as IPListTab, label: 'Whitelist', icon: CheckIcon, activeClass: 'bg-emerald-600 text-white hover:bg-emerald-700' },
            { tab: 'blacklist' as IPListTab, label: 'Blacklist', icon: XMarkIcon, activeClass: 'bg-red-600 text-white hover:bg-red-700' },
            { tab: 'protected' as IPListTab, label: 'Protected', icon: ServerStackIcon, activeClass: 'bg-amber-600 text-white hover:bg-amber-700' },
          ].map(({ tab, label, icon: Icon, activeClass }) => (
            <button key={tab} onClick={() => setIPListTab(tab)} className={clsx('btn btn-sm', ipListTab === tab ? activeClass : 'btn-secondary')}>
              <Icon className="h-4 w-4 inline mr-1" /> {label}
            </button>
          ))}
        </div>
      </div>

      {/* IP List Card */}
      <div className="card overflow-hidden">
        <div className="card-header flex items-center justify-between flex-wrap gap-3">
          <h3 className={clsx('font-medium', ipListTab === 'whitelist' ? 'text-emerald-600' : ipListTab === 'blacklist' ? 'text-red-600' : 'text-amber-600')}>
            {ipListTab === 'whitelist' ? 'Trusted IPs' : ipListTab === 'blacklist' ? 'Blocked IPs' : 'Protected Servers'}
            <span className="ml-2 text-sm text-slate-500 font-normal">({filteredEntries.length})</span>
          </h3>
          <div className="flex items-center gap-2 flex-wrap">
            <div className="relative">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500 dark:text-slate-400" />
              <input type="text" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Filter..." className="input pl-9 py-1.5 text-sm w-40" />
            </div>
            <button onClick={() => setShowBulkModal(true)} className="btn btn-secondary btn-sm"><PlusIcon className="h-4 w-4" /> Bulk</button>
            {ipListTab !== 'protected' && (
              <button onClick={handleClearList} className={clsx('btn btn-sm text-slate-900 dark:text-white', confirmClear ? 'bg-orange-600 hover:bg-orange-700' : 'btn-danger')}>
                {confirmClear ? 'Confirm?' : 'Clear All'}
              </button>
            )}
            <button onClick={() => setShowAddModal(true)} className={clsx('btn btn-sm text-slate-900 dark:text-white', ipListTab === 'whitelist' ? 'bg-emerald-600 hover:bg-emerald-700' : ipListTab === 'blacklist' ? 'bg-red-600 hover:bg-red-700' : 'bg-amber-600 hover:bg-amber-700')}>
              <PlusIcon className="h-4 w-4" /> Add IP
            </button>
          </div>
        </div>

        {isIPListLoading() ? (
          <div className="p-6"><SkeletonCard lines={4} /></div>
        ) : filteredEntries.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="table">
              <thead>
                <tr>
                  {ipListTab === 'protected' && <th className="px-2 py-3 w-8"></th>}
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase">IP Address</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase">Description</th>
                  {ipListTab === 'whitelist' && <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase">Mode</th>}
                  {ipListTab === 'protected' && <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase">Profile</th>}
                  <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase">Added</th>
                  {ipListTab !== 'protected' && <th className="px-4 py-3 text-left text-xs font-medium text-slate-500 uppercase">Expires</th>}
                  <th className="px-4 py-3 text-right text-xs font-medium text-slate-500 uppercase w-24">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                {filteredEntries.map((entry) => (
                  <React.Fragment key={entry.ip}>
                    <tr className={clsx('hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors', expandedIP === entry.ip && 'bg-slate-50/50 dark:bg-slate-800/20')}>
                      {ipListTab === 'protected' && (
                        <td className="px-2 py-3">
                          <button onClick={() => setExpandedIP(expandedIP === entry.ip ? null : entry.ip)} className="p-1 rounded hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors">
                            <ChevronDownIcon className={clsx('h-4 w-4 text-slate-500 dark:text-slate-400 transition-transform', expandedIP === entry.ip && 'rotate-180')} />
                          </button>
                        </td>
                      )}
                      <td className="px-4 py-3 font-mono text-sm font-medium text-slate-900 dark:text-white">{entry.ip}</td>
                      <td className="px-4 py-3 text-sm text-slate-500 max-w-[200px] truncate">{entry.description || '-'}</td>
                      {ipListTab === 'whitelist' && (
                        <td className="px-4 py-3 text-sm">
                          <span className={clsx('inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium', entry.mode === 'track' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300' : 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-300')}>
                            {entry.mode === 'track' ? 'Track' : 'Bypass'}
                          </span>
                        </td>
                      )}
                      {ipListTab === 'protected' && (
                        <td className="px-4 py-3 text-sm">
                          <ProfileBadge entry={entry} />
                        </td>
                      )}
                      <td className="px-4 py-3 text-sm text-slate-500">{entry.added || entry.created ? new Date(entry.added || entry.created!).toLocaleDateString() : '-'}</td>
                      {ipListTab !== 'protected' && <td className="px-4 py-3 text-sm text-slate-500">{entry.expires ? new Date(entry.expires).toLocaleDateString() : 'Never'}</td>}
                      <td className="px-4 py-3 text-right">
                        <div className="flex items-center justify-end gap-1">
                          {ipListTab === 'protected' && (
                            <button onClick={() => openEditProfile(entry)} className="text-blue-500 hover:text-blue-700 transition-colors p-1.5 rounded hover:bg-blue-50 dark:hover:bg-blue-900/20" title="Edit profile">
                              <PencilSquareIcon className="h-4 w-4" />
                            </button>
                          )}
                          <button onClick={() => removeIPMutation.mutate({ ip: entry.ip })} className="text-red-500 hover:text-red-700 transition-colors p-1.5 rounded hover:bg-red-50 dark:hover:bg-red-900/20" title="Remove">
                            <TrashIcon className="h-4 w-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                    {ipListTab === 'protected' && expandedIP === entry.ip && (
                      <ProfileDetail entry={entry} />
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState type="empty" icon={ShieldCheckIcon} title="No entries" description={`No IPs in the ${ipListTab}. Add an IP to get started.`} size="sm" action={{ label: 'Add IP', onClick: () => setShowAddModal(true) }} />
        )}
      </div>

        </div>
      )}

      {/* ==================== ATTACK PROTECTION SECTION ==================== */}
      {mainCategory === 'attack-protection' && (
        <div className="space-y-6 animate-fade-in">

          {/* Sub-tabs */}
          <div className="flex gap-2">
            {([
              { tab: 'signatures' as ProtectionTab, label: 'Attack Signatures' },
              { tab: 'protocols' as ProtectionTab, label: 'Protocol Filter' },
              { tab: 'stages' as ProtectionTab, label: 'Protection Stages' },
            ]).map(({ tab, label }) => (
              <button key={tab} onClick={() => setProtectionTab(tab)} className={clsx('btn btn-sm', protectionTab === tab ? 'btn-primary' : 'btn-secondary')}>
                {label}
              </button>
            ))}
          </div>

          {/* ====== SIGNATURES TAB ====== */}
          {protectionTab === 'signatures' && signaturesLoading && (
            <div className="space-y-4"><SkeletonCard lines={2} /><SkeletonCard lines={4} /></div>
          )}
          {protectionTab === 'signatures' && !signaturesLoading && !signaturesData && (
            <EmptyState type="offline" title="Backend Not Available" description="Ensure FastAPI backend is running on port 8000" />
          )}
          {protectionTab === 'signatures' && !signaturesLoading && signaturesData && (
            <div className="space-y-6 animate-fade-in">
              {/* Master toggle */}
              <div className="card">
                <div className="card-body flex items-center justify-between">
                  <div>
                    <h3 className="font-medium text-slate-900 dark:text-white">Attack Signature Detection</h3>
                    <p className="text-sm text-slate-500 mt-0.5">Detect known attack patterns and tools</p>
                  </div>
                  <Toggle enabled={!!signaturesData.config.enabled} onChange={toggleSignaturesEnabled} label="Signatures" />
                </div>
              </div>

              {/* Signature categories */}
              {SIGNATURE_CATEGORY_ORDER.map(cat => {
                const sigs = signaturesData.categories?.[cat];
                if (!sigs || sigs.length === 0) return null;
                const enabledCount = sigs.filter(s => s.enabled).length;
                return (
                  <div key={cat} className="card overflow-hidden">
                    <div className="card-header">
                      <div className="flex items-center justify-between">
                        <div>
                          <h4 className="font-medium text-slate-900 dark:text-white">{SIGNATURE_CATEGORY_LABELS[cat]?.label || cat}</h4>
                          <p className="text-xs text-slate-500 mt-0.5">{SIGNATURE_CATEGORY_LABELS[cat]?.description || ''}</p>
                        </div>
                        <span className="text-xs font-medium text-slate-500">{enabledCount}/{sigs.length}</span>
                      </div>
                    </div>
                    <div className="card-body grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                      {sigs.map(sig => (
                        <div key={sig.id} className={clsx(
                          'flex items-center justify-between p-3 rounded-lg border transition-colors',
                          sig.enabled
                            ? 'bg-emerald-50 border-emerald-200 dark:bg-emerald-900/10 dark:border-emerald-700'
                            : 'bg-slate-50 border-slate-200 dark:bg-slate-800/50 dark:border-slate-700'
                        )}>
                          <div className="flex-1 min-w-0 mr-3">
                            <div className="text-sm font-medium text-slate-900 dark:text-white">{sig.name}</div>
                            {sig.description && <div className="text-xs text-slate-500 truncate">{sig.description}</div>}
                          </div>
                          <Toggle size="sm" enabled={sig.enabled} onChange={(v) => toggleSignature(sig.id, v)} label={sig.name} />
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })}

              {/* Options */}
              <div className="card">
                <div className="card-header">
                  <h4 className="font-medium text-slate-900 dark:text-white">Signature Options</h4>
                </div>
                <div className="card-body divide-y divide-slate-100 dark:divide-slate-800">
                  {[
                    { key: 'log_matches', label: 'Log Matches', desc: 'Record signature detections in logs' },
                    { key: 'block_amplification', label: 'Block Amplification', desc: 'Drop reflection/amplification attacks' },
                    { key: 'block_scans', label: 'Block Scans', desc: 'Block port scanning attempts' },
                  ].map(opt => (
                    <div key={opt.key} className="flex items-center justify-between py-3 first:pt-0 last:pb-0">
                      <div>
                        <div className="text-sm font-medium text-slate-900 dark:text-white">{opt.label}</div>
                        <div className="text-xs text-slate-500">{opt.desc}</div>
                      </div>
                      <Toggle
                        size="sm"
                        enabled={!!(signaturesData.config as Record<string, unknown>)[opt.key]}
                        onChange={async (v) => {
                          try {
                            await api.updateLayer1ConfigValue('signatures', opt.key, v);
                            toast.success('Updated');
                          } catch { toast.error('Failed'); }
                          finally { queryClient.invalidateQueries({ queryKey: ['signatures'] }); }
                        }}
                        label={opt.label}
                      />
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ====== PROTOCOLS TAB ====== */}
          {protectionTab === 'protocols' && protocolsLoading && (
            <div className="space-y-4"><SkeletonCard lines={2} /><SkeletonCard lines={4} /></div>
          )}
          {protectionTab === 'protocols' && !protocolsLoading && !protocolsData && (
            <EmptyState type="offline" title="Backend Not Available" description="Ensure FastAPI backend is running on port 8000" />
          )}
          {protectionTab === 'protocols' && !protocolsLoading && protocolsData && (
            <div className="space-y-6 animate-fade-in">
              <div className="card">
                {/* Master toggle */}
                <div className="card-body flex items-center justify-between border-b border-slate-100 dark:border-slate-800">
                  <div>
                    <h3 className="font-medium text-slate-900 dark:text-white">Protocol Filter</h3>
                    <p className="text-sm text-slate-500 mt-0.5">Control which IP protocols are allowed through</p>
                  </div>
                  <Toggle enabled={protocolsData.enabled} onChange={toggleProtocolsEnabled} label="Protocol filter" />
                </div>

                {/* Default action */}
                <div className="card-body border-b border-slate-100 dark:border-slate-800">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-sm font-medium text-slate-900 dark:text-white">Default Action</div>
                      <div className="text-xs text-slate-500">Action for protocols not in the allowed list</div>
                    </div>
                    <select
                      value={protocolsData.default_action}
                      onChange={(e) => setProtocolAction(e.target.value as 'drop' | 'accept' | 'rate_limit')}
                      className="input text-sm w-48"
                    >
                      <option value="drop">Drop - Block unknown</option>
                      <option value="accept">Accept - Allow all</option>
                      <option value="rate_limit">Rate Limit - Throttle</option>
                    </select>
                  </div>
                </div>

                {/* Allowed protocols */}
                <div className="card-body">
                  <div className="flex items-center justify-between mb-3">
                    <div className="text-sm font-medium text-slate-900 dark:text-white">
                      Allowed Protocols <span className="text-slate-500 dark:text-slate-400">({protocolsData.allowed_protocols.length})</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <select value={newProtocol} onChange={(e) => setNewProtocol(e.target.value)} className="input text-sm w-44">
                        <option value="">Select protocol...</option>
                        {protocolsData.all_protocols
                          .filter(p => !protocolsData.allowed_protocols.some(a => a.number === p.number))
                          .map(p => (
                            <option key={p.number} value={p.number}>{p.name} ({p.number})</option>
                          ))}
                      </select>
                      <button onClick={addProtocol} disabled={!newProtocol} className="btn btn-primary btn-sm disabled:opacity-50">
                        <PlusIcon className="h-4 w-4" /> Add
                      </button>
                    </div>
                  </div>

                  {protocolsData.allowed_protocols.length > 0 ? (
                    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
                      {protocolsData.allowed_protocols.map(proto => (
                        <div key={proto.number} className="flex items-center justify-between p-2.5 rounded-lg bg-emerald-50 border border-emerald-200 dark:bg-emerald-900/10 dark:border-emerald-700">
                          <div>
                            <div className="text-sm font-medium text-slate-900 dark:text-white">{proto.name}</div>
                            <div className="text-xs text-slate-500 dark:text-slate-400">Protocol {proto.number}</div>
                          </div>
                          <button onClick={() => removeProtocol(proto.number)} className="text-red-400 hover:text-red-600 p-1 rounded hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors">
                            <XMarkIcon className="h-4 w-4" />
                          </button>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-6 text-sm text-slate-500 dark:text-slate-400">No protocols explicitly allowed. All non-TCP/UDP/ICMP traffic uses the default action.</div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* ====== PROTECTION STAGES TAB ====== */}
          {protectionTab === 'stages' && stagesLoading && (
            <div className="space-y-4"><SkeletonCard lines={2} /><SkeletonCard lines={4} /><SkeletonCard lines={4} /></div>
          )}
          {protectionTab === 'stages' && !stagesLoading && !stagesData && (
            <EmptyState type="offline" title="Backend Not Available" description="Ensure FastAPI backend is running on port 8000" />
          )}
          {protectionTab === 'stages' && !stagesLoading && stagesData && (
            <div className="space-y-6 animate-fade-in">
              <InfoBanner variant="warning">
                <div className="font-medium">Protection Stages</div>
                <div className="text-sm mt-0.5">Toggle individual protection features. Disabling may expose servers to attacks.</div>
              </InfoBanner>

              {/* Active stages counter */}
              <div className="card">
                <div className="card-body">
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-blue-100 dark:bg-blue-900/40 rounded-lg">
                      <span className="text-xl font-bold text-blue-600">{activeStagesCount}</span>
                    </div>
                    <div>
                      <div className="text-sm font-medium text-slate-900 dark:text-white">Active Stages</div>
                      <div className="text-xs text-slate-500 dark:text-slate-400">{activeStagesCount} of {totalStagesCount} enabled</div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Stage categories */}
              {STAGE_ORDER.map(cat => {
                const catStages = (stagesData[cat] || []).filter(s => !STAGES_HIDDEN_FROM_LIST.has(s.id));
                if (catStages.length === 0) return null;
                return (
                <div key={cat} className="card overflow-hidden">
                  <div className="card-header flex items-center gap-2">
                    <span className={clsx('w-2 h-2 rounded-full', STAGE_COLORS[cat] || 'bg-emerald-500')} />
                    <h4 className="font-medium text-slate-900 dark:text-white">{STAGE_CATEGORY_NAMES[cat] || cat}</h4>
                  </div>
                  <div className="card-body grid grid-cols-1 md:grid-cols-2 gap-3">
                    {catStages.map(stage => (
                      <div key={stage.id} className={clsx(
                        'flex items-center justify-between p-4 rounded-lg border transition-colors',
                        stage.enabled
                          ? 'bg-emerald-50 border-emerald-200 dark:bg-emerald-900/10 dark:border-emerald-700'
                          : 'bg-slate-50 border-slate-200 dark:bg-slate-800/50 dark:border-slate-700'
                      )}>
                        <div className="flex-1 min-w-0 mr-4">
                          <div className="font-medium text-slate-900 dark:text-white">{stage.name}</div>
                          <div className="text-sm text-slate-500 truncate">{stage.description}</div>
                        </div>
                        <Toggle
                          enabled={stage.enabled}
                          onChange={(v) => toggleStage(stage.id, v)}
                          label={`Toggle ${stage.name}`}
                        />
                      </div>
                    ))}
                  </div>
                </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ==================== ADD IP MODAL ==================== */}
      <Modal open={showAddModal} onClose={() => setShowAddModal(false)} title={`Add to ${ipListTab}`}>
        <form onSubmit={(e) => { e.preventDefault(); addIPMutation.mutate({ ip: newIP, description: newDescription || undefined, expires_hours: newDuration ? parseInt(newDuration) : undefined, profile: ipListTab === 'protected' ? newProfile : undefined, mode: ipListTab === 'whitelist' ? newMode : undefined }); }} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">IP / CIDR</label>
            <input type="text" value={newIP} onChange={(e) => setNewIP(e.target.value)} placeholder="192.168.1.1 or 10.0.0.0/24" className="input w-full" required />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Description</label>
            <input type="text" value={newDescription} onChange={(e) => setNewDescription(e.target.value)} className="input w-full" />
          </div>
          {ipListTab === 'protected' && (
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Protection Profile</label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {templateList.map(t => {
                  const theme = getTheme(t.name);
                  return (
                    <button key={t.name} type="button" onClick={() => setNewProfile(t.name)}
                      className={clsx('p-3 rounded-lg border-2 text-left transition-all', newProfile === t.name ? `${theme.border} ${theme.bg} ring-1 ring-offset-1` : 'border-slate-200 dark:border-slate-700 hover:border-slate-300')}>
                      <div className="flex items-center gap-2">
                        <span className={clsx('w-2.5 h-2.5 rounded-full', theme.dot)} />
                        <span className="text-sm font-semibold text-slate-900 dark:text-white">{getProfileLabel(t.name)}</span>
                      </div>
                      <p className="text-xs text-slate-500 mt-1">{t.description || ''}</p>
                    </button>
                  );
                })}
              </div>
            </div>
          )}
          {ipListTab !== 'protected' && (
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Auto-expire</label>
              <select value={newDuration} onChange={(e) => setNewDuration(e.target.value)} className="input w-full">
                <option value="">Never</option>
                <option value="1">1 hour</option>
                <option value="24">24 hours</option>
                <option value="168">7 days</option>
                <option value="720">30 days</option>
              </select>
            </div>
          )}
          {ipListTab === 'whitelist' && (
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Whitelist Mode</label>
              <div className="flex gap-3">
                <label className={clsx('flex-1 p-3 rounded-lg border-2 cursor-pointer text-center transition-all', newMode === 'bypass' ? 'border-emerald-500 bg-emerald-50 dark:bg-emerald-900/20' : 'border-slate-200 dark:border-slate-700 hover:border-slate-300')}>
                  <input type="radio" name="wl_mode" value="bypass" checked={newMode === 'bypass'} onChange={() => setNewMode('bypass')} className="sr-only" />
                  <div className="text-sm font-medium text-slate-900 dark:text-white">Bypass</div>
                  <div className="text-xs text-slate-500 mt-0.5">Skip all checks</div>
                </label>
                <label className={clsx('flex-1 p-3 rounded-lg border-2 cursor-pointer text-center transition-all', newMode === 'track' ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20' : 'border-slate-200 dark:border-slate-700 hover:border-slate-300')}>
                  <input type="radio" name="wl_mode" value="track" checked={newMode === 'track'} onChange={() => setNewMode('track')} className="sr-only" />
                  <div className="text-sm font-medium text-slate-900 dark:text-white">Track & Allow</div>
                  <div className="text-xs text-slate-500 mt-0.5">Run checks, never drop</div>
                </label>
              </div>
            </div>
          )}
          <div className="flex justify-end gap-3 pt-4 border-t border-slate-200 dark:border-slate-700">
            <button type="button" onClick={() => setShowAddModal(false)} className="btn btn-secondary">Cancel</button>
            <button type="submit" disabled={addIPMutation.isPending} className={clsx('btn text-slate-900 dark:text-white disabled:opacity-50', ipListTab === 'whitelist' ? 'bg-emerald-600 hover:bg-emerald-700' : ipListTab === 'blacklist' ? 'bg-red-600 hover:bg-red-700' : 'bg-amber-600 hover:bg-amber-700')}>
              {addIPMutation.isPending ? 'Adding...' : 'Add'}
            </button>
          </div>
        </form>
      </Modal>

      {/* ==================== BULK IMPORT MODAL ==================== */}
      <Modal open={showBulkModal} onClose={() => setShowBulkModal(false)} title={`Bulk Import to ${ipListTab}`} size="lg">
        <div className="space-y-4">
          <div className="bg-slate-50 dark:bg-slate-800 rounded-lg p-3 text-sm">
            <p className="font-medium text-slate-900 dark:text-white mb-1">Format: One IP per line</p>
            <p className="text-slate-500 dark:text-slate-400">Optionally add description after comma or tab:</p>
            <code className="block mt-2 text-xs bg-slate-200 dark:bg-slate-700 p-2 rounded font-mono">192.168.1.1, Web server<br />10.0.0.0/24&#9;Internal<br />8.8.8.8</code>
          </div>
          <textarea value={bulkIPs} onChange={(e) => setBulkIPs(e.target.value)} placeholder="Enter IP addresses..." rows={8} className="input w-full font-mono text-sm resize-y" />
          <p className="text-xs text-slate-500">{bulkIPs.split('\n').filter(l => l.trim()).length} IPs to import</p>
          <div className="flex justify-end gap-3 pt-4 border-t border-slate-200 dark:border-slate-700">
            <button onClick={() => { setShowBulkModal(false); setBulkIPs(''); }} className="btn btn-secondary">Cancel</button>
            <button onClick={handleBulkImport} disabled={!bulkIPs.trim()} className={clsx('btn text-slate-900 dark:text-white disabled:opacity-50', ipListTab === 'whitelist' ? 'bg-emerald-600 hover:bg-emerald-700' : ipListTab === 'blacklist' ? 'bg-red-600 hover:bg-red-700' : 'bg-amber-600 hover:bg-amber-700')}>Import All</button>
          </div>
        </div>
      </Modal>

      {/* ==================== EDIT PROFILE MODAL ==================== */}
      <Modal open={showEditModal} onClose={() => setShowEditModal(false)} title={`Protection Profile`} size="lg">
        <div className="space-y-5">
          {/* IP identifier */}
          <div className="flex items-center gap-3 p-3 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700">
            <ServerStackIcon className="h-5 w-5 text-amber-500" />
            <div>
              <div className="font-mono font-semibold text-slate-900 dark:text-white">{editingIP?.ip}</div>
              <div className="text-xs text-slate-500">{editingIP?.description || 'No description'}</div>
            </div>
          </div>

          {/* Template selector cards */}
          <div>
            <label className="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">Profile Template</label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              {templateList.map(t => {
                const theme = getTheme(t.name);
                const isSelected = editProfile === t.name;
                return (
                  <button key={t.name} type="button" onClick={() => handleTemplateChange(t.name)}
                    className={clsx(
                      'relative p-3 rounded-lg border-2 text-left transition-all',
                      isSelected ? `${theme.border} ${theme.bg}` : 'border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-300 dark:border-slate-600'
                    )}>
                    {isSelected && <span className="absolute top-2 right-2"><CheckIcon className="h-4 w-4 text-blue-600" /></span>}
                    <div className="flex items-center gap-2 mb-1">
                      <span className={clsx('w-2.5 h-2.5 rounded-full', theme.dot)} />
                      <span className="text-sm font-semibold text-slate-900 dark:text-white">{getProfileLabel(t.name)}</span>
                    </div>
                    <p className="text-[11px] text-slate-500 leading-tight">{t.description || ''}</p>
                    {t.tcp_ports && <p className="text-[10px] font-mono text-slate-500 dark:text-slate-400 mt-1">TCP: {t.tcp_ports.join(', ')}</p>}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Override fields */}
          <div className="border-t border-slate-200 dark:border-slate-700 pt-4">
            <div className="flex items-center justify-between mb-3">
              <h4 className="text-sm font-semibold text-slate-700 dark:text-slate-300">Per-IP Overrides</h4>
              <span className="text-[10px] text-slate-500 dark:text-slate-400 bg-slate-100 dark:bg-slate-800 px-2 py-0.5 rounded-full">Empty = use template default</span>
            </div>

            <div className="space-y-4">
              {/* Rate Limits */}
              <div>
                <h5 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1">
                  <SignalIcon className="h-3 w-3" /> Rate Limits
                </h5>
                <div className="grid grid-cols-2 gap-3">
                  {renderOverrideField('PPS Limit (normal)', 'pps_limit')}
                  {renderOverrideField('BPS Limit (normal)', 'bps_limit')}
                  {renderOverrideField('PPS Limit (attack)', 'attack_pps_limit')}
                  {renderOverrideField('BPS Limit (attack)', 'attack_bps_limit')}
                </div>
              </div>

              {/* Connection & SYN */}
              <div>
                <h5 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1">
                  <LockClosedIcon className="h-3 w-3" /> Connection & SYN Proxy
                </h5>
                <div className="grid grid-cols-2 gap-3">
                  {renderOverrideField('Max Connections / Source', 'max_conn_per_src')}
                  <div>
                    <label className="block text-xs font-medium text-slate-500 dark:text-slate-400 mb-1">SYN Proxy Mode</label>
                    <select
                      value={editOverrides.syn_proxy_mode || ''}
                      onChange={(e) => setEditOverrides(prev => ({ ...prev, syn_proxy_mode: e.target.value }))}
                      className={clsx('input w-full text-sm', editOverrides.syn_proxy_mode?.trim() && 'ring-1 ring-blue-300 dark:ring-blue-700')}
                    >
                      <option value="">{getTemplateDefault('syn_proxy_mode') ? `${getTemplateDefault('syn_proxy_mode')} (from template)` : 'Global (default)'}</option>
                      <option value="global">Global</option>
                      <option value="disabled">Disabled</option>
                      <option value="always">Always</option>
                      <option value="threshold">Threshold</option>
                    </select>
                    {editOverrides.syn_proxy_mode?.trim() && getTemplateDefault('syn_proxy_mode') && (
                      <p className="text-[10px] text-blue-500 mt-0.5">Override (template: {getTemplateDefault('syn_proxy_mode')})</p>
                    )}
                  </div>
                  {(editOverrides.syn_proxy_mode === 'threshold' || (!editOverrides.syn_proxy_mode && getTemplateDefault('syn_proxy_mode') === 'threshold')) &&
                    renderOverrideField('SYN Challenge Threshold (PPS)', 'syn_challenge_threshold')
                  }
                </div>
              </div>

              {/* Protocol Controls (with integrated port allowlists) */}
              <div>
                <h5 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1">
                  <BoltIcon className="h-3 w-3" /> Protocol Controls
                </h5>
                <p className="text-[10px] text-slate-500 dark:text-slate-400 mb-2">Per-protocol action and allowlists. Empty = all allowed.</p>
                <div className="space-y-3">
                  {(['tcp', 'udp', 'icmp', 'other'] as const).map(proto => {
                    const actionField = `${proto}_action`;
                    const rateField = `${proto}_rate_limit_pps`;
                    const actionVal = editOverrides[actionField] || '';
                    const effectiveAction = actionVal || (editEffective[actionField] as string) || 'allow';
                    const templateAction = getTemplateDefault(actionField);
                    const templateRate = getTemplateDefault(rateField);
                    const hasPorts = proto === 'tcp' || proto === 'udp';
                    const portsField = `${proto}_ports`;
                    const showPorts = hasPorts && effectiveAction !== 'drop';
                    const showProtos = proto === 'other' && effectiveAction !== 'drop';
                    return (
                      <div key={proto} className="p-2 rounded-lg bg-slate-50 dark:bg-slate-800/30">
                        <div className="flex items-center gap-3">
                          <span className="text-xs font-bold text-slate-600 dark:text-slate-300 w-12 uppercase">{proto}</span>
                          <select
                            value={actionVal}
                            onChange={(e) => setEditOverrides(prev => ({ ...prev, [actionField]: e.target.value }))}
                            className={clsx('input text-sm w-32', actionVal.trim() && 'ring-1 ring-blue-300 dark:ring-blue-700')}
                          >
                            <option value="">{templateAction ? `${templateAction} (template)` : 'Allow (default)'}</option>
                            <option value="allow">Allow</option>
                            <option value="drop">Drop</option>
                            <option value="rate_limit">Rate Limit</option>
                          </select>
                          {effectiveAction === 'rate_limit' && (
                            <div className="flex items-center gap-1">
                              <input
                                type="number"
                                value={editOverrides[rateField] || ''}
                                onChange={(e) => setEditOverrides(prev => ({ ...prev, [rateField]: e.target.value }))}
                                placeholder={templateRate ? `${templateRate} (template)` : 'PPS limit'}
                                className={clsx('input text-sm w-28', editOverrides[rateField]?.trim() && 'ring-1 ring-blue-300 dark:ring-blue-700')}
                                min={0}
                              />
                              <span className="text-[10px] text-slate-500 dark:text-slate-400">pps</span>
                            </div>
                          )}
                          {effectiveAction === 'drop' && (
                            <span className="text-[10px] font-semibold text-red-500">ALL {proto.toUpperCase()} blocked</span>
                          )}
                        </div>
                        {showPorts && (
                          <div className="mt-1.5 ml-[60px]">
                            <div className="flex items-center gap-2">
                              <span className="text-[10px] text-slate-500 dark:text-slate-400 w-10">Ports:</span>
                              <input
                                type="text"
                                value={editOverrides[portsField] || ''}
                                onChange={(e) => setEditOverrides(prev => ({ ...prev, [portsField]: e.target.value }))}
                                placeholder={getTemplateDefault(portsField) || 'All ports allowed'}
                                className={clsx('input text-sm flex-1', editOverrides[portsField]?.trim() && 'ring-1 ring-blue-300 dark:ring-blue-700')}
                              />
                            </div>
                            {editOverrides[portsField]?.trim() && getTemplateDefault(portsField) && (
                              <p className="text-[10px] text-blue-500 mt-0.5 ml-12">Override (template: {getTemplateDefault(portsField)})</p>
                            )}
                          </div>
                        )}
                        {showProtos && (
                          <div className="mt-1.5 ml-[60px]">
                            <div className="flex items-center gap-2">
                              <span className="text-[10px] text-slate-500 dark:text-slate-400 w-10">Protos:</span>
                              <input
                                type="text"
                                value={editOverrides.other_allowed_protos || ''}
                                onChange={(e) => setEditOverrides(prev => ({ ...prev, other_allowed_protos: e.target.value }))}
                                placeholder={getTemplateDefault('other_allowed_protos') || 'All protocols allowed'}
                                className={clsx('input text-sm flex-1', editOverrides.other_allowed_protos?.trim() && 'ring-1 ring-blue-300 dark:ring-blue-700')}
                              />
                            </div>
                            <p className="text-[10px] text-slate-500 dark:text-slate-400 mt-0.5 ml-12">IP proto numbers: GRE=47, ESP=50, AH=51, OSPF=89, SCTP=132</p>
                            {editOverrides.other_allowed_protos?.trim() && getTemplateDefault('other_allowed_protos') && (
                              <p className="text-[10px] text-blue-500 mt-0.5 ml-12">Override (template: {getTemplateDefault('other_allowed_protos')})</p>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>

          {/* Effective settings preview */}
          <div className="border-t border-slate-200 dark:border-slate-700 pt-4">
            <h4 className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">Effective Settings (preview)</h4>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
              <div className="p-2 rounded bg-slate-50 dark:bg-slate-800/50">
                <div className="text-slate-500 dark:text-slate-400">PPS</div>
                <div className="font-mono font-semibold text-slate-900 dark:text-white">{formatPPS(editEffective.pps_limit as number)}</div>
              </div>
              <div className="p-2 rounded bg-slate-50 dark:bg-slate-800/50">
                <div className="text-slate-500 dark:text-slate-400">Attack PPS</div>
                <div className="font-mono font-semibold text-red-600">{formatPPS(editEffective.attack_pps_limit as number)}</div>
              </div>
              <div className="p-2 rounded bg-slate-50 dark:bg-slate-800/50">
                <div className="text-slate-500 dark:text-slate-400">SYN Proxy</div>
                <div className={clsx('font-semibold', SYN_MODE_LABELS[(editEffective.syn_proxy_mode as string) || 'global']?.color)}>
                  {SYN_MODE_LABELS[(editEffective.syn_proxy_mode as string) || 'global']?.label || 'Global'}
                </div>
              </div>
              <div className="p-2 rounded bg-slate-50 dark:bg-slate-800/50">
                <div className="text-slate-500 dark:text-slate-400">TCP Ports</div>
                <div className="font-mono font-semibold text-slate-900 dark:text-white truncate">{formatPorts(editEffective.tcp_ports as number[])}</div>
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="flex justify-end gap-3 pt-4 border-t border-slate-200 dark:border-slate-700">
            <button type="button" onClick={() => setShowEditModal(false)} className="btn btn-secondary">Cancel</button>
            <button onClick={handleSaveProfile} disabled={updateProfileMutation.isPending} className="btn bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50">
              {updateProfileMutation.isPending ? 'Saving...' : 'Save Profile'}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

export default RulesPage;
