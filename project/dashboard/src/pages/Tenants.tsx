/**
 * Tenant Management Page (Multi-Tenant)
 *
 * Full CRUD interface for managing tenants:
 * - List all tenants with filtering and search
 * - Create new tenants
 * - Edit tenant details, quotas, and features
 * - Delete/suspend tenants
 * - View tenant statistics summary
 */

import { useState, useEffect, useCallback, Fragment } from 'react';
import { logError } from '../utils/logger';
import { Dialog, Transition, Tab } from '@headlessui/react';
import { clsx } from 'clsx';
import {
  BuildingOfficeIcon,
  PlusIcon,
  PencilSquareIcon,
  TrashIcon,
  MagnifyingGlassIcon,
  ArrowPathIcon,
  XMarkIcon,
  ExclamationTriangleIcon,
  CheckIcon,
  PauseIcon,
  PlayIcon,
} from '@heroicons/react/24/outline';
import { useAuthStore, useTenantStore, useNotificationStore } from '../store';
import {
  Tenant,
  TenantCreate,
  TenantUpdate,
  TenantStatus,
  TenantTier,
  TenantType,
  TenantQuotas,
  TenantFeatures,
} from '../types';
import { LoadingSpinner, EmptyState } from '../components/ui';

// ============================================================================
// Types
// ============================================================================

interface TenantFormData {
  name: string;
  description: string;
  tier: TenantTier;
  tenant_type: TenantType;
  protected_ips: string;
  protected_prefixes: string;
  contact_email: string;
  contact_phone: string;
  quotas: Partial<TenantQuotas>;
  features: Partial<TenantFeatures>;
}

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_QUOTAS: TenantQuotas = {
  max_clean_bps: 1_000_000_000,
  max_attack_bps: 10_000_000_000,
  max_clean_pps: 1_000_000,
  max_attack_pps: 10_000_000,
  max_flows: 100_000,
  max_connections: 50_000,
  max_policies: 100,
  max_blacklist: 10_000,
  max_whitelist: 1_000,
  max_custom_signatures: 50,
  api_requests_per_minute: 60,
  api_requests_per_hour: 1_000,
};

const TIER_QUOTAS: Record<TenantTier, Partial<TenantQuotas>> = {
  [TenantTier.FREE]: {
    max_clean_bps: 100_000_000,
    max_flows: 10_000,
    max_policies: 10,
  },
  [TenantTier.BASIC]: {
    max_clean_bps: 500_000_000,
    max_flows: 50_000,
    max_policies: 50,
  },
  [TenantTier.STANDARD]: {
    max_clean_bps: 1_000_000_000,
    max_flows: 200_000,
    max_policies: 100,
  },
  [TenantTier.PREMIUM]: {
    max_clean_bps: 5_000_000_000,
    max_flows: 500_000,
    max_policies: 500,
  },
  [TenantTier.ENTERPRISE]: {
    max_clean_bps: 10_000_000_000,
    max_flows: 1_000_000,
    max_policies: 1_000,
  },
  [TenantTier.CUSTOM]: DEFAULT_QUOTAS,
};

const DEFAULT_FEATURES: TenantFeatures = {
  l1_basic: true,
  l1_advanced: false,
  l2_anomaly: true,
  l3_ml: false,
  l4_reputation: false,
  l4_challenges: false,
  l4_bot_mgmt: false,
  l5_intel: false,
  realtime_dashboard: true,
  api_access: true,
  custom_reports: false,
  managed_rules: false,
  carpet_bomb_detection: false,
};

const TIER_FEATURES: Record<TenantTier, Partial<TenantFeatures>> = {
  [TenantTier.FREE]: { l1_basic: true, l2_anomaly: true, carpet_bomb_detection: false },
  [TenantTier.BASIC]: { l1_basic: true, l2_anomaly: true, l3_ml: true, carpet_bomb_detection: false },
  [TenantTier.STANDARD]: { l1_basic: true, l1_advanced: true, l2_anomaly: true, l3_ml: true, l4_reputation: true, carpet_bomb_detection: true },
  [TenantTier.PREMIUM]: {
    l1_basic: true, l1_advanced: true, l2_anomaly: true, l3_ml: true,
    l4_reputation: true, l4_challenges: true, l4_bot_mgmt: true, custom_reports: true,
    carpet_bomb_detection: true,
  },
  [TenantTier.ENTERPRISE]: {
    l1_basic: true, l1_advanced: true, l2_anomaly: true, l3_ml: true,
    l4_reputation: true, l4_challenges: true, l4_bot_mgmt: true,
    l5_intel: true, custom_reports: true, managed_rules: true,
    carpet_bomb_detection: true,
  },
  [TenantTier.CUSTOM]: DEFAULT_FEATURES,
};

const statusColors: Record<TenantStatus, { bg: string; text: string }> = {
  [TenantStatus.ACTIVE]: { bg: 'bg-emerald-500/20', text: 'text-emerald-400' },
  [TenantStatus.ATTACK_MODE]: { bg: 'bg-red-500/20', text: 'text-red-400' },
  [TenantStatus.PROVISIONING]: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  [TenantStatus.SUSPENDED]: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
  [TenantStatus.MAINTENANCE]: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  [TenantStatus.MIGRATING]: { bg: 'bg-purple-500/20', text: 'text-purple-400' },
  [TenantStatus.DISABLED]: { bg: 'bg-slate-500/20', text: 'text-slate-500 dark:text-slate-400' },
};

const tierColors: Record<TenantTier, string> = {
  [TenantTier.FREE]: 'bg-slate-500',
  [TenantTier.BASIC]: 'bg-blue-500',
  [TenantTier.STANDARD]: 'bg-emerald-500',
  [TenantTier.PREMIUM]: 'bg-purple-500',
  [TenantTier.ENTERPRISE]: 'bg-amber-500',
  [TenantTier.CUSTOM]: 'bg-pink-500',
};

// ============================================================================
// Helper Functions
// ============================================================================

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatNumber(num: number): string {
  if (num < 1000) return num.toString();
  if (num < 1_000_000) return `${(num / 1000).toFixed(1)}K`;
  return `${(num / 1_000_000).toFixed(1)}M`;
}

function formatBps(bps: number): string {
  return formatBytes(bps) + 'ps';
}

// ============================================================================
// Tenant Form Modal
// ============================================================================

interface TenantFormModalProps {
  isOpen: boolean;
  onClose: () => void;
  tenant?: Tenant | null;
  onSubmit: (data: TenantCreate | TenantUpdate) => Promise<void>;
}

function TenantFormModal({ isOpen, onClose, tenant, onSubmit }: TenantFormModalProps) {
  const isEdit = !!tenant;
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState<TenantFormData>({
    name: '',
    description: '',
    tier: TenantTier.STANDARD,
    tenant_type: TenantType.DIRECT,
    protected_ips: '',
    protected_prefixes: '',
    contact_email: '',
    contact_phone: '',
    quotas: { ...DEFAULT_QUOTAS },
    features: { ...DEFAULT_FEATURES },
  });

  // Initialize form data when editing
  useEffect(() => {
    if (tenant) {
      setFormData({
        name: tenant.name,
        description: tenant.description || '',
        tier: tenant.tier,
        tenant_type: tenant.tenant_type,
        protected_ips: tenant.protected_ips.join('\n'),
        protected_prefixes: tenant.protected_prefixes.join('\n'),
        contact_email: tenant.contact.primary_email,
        contact_phone: tenant.contact.phone || '',
        quotas: { ...tenant.quotas },
        features: { ...tenant.features },
      });
    } else {
      // Reset form for new tenant
      setFormData({
        name: '',
        description: '',
        tier: TenantTier.STANDARD,
        tenant_type: TenantType.DIRECT,
        protected_ips: '',
        protected_prefixes: '',
        contact_email: '',
        contact_phone: '',
        quotas: { ...DEFAULT_QUOTAS },
        features: { ...DEFAULT_FEATURES },
      });
    }
  }, [tenant, isOpen]);

  // Update quotas/features when tier changes
  const handleTierChange = (tier: TenantTier) => {
    setFormData((prev) => ({
      ...prev,
      tier,
      quotas: { ...DEFAULT_QUOTAS, ...TIER_QUOTAS[tier] },
      features: { ...DEFAULT_FEATURES, ...TIER_FEATURES[tier] },
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      const data: TenantCreate | TenantUpdate = {
        name: formData.name,
        description: formData.description || undefined,
        tier: formData.tier,
        ...(isEdit ? {} : { tenant_type: formData.tenant_type }),
        protected_ips: formData.protected_ips.split('\n').filter(Boolean),
        protected_prefixes: formData.protected_prefixes.split('\n').filter(Boolean),
        quotas: formData.quotas,
        features: formData.features,
        contact: {
          primary_email: formData.contact_email,
          phone: formData.contact_phone || undefined,
        },
      };

      await onSubmit(data);
      onClose();
    } finally {
      setLoading(false);
    }
  };

  return (
    <Transition appear show={isOpen} as={Fragment}>
      <Dialog as="div" className="relative z-50" onClose={onClose}>
        <Transition.Child
          as={Fragment}
          enter="ease-out duration-300"
          enterFrom="opacity-0"
          enterTo="opacity-100"
          leave="ease-in duration-200"
          leaveFrom="opacity-100"
          leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-black/60 backdrop-blur-sm" />
        </Transition.Child>

        <div className="fixed inset-0 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4">
            <Transition.Child
              as={Fragment}
              enter="ease-out duration-300"
              enterFrom="opacity-0 scale-95"
              enterTo="opacity-100 scale-100"
              leave="ease-in duration-200"
              leaveFrom="opacity-100 scale-100"
              leaveTo="opacity-0 scale-95"
            >
              <Dialog.Panel className="w-full max-w-3xl transform overflow-hidden rounded-xl bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 shadow-2xl transition-all">
                {/* Header */}
                <div className="flex items-center justify-between px-6 py-4 border-b border-slate-300 dark:border-slate-700">
                  <Dialog.Title className="text-lg font-semibold text-slate-900 dark:text-white">
                    {isEdit ? 'Edit Tenant' : 'Create New Tenant'}
                  </Dialog.Title>
                  <button
                    onClick={onClose}
                    className="p-1.5 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors"
                  >
                    <XMarkIcon className="h-5 w-5" />
                  </button>
                </div>

                {/* Form */}
                <form onSubmit={handleSubmit}>
                  <Tab.Group>
                    <Tab.List className="flex border-b border-slate-300 dark:border-slate-700 px-6">
                      {['Basic Info', 'Protection', 'Quotas', 'Features'].map((tab) => (
                        <Tab
                          key={tab}
                          className={({ selected }) =>
                            clsx(
                              'px-4 py-3 text-sm font-medium border-b-2 -mb-px transition-colors focus:outline-none',
                              selected
                                ? 'text-brand-400 border-brand-500'
                                : 'text-slate-500 dark:text-slate-400 border-transparent hover:text-slate-900 dark:hover:text-white hover:border-slate-300 dark:border-slate-600'
                            )
                          }
                        >
                          {tab}
                        </Tab>
                      ))}
                    </Tab.List>

                    <Tab.Panels className="p-6 max-h-[60vh] overflow-y-auto">
                      {/* Basic Info Panel */}
                      <Tab.Panel className="space-y-4">
                        <div>
                          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                            Tenant Name *
                          </label>
                          <input
                            type="text"
                            required
                            value={formData.name}
                            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                            className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
                            placeholder="e.g., Acme Corporation"
                          />
                        </div>

                        <div>
                          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                            Description
                          </label>
                          <textarea
                            rows={3}
                            value={formData.description}
                            onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                            className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 resize-none"
                            placeholder="Brief description of the tenant..."
                          />
                        </div>

                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                              Tier
                            </label>
                            <select
                              value={formData.tier}
                              onChange={(e) => handleTierChange(e.target.value as TenantTier)}
                              className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
                            >
                              {Object.values(TenantTier).map((tier) => (
                                <option key={tier} value={tier}>
                                  {tier.charAt(0).toUpperCase() + tier.slice(1)}
                                </option>
                              ))}
                            </select>
                          </div>

                          {!isEdit && (
                            <div>
                              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                                Type
                              </label>
                              <select
                                value={formData.tenant_type}
                                onChange={(e) => setFormData({ ...formData, tenant_type: e.target.value as TenantType })}
                                className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
                              >
                                {Object.values(TenantType).map((type) => (
                                  <option key={type} value={type}>
                                    {type.charAt(0).toUpperCase() + type.slice(1)}
                                  </option>
                                ))}
                              </select>
                            </div>
                          )}
                        </div>

                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                              Primary Email *
                            </label>
                            <input
                              type="email"
                              required
                              value={formData.contact_email}
                              onChange={(e) => setFormData({ ...formData, contact_email: e.target.value })}
                              className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
                              placeholder="admin@example.com"
                            />
                          </div>

                          <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                              Phone
                            </label>
                            <input
                              type="tel"
                              value={formData.contact_phone}
                              onChange={(e) => setFormData({ ...formData, contact_phone: e.target.value })}
                              className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
                              placeholder="+1 (555) 123-4567"
                            />
                          </div>
                        </div>
                      </Tab.Panel>

                      {/* Protection Panel */}
                      <Tab.Panel className="space-y-4">
                        <div>
                          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                            Protected IPs (one per line)
                          </label>
                          <textarea
                            rows={6}
                            value={formData.protected_ips}
                            onChange={(e) => setFormData({ ...formData, protected_ips: e.target.value })}
                            className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 font-mono text-sm"
                            placeholder="192.168.1.1&#10;10.0.0.50&#10;172.16.0.100"
                          />
                          <p className="mt-1 text-xs text-slate-500">
                            Individual IP addresses to protect
                          </p>
                        </div>

                        <div>
                          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                            Protected Prefixes (CIDR notation, one per line)
                          </label>
                          <textarea
                            rows={6}
                            value={formData.protected_prefixes}
                            onChange={(e) => setFormData({ ...formData, protected_prefixes: e.target.value })}
                            className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white placeholder-slate-500 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 font-mono text-sm"
                            placeholder="192.168.0.0/24&#10;10.0.0.0/16&#10;172.16.0.0/12"
                          />
                          <p className="mt-1 text-xs text-slate-500">
                            IP ranges in CIDR notation (e.g., 192.168.0.0/24)
                          </p>
                        </div>
                      </Tab.Panel>

                      {/* Quotas Panel */}
                      <Tab.Panel className="space-y-6">
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                              Max Clean Traffic (bps)
                            </label>
                            <input
                              type="number"
                              value={formData.quotas.max_clean_bps}
                              onChange={(e) => setFormData({
                                ...formData,
                                quotas: { ...formData.quotas, max_clean_bps: parseInt(e.target.value) || 0 }
                              })}
                              className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
                            />
                            <p className="mt-1 text-xs text-slate-500">
                              {formatBps(formData.quotas.max_clean_bps || 0)}
                            </p>
                          </div>

                          <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                              Max Attack Traffic (bps)
                            </label>
                            <input
                              type="number"
                              value={formData.quotas.max_attack_bps}
                              onChange={(e) => setFormData({
                                ...formData,
                                quotas: { ...formData.quotas, max_attack_bps: parseInt(e.target.value) || 0 }
                              })}
                              className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
                            />
                            <p className="mt-1 text-xs text-slate-500">
                              {formatBps(formData.quotas.max_attack_bps || 0)}
                            </p>
                          </div>

                          <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                              Max Flows
                            </label>
                            <input
                              type="number"
                              value={formData.quotas.max_flows}
                              onChange={(e) => setFormData({
                                ...formData,
                                quotas: { ...formData.quotas, max_flows: parseInt(e.target.value) || 0 }
                              })}
                              className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
                            />
                          </div>

                          <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                              Max Connections
                            </label>
                            <input
                              type="number"
                              value={formData.quotas.max_connections}
                              onChange={(e) => setFormData({
                                ...formData,
                                quotas: { ...formData.quotas, max_connections: parseInt(e.target.value) || 0 }
                              })}
                              className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
                            />
                          </div>

                          <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                              Max Policies
                            </label>
                            <input
                              type="number"
                              value={formData.quotas.max_policies}
                              onChange={(e) => setFormData({
                                ...formData,
                                quotas: { ...formData.quotas, max_policies: parseInt(e.target.value) || 0 }
                              })}
                              className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
                            />
                          </div>

                          <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5">
                              Max Blacklist Entries
                            </label>
                            <input
                              type="number"
                              value={formData.quotas.max_blacklist}
                              onChange={(e) => setFormData({
                                ...formData,
                                quotas: { ...formData.quotas, max_blacklist: parseInt(e.target.value) || 0 }
                              })}
                              className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-slate-900 dark:text-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
                            />
                          </div>
                        </div>
                      </Tab.Panel>

                      {/* Features Panel */}
                      <Tab.Panel className="space-y-6">
                        <div className="space-y-3">
                          <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300">Protection Layers</h3>
                          <div className="grid grid-cols-2 gap-3">
                            {[
                              { key: 'l1_basic', label: 'L1 Basic (Rate Limiting)' },
                              { key: 'l1_advanced', label: 'L1 Advanced (SYN Proxy, TCP Fingerprint)' },
                              { key: 'l2_anomaly', label: 'L2 Anomaly Detection' },
                              { key: 'carpet_bomb_detection', label: 'Carpet Bomb Attack Detection (Subnet /24 Aggregation)' },
                              { key: 'l3_ml', label: 'L3 ML Attribution' },
                              { key: 'l4_reputation', label: 'L4 Reputation Engine' },
                              { key: 'l4_challenges', label: 'L4 Challenge System' },
                              { key: 'l4_bot_mgmt', label: 'L4 Bot Management' },
                              { key: 'l5_intel', label: 'L5 Strategic Intelligence' },
                            ].map(({ key, label }) => (
                              <label key={key} className="flex items-center gap-3 p-3 bg-slate-100 dark:bg-slate-800 rounded-lg cursor-pointer hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors">
                                <input
                                  type="checkbox"
                                  checked={formData.features[key as keyof TenantFeatures] as boolean}
                                  onChange={(e) => setFormData({
                                    ...formData,
                                    features: { ...formData.features, [key]: e.target.checked }
                                  })}
                                  className="h-4 w-4 rounded border-slate-300 dark:border-slate-600 bg-slate-200 dark:bg-slate-700 text-brand-500 focus:ring-brand-500 focus:ring-offset-white dark:focus:ring-offset-slate-900"
                                />
                                <span className="text-sm text-slate-700 dark:text-slate-300">{label}</span>
                              </label>
                            ))}
                          </div>
                        </div>

                        <div className="space-y-3">
                          <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300">Additional Features</h3>
                          <div className="grid grid-cols-2 gap-3">
                            {[
                              { key: 'realtime_dashboard', label: 'Real-time Dashboard' },
                              { key: 'api_access', label: 'API Access' },
                              { key: 'custom_reports', label: 'Custom Reports' },
                              { key: 'managed_rules', label: 'Managed Rules' },
                            ].map(({ key, label }) => (
                              <label key={key} className="flex items-center gap-3 p-3 bg-slate-100 dark:bg-slate-800 rounded-lg cursor-pointer hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors">
                                <input
                                  type="checkbox"
                                  checked={formData.features[key as keyof TenantFeatures] as boolean}
                                  onChange={(e) => setFormData({
                                    ...formData,
                                    features: { ...formData.features, [key]: e.target.checked }
                                  })}
                                  className="h-4 w-4 rounded border-slate-300 dark:border-slate-600 bg-slate-200 dark:bg-slate-700 text-brand-500 focus:ring-brand-500 focus:ring-offset-white dark:focus:ring-offset-slate-900"
                                />
                                <span className="text-sm text-slate-700 dark:text-slate-300">{label}</span>
                              </label>
                            ))}
                          </div>
                        </div>
                      </Tab.Panel>
                    </Tab.Panels>
                  </Tab.Group>

                  {/* Footer */}
                  <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50">
                    <button
                      type="button"
                      onClick={onClose}
                      className="px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition-colors"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={loading}
                      className={clsx(
                        'inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-slate-900 dark:text-white',
                        'bg-brand-600 hover:bg-brand-500 transition-colors',
                        'disabled:opacity-50 disabled:cursor-not-allowed'
                      )}
                    >
                      {loading && <LoadingSpinner size="sm" />}
                      {isEdit ? 'Save Changes' : 'Create Tenant'}
                    </button>
                  </div>
                </form>
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </div>
      </Dialog>
    </Transition>
  );
}

// ============================================================================
// Delete Confirmation Modal
// ============================================================================

interface DeleteConfirmModalProps {
  isOpen: boolean;
  onClose: () => void;
  tenant: Tenant | null;
  onConfirm: () => Promise<void>;
}

function DeleteConfirmModal({ isOpen, onClose, tenant, onConfirm }: DeleteConfirmModalProps) {
  const [loading, setLoading] = useState(false);

  const handleConfirm = async () => {
    setLoading(true);
    try {
      await onConfirm();
      onClose();
    } finally {
      setLoading(false);
    }
  };

  return (
    <Transition appear show={isOpen} as={Fragment}>
      <Dialog as="div" className="relative z-50" onClose={onClose}>
        <Transition.Child
          as={Fragment}
          enter="ease-out duration-300"
          enterFrom="opacity-0"
          enterTo="opacity-100"
          leave="ease-in duration-200"
          leaveFrom="opacity-100"
          leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-black/60 backdrop-blur-sm" />
        </Transition.Child>

        <div className="fixed inset-0 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4">
            <Transition.Child
              as={Fragment}
              enter="ease-out duration-300"
              enterFrom="opacity-0 scale-95"
              enterTo="opacity-100 scale-100"
              leave="ease-in duration-200"
              leaveFrom="opacity-100 scale-100"
              leaveTo="opacity-0 scale-95"
            >
              <Dialog.Panel className="w-full max-w-md transform overflow-hidden rounded-xl bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 shadow-2xl transition-all">
                <div className="p-6">
                  <div className="flex items-center gap-4">
                    <div className="flex h-12 w-12 items-center justify-center rounded-full bg-red-500/20">
                      <ExclamationTriangleIcon className="h-6 w-6 text-red-400" />
                    </div>
                    <div>
                      <Dialog.Title className="text-lg font-semibold text-slate-900 dark:text-white">
                        Delete Tenant
                      </Dialog.Title>
                      <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                        This action cannot be undone.
                      </p>
                    </div>
                  </div>

                  <div className="mt-4 p-4 bg-slate-100 dark:bg-slate-800 rounded-lg border border-slate-300 dark:border-slate-700">
                    <p className="text-sm text-slate-700 dark:text-slate-300">
                      Are you sure you want to delete{' '}
                      <span className="font-semibold text-slate-900 dark:text-white">{tenant?.name}</span>?
                      All associated data, policies, and configurations will be permanently removed.
                    </p>
                  </div>

                  <div className="mt-6 flex items-center justify-end gap-3">
                    <button
                      type="button"
                      onClick={onClose}
                      className="px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition-colors"
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      onClick={handleConfirm}
                      disabled={loading}
                      className={clsx(
                        'inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-slate-900 dark:text-white',
                        'bg-red-600 hover:bg-red-500 transition-colors',
                        'disabled:opacity-50 disabled:cursor-not-allowed'
                      )}
                    >
                      {loading && <LoadingSpinner size="sm" />}
                      Delete Tenant
                    </button>
                  </div>
                </div>
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </div>
      </Dialog>
    </Transition>
  );
}

// ============================================================================
// Tenant Stats Card
// ============================================================================

interface TenantStatsCardProps {
  tenant: Tenant;
}

function TenantStatsCard({ tenant }: TenantStatsCardProps) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 p-4 bg-slate-100 dark:bg-slate-800/50 rounded-lg border border-slate-300 dark:border-slate-700">
      <div>
        <p className="text-2xs uppercase tracking-wider text-slate-500">Traffic</p>
        <p className="text-lg font-semibold text-slate-900 dark:text-white mt-1">
          {formatBps(tenant.current_traffic_bps ?? 0)}
        </p>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          {formatNumber(tenant.current_traffic_pps ?? 0)} pps
        </p>
      </div>

      <div>
        <p className="text-2xs uppercase tracking-wider text-slate-500">Attacks (24h)</p>
        <p className="text-lg font-semibold text-slate-900 dark:text-white mt-1">
          {tenant.attack_count_24h}
        </p>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          {tenant.last_attack_at ? `Last: ${new Date(tenant.last_attack_at).toLocaleDateString()}` : 'No recent attacks'}
        </p>
      </div>

      <div>
        <p className="text-2xs uppercase tracking-wider text-slate-500">Protected IPs</p>
        <p className="text-lg font-semibold text-slate-900 dark:text-white mt-1">
          {tenant.protected_ips.length}
        </p>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          {tenant.protected_prefixes.length} prefixes
        </p>
      </div>

      <div>
        <p className="text-2xs uppercase tracking-wider text-slate-500">Status</p>
        <div className={clsx(
          'inline-flex items-center gap-1.5 mt-1 px-2 py-1 rounded-full text-xs font-medium',
          statusColors[tenant.status].bg,
          statusColors[tenant.status].text
        )}>
          <div className={clsx(
            'h-1.5 w-1.5 rounded-full',
            tenant.status === TenantStatus.ATTACK_MODE ? 'bg-red-500 animate-pulse' :
            tenant.status === TenantStatus.ACTIVE ? 'bg-emerald-500' : 'bg-slate-500'
          )} />
          {tenant.status.replace('_', ' ')}
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Main Page Component
// ============================================================================

export function TenantsPage() {
  const { user } = useAuthStore();
  const { tenants, setTenants, setCurrentTenant } = useTenantStore();
  const { addNotification } = useNotificationStore();

  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterTier, setFilterTier] = useState<TenantTier | 'all'>('all');
  const [filterStatus, setFilterStatus] = useState<TenantStatus | 'all'>('all');
  const [sortBy, setSortBy] = useState<'name' | 'id' | 'created_at' | 'traffic'>('name');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');

  // Modal states
  const [formModalOpen, setFormModalOpen] = useState(false);
  const [deleteModalOpen, setDeleteModalOpen] = useState(false);
  const [selectedTenant, setSelectedTenant] = useState<Tenant | null>(null);

  // API URL
  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v2';

  // Fetch tenants
  const fetchTenants = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetch(`${apiUrl}/tenants`, {
        credentials: 'include',  // Send cookies for auth
      });

      if (response.ok) {
        const data = await response.json();
        setTenants(data.items || data);
      } else {
        throw new Error('Failed to fetch tenants');
      }
    } catch (error) {
      logError('Tenants.fetchTenants', error);
      addNotification({
        type: 'error',
        title: 'Failed to load tenants',
        message: 'Please try refreshing the page.',
      });
    } finally {
      setLoading(false);
    }
  }, [apiUrl, setTenants, addNotification]);

  useEffect(() => {
    fetchTenants();
  }, [fetchTenants]);

  // Create tenant
  const handleCreate = async (data: TenantCreate) => {
    const response = await fetch(`${apiUrl}/tenants`, {
      method: 'POST',
      credentials: 'include',  // Send cookies for auth
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    });

    if (!response.ok) {
      throw new Error('Failed to create tenant');
    }

    addNotification({
      type: 'success',
      title: 'Tenant created',
      message: `${data.name} has been created successfully.`,
    });

    fetchTenants();
  };

  // Update tenant
  const handleUpdate = async (data: TenantUpdate) => {
    if (!selectedTenant) return;

    const response = await fetch(`${apiUrl}/tenants/${selectedTenant.id}`, {
      method: 'PUT',
      credentials: 'include',  // Send cookies for auth
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    });

    if (!response.ok) {
      throw new Error('Failed to update tenant');
    }

    addNotification({
      type: 'success',
      title: 'Tenant updated',
      message: `${selectedTenant.name} has been updated successfully.`,
    });

    fetchTenants();
  };

  // Delete tenant
  const handleDelete = async () => {
    if (!selectedTenant) return;

    const response = await fetch(`${apiUrl}/tenants/${selectedTenant.id}`, {
      method: 'DELETE',
      credentials: 'include',  // Send cookies for auth
    });

    if (!response.ok) {
      throw new Error('Failed to delete tenant');
    }

    addNotification({
      type: 'success',
      title: 'Tenant deleted',
      message: `${selectedTenant.name} has been deleted.`,
    });

    // Clear current tenant if it was deleted
    setCurrentTenant(null);
    fetchTenants();
  };

  // Toggle tenant status
  const handleToggleStatus = async (tenant: Tenant) => {
    const newStatus = tenant.status === TenantStatus.SUSPENDED
      ? TenantStatus.ACTIVE
      : TenantStatus.SUSPENDED;

    const response = await fetch(`${apiUrl}/tenants/${tenant.id}`, {
      method: 'PUT',
      credentials: 'include',  // Send cookies for auth
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ status: newStatus }),
    });

    if (response.ok) {
      addNotification({
        type: 'success',
        title: `Tenant ${newStatus === TenantStatus.SUSPENDED ? 'suspended' : 'activated'}`,
        message: `${tenant.name} is now ${newStatus}.`,
      });
      fetchTenants();
    }
  };

  // Filter and sort tenants
  const filteredTenants = tenants
    .filter((tenant) => {
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        if (
          !tenant.name.toLowerCase().includes(query) &&
          !tenant.id.toString().includes(query) &&
          !tenant.contact.primary_email.toLowerCase().includes(query)
        ) {
          return false;
        }
      }
      if (filterTier !== 'all' && tenant.tier !== filterTier) return false;
      if (filterStatus !== 'all' && tenant.status !== filterStatus) return false;
      return true;
    })
    .sort((a, b) => {
      let comparison = 0;
      switch (sortBy) {
        case 'name':
          comparison = a.name.localeCompare(b.name);
          break;
        case 'id':
          comparison = a.id - b.id;
          break;
        case 'created_at':
          comparison = new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
          break;
        case 'traffic':
          comparison = (a.current_traffic_bps ?? 0) - (b.current_traffic_bps ?? 0);
          break;
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

  // Stats summary
  const stats = {
    total: tenants.length,
    active: tenants.filter(t => t.status === TenantStatus.ACTIVE).length,
    underAttack: tenants.filter(t => t.status === TenantStatus.ATTACK_MODE).length,
    suspended: tenants.filter(t => t.status === TenantStatus.SUSPENDED).length,
  };

  if (!user?.is_admin) {
    return (
      <EmptyState
        icon={BuildingOfficeIcon}
        title="Access Denied"
        description="You don't have permission to manage tenants."
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Tenant Management</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Manage tenants, quotas, and protection settings
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchTenants}
            disabled={loading}
            className="p-2 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors"
          >
            <ArrowPathIcon className={clsx('h-5 w-5', loading && 'animate-spin')} />
          </button>
          <button
            onClick={() => {
              setSelectedTenant(null);
              setFormModalOpen(true);
            }}
            className="inline-flex items-center gap-2 px-4 py-2 bg-brand-600 hover:bg-brand-500 text-white rounded-lg text-sm font-medium transition-colors"
          >
            <PlusIcon className="h-5 w-5" />
            Add Tenant
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 bg-slate-100 dark:bg-slate-800 rounded-lg border border-slate-300 dark:border-slate-700">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-brand-500/20 rounded-lg">
              <BuildingOfficeIcon className="h-5 w-5 text-brand-400" />
            </div>
            <div>
              <p className="text-2xs uppercase tracking-wider text-slate-500">Total Tenants</p>
              <p className="text-xl font-bold text-slate-900 dark:text-white">{stats.total}</p>
            </div>
          </div>
        </div>

        <div className="p-4 bg-slate-100 dark:bg-slate-800 rounded-lg border border-slate-300 dark:border-slate-700">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-emerald-500/20 rounded-lg">
              <CheckIcon className="h-5 w-5 text-emerald-400" />
            </div>
            <div>
              <p className="text-2xs uppercase tracking-wider text-slate-500">Active</p>
              <p className="text-xl font-bold text-slate-900 dark:text-white">{stats.active}</p>
            </div>
          </div>
        </div>

        <div className="p-4 bg-slate-100 dark:bg-slate-800 rounded-lg border border-slate-300 dark:border-slate-700">
          <div className="flex items-center gap-3">
            <div className={clsx('p-2 rounded-lg', stats.underAttack > 0 ? 'bg-red-500/20' : 'bg-slate-200 dark:bg-slate-700')}>
              <ExclamationTriangleIcon className={clsx('h-5 w-5', stats.underAttack > 0 ? 'text-red-400' : 'text-slate-500 dark:text-slate-400')} />
            </div>
            <div>
              <p className="text-2xs uppercase tracking-wider text-slate-500">Under Attack</p>
              <p className={clsx('text-xl font-bold', stats.underAttack > 0 ? 'text-red-400' : 'text-slate-900 dark:text-white')}>
                {stats.underAttack}
              </p>
            </div>
          </div>
        </div>

        <div className="p-4 bg-slate-100 dark:bg-slate-800 rounded-lg border border-slate-300 dark:border-slate-700">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-orange-500/20 rounded-lg">
              <PauseIcon className="h-5 w-5 text-orange-400" />
            </div>
            <div>
              <p className="text-2xs uppercase tracking-wider text-slate-500">Suspended</p>
              <p className="text-xl font-bold text-slate-900 dark:text-white">{stats.suspended}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-4 p-4 bg-slate-100 dark:bg-slate-800/50 rounded-lg border border-slate-300 dark:border-slate-700">
        <div className="flex-1 relative">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-500" />
          <input
            type="text"
            placeholder="Search tenants by name, ID, or email..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white placeholder-slate-500 focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
          />
        </div>

        <select
          value={filterTier}
          onChange={(e) => setFilterTier(e.target.value as TenantTier | 'all')}
          className="px-3 py-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
        >
          <option value="all">All Tiers</option>
          {Object.values(TenantTier).map((tier) => (
            <option key={tier} value={tier}>
              {tier.charAt(0).toUpperCase() + tier.slice(1)}
            </option>
          ))}
        </select>

        <select
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value as TenantStatus | 'all')}
          className="px-3 py-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
        >
          <option value="all">All Status</option>
          {Object.values(TenantStatus).map((status) => (
            <option key={status} value={status}>
              {status.replace('_', ' ')}
            </option>
          ))}
        </select>

        <select
          value={`${sortBy}-${sortOrder}`}
          onChange={(e) => {
            const [by, order] = e.target.value.split('-');
            setSortBy(by as typeof sortBy);
            setSortOrder(order as typeof sortOrder);
          }}
          className="px-3 py-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
        >
          <option value="name-asc">Name (A-Z)</option>
          <option value="name-desc">Name (Z-A)</option>
          <option value="id-asc">ID (Low-High)</option>
          <option value="id-desc">ID (High-Low)</option>
          <option value="created_at-desc">Newest First</option>
          <option value="created_at-asc">Oldest First</option>
          <option value="traffic-desc">Most Traffic</option>
          <option value="traffic-asc">Least Traffic</option>
        </select>
      </div>

      {/* Tenant List */}
      {loading ? (
        <div className="flex items-center justify-center py-12">
          <LoadingSpinner />
        </div>
      ) : filteredTenants.length === 0 ? (
        <EmptyState
          icon={BuildingOfficeIcon}
          title="No tenants found"
          description={searchQuery || filterTier !== 'all' || filterStatus !== 'all'
            ? 'Try adjusting your search or filters.'
            : 'Get started by creating your first tenant.'}
          action={
            !searchQuery && filterTier === 'all' && filterStatus === 'all' ? (
              <button
                onClick={() => {
                  setSelectedTenant(null);
                  setFormModalOpen(true);
                }}
                className="inline-flex items-center gap-2 px-4 py-2 bg-brand-600 hover:bg-brand-500 text-white rounded-lg text-sm font-medium transition-colors"
              >
                <PlusIcon className="h-5 w-5" />
                Create Tenant
              </button>
            ) : undefined
          }
        />
      ) : (
        <div className="space-y-4">
          {filteredTenants.map((tenant) => (
            <div
              key={tenant.id}
              className="bg-slate-100 dark:bg-slate-800 rounded-xl border border-slate-300 dark:border-slate-700 overflow-hidden hover:border-slate-300 dark:border-slate-600 transition-colors"
            >
              {/* Tenant Header */}
              <div className="p-4 flex items-center gap-4">
                <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-slate-200 dark:bg-slate-700">
                  <BuildingOfficeIcon className="h-6 w-6 text-slate-700 dark:text-slate-300" />
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3">
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white truncate">
                      {tenant.name}
                    </h3>
                    <span className={clsx(
                      'inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium text-slate-900 dark:text-white',
                      tierColors[tenant.tier]
                    )}>
                      {tenant.tier}
                    </span>
                    {tenant.features?.carpet_bomb_detection && (
                      <span className="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">
                        Carpet-Bomb Shield (/24)
                      </span>
                    )}
                    <span className={clsx(
                      'inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium',
                      statusColors[tenant.status].bg,
                      statusColors[tenant.status].text
                    )}>
                      <div className={clsx(
                        'h-1.5 w-1.5 rounded-full',
                        tenant.status === TenantStatus.ATTACK_MODE ? 'bg-red-500 animate-pulse' :
                        tenant.status === TenantStatus.ACTIVE ? 'bg-emerald-500' : 'bg-current'
                      )} />
                      {tenant.status.replace('_', ' ')}
                    </span>
                  </div>
                  <p className="text-sm text-slate-500 dark:text-slate-400">
                    ID: {tenant.id} | {tenant.contact.primary_email}
                    {tenant.description && ` | ${tenant.description}`}
                  </p>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleToggleStatus(tenant)}
                    className={clsx(
                      'p-2 rounded-lg transition-colors',
                      tenant.status === TenantStatus.SUSPENDED
                        ? 'text-emerald-400 hover:bg-emerald-500/20'
                        : 'text-orange-400 hover:bg-orange-500/20'
                    )}
                    title={tenant.status === TenantStatus.SUSPENDED ? 'Activate' : 'Suspend'}
                  >
                    {tenant.status === TenantStatus.SUSPENDED ? (
                      <PlayIcon className="h-5 w-5" />
                    ) : (
                      <PauseIcon className="h-5 w-5" />
                    )}
                  </button>
                  <button
                    onClick={() => {
                      setSelectedTenant(tenant);
                      setFormModalOpen(true);
                    }}
                    className="p-2 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg transition-colors"
                    title="Edit"
                  >
                    <PencilSquareIcon className="h-5 w-5" />
                  </button>
                  <button
                    onClick={() => {
                      setSelectedTenant(tenant);
                      setDeleteModalOpen(true);
                    }}
                    className="p-2 text-slate-500 dark:text-slate-400 hover:text-red-400 hover:bg-red-500/20 rounded-lg transition-colors"
                    title="Delete"
                  >
                    <TrashIcon className="h-5 w-5" />
                  </button>
                </div>
              </div>

              {/* Stats */}
              <TenantStatsCard tenant={tenant} />
            </div>
          ))}
        </div>
      )}

      {/* Modals */}
      <TenantFormModal
        isOpen={formModalOpen}
        onClose={() => setFormModalOpen(false)}
        tenant={selectedTenant}
        onSubmit={(data) => selectedTenant ? handleUpdate(data as TenantUpdate) : handleCreate(data as TenantCreate)}
      />

      <DeleteConfirmModal
        isOpen={deleteModalOpen}
        onClose={() => setDeleteModalOpen(false)}
        tenant={selectedTenant}
        onConfirm={handleDelete}
      />
    </div>
  );
}

export default TenantsPage;
