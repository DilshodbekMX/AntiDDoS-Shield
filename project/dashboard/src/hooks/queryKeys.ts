/**
 * Centralized Query Keys
 *
 * All React Query keys are defined here to:
 * - Prevent key collisions
 * - Enable type-safe cache invalidation
 * - Make it easy to find all queries for a resource
 */

export const queryKeys = {
  // ==================== Auth ====================
  auth: {
    all: ['auth'] as const,
    me: () => [...queryKeys.auth.all, 'me'] as const,
  },

  // ==================== Stats ====================
  stats: {
    all: ['stats'] as const,
    realtime: () => [...queryKeys.stats.all, 'realtime'] as const,
    history: (params?: Record<string, unknown>) =>
      [...queryKeys.stats.all, 'history', params] as const,
    traffic: () =>
      [...queryKeys.stats.all, 'traffic'] as const,
    perIp: () => [...queryKeys.stats.all, 'per-ip'] as const,
    perIpSingle: (ip: string) => [...queryKeys.stats.all, 'per-ip', ip] as const,
    dpdk: () => [...queryKeys.stats.all, 'dpdk'] as const,
    sysmon: () => [...queryKeys.stats.all, 'sysmon'] as const,
  },

  // ==================== Attacks ====================
  attacks: {
    all: ['attacks'] as const,
    lists: () => [...queryKeys.attacks.all, 'list'] as const,
    list: (filters: Record<string, unknown>) =>
      [...queryKeys.attacks.lists(), filters] as const,
    active: () =>
      [...queryKeys.attacks.all, 'active'] as const,
    detail: (attackId: string) =>
      [...queryKeys.attacks.all, attackId] as const,
  },

  // ==================== IP Lists ====================
  ipLists: {
    all: ['ipLists'] as const,
    blacklist: (params?: Record<string, unknown>) =>
      [...queryKeys.ipLists.all, 'blacklist', params] as const,
    whitelist: (params?: Record<string, unknown>) =>
      [...queryKeys.ipLists.all, 'whitelist', params] as const,
    protected: () => [...queryKeys.ipLists.all, 'protected'] as const,
  },

  // ==================== Policies ====================
  policies: {
    all: ['policies'] as const,
    lists: () => [...queryKeys.policies.all, 'list'] as const,
    list: (filters: Record<string, unknown>) =>
      [...queryKeys.policies.lists(), filters] as const,
    detail: (policyId: number) =>
      [...queryKeys.policies.all, policyId] as const,
  },

  // ==================== Rules ====================
  rules: {
    all: ['rules'] as const,
    whitelist: () => [...queryKeys.rules.all, 'whitelist'] as const,
    blacklist: () => [...queryKeys.rules.all, 'blacklist'] as const,
    protected: () => [...queryKeys.rules.all, 'protected'] as const,
    stats: () => [...queryKeys.rules.all, 'stats'] as const,
    check: (ip: string) => [...queryKeys.rules.all, 'check', ip] as const,
  },

  // ==================== Layer 1 Config ====================
  layer1: {
    all: ['layer1'] as const,
    config: () => [...queryKeys.layer1.all, 'config'] as const,
    schema: () => [...queryKeys.layer1.all, 'schema'] as const,
    section: (section: string) =>
      [...queryKeys.layer1.all, 'section', section] as const,
    stages: () => [...queryKeys.layer1.all, 'stages'] as const,
    geo: () => [...queryKeys.layer1.all, 'geo'] as const,
    countries: () => [...queryKeys.layer1.all, 'countries'] as const,
    signatures: () => [...queryKeys.layer1.all, 'signatures'] as const,
    protocols: () => [...queryKeys.layer1.all, 'protocols'] as const,
  },

  // ==================== Layer 2 Config ====================
  layer2: {
    all: ['layer2'] as const,
    config: () => [...queryKeys.layer2.all, 'config'] as const,
    adaptive: () => [...queryKeys.layer2.all, 'adaptive'] as const,
  },

  // ==================== Reports ====================
  reports: {
    all: ['reports'] as const,
    lists: () => [...queryKeys.reports.all, 'list'] as const,
    list: (filters: Record<string, unknown>) =>
      [...queryKeys.reports.lists(), filters] as const,
    detail: (reportId: string) =>
      [...queryKeys.reports.all, reportId] as const,
  },

  // ==================== Tokens ====================
  tokens: {
    all: ['tokens'] as const,
    list: () => [...queryKeys.tokens.all, 'list'] as const,
  },

  // ==================== Webhooks ====================
  webhooks: {
    all: ['webhooks'] as const,
    list: () => [...queryKeys.webhooks.all, 'list'] as const,
    detail: (webhookId: string) =>
      [...queryKeys.webhooks.all, webhookId] as const,
  },

  // ==================== Investigation ====================
  investigation: {
    all: ['investigation'] as const,
    ip: (ip: string) =>
      [...queryKeys.investigation.all, ip] as const,
  },

  // ==================== Anomaly ====================
  anomaly: {
    all: ['anomaly'] as const,
    realtime: () => [...queryKeys.anomaly.all, 'realtime'] as const,
    perIp: () => [...queryKeys.anomaly.all, 'per-ip'] as const,
    perIpSummary: () => [...queryKeys.anomaly.all, 'per-ip-summary'] as const,
  },
} as const;

// Type helper for extracting query key types
export type QueryKeys = typeof queryKeys;
