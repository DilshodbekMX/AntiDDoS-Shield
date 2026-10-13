/**
 * Custom API Hooks
 *
 * Centralized React Query hooks for data fetching.
 * Provides consistent caching, loading states, and error handling.
 */

import { useQuery, useMutation, useQueryClient, UseQueryOptions } from '@tanstack/react-query';
import { api } from '../services/api';
import { queryKeys } from './queryKeys';
import type {
  IPListEntryCreate,
  PolicyCreate,
  PolicyUpdate,
  User,
  ReportRequest,
  TokenCreate,
  WebhookCreate,
  WebhookUpdate,
} from '../types';

// ==================== Auth Hooks ====================

export function useCurrentUser(options?: Omit<UseQueryOptions<User | null>, 'queryKey' | 'queryFn'>) {
  return useQuery({
    queryKey: queryKeys.auth.me(),
    queryFn: () => api.checkAuth(),
    staleTime: 5 * 60 * 1000, // 5 minutes
    retry: false,
    ...options,
  });
}

// ==================== Stats Hooks ====================

export function useRealtimeStats() {
  return useQuery({
    queryKey: queryKeys.stats.realtime(),
    queryFn: () => api.getRealtimeStats(),
    refetchInterval: 2000, // Poll every 2 seconds
  });
}

export function useSysmonStats() {
  return useQuery({
    queryKey: queryKeys.stats.sysmon(),
    queryFn: () => api.getRealtimeSysmon(),
    refetchInterval: 5000,
  });
}

export function usePerIpStats() {
  return useQuery({
    queryKey: queryKeys.stats.perIp(),
    queryFn: () => api.getPerIPStats(),
    refetchInterval: 5000,
  });
}

// ==================== Attack Hooks ====================

export function useAttacks(
  params?: {
    is_active?: boolean;
    attack_type?: string;
    severity?: string;
    page?: number;
    per_page?: number;
  }
) {
  return useQuery({
    queryKey: queryKeys.attacks.list(params || {}),
    queryFn: () => api.getAttacks(params),
  });
}

export function useActiveAttacks() {
  return useQuery({
    queryKey: queryKeys.attacks.active(),
    queryFn: () => api.getActiveAttacks(),
    refetchInterval: 10000,
  });
}

export function useAttack(attackId: string) {
  return useQuery({
    queryKey: queryKeys.attacks.detail(attackId),
    queryFn: () => api.getAttack(attackId),
    enabled: !!attackId,
  });
}

// ==================== IP List Hooks ====================

export function useBlacklist(
  params?: { search?: string; page?: number; per_page?: number }
) {
  return useQuery({
    queryKey: queryKeys.ipLists.blacklist(params),
    queryFn: () => api.getBlacklist(params),
  });
}

export function useWhitelist(
  params?: { search?: string; page?: number; per_page?: number }
) {
  return useQuery({
    queryKey: queryKeys.ipLists.whitelist(params),
    queryFn: () => api.getWhitelist(params),
  });
}

export function useAddToBlacklist() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: IPListEntryCreate) => api.addToBlacklist(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.ipLists.blacklist() });
    },
  });
}

export function useAddToWhitelist() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: IPListEntryCreate) => api.addToWhitelist(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.ipLists.whitelist() });
    },
  });
}

export function useRemoveFromBlacklist() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (ip: string) => api.removeFromBlacklist(ip),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.ipLists.blacklist() });
    },
  });
}

export function useRemoveFromWhitelist() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (ip: string) => api.removeFromWhitelist(ip),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.ipLists.whitelist() });
    },
  });
}

// ==================== Policy Hooks ====================

export function usePolicies(
  params?: {
    enabled?: boolean;
    action?: string;
    source?: string;
    page?: number;
    per_page?: number;
  }
) {
  return useQuery({
    queryKey: queryKeys.policies.list(params || {}),
    queryFn: () => api.getPolicies(params),
  });
}

export function usePolicy(policyId: number) {
  return useQuery({
    queryKey: queryKeys.policies.detail(policyId),
    queryFn: () => api.getPolicy(policyId),
    enabled: policyId > 0,
  });
}

export function useCreatePolicy() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: PolicyCreate) => api.createPolicy(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.policies.lists() });
    },
  });
}

export function useUpdatePolicy() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ policyId, data }: { policyId: number; data: PolicyUpdate }) =>
      api.updatePolicy(policyId, data),
    onSuccess: (_, { policyId }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.policies.detail(policyId) });
      queryClient.invalidateQueries({ queryKey: queryKeys.policies.lists() });
    },
  });
}

export function useDeletePolicy() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (policyId: number) => api.deletePolicy(policyId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.policies.lists() });
    },
  });
}

export function useTogglePolicy() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ policyId, enabled }: { policyId: number; enabled: boolean }) =>
      api.togglePolicy(policyId, enabled),
    onSuccess: (_, { policyId }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.policies.detail(policyId) });
      queryClient.invalidateQueries({ queryKey: queryKeys.policies.lists() });
    },
  });
}

// ==================== Rules Hooks ====================

export function useRulesWhitelist() {
  return useQuery({
    queryKey: queryKeys.rules.whitelist(),
    queryFn: () => api.getRulesWhitelist(),
  });
}

export function useRulesBlacklist() {
  return useQuery({
    queryKey: queryKeys.rules.blacklist(),
    queryFn: () => api.getRulesBlacklist(),
  });
}

export function useRulesProtected() {
  return useQuery({
    queryKey: queryKeys.rules.protected(),
    queryFn: () => api.getRulesProtected(),
  });
}

export function useRulesStats() {
  return useQuery({
    queryKey: queryKeys.rules.stats(),
    queryFn: () => api.getRulesStats(),
  });
}

export function useAddRulesWhitelist() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: { ip: string; description?: string; expires_hours?: number }) =>
      api.addRulesWhitelist(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.rules.whitelist() });
      queryClient.invalidateQueries({ queryKey: queryKeys.rules.stats() });
    },
  });
}

export function useAddRulesBlacklist() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: { ip: string; description?: string; expires_hours?: number }) =>
      api.addRulesBlacklist(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.rules.blacklist() });
      queryClient.invalidateQueries({ queryKey: queryKeys.rules.stats() });
    },
  });
}

export function useRemoveRulesWhitelist() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (ip: string) => api.removeRulesWhitelist(ip),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.rules.whitelist() });
      queryClient.invalidateQueries({ queryKey: queryKeys.rules.stats() });
    },
  });
}

export function useRemoveRulesBlacklist() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (ip: string) => api.removeRulesBlacklist(ip),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.rules.blacklist() });
      queryClient.invalidateQueries({ queryKey: queryKeys.rules.stats() });
    },
  });
}

// ==================== Layer 1 Config Hooks ====================

export function useLayer1Config() {
  return useQuery({
    queryKey: queryKeys.layer1.config(),
    queryFn: () => api.getLayer1Config(),
    staleTime: 60 * 1000,
  });
}

export function useLayer1Schema() {
  return useQuery({
    queryKey: queryKeys.layer1.schema(),
    queryFn: () => api.getLayer1ConfigSchema(),
    staleTime: 5 * 60 * 1000, // Schema rarely changes
  });
}

export function useLayer1Stages() {
  return useQuery({
    queryKey: queryKeys.layer1.stages(),
    queryFn: () => api.getLayer1Stages(),
  });
}

export function useGeoBlocking() {
  return useQuery({
    queryKey: queryKeys.layer1.geo(),
    queryFn: () => api.getGeoBlocking(),
  });
}

export function useSignatures() {
  return useQuery({
    queryKey: queryKeys.layer1.signatures(),
    queryFn: () => api.getSignatures(),
  });
}

export function useProtocols() {
  return useQuery({
    queryKey: queryKeys.layer1.protocols(),
    queryFn: () => api.getProtocols(),
  });
}

// ==================== Layer 2 Config Hooks ====================

export function useLayer2Config() {
  return useQuery({
    queryKey: queryKeys.layer2.config(),
    queryFn: () => api.getLayer2Config(),
    staleTime: 60 * 1000,
  });
}

export function useAdaptiveConfig() {
  return useQuery({
    queryKey: queryKeys.layer2.adaptive(),
    queryFn: () => api.getAdaptiveConfig(),
  });
}

export function useUpdateLayer2Config() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: Record<string, unknown>) => api.updateLayer2Config(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.layer2.all });
    },
  });
}

// ==================== Anomaly Hooks ====================

export function useRealtimeAnomaly() {
  return useQuery({
    queryKey: queryKeys.anomaly.realtime(),
    queryFn: () => api.getRealtimeAnomaly(),
    refetchInterval: 5000,
  });
}

export function usePerIpAnomaly() {
  return useQuery({
    queryKey: queryKeys.anomaly.perIp(),
    queryFn: () => api.getPerIPAnomaly(),
    refetchInterval: 5000,
  });
}

export function usePerIpAnomalySummary() {
  return useQuery({
    queryKey: queryKeys.anomaly.perIpSummary(),
    queryFn: () => api.getPerIPAnomalySummary(),
    refetchInterval: 10000,
  });
}

// ==================== Investigation Hooks ====================

export function useInvestigateIP(ip: string) {
  return useQuery({
    queryKey: queryKeys.investigation.ip(ip),
    queryFn: () => api.investigateIP(ip),
    enabled: !!ip,
    staleTime: 30 * 1000,
  });
}

export function useBlockIP() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({
      ip,
      duration_seconds,
      reason,
    }: {
      ip: string;
      duration_seconds: number;
      reason: string;
    }) => api.blockIP(ip, duration_seconds, reason),
    onSuccess: (_, { ip }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.investigation.ip(ip) });
      queryClient.invalidateQueries({ queryKey: queryKeys.rules.blacklist() });
    },
  });
}

export function useUnblockIP() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (ip: string) => api.unblockIP(ip),
    onSuccess: (_, ip) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.investigation.ip(ip) });
      queryClient.invalidateQueries({ queryKey: queryKeys.rules.blacklist() });
    },
  });
}

// ==================== Reports Hooks ====================

export function useReports(
  params?: { page?: number; per_page?: number; report_type?: string }
) {
  return useQuery({
    queryKey: queryKeys.reports.list(params || {}),
    queryFn: () => api.getReports(params),
  });
}

export function useReport(reportId: string) {
  return useQuery({
    queryKey: queryKeys.reports.detail(reportId),
    queryFn: () => api.getReport(reportId),
    enabled: !!reportId,
  });
}

export function useGenerateReport() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (request: ReportRequest) => api.generateReport(request),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.reports.lists() });
    },
  });
}

// ==================== Tokens Hooks ====================

export function useTokens() {
  return useQuery({
    queryKey: queryKeys.tokens.list(),
    queryFn: () => api.getTokens(),
  });
}

export function useCreateToken() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: TokenCreate) => api.createToken(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.tokens.list() });
    },
  });
}

export function useRevokeToken() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (tokenId: string) => api.revokeToken(tokenId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.tokens.list() });
    },
  });
}

// ==================== Webhooks Hooks ====================

export function useWebhooks() {
  return useQuery({
    queryKey: queryKeys.webhooks.list(),
    queryFn: () => api.getWebhooks(),
  });
}

export function useWebhook(webhookId: string) {
  return useQuery({
    queryKey: queryKeys.webhooks.detail(webhookId),
    queryFn: () => api.getWebhook(webhookId),
    enabled: !!webhookId,
  });
}

export function useCreateWebhook() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: WebhookCreate) => api.createWebhook(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.webhooks.list() });
    },
  });
}

export function useUpdateWebhook() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ webhookId, data }: { webhookId: string; data: WebhookUpdate }) =>
      api.updateWebhook(webhookId, data),
    onSuccess: (_, { webhookId }) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.webhooks.detail(webhookId) });
      queryClient.invalidateQueries({ queryKey: queryKeys.webhooks.list() });
    },
  });
}

export function useDeleteWebhook() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (webhookId: string) => api.deleteWebhook(webhookId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.webhooks.list() });
    },
  });
}

export function useTestWebhook() {
  return useMutation({
    mutationFn: (webhookId: string) => api.testWebhook(webhookId),
  });
}
