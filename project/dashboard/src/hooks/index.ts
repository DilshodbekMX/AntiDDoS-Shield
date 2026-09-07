/**
 * Hooks Module
 *
 * Central export for all custom hooks.
 */

// Query keys for React Query cache management
export { queryKeys } from './queryKeys';
export type { QueryKeys } from './queryKeys';

// API hooks for data fetching
export {
  // Auth
  useCurrentUser,
  // Stats
  useRealtimeStats,
  useSysmonStats,
  usePerIpStats,
  // Attacks
  useAttacks,
  useActiveAttacks,
  useAttack,
  // IP Lists
  useBlacklist,
  useWhitelist,
  useAddToBlacklist,
  useAddToWhitelist,
  useRemoveFromBlacklist,
  useRemoveFromWhitelist,
  // Policies
  usePolicies,
  usePolicy,
  useCreatePolicy,
  useUpdatePolicy,
  useDeletePolicy,
  useTogglePolicy,
  // Rules
  useRulesWhitelist,
  useRulesBlacklist,
  useRulesProtected,
  useRulesStats,
  useAddRulesWhitelist,
  useAddRulesBlacklist,
  useRemoveRulesWhitelist,
  useRemoveRulesBlacklist,
  // Layer 1
  useLayer1Config,
  useLayer1Schema,
  useLayer1Stages,
  useGeoBlocking,
  useSignatures,
  useProtocols,
  // Layer 2
  useLayer2Config,
  useAdaptiveConfig,
  useUpdateLayer2Config,
  // Anomaly
  useRealtimeAnomaly,
  usePerIpAnomaly,
  usePerIpAnomalySummary,
  // Investigation
  useInvestigateIP,
  useBlockIP,
  useUnblockIP,
  // Reports
  useReports,
  useReport,
  useGenerateReport,
  // Tokens
  useTokens,
  useCreateToken,
  useRevokeToken,
  // Webhooks
  useWebhooks,
  useWebhook,
  useCreateWebhook,
  useUpdateWebhook,
  useDeleteWebhook,
  useTestWebhook,
} from './useApi';
