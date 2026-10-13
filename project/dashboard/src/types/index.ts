/**
 * Type definitions for Anti-DDoS Dashboard
 *
 * Synchronized with FastAPI models in backend/api/models.py
 */

// ==================== Enums ====================

export enum AttackType {
  UNKNOWN = 'unknown',
  SYN_FLOOD = 'syn_flood',
  UDP_FLOOD = 'udp_flood',
  ICMP_FLOOD = 'icmp_flood',
  DNS_AMPLIFICATION = 'dns_amplification',
  NTP_AMPLIFICATION = 'ntp_amplification',
  MEMCACHED_AMPLIFICATION = 'memcached_amplification',
  HTTP_FLOOD = 'http_flood',
  SLOWLORIS = 'slowloris',
  ACK_FLOOD = 'ack_flood',
  RST_FLOOD = 'rst_flood',
  FIN_FLOOD = 'fin_flood',
  FRAGMENT_FLOOD = 'fragment_flood',
  CARPET_BOMB = 'carpet_bomb',
  VOLUMETRIC = 'volumetric',
  APPLICATION = 'application',
}

export enum AttackSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

export enum StatsPeriod {
  REALTIME = 'realtime',
  HOUR_1 = '1h',
  HOUR_24 = '24h',
  DAY_7 = '7d',
  DAY_30 = '30d',
}

export enum IPListType {
  WHITELIST = 'whitelist',
  BLACKLIST = 'blacklist',
  GREYLIST = 'greylist',
}

export enum PolicyAction {
  ALLOW = 'allow',
  BLOCK = 'block',
  RATE_LIMIT = 'rate_limit',
  CHALLENGE = 'challenge',
  LOG = 'log',
}

export enum PolicySource {
  MANUAL = 'manual',
  ML = 'ml',
  THREAT_INTEL = 'threat_intel',
}

export enum ReportType {
  INCIDENT = 'incident',
  TRAFFIC = 'traffic',
  SECURITY = 'security',
  SLA = 'sla',
  EXECUTIVE = 'executive',
  CUSTOM = 'custom',
}

export enum ReportFormat {
  PDF = 'pdf',
  HTML = 'html',
  JSON = 'json',
  CSV = 'csv',
}

export enum WebhookEvent {
  ATTACK_STARTED = 'attack.started',
  ATTACK_ENDED = 'attack.ended',
  ATTACK_MITIGATED = 'attack.mitigated',
  THRESHOLD_EXCEEDED = 'threshold.exceeded',
  CONFIG_CHANGED = 'config.changed',
  SLA_BREACH = 'sla.breach',
}

// ==================== API Response ====================

export interface APIResponse<T = unknown> {
  success: boolean;
  data?: T;
  message?: string;
  error?: string;
  timestamp: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
  pages: number;
}

// ==================== Statistics ====================

export interface TrafficStats {
  packets_in: number;
  packets_out: number;
  bytes_in: number;
  bytes_out: number;
  packets_dropped: number;
  bytes_dropped: number;
  drop_rate_pct: number;
  current_pps: number;
  current_bps: number;
  peak_pps_24h: number;
  peak_bps_24h: number;
}

export interface SecurityStats {
  attacks_detected: number;
  attacks_mitigated: number;
  attacks_active: number;
  avg_mitigation_time_ms: number;
  false_positives: number;
  blacklist_hits: number;
  whitelist_hits: number;
  rate_limit_drops: number;
  syn_proxy_challenges: number;
  syn_proxy_passes: number;
  geo_blocks: number;
}

export interface LayerStats {
  packets_processed: number;
  packets_dropped: number;
  decisions_made: number;
  avg_latency_ns: number;
  errors: number;
}

export interface SLAStats {
  availability_pct: number;
  mttd_ms: number;
  mttr_ms: number;
  mitigation_effectiveness_pct: number;
  false_positive_rate_pct: number;
  sla_breaches: number;
}

export interface SystemStats {
  timestamp: string;
  period: StatsPeriod;
  traffic: TrafficStats;
  security: SecurityStats;
  layer1: LayerStats;
  layer2: LayerStats;
  sla: SLAStats;
}

export interface StatsHistoryPoint {
  timestamp: string;
  rx_bps: number;
  tx_bps: number;
  drop_bps: number;
  rx_pps: number;
  tx_pps: number;
  drop_pps: number;
  fwd_bps?: number;  // Forwarded to protected network (rx - dropped)
  fwd_pps?: number;
}

export interface StatsSummary {
  current_pps: number;
  current_bps: number;
  drop_rate_pct: number;
  active_attacks: number;
  attacks_24h: number;
  blacklist_hits_24h: number;
  syn_proxy_challenges: number;
  availability_pct: number;
}

// ==================== Attacks ====================

export interface Attack {
  id: string;
  attack_type: AttackType;
  severity: AttackSeverity;
  target_ip: string;
  target_port?: number;
  source_ips_count: number;
  peak_pps: number;
  peak_bps: number;
  started_at: string;
  ended_at?: string;
  duration_seconds?: number;
  is_active: boolean;
  mitigated: boolean;
  mitigation_time_ms?: number;
  total_packets_dropped: number;
  total_bytes_dropped: number;
  top_source_ips: string[];
  signatures_matched: string[];
  ml_confidence?: number;
  spoofed_mode?: boolean;
  randomness_pct?: number;
  rate_limit_pct?: number;
  // Detection details
  cusum_triggered?: boolean;
  jsd_triggered?: boolean;
  fast_triggered?: boolean;
  confidence_pct?: number;
  sensitivity_preset?: number;
  learning_phase?: number;
  cool_down_remaining_sec?: number;
  peak_z_feature_name?: string;
}

export interface AttackSummary {
  id: string;
  attack_type: AttackType;
  severity: AttackSeverity;
  target_ip: string;
  started_at: string;
  ended_at?: string;
  is_active: boolean;
  mitigated: boolean;
  peak_pps: number;
  peak_bps: number;
}

// ==================== IP Lists ====================

export interface IPListEntry {
  id: number;
  list_type: IPListType;
  ip: string;
  description?: string;
  expires_at?: string;
  created_at: string;
  created_by: string;
  hit_count: number;
  last_hit_at?: string;
  is_expired: boolean;
}

export interface IPListEntryCreate {
  ip: string;
  description?: string;
  expires_at?: string;
  duration_seconds?: number;
}

export interface IPListBulkAdd {
  ips: string[];
  description?: string;
  duration_seconds?: number;
}

// ==================== Policies ====================

export interface PolicyCondition {
  field: string;
  operator: string;
  value: unknown;
}

export interface Policy {
  id: number;
  name: string;
  description?: string;
  priority: number;
  action: PolicyAction;
  conditions: PolicyCondition[];
  enabled: boolean;
  expires_at?: string;
  created_at: string;
  updated_at: string;
  created_by: string;
  is_expired: boolean;
  hit_count: number;
  last_hit_at?: string;
  source: 'manual' | 'ml' | 'threat_intel';
  rate_limit_pps?: number;
  rate_limit_bps?: number;
  match_count?: number;
}

export interface PolicyCreate {
  name: string;
  description?: string;
  priority?: number;
  action: PolicyAction;
  conditions: PolicyCondition[];
  enabled?: boolean;
  expires_at?: string;
  rate_limit_pps?: number;
  rate_limit_bps?: number;
}

export interface PolicyUpdate {
  name?: string;
  description?: string;
  priority?: number;
  action?: PolicyAction;
  conditions?: PolicyCondition[];
  enabled?: boolean;
  expires_at?: string;
}

// ==================== Configuration ====================

export interface Layer1Config {
  enabled: boolean;
  rate_limit_pps: number;
  rate_limit_bps: number;
  syn_rate_limit: number;
  udp_rate_limit: number;
  icmp_rate_limit: number;
  syn_proxy_enabled: boolean;
  syn_proxy_mode: 'off' | 'auto' | 'always';
  tcp_fingerprint_enabled: boolean;
  geo_blocking_enabled: boolean;
  blocked_countries: string[];
  monitor_only?: boolean;
  tap_mode?: boolean;
}

export interface Layer2Config {
  enabled: boolean;
  detection_sensitivity: 'low' | 'medium' | 'high';
  z_score_threshold: number;
  baseline_learning_hours: number;
  anomaly_cooldown_seconds: number;
}

export interface BaselineProfile {
  id: string;
  name: string;
  description: string;
  source: string;
}

export interface SystemConfig {
  layer1: Layer1Config;
  layer2: Layer2Config;
  updated_at: string;
}

// ==================== Auth ====================

export interface User {
  user_id: string;
  permissions: string[];
  is_admin: boolean;
  auth_type: 'jwt' | 'api_key' | 'cookie';
}

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: string;
  permissions: string[];
}

// ==================== Reports ====================

export interface Report {
  id: string;
  report_type: ReportType;
  format: ReportFormat;
  start_date: string;
  end_date: string;
  generated_at: string;
  generated_by: string;
  file_path?: string;
  file_size_bytes?: number;
  status: string;
}

export interface ReportRequest {
  report_type: ReportType;
  format?: ReportFormat;
  start_date: string;
  end_date: string;
  include_charts?: boolean;
  include_details?: boolean;
  custom_sections?: string[];
}

// ==================== API Tokens ====================

export interface TokenCreate {
  name: string;
  permissions?: string[];
  expires_in_hours?: number;
}

export interface Token {
  id: string;
  name: string;
  token: string;
  permissions: string[];
  created_at: string;
  expires_at: string;
}

export interface TokenInfo {
  id: string;
  name: string;
  permissions: string[];
  created_at: string;
  expires_at: string;
  last_used_at?: string;
}

// ==================== Webhooks ====================

export interface WebhookCreate {
  url: string;
  events: WebhookEvent[];
  secret?: string;
  enabled?: boolean;
}

export interface Webhook {
  id: string;
  url: string;
  events: WebhookEvent[];
  secret?: string;
  enabled: boolean;
  created_at: string;
  last_triggered_at?: string;
  failure_count: number;
}

export interface WebhookUpdate {
  url?: string;
  events?: WebhookEvent[];
  secret?: string;
  enabled?: boolean;
}

// ==================== Protection Profiles ====================

export type SynProxyMode = 'global' | 'disabled' | 'always' | 'threshold';
export type ProtoAction = 'allow' | 'drop' | 'rate_limit';

export interface ProtectionProfile {
  name: string;
  description?: string;
  pps_limit?: number;
  bps_limit?: number;
  attack_pps_limit?: number;
  attack_bps_limit?: number;
  max_conn_per_src?: number;
  max_conn_total?: number;
  syn_proxy_mode?: SynProxyMode;
  syn_challenge_threshold?: number;
  tcp_ports?: number[];
  udp_ports?: number[];
  // Per-protocol actions
  tcp_action?: ProtoAction;
  udp_action?: ProtoAction;
  icmp_action?: ProtoAction;
  other_action?: ProtoAction;
  // Per-protocol aggregate PPS rate limits
  tcp_rate_limit_pps?: number;
  udp_rate_limit_pps?: number;
  icmp_rate_limit_pps?: number;
  other_rate_limit_pps?: number;
  // Allowed IP protocol numbers for "other" category (e.g. [47, 50] for GRE+ESP)
  other_allowed_protos?: number[];
}

export interface ProtectedIPWithProfile {
  ip: string;
  description?: string;
  profile: string;
  overrides?: Partial<ProtectionProfile>;
}

// ==================== Config History ====================

export interface ConfigHistoryEntry {
  id: number;
  version: number;
  description: string | null;
  created_at: string | null;
}

// ==================== Realtime DPDK ====================

export interface PortStats {
  port_id: number;
  rx_packets: number;
  tx_packets: number;
  rx_bytes: number;
  tx_bytes: number;
  dropped: number;
  rx_pps: number;
  tx_pps: number;
  rx_bps: number;  // bits/s from C (bytes_diff * 8)
  tx_bps: number;  // bits/s from C
  rx_mbps: number;
  tx_mbps: number;
  rx_kpps: number;
  tx_kpps: number;
}

export interface RealtimeStats {
  timestamp: number;
  timestamp_str: string;
  connected: boolean;
  ports: Record<string, PortStats>;
}

export interface TrafficHistorySample {
  timestamp: number;
  timestamp_str: string;
  pps: number;
  bps: number;
  drops: number;
  attacks: number;
  rx_bps: number;   // bytes/s (converted from bits/s in backend)
  tx_bps: number;   // bytes/s
  rx_pps: number;
  tx_pps: number;
  drop_pps: number;  // computed from drop-reason counter deltas
  fwd_bps: number;   // bytes/s
  fwd_pps: number;
  drop_bps: number;  // bytes/s
}

export interface AnomalyStatus {
  timestamp: number;
  timestamp_str?: string;
  active: boolean;
  level: number;
  level_name: string;
  tier_agreement: number;
  max_z_score: number;
  confidence: number;  // 0-100 percentage
  primary_feature: number;
  primary_feature_name: string;
  duration_sec: number;
  cool_down_remaining: number;
  baselines_frozen: boolean;
  tier1_ready: boolean;
  tier2_ready_count: number;
  tier3_ready_count: number;
  baseline_updates: number;
  detection_cycles: number;
  detection_count: number;
  packets_per_sec: number;
  bytes_per_sec: number;
  syn_per_sec: number;
  unique_src_ips: number;
  unique_flows: number;
  heavy_hitters: number;
  rate_limit_pct: number;
  current_threshold: number;
  // Learning state
  learning_phase: number;
  learning_phase_name: string;
  tier1_progress: number;
  tier2_progress: number;
  tier3_progress: number;
  tier1_eta_sec: number;
  tier2_eta_sec: number;
  tier3_eta_sec: number;
  baseline_age_sec: number;
  // Alert-Only Mode
  mitigation_active: boolean;
  learning_action: number;
  suppressed_count: number;
  // Progressive trust
  trust_multiplier: number;
  // Detection method state
  sensitivity_preset: number;
  cusum_active: boolean;
  jsd_active: boolean;
  fast_active: boolean;
  fp_rate: number;
  tp_rate: number;
  adaptive_adjustments: number;
}

export interface SuppressedDetection {
  timestamp: string;
  level_name: string;
  max_z_score: number;
  tier_agreement: number;
  primary_feature_name: string;
  action: string;
}

export interface PerIPAnomalyEntry {
  dst_ip_str: string;
  anomaly_active: boolean;
  level: number;
  level_name: string;
  attack_type_name: string;
  anomaly_protocol_name: string;
  anomaly_dst_port: number;
  max_z_score: number;
  tier_agreement: number;
  anomalous_feature_count: number;
  packets_per_sec: number;
  bytes_per_sec: number;
  unique_src_ips: number;
  duration_sec: number;
  started_at: string;
  spoofed_mode: boolean;
  randomness_pct: number;
  rate_limit_pct: number;
  // Detection details
  detection_method: number;
  sensitivity_preset: number;
  learning_phase: number;
  tier1_progress: number;
  cool_down_remaining_sec: number;
  peak_z_feature: number;
  peak_z_feature_name: string;
  cusum_triggered: boolean;
  jsd_triggered: boolean;
  fast_triggered: boolean;
  confidence: number;
  severity: number;
}

export interface PerIPAnomalyResponse {
  per_ip_anomalies: PerIPAnomalyEntry[];
  count: number;
  any_active: boolean;
}

export interface PerIPAnomalySummary {
  total_protected_ips: number;
  anomalous_ips: number;
  healthy_ips: number;
  max_severity_level: number;
  max_severity_name: string;
  max_z_score: number;
}

// ==================== Per-IP Stats ====================

export interface PerIPStatsEntry {
  dst_ip: number;
  dst_ip_str: string;
  has_traffic_data: boolean;
  packets_per_sec: number;
  bytes_per_sec: number;
  flows_per_sec: number;
  total_packets: number;
  active_flows: number;
  syn_per_sec: number;
  syn_ack_per_sec: number;
  ack_per_sec: number;
  rst_per_sec: number;
  fin_per_sec: number;
  tcp_ratio: number;
  udp_ratio: number;
  icmp_ratio: number;
  other_ratio: number;
  unique_src_ips: number;
  unique_flows: number;
  max_flow_fraction: number;
  topk_flow_share: number;
  heavy_hitter_count: number;
  avg_packets_per_flow: number;
  flow_duration_avg_ms: number;
  anomaly_active: boolean;
  anomaly_level: number;
  anomaly_level_name: string;
  max_z_score: number;
  tier_agreement: number;
  anomaly_protocol: number;
  anomaly_protocol_name: string;
  attack_type: number;
  attack_type_name: string;
  anomaly_dst_port: number;
  flash_crowd_score: number;
  syn_completion_pct: number;
  response_ratio_pct: number;
  spoofed_mode: boolean;
  randomness_pct: number;
  rate_limit_pct: number;
  // Detection details
  detection_method: number;
  sensitivity_preset: number;
  learning_phase: number;
  tier1_progress: number;
  cool_down_remaining_sec: number;
  peak_z_feature: number;
  cusum_triggered: boolean;
  jsd_triggered: boolean;
  fast_triggered: boolean;
  confidence: number;
  severity: number;
}

export interface PerIPStatsResponse {
  protected_ips: PerIPStatsEntry[];
  count: number;
  totals: {
    packets_per_sec: number;
    bytes_per_sec: number;
    total_packets: number;
  };
}

// ==================== Baselines Visualization ====================

export interface BaselineTierSlot {
  mean: number;
  stddev: number;
  samples: number;
  ready: boolean;
}

export interface LearningStatus {
  phase: 'immediate' | 'hourly' | 'weekly' | 'mature';
  phase_label: string;
  eta: string | null;
  tier1_progress: string;
  tier2_progress: string;
  tier3_progress: string;
}

export interface BaselinesData {
  feature: string;
  features_available: string[];
  total_updates: number;
  save_timestamp: number;
  immediate: BaselineTierSlot[];  // 3 sub-tiers: 1s, 10s, 60s
  hourly: BaselineTierSlot[];
  weekly: BaselineTierSlot[];
  per_ip?: string | null;
  fallback?: 'no_data' | null;
  learning_status?: LearningStatus | null;
}

/** Time-appropriate baseline summary (weekly -> hourly -> immediate fallback) */
export interface BaselinesSummary {
  features: Record<string, BaselineTierSlot>;
  total_updates: number;
  save_timestamp: number;
  tier_used: string;
}

// ==================== Per-IP Layer 2 Config ====================

export interface PerIPL2ConfigOverrides {
  z_score_threshold?: number | null;
  min_tier_agreement?: number | null;
  min_features_per_tier?: number | null;
  cool_down_seconds?: number | null;
  baseline_freeze_enabled?: boolean | null;
  alpha_immediate_1s?: number | null;
  alpha_immediate_10s?: number | null;
  alpha_immediate_60s?: number | null;
  min_samples_immediate_1s?: number | null;
  min_samples_immediate_10s?: number | null;
  min_samples_immediate_60s?: number | null;
  warmup_pps_threshold?: number | null;
  warmup_syn_threshold?: number | null;
}

export interface PerIPL2ConfigResponse {
  ip_address: string;
  is_active: boolean;
  version: number;
  overrides: Record<string, number | boolean>;
  effective: Record<string, number | boolean>;
  global_defaults?: Record<string, number | boolean>;
  updated_at: string | null;
  updated_by: string | null;
}

// ==================== Pagination ====================

export interface PaginationParams {
  page?: number;
  per_page?: number;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
}

// ==================== Multi-Tenant ====================

export enum TenantStatus {
  ACTIVE = 'active',
  ATTACK_MODE = 'attack_mode',
  PROVISIONING = 'provisioning',
  SUSPENDED = 'suspended',
  MAINTENANCE = 'maintenance',
  MIGRATING = 'migrating',
  DISABLED = 'disabled',
}

export enum TenantTier {
  FREE = 'free',
  BASIC = 'basic',
  STANDARD = 'standard',
  PREMIUM = 'premium',
  ENTERPRISE = 'enterprise',
  CUSTOM = 'custom',
}

export enum TenantType {
  DIRECT = 'direct',
  RESELLER = 'reseller',
  INTERNAL = 'internal',
  TRIAL = 'trial',
}

export interface TenantQuotas {
  max_clean_bps: number;
  max_attack_bps: number;
  max_clean_pps: number;
  max_attack_pps: number;
  max_flows: number;
  max_connections: number;
  max_policies: number;
  max_blacklist: number;
  max_whitelist: number;
  max_custom_signatures: number;
  api_requests_per_minute: number;
  api_requests_per_hour: number;
}

export interface TenantFeatures {
  l1_basic: boolean;
  l1_advanced: boolean;
  l2_anomaly: boolean;
  l3_ml: boolean;
  l4_reputation: boolean;
  l4_challenges: boolean;
  l4_bot_mgmt: boolean;
  l5_intel: boolean;
  realtime_dashboard: boolean;
  api_access: boolean;
  custom_reports: boolean;
  managed_rules: boolean;
  carpet_bomb_detection?: boolean;
}

export interface TenantContact {
  primary_email: string;
  phone?: string;
  name?: string;
}

export interface Tenant {
  id: number;
  name: string;
  description?: string;
  status: TenantStatus;
  tier: TenantTier;
  tenant_type: TenantType;
  protected_ips: string[];
  protected_prefixes: string[];
  contact: TenantContact;
  quotas: TenantQuotas;
  features: TenantFeatures;
  created_at: string;
  updated_at: string;
  last_attack_at?: string;
  // Runtime stats (populated by live data endpoints)
  current_traffic_pps?: number;
  current_traffic_bps?: number;
  attack_count_24h?: number;
}

export interface TenantCreate {
  name: string;
  description?: string;
  tier?: TenantTier;
  tenant_type?: TenantType;
  protected_ips?: string[];
  protected_prefixes?: string[];
  contact_email?: string;
  contact_phone?: string;
  contact?: Partial<TenantContact>;
  quotas?: Partial<TenantQuotas>;
  features?: Partial<TenantFeatures>;
}

export interface TenantUpdate extends Partial<TenantCreate> {
  status?: TenantStatus;
}
