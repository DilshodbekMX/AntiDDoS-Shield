/**
 * API response types derived from backend Pydantic models.
 *
 * Source of truth: backend/api/models.py + backend/api/routers/realtime.py
 * Keep in sync when adding new backend fields.
 */

// ==================== Stats (GET /stats) ====================

/** backend: TrafficStats */
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

/** backend: SecurityStats */
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

/** backend: LayerStats */
export interface LayerStats {
  packets_processed: number;
  packets_dropped: number;
  decisions_made: number;
  avg_latency_ns: number;
  errors: number;
}

/** backend: SLAStats */
export interface SLAStats {
  availability_pct: number;
  mttd_ms: number;
  mttr_ms: number;
  mitigation_effectiveness_pct: number;
  false_positive_rate_pct: number;
  sla_breaches: number;
}

/** backend: SystemStats -- returned by GET /stats */
export interface SystemStats {
  timestamp: string;
  period: string;
  traffic: TrafficStats;
  security: SecurityStats;
  layer1: LayerStats;
  layer2: LayerStats;
  sla: SLAStats;
}

// ==================== Realtime Metrics (GET /stats/realtime) ====================

/** backend: stats_service.get_realtime_metrics() return dict */
export interface RealtimeMetrics {
  timestamp: string;
  pps: number;
  bps: number;
  drop_pps: number;
  active_flows: number;
  syn_proxy_active: number;
  anomaly_score: number;
  attack_active: boolean;
  attack_level: number;
  attack_level_name: string;
  max_z_score: number;
  primary_feature: string;
  heavy_hitters: number;
  unique_src_ips: number;
  connected: boolean;
  protected_ips_count: number;
}

// ==================== Realtime Traffic (GET /realtime/traffic) ====================

/** backend: TrafficEntry */
export interface TrafficEntry {
  timestamp: number;
  timestamp_str: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  protocol_num: number;
  flags: number;
  length: number;
  port_id: number;
  direction: string;
}

/** backend: ProtocolStat */
export interface ProtocolStat {
  packets: number;
  bytes: number;
  pps: number;
}

/** backend: ProtocolStats */
export interface ProtocolStats {
  tcp: ProtocolStat;
  udp: ProtocolStat;
  icmp: ProtocolStat;
  other: ProtocolStat;
}

/** backend: TrafficResponse -- returned by GET /realtime/traffic */
export interface TrafficResponse {
  connected: boolean;
  entries: TrafficEntry[];
  protocol_stats?: ProtocolStats;
  drop_reasons?: Record<string, number>;
  drop_reasons_total?: Record<string, number>;
  total_dropped?: number;
}

// ==================== Sysmon (GET /realtime/sysmon) ====================

/** backend: LcoreStats */
export interface LcoreStats {
  lcore_id: number;
  is_active: boolean;
  busy_cycles: number;
  idle_cycles: number;
  utilization_pct: number;
}

/** backend: MempoolStats */
export interface MempoolStats {
  name: string;
  size: number;
  avail_count: number;
  in_use_count: number;
  usage_pct: number;
}

/** backend: CpuStats */
export interface CpuStats {
  cpu_id: number;
  usage_pct: number;
  user_pct: number;
  system_pct: number;
  idle_pct: number;
  iowait_pct: number;
}

/** backend: DPDKResources */
export interface DPDKResources {
  lcores: LcoreStats[];
  avg_lcore_utilization: number;
  mempools: MempoolStats[];
  hugepage_total_mb: number;
  hugepage_used_mb: number;
  hugepage_usage_pct: number;
}

/** backend: SystemResources */
export interface SystemResources {
  cpus: CpuStats[];
  avg_cpu_usage: number;
  mem_total_gb: number;
  mem_used_gb: number;
  mem_available_gb: number;
  mem_usage_pct: number;
  load_1min: number;
  load_5min: number;
  load_15min: number;
}

/** backend: SysmonResponse -- returned by GET /realtime/sysmon */
export interface SysmonResponse {
  timestamp: number;
  timestamp_str?: string;
  dpdk: DPDKResources;
  system: SystemResources;
}

// ==================== Scheduled Reports ====================

/** backend: report_service.create_scheduled_report() dict */
export interface ScheduledReport {
  id: string;
  frequency: string;
  time: string;
  report_type: string;
  format: string;
  recipients: string[];
  enabled: boolean;
  created_at: string;
  created_by: string;
  last_run: string | null;
  next_run: string | null;
}

// ==================== Per-IP Anomaly dict (getRealtimeAnomalyPerIP) ====================

/**
 * Result of getRealtimeAnomalyPerIP -- a dict keyed by IP string.
 * Import PerIPAnomalyEntry from types/index.ts; exported here for api.ts consumers.
 */
export type { PerIPAnomalyEntry } from './index';
export type PerIPAnomalyDict = Record<string, import('./index').PerIPAnomalyEntry>;

// ==================== Port Stats History ====================

/** backend: TrafficHistorySample (inline in realtime router) */
export interface PortStatsHistorySample {
  timestamp: number;
  timestamp_str: string;
  pps: number;
  bps: number;
  drops: number;
  attacks: number;
  rx_bps: number;
  tx_bps: number;
  rx_pps: number;
  tx_pps: number;
  drop_pps: number;
  fwd_bps: number;
  fwd_pps: number;
  drop_bps: number;
}

// ==================== Recharts tooltip types ====================

/** Recharts TooltipProps payload entry */
export interface RechartsPayloadEntry {
  name: string;
  value: number;
  color: string;
  dataKey: string;
  payload: Record<string, number | string>;
}

/** Props passed to a custom Recharts tooltip component */
export interface RechartsTooltipProps {
  active?: boolean;
  payload?: RechartsPayloadEntry[];
  label?: string;
}
