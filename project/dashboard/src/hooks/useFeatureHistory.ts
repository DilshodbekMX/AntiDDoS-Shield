/**
 * Client-side per-IP feature history ring buffer with detection metrics.
 *
 * Accumulates per-IP detection features (polled every 1s) in a ring buffer
 * for time-series chart rendering. Each sample stores:
 *  - Raw feature value
 *  - C Layer 2 EWMA baseline means (5 tiers: 1s, 10s, 60s, hourly, weekly)
 *  - Client-side detection metrics (z-score, CUSUM, JSD, log z-score, threshold)
 *
 * Detection metrics are computed client-side using the same algorithms as C Layer 2:
 *  - Z-Score: |value - baseline| / stddev (Welford online variance)
 *  - CUSUM: cumulative sum for slow-ramp detection (k=0.25, h=5.0)
 *  - Log Z-Score: z-score on log-transformed values (cardinality features)
 *  - JSD: Jensen-Shannon divergence for protocol distribution changes
 *  - Threshold: simple comparison against fixed threshold
 */

import { useRef, useCallback, useState } from 'react';

// ==================== Detection Method Types ====================

export type DetectionMethod = 'zscore' | 'cusum' | 'log_zscore' | 'jsd' | 'threshold';

export interface DetectionConfig {
  method: DetectionMethod;
  weight: number;
  bidirectional: boolean;
  threshold?: number;  // For threshold method
  cusumK?: number;     // CUSUM slack parameter (default 0.25)
  cusumH?: number;     // CUSUM decision interval (default 5.0)
}

/** Detection configuration for each C Layer 2 feature */
export const FEATURE_DETECTION: Record<string, DetectionConfig> = {
  // Tier 0 -- Volume (CUSUM)
  packets_per_sec:     { method: 'cusum', weight: 1.0, bidirectional: false, cusumK: 0.25, cusumH: 5.0 },
  bytes_per_sec:       { method: 'cusum', weight: 1.0, bidirectional: false, cusumK: 0.25, cusumH: 5.0 },
  bytes_per_packet:    { method: 'zscore', weight: 0.8, bidirectional: true },
  flows_per_sec:       { method: 'cusum', weight: 1.0, bidirectional: false, cusumK: 0.25, cusumH: 5.0 },
  // Tier 1 -- TCP Flags (Z-Score)
  syn_per_sec:         { method: 'zscore', weight: 1.0, bidirectional: false },
  syn_ack_per_sec:     { method: 'zscore', weight: 0.8, bidirectional: false },
  ack_per_sec:         { method: 'zscore', weight: 0.3, bidirectional: false },
  rst_per_sec:         { method: 'zscore', weight: 0.7, bidirectional: false },
  fin_per_sec:         { method: 'zscore', weight: 0.3, bidirectional: false },
  syn_ack_ratio:       { method: 'zscore', weight: 1.0, bidirectional: false },
  rst_syn_ratio:       { method: 'zscore', weight: 1.0, bidirectional: false },
  // Tier 2 -- Protocol Mix (JSD)
  tcp_ratio:           { method: 'jsd', weight: 0.5, bidirectional: false },
  udp_ratio:           { method: 'jsd', weight: 0.5, bidirectional: false },
  icmp_ratio:          { method: 'jsd', weight: 0.5, bidirectional: false },
  other_ratio:         { method: 'jsd', weight: 0.5, bidirectional: false },
  // Tier 3 -- Cardinality (Log Z-Score)
  unique_src_ips:      { method: 'log_zscore', weight: 1.0, bidirectional: true },
  unique_dst_ports:    { method: 'log_zscore', weight: 0.8, bidirectional: true },
  unique_flows:        { method: 'log_zscore', weight: 1.0, bidirectional: true },
  src_ip_entropy:      { method: 'zscore', weight: 0.5, bidirectional: false },
  // Tier 4 -- Churn (CUSUM)
  new_srcip_rate:      { method: 'cusum', weight: 1.0, bidirectional: false, cusumK: 0.25, cusumH: 5.0 },
  // Tier 5 -- Concentration (Threshold)
  max_flow_fraction:   { method: 'threshold', weight: 0.8, bidirectional: false, threshold: 15 },
  topk_flow_share:     { method: 'threshold', weight: 0.6, bidirectional: false, threshold: 30 },
  heavy_hitter_count:  { method: 'zscore', weight: 0.7, bidirectional: false },
  // Tier 6 -- Flow Behavior (Z-Score)
  avg_packets_per_flow: { method: 'zscore', weight: 0.8, bidirectional: true },
  flow_duration_avg_ms: { method: 'zscore', weight: 0.8, bidirectional: true },
  // Tier 7 -- TCP Flag Ratios (Z-Score)
  syn_tcp_ratio:       { method: 'zscore', weight: 1.0, bidirectional: false },
  synack_tcp_ratio:    { method: 'zscore', weight: 0.8, bidirectional: false },
  ack_tcp_ratio:       { method: 'zscore', weight: 0.8, bidirectional: true },
  rst_tcp_ratio:       { method: 'zscore', weight: 1.0, bidirectional: false },
  fin_tcp_ratio:       { method: 'zscore', weight: 0.8, bidirectional: false },
  // Tier 8 -- Burst & Density
  burst_factor:        { method: 'zscore', weight: 1.0, bidirectional: false },
  udp_flow_ratio:      { method: 'zscore', weight: 0.7, bidirectional: true },
  icmp_echo_ratio:     { method: 'zscore', weight: 0.7, bidirectional: false },
  dst_port_density:    { method: 'zscore', weight: 0.8, bidirectional: true },
  // Tier 10 -- Packet Characteristics
  small_pkt_ratio:     { method: 'zscore', weight: 0.7, bidirectional: false },
  fragment_ratio:      { method: 'zscore', weight: 0.8, bidirectional: false },
  ttl_mean:            { method: 'zscore', weight: 0.5, bidirectional: true },
  tcp_completion_rate: { method: 'zscore', weight: 0.9, bidirectional: true },
  src_port_entropy:    { method: 'zscore', weight: 0.6, bidirectional: true },
};

// ==================== Feature Keys ====================

/** All feature keys tracked per sample (C Layer 2's 39 + dashboard extras) */
export const FEATURE_KEYS = [
  // C Layer 2 detection features (indices 0-38)
  'packets_per_sec', 'bytes_per_sec', 'flows_per_sec',
  'syn_per_sec', 'syn_ack_per_sec', 'ack_per_sec', 'rst_per_sec', 'fin_per_sec',
  'tcp_ratio', 'udp_ratio', 'icmp_ratio', 'other_ratio',
  'syn_ack_ratio', 'rst_syn_ratio', 'bytes_per_packet',
  'unique_src_ips', 'unique_dst_ports', 'unique_flows',
  'new_srcip_rate',
  'max_flow_fraction', 'topk_flow_share', 'heavy_hitter_count',
  'avg_packets_per_flow', 'flow_duration_avg_ms',
  'syn_tcp_ratio', 'synack_tcp_ratio', 'ack_tcp_ratio', 'rst_tcp_ratio', 'fin_tcp_ratio',
  'burst_factor',
  'udp_flow_ratio',
  'icmp_echo_ratio',
  'dst_port_density',
  'src_ip_entropy', 'src_port_entropy',
  'small_pkt_ratio', 'fragment_ratio', 'ttl_mean',
  'tcp_completion_rate',
  // Dashboard extras (not in C detection, display-only)
  'active_flows',
  'syn_completion_pct', 'response_ratio_pct', 'flash_crowd_score',
] as const;

export type FeatureKey = typeof FEATURE_KEYS[number];

// ==================== Baseline Tiers ====================

/**
 * Baseline tier definitions.
 * C exports 5 tiers with keys like bl_{tier}_{feature}.
 */
export const BASELINE_TIERS = [
  { id: '1s',     label: '1s EWMA',  color: '#f87171', dash: '2 2' },   // red-400
  { id: '10s',    label: '10s EWMA', color: '#facc15', dash: '6 3' },   // yellow-400
  { id: '60s',    label: '60s EWMA', color: '#fb923c', dash: '8 4' },   // orange-400
  { id: 'hourly', label: 'ToD',      color: '#22d3ee', dash: '4 4' },   // cyan-400
  { id: 'weekly', label: 'DoW',      color: '#a78bfa', dash: '10 4' },  // violet-400
] as const;

/** Feature keys that have C-exported baselines in the API response */
const C_BASELINE_FEATURE_KEYS = [
  'packets_per_sec', 'bytes_per_sec', 'flows_per_sec',
  'syn_per_sec', 'syn_ack_per_sec', 'ack_per_sec', 'rst_per_sec', 'fin_per_sec',
  'tcp_ratio', 'udp_ratio', 'icmp_ratio',
  'unique_src_ips', 'unique_flows',
  'max_flow_fraction', 'topk_flow_share', 'heavy_hitter_count',
  'avg_packets_per_flow', 'flow_duration_avg_ms',
] as const;

/** Feature keys that get client-side EWMA (no C baselines available) */
const CLIENT_EWMA_FEATURE_KEYS = [
  'bytes_per_packet', 'syn_ack_ratio', 'other_ratio',
  'rst_syn_ratio', 'unique_dst_ports', 'new_srcip_rate', 'src_ip_entropy',
  'small_pkt_ratio', 'fragment_ratio', 'ttl_mean',
  'tcp_completion_rate', 'src_port_entropy',
  'syn_completion_pct', 'response_ratio_pct', 'flash_crowd_score',
] as const;

/** All feature keys that have baseline lines (union of C + client-side) */
export const BASELINE_FEATURE_KEYS = [
  ...C_BASELINE_FEATURE_KEYS,
  ...CLIENT_EWMA_FEATURE_KEYS,
] as const;

/** EWMA alpha per tier (same as C Layer 2) */
const EWMA_ALPHAS: Record<string, number> = {
  '1s': 0.8,
  '10s': 0.18,
  '60s': 0.033,
  'hourly': 0.1,
  'weekly': 0.05,
};

/**
 * Build API response key for a baseline tier + feature.
 * e.g. getBaselineAPIKey('10s', 'packets_per_sec') -> 'bl_10s_packets_per_sec'
 */
export function getBaselineAPIKey(tierId: string, featureKey: string): string {
  return `bl_${tierId}_${featureKey}`;
}

// ==================== Sample Interface ====================

// Use index signature for baseline and detection fields -- they're dynamic
export interface FeatureSample {
  timestamp: number;
  timestamp_str: string;
  packets_per_sec: number;
  bytes_per_sec: number;
  flows_per_sec: number;
  syn_per_sec: number;
  syn_ack_per_sec: number;
  ack_per_sec: number;
  rst_per_sec: number;
  fin_per_sec: number;
  tcp_ratio: number;
  udp_ratio: number;
  icmp_ratio: number;
  other_ratio: number;
  syn_ack_ratio: number;
  rst_syn_ratio: number;
  bytes_per_packet: number;
  unique_src_ips: number;
  unique_dst_ports: number;
  unique_flows: number;
  new_srcip_rate: number;
  max_flow_fraction: number;
  topk_flow_share: number;
  heavy_hitter_count: number;
  avg_packets_per_flow: number;
  flow_duration_avg_ms: number;
  syn_tcp_ratio: number;
  synack_tcp_ratio: number;
  ack_tcp_ratio: number;
  rst_tcp_ratio: number;
  fin_tcp_ratio: number;
  burst_factor: number;
  udp_flow_ratio: number;
  icmp_echo_ratio: number;
  dst_port_density: number;
  src_ip_entropy: number;
  small_pkt_ratio: number;
  fragment_ratio: number;
  ttl_mean: number;
  tcp_completion_rate: number;
  src_port_entropy: number;
  active_flows: number;
  syn_completion_pct: number;
  response_ratio_pct: number;
  flash_crowd_score: number;
  // Dynamic keys: bl_{tier}_{feature}, det_{feature}, cusum_high_{feature}, cusum_low_{feature}
  [key: string]: number | string | undefined;
}

/** Raw API response shape */
interface PerIPAPIResponse {
  packets_per_sec: number;
  bytes_per_sec: number;
  flows_per_sec: number;
  syn_per_sec: number;
  syn_ack_per_sec: number;
  ack_per_sec: number;
  rst_per_sec: number;
  fin_per_sec: number;
  tcp_ratio: number;
  udp_ratio: number;
  icmp_ratio: number;
  unique_src_ips: number;
  unique_flows: number;
  max_flow_fraction: number;
  topk_flow_share: number;
  heavy_hitter_count: number;
  avg_packets_per_flow: number;
  flow_duration_avg_ms: number;
  active_flows: number;
  [key: string]: unknown;
}

// ==================== Detection State ====================

/** Per-feature running statistics for detection computation (Welford's online algorithm) */
interface FeatureDetState {
  n: number;           // Sample count
  mean: number;        // Running mean
  m2: number;          // Running M2 (sum of squared deviations) for variance
  logMean: number;     // Log-space running mean (for log_zscore)
  logM2: number;       // Log-space M2
  cusumHigh: number;   // CUSUM S+ accumulator
  cusumLow: number;    // CUSUM S- accumulator
}

function newDetState(): FeatureDetState {
  return { n: 0, mean: 0, m2: 0, logMean: 0, logM2: 0, cusumHigh: 0, cusumLow: 0 };
}

/** Compute JSD between two probability distributions (each summing to ~1) */
function jensenShannonDivergence(p: number[], q: number[]): number {
  const eps = 1e-10;
  let jsd = 0;
  for (let i = 0; i < p.length; i++) {
    const pi = Math.max(p[i], eps);
    const qi = Math.max(q[i], eps);
    const mi = (pi + qi) / 2;
    jsd += 0.5 * pi * Math.log2(pi / mi) + 0.5 * qi * Math.log2(qi / mi);
  }
  return Math.max(0, jsd);
}

// ==================== Constants ====================

const MAX_SAMPLES = 600;      // 10 minutes at 1s intervals
const MIN_SAMPLES_FOR_DET = 10; // Minimum samples before detection is meaningful

// ==================== Hook ====================

export function useFeatureHistory() {
  const historyRef = useRef<Map<string, FeatureSample[]>>(new Map());
  /** Tracks previous EWMA values per ip+tier+feature for client-side computation */
  const ewmaRef = useRef<Map<string, number>>(new Map());
  /** Tracks per-feature detection state per ip */
  const detStateRef = useRef<Map<string, FeatureDetState>>(new Map());
  const [tick, setTick] = useState(0);

  const addSample = useCallback((ip: string, data: PerIPAPIResponse) => {
    if (!ip || !data) return;

    const pps = data.packets_per_sec || 0;
    const bps = data.bytes_per_sec || 0;
    const synPs = data.syn_per_sec || 0;
    const rstPs = data.rst_per_sec || 0;
    const uniqueSrcIps = data.unique_src_ips || 0;

    const now = Date.now();
    const sample: FeatureSample = {
      timestamp: now,
      timestamp_str: new Date(now).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      }),
      packets_per_sec: pps,
      bytes_per_sec: bps,
      flows_per_sec: data.flows_per_sec || 0,
      syn_per_sec: synPs,
      syn_ack_per_sec: data.syn_ack_per_sec || 0,
      ack_per_sec: data.ack_per_sec || 0,
      rst_per_sec: rstPs,
      fin_per_sec: data.fin_per_sec || 0,
      tcp_ratio: data.tcp_ratio || 0,
      udp_ratio: data.udp_ratio || 0,
      icmp_ratio: data.icmp_ratio || 0,
      other_ratio: (data.other_ratio as number) || 0,
      syn_ack_ratio: synPs > 0 ? (data.syn_ack_per_sec || 0) / synPs : 0,
      rst_syn_ratio: (data.rst_syn_ratio as number) ?? (synPs > 0 ? rstPs / synPs : 0),
      bytes_per_packet: pps > 0 ? bps / pps : 0,
      unique_src_ips: uniqueSrcIps,
      unique_dst_ports: (data.unique_dst_ports as number) || 0,
      unique_flows: data.unique_flows || 0,
      new_srcip_rate: (data.new_srcip_rate as number) || 0,
      max_flow_fraction: data.max_flow_fraction || 0,
      topk_flow_share: data.topk_flow_share || 0,
      heavy_hitter_count: data.heavy_hitter_count || 0,
      avg_packets_per_flow: data.avg_packets_per_flow || 0,
      flow_duration_avg_ms: data.flow_duration_avg_ms || 0,
      syn_tcp_ratio: (data.syn_tcp_ratio as number) || 0,
      synack_tcp_ratio: (data.synack_tcp_ratio as number) || 0,
      ack_tcp_ratio: (data.ack_tcp_ratio as number) || 0,
      rst_tcp_ratio: (data.rst_tcp_ratio as number) || 0,
      fin_tcp_ratio: (data.fin_tcp_ratio as number) || 0,
      burst_factor: (data.burst_factor as number) || 100,
      udp_flow_ratio: (data.udp_flow_ratio as number) || 0,
      icmp_echo_ratio: (data.icmp_echo_ratio as number) || 0,
      dst_port_density: (data.dst_port_density as number) || 0,
      src_ip_entropy: (data.src_ip_entropy as number) ?? (uniqueSrcIps > 0 ? Math.log2(uniqueSrcIps) : 0),
      small_pkt_ratio: (data.small_pkt_ratio as number) || 0,
      fragment_ratio: (data.fragment_ratio as number) || 0,
      ttl_mean: (data.ttl_mean as number) || 0,
      tcp_completion_rate: (data.tcp_completion_rate as number) || 0,
      src_port_entropy: (data.src_port_entropy as number) || 0,
      active_flows: data.active_flows || 0,
      syn_completion_pct: (data.syn_completion_pct as number) || 0,
      response_ratio_pct: (data.response_ratio_pct as number) || 0,
      flash_crowd_score: (data.flash_crowd_score as number) || 0,
    };

    // Copy all C Layer 2 EWMA baseline means from API response (bl_{tier}_{feature})
    for (const tier of BASELINE_TIERS) {
      for (const feat of C_BASELINE_FEATURE_KEYS) {
        const apiKey = getBaselineAPIKey(tier.id, feat);
        const val = data[apiKey];
        if (typeof val === 'number' && val > 0) {
          sample[apiKey] = val;
        }
      }
    }

    // Client-side EWMA for derived/anomaly features (no C baselines available)
    for (const feat of CLIENT_EWMA_FEATURE_KEYS) {
      const val = sample[feat] as number;
      for (const tier of BASELINE_TIERS) {
        const blKey = getBaselineAPIKey(tier.id, feat);
        const stateKey = `${ip}_${blKey}`;
        const alpha = EWMA_ALPHAS[tier.id];
        const prev = ewmaRef.current.get(stateKey);
        const ewma = prev !== undefined ? alpha * val + (1 - alpha) * prev : val;
        ewmaRef.current.set(stateKey, ewma);
        if (ewma > 0) {
          sample[blKey] = ewma;
        }
      }
    }

    // ===== Detection metric computation =====
    // Compute z-score, CUSUM, JSD, log z-score, threshold for each feature

    // First, compute JSD for protocol group (shared across tcp/udp/icmp/other_ratio)
    const protoKeys = ['tcp_ratio', 'udp_ratio', 'icmp_ratio', 'other_ratio'] as const;
    const currentProto = protoKeys.map(k => (sample[k] as number) / 100);
    const baselineProto = protoKeys.map(k => {
      const blKey = getBaselineAPIKey('60s', k);
      const bl = sample[blKey];
      return typeof bl === 'number' && bl > 0 ? bl / 100 : 0.25; // uniform if no baseline
    });
    // Normalize distributions
    const sumCurrent = currentProto.reduce((a, b) => a + b, 0) || 1;
    const sumBaseline = baselineProto.reduce((a, b) => a + b, 0) || 1;
    const normCurrent = currentProto.map(v => v / sumCurrent);
    const normBaseline = baselineProto.map(v => v / sumBaseline);
    const jsdValue = jensenShannonDivergence(normCurrent, normBaseline);

    // Compute per-feature detection metrics
    for (const [feat, config] of Object.entries(FEATURE_DETECTION)) {
      const val = sample[feat] as number;
      const stateKey = `${ip}_det_${feat}`;

      let state = detStateRef.current.get(stateKey);
      if (!state) {
        state = newDetState();
        detStateRef.current.set(stateKey, state);
      }

      // Update Welford running statistics
      state.n++;
      const delta = val - state.mean;
      state.mean += delta / state.n;
      const delta2 = val - state.mean;
      state.m2 += delta * delta2;

      // Update log-space statistics for log_zscore features
      if (config.method === 'log_zscore') {
        const logVal = Math.log2(Math.max(1, val + 1));
        const logDelta = logVal - state.logMean;
        state.logMean += logDelta / state.n;
        const logDelta2 = logVal - state.logMean;
        state.logM2 += logDelta * logDelta2;
      }

      // Skip detection until we have enough samples
      if (state.n < MIN_SAMPLES_FOR_DET) continue;

      const variance = state.m2 / state.n;
      const stddev = Math.sqrt(Math.max(variance, 1e-10));

      // Use 60s EWMA baseline as reference mean (more stable than running mean)
      const blKey60s = getBaselineAPIKey('60s', feat);
      const baselineMean = (sample[blKey60s] as number) || state.mean;

      let detScore = 0;

      switch (config.method) {
        case 'zscore': {
          const z = (val - baselineMean) / stddev;
          detScore = config.bidirectional ? Math.abs(z) : Math.max(0, z);
          break;
        }

        case 'cusum': {
          const k = (config.cusumK ?? 0.25) * stddev;
          const h = (config.cusumH ?? 5.0) * stddev;
          state.cusumHigh = Math.max(0, state.cusumHigh + (val - baselineMean - k));
          state.cusumLow = Math.max(0, state.cusumLow - (val - baselineMean + k));
          // Also compute z-score for the value
          const z = Math.max(0, (val - baselineMean) / stddev);
          // Normalized CUSUM score: how close to alarm threshold
          const cusumScore = h > 0 ? Math.max(state.cusumHigh, state.cusumLow) / h : 0;
          // Emit both z-score and CUSUM
          detScore = z;
          sample[`cusum_${feat}`] = Math.min(cusumScore, 20); // cap for chart
          // Alarm: reset CUSUM after triggering
          if (state.cusumHigh > h) state.cusumHigh = 0;
          if (state.cusumLow > h) state.cusumLow = 0;
          break;
        }

        case 'log_zscore': {
          const logVal = Math.log2(Math.max(1, val + 1));
          const logBaseline = Math.log2(Math.max(1, baselineMean + 1));
          const logVariance = state.logM2 / state.n;
          const logStddev = Math.sqrt(Math.max(logVariance, 1e-10));
          const z = (logVal - logBaseline) / logStddev;
          detScore = config.bidirectional ? Math.abs(z) : Math.max(0, z);
          break;
        }

        case 'jsd': {
          // JSD is computed once for the protocol group, shared across all 4 ratios
          // Scale to 0-10 range for visual consistency with z-scores (JSD range is 0-1)
          detScore = jsdValue * 10;
          break;
        }

        case 'threshold': {
          const thresh = config.threshold ?? 50;
          detScore = (val / thresh) * 6; // Scale so threshold=6 (matches z-score alarm level)
          break;
        }
      }

      sample[`det_${feat}`] = Math.round(detScore * 100) / 100;
    }

    let buffer = historyRef.current.get(ip);
    if (!buffer) {
      // Evict oldest IP history if at capacity (prevents unbounded memory growth)
      const MAX_IPS = 50;
      if (historyRef.current.size >= MAX_IPS) {
        const firstKey = historyRef.current.keys().next().value;
        if (firstKey) {
          historyRef.current.delete(firstKey);
          // Also clean up associated EWMA and detection state for evicted IP
          for (const key of [...ewmaRef.current.keys()]) {
            if (key.startsWith(`${firstKey}_`)) ewmaRef.current.delete(key);
          }
          for (const key of [...detStateRef.current.keys()]) {
            if (key.startsWith(`${firstKey}_`)) detStateRef.current.delete(key);
          }
        }
      }
      buffer = [];
      historyRef.current.set(ip, buffer);
    }
    buffer.push(sample);
    if (buffer.length > MAX_SAMPLES) {
      buffer.splice(0, buffer.length - MAX_SAMPLES);
    }

    setTick(t => t + 1);
  }, []);

  const getHistory = useCallback((ip: string | null): FeatureSample[] => {
    if (!ip) return [];
    return historyRef.current.get(ip) || [];
  }, []);

  const getSampleCount = useCallback((ip: string | null): number => {
    if (!ip) return 0;
    return historyRef.current.get(ip)?.length || 0;
  }, []);

  return { addSample, getHistory, getSampleCount, tick };
}
