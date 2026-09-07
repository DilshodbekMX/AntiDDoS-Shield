/**
 * Shared tier definitions for Feature Monitor and Feature History pages.
 */

import { formatPPS, formatBytes, formatNumber } from '../utils/formatting';

export const fmtPct = (v: number) => `${v.toFixed(1)}%`;
export const fmtDec = (v: number) => v < 10 ? v.toFixed(2) : formatNumber(v);
export const fmtSigned = (v: number) => (v >= 0 ? '+' : '') + formatNumber(v);
export const fmtBits = (v: number) => `${v.toFixed(1)} bits`;

export interface FeatureDef {
  key: string;
  label: string;
  format: (v: number) => string;
  color: string;
}

export interface TierDef {
  id: string;
  name: string;
  features: FeatureDef[];
}

export const TIERS: TierDef[] = [
  {
    id: 'volume',
    name: 'Tier 0 \u2014 Volume',
    features: [
      { key: 'packets_per_sec', label: 'PPS', format: formatPPS, color: '#6366f1' },
      { key: 'bytes_per_sec', label: 'BPS', format: formatBytes, color: '#3b82f6' },
      { key: 'bytes_per_packet', label: 'Bytes/Pkt', format: fmtDec, color: '#f59e0b' },
      { key: 'flows_per_sec', label: 'FPS (HLL)', format: formatNumber, color: '#10b981' },
    ],
  },
  {
    id: 'tcp',
    name: 'Tier 1 \u2014 TCP Flags',
    features: [
      { key: 'syn_per_sec', label: 'SYN/sec', format: formatNumber, color: '#ef4444' },
      { key: 'syn_ack_per_sec', label: 'SYN-ACK/sec', format: formatNumber, color: '#f59e0b' },
      { key: 'ack_per_sec', label: 'ACK/sec', format: formatNumber, color: '#3b82f6' },
      { key: 'rst_per_sec', label: 'RST/sec', format: formatNumber, color: '#ec4899' },
      { key: 'fin_per_sec', label: 'FIN/sec', format: formatNumber, color: '#8b5cf6' },
      { key: 'syn_ack_ratio', label: 'SYN-ACK Ratio', format: fmtDec, color: '#14b8a6' },
      { key: 'rst_syn_ratio', label: 'RST/SYN Ratio', format: fmtDec, color: '#f43f5e' },
    ],
  },
  {
    id: 'protocol',
    name: 'Tier 2 \u2014 Protocol Mix',
    features: [
      { key: 'tcp_ratio', label: 'TCP %', format: fmtPct, color: '#3b82f6' },
      { key: 'udp_ratio', label: 'UDP %', format: fmtPct, color: '#10b981' },
      { key: 'icmp_ratio', label: 'ICMP %', format: fmtPct, color: '#f59e0b' },
      { key: 'other_ratio', label: 'Other %', format: fmtPct, color: '#94a3b8' },
    ],
  },
  {
    id: 'cardinality',
    name: 'Tier 3 \u2014 Cardinality',
    features: [
      { key: 'unique_src_ips', label: 'Unique Src IPs', format: formatNumber, color: '#6366f1' },
      { key: 'unique_dst_ports', label: 'Unique Dst Ports', format: formatNumber, color: '#3b82f6' },
      { key: 'unique_flows', label: 'Unique Flows', format: formatNumber, color: '#8b5cf6' },
      { key: 'src_ip_entropy', label: 'Src IP Entropy', format: fmtBits, color: '#22d3ee' },
    ],
  },
  {
    id: 'churn',
    name: 'Tier 4 \u2014 Churn',
    features: [
      { key: 'new_srcip_rate', label: 'New Src IP Rate', format: fmtSigned, color: '#10b981' },
    ],
  },
  {
    id: 'concentration',
    name: 'Tier 5 \u2014 Concentration',
    features: [
      { key: 'max_flow_fraction', label: 'Max Flow %', format: fmtPct, color: '#ef4444' },
      { key: 'topk_flow_share', label: 'Top-K Share %', format: fmtPct, color: '#f59e0b' },
      { key: 'heavy_hitter_count', label: 'Heavy Hitters', format: formatNumber, color: '#ec4899' },
    ],
  },
  {
    id: 'flow',
    name: 'Tier 6 \u2014 Flow Behavior',
    features: [
      { key: 'avg_packets_per_flow', label: 'Avg Pkts/Flow', format: fmtDec, color: '#6366f1' },
      { key: 'flow_duration_avg_ms', label: 'Avg Duration (ms)', format: fmtDec, color: '#10b981' },
      { key: 'active_flows', label: 'Active Flows', format: formatNumber, color: '#3b82f6' },
    ],
  },
  {
    id: 'tcp_flag_ratios',
    name: 'Tier 7 \u2014 TCP Flag Ratios',
    features: [
      { key: 'syn_tcp_ratio', label: 'SYN/TCP %', format: fmtPct, color: '#ef4444' },
      { key: 'synack_tcp_ratio', label: 'SYNACK/TCP %', format: fmtPct, color: '#10b981' },
      { key: 'ack_tcp_ratio', label: 'ACK/TCP %', format: fmtPct, color: '#3b82f6' },
      { key: 'rst_tcp_ratio', label: 'RST/TCP %', format: fmtPct, color: '#f59e0b' },
      { key: 'fin_tcp_ratio', label: 'FIN/TCP %', format: fmtPct, color: '#8b5cf6' },
    ],
  },
  {
    id: 'burst_density',
    name: 'Tier 8 \u2014 Burst & Density',
    features: [
      { key: 'burst_factor', label: 'Burst Factor', format: fmtDec, color: '#ef4444' },
      { key: 'udp_flow_ratio', label: 'UDP Flow Ratio', format: fmtDec, color: '#3b82f6' },
      { key: 'icmp_echo_ratio', label: 'ICMP Echo %', format: fmtPct, color: '#f59e0b' },
      { key: 'dst_port_density', label: 'Dst Port Density', format: fmtDec, color: '#8b5cf6' },
    ],
  },
  {
    id: 'anomaly',
    name: 'Tier 9 \u2014 Anomaly Indicators',
    features: [
      { key: 'syn_completion_pct', label: 'SYN Completion %', format: fmtPct, color: '#ef4444' },
      { key: 'response_ratio_pct', label: 'Response Ratio %', format: fmtPct, color: '#f59e0b' },
      { key: 'flash_crowd_score', label: 'Flash Crowd Score', format: fmtPct, color: '#8b5cf6' },
    ],
  },
  {
    id: 'packet_chars',
    name: 'Tier 10 \u2014 Packet Characteristics',
    features: [
      { key: 'small_pkt_ratio', label: 'Small Pkt %', format: fmtPct, color: '#ef4444' },
      { key: 'fragment_ratio', label: 'Fragment %', format: fmtPct, color: '#f59e0b' },
      { key: 'ttl_mean', label: 'Avg TTL', format: fmtDec, color: '#3b82f6' },
      { key: 'tcp_completion_rate', label: 'TCP Completion %', format: fmtPct, color: '#10b981' },
      { key: 'src_port_entropy', label: 'Src Port Entropy', format: fmtBits, color: '#8b5cf6' },
    ],
  },
];

/** L2 feature names in enum order (matches baselines.h) for DB vector index mapping */
export const L2_FEATURE_NAMES = [
  'packets_per_sec', 'bytes_per_sec', 'flows_per_sec',
  'syn_per_sec', 'syn_ack_per_sec', 'ack_per_sec', 'rst_per_sec', 'fin_per_sec',
  'tcp_ratio', 'udp_ratio', 'icmp_ratio', 'other_ratio',
  'syn_ack_ratio', 'rst_syn_ratio', 'bytes_per_packet',
  'unique_src_ips', 'unique_dst_ports', 'unique_flows',
  'new_srcip_rate',
  'max_flow_fraction', 'topk_flow_share', 'heavy_hitter_count',
  'avg_packets_per_flow', 'flow_duration_avg',
  'syn_tcp_ratio', 'synack_tcp_ratio', 'ack_tcp_ratio', 'rst_tcp_ratio', 'fin_tcp_ratio',
  'burst_factor', 'udp_flow_ratio', 'icmp_echo_ratio', 'dst_port_density',
  'src_ip_entropy', 'src_port_entropy',
  'small_pkt_ratio', 'fragment_ratio', 'ttl_mean',
  'tcp_completion_rate',
] as const;
