/**
 * Shared feature configuration for Layer 2 anomaly detection.
 *
 * Used by both ConfigPage (Feature Selection tab) and AssetDetail (per-IP feature section).
 */

export const FEATURE_DISPLAY_NAMES: Record<string, string> = {
  packets_per_sec: 'Packets/s',
  bytes_per_sec: 'Bytes/s',
  flows_per_sec: 'Flows/s',
  syn_per_sec: 'SYN/s',
  syn_ack_per_sec: 'SYN-ACK/s',
  ack_per_sec: 'ACK/s',
  rst_per_sec: 'RST/s',
  fin_per_sec: 'FIN/s',
  tcp_ratio: 'TCP %',
  udp_ratio: 'UDP %',
  icmp_ratio: 'ICMP %',
  other_ratio: 'Other %',
  syn_ack_ratio: 'SYN-ACK Ratio',
  rst_syn_ratio: 'RST/SYN Ratio',
  bytes_per_packet: 'Bytes/Pkt',
  unique_src_ips: 'Unique Src IPs',
  unique_dst_ports: 'Unique Dst Ports',
  unique_flows: 'Unique Flows',
  new_srcip_rate: 'New SrcIP Rate',
  max_flow_fraction: 'Max Flow %',
  topk_flow_share: 'Top-K Flow Share',
  heavy_hitter_count: 'Heavy Hitters',
  avg_packets_per_flow: 'Avg Pkts/Flow',
  flow_duration_avg: 'Flow Duration (ms)',
  syn_tcp_ratio: 'SYN/TCP %',
  synack_tcp_ratio: 'SYNACK/TCP %',
  ack_tcp_ratio: 'ACK/TCP %',
  rst_tcp_ratio: 'RST/TCP %',
  fin_tcp_ratio: 'FIN/TCP %',
  burst_factor: 'Burst Factor',
  udp_flow_ratio: 'UDP Flow Ratio',
  icmp_echo_ratio: 'ICMP Echo %',
  dst_port_density: 'Dst Port Density',
  src_ip_entropy: 'Src IP Entropy',
  small_pkt_ratio: 'Small Pkt %',
  fragment_ratio: 'Fragment %',
  ttl_mean: 'Avg TTL',
  tcp_completion_rate: 'TCP Completion',
  src_port_entropy: 'Src Port Entropy',
};

export const FEATURE_GROUP_ORDER = [
  'Volume', 'TCP Flags', 'Protocol Mix', 'Ratios',
  'Cardinality', 'Churn', 'Concentration', 'Flow Behavior',
  'TCP Flag Ratios', 'Entropy', 'Packet Characteristics',
];

export const GROUP_DESCRIPTIONS: Record<string, string> = {
  'Volume': 'Packet rate, byte rate, and flow rate. Core volumetric flood indicators. Always active in auto-select (never downweighted).',
  'TCP Flags': 'Per-second rates of each TCP flag type. Key for detecting SYN floods, ACK floods, RST storms, and FIN attacks independently.',
  'Protocol Mix': 'Percentage breakdown of TCP/UDP/ICMP/Other. Shifts from your normal mix reveal protocol-specific floods displacing legitimate traffic.',
  'Ratios': 'Cross-feature ratios (SYN:ACK, RST:SYN, bytes/packet). Detect handshake imbalances and abnormal packet sizes without absolute thresholds.',
  'Cardinality': 'HyperLogLog-estimated unique counts of source IPs, destination ports, and flows. Distinguishes distributed botnets from single-source attacks.',
  'Churn': 'Rate of change in unique source IPs between detection windows. High churn signals IP rotation (botnet) or random spoofing.',
  'Concentration': 'Traffic distribution across flows using Count-Min Sketch. Identifies heavy hitters and determines if attack traffic is concentrated or spread.',
  'Flow Behavior': 'Per-flow statistics from the flow table (avg packets/flow, avg duration). Short-lived low-packet flows are a strong attack indicator.',
  'TCP Flag Ratios': 'Percentage of each TCP flag relative to total TCP traffic. Normalized view that works regardless of absolute volume.',
  'Entropy': 'Hartley entropy (log2 of unique source IPs). Low entropy = few sources, high entropy = many sources or spoofed IPs.',
  'Packet Characteristics': 'Low-level packet properties: small packet ratio, IP fragments, and TTL distribution. Detects crafted floods with uniform characteristics.',
};

export interface FeatureInfo {
  description: string;
  calculation: string;
  unit: string;
  insight: string;
}

export const FEATURE_INFO: Record<string, FeatureInfo> = {
  packets_per_sec: {
    description: 'Total packets received per second for this protected IP.',
    calculation: '(pkt_count_now - pkt_count_prev) / time_delta_sec',
    unit: 'pps',
    insight: 'Sudden spikes indicate volumetric floods (SYN, UDP, ICMP).',
  },
  bytes_per_sec: {
    description: 'Total bytes received per second for this protected IP.',
    calculation: '(byte_count_now - byte_count_prev) / time_delta_sec',
    unit: 'Bytes/s',
    insight: 'High BPS with low PPS suggests large-packet amplification attacks.',
  },
  flows_per_sec: {
    description: 'New unique flows established per second (HyperLogLog estimate).',
    calculation: '(new_flows_now - new_flows_prev) / time_delta_sec',
    unit: 'flows/s',
    insight: 'High flow rate with low packets/flow indicates connection exhaustion attacks.',
  },
  syn_per_sec: {
    description: 'TCP SYN packets (handshake initiations) received per second.',
    calculation: '(syn_count_now - syn_count_prev) / time_delta_sec',
    unit: 'pps',
    insight: 'Primary indicator for SYN flood attacks. SYN flag set, ACK flag clear.',
  },
  syn_ack_per_sec: {
    description: 'TCP SYN-ACK packets (server responses) received per second.',
    calculation: '(synack_count_now - synack_count_prev) / time_delta_sec',
    unit: 'pps',
    insight: 'High SYN-ACK with no matching SYN indicates reflection attacks.',
  },
  ack_per_sec: {
    description: 'TCP ACK packets received per second.',
    calculation: '(ack_count_now - ack_count_prev) / time_delta_sec',
    unit: 'pps',
    insight: 'ACK flood detection. High ACK rate without established flows is anomalous.',
  },
  rst_per_sec: {
    description: 'TCP RST (reset) packets received per second.',
    calculation: '(rst_count_now - rst_count_prev) / time_delta_sec',
    unit: 'pps',
    insight: 'High RST rate indicates connection resets from blocked or spoofed traffic.',
  },
  fin_per_sec: {
    description: 'TCP FIN (connection close) packets received per second.',
    calculation: '(fin_count_now - fin_count_prev) / time_delta_sec',
    unit: 'pps',
    insight: 'Unusual FIN floods can exhaust server connection tracking resources.',
  },
  tcp_ratio: {
    description: 'TCP traffic as a percentage of all packets.',
    calculation: 'tcp_packets * 100 / total_packets',
    unit: '%',
    insight: 'Sudden drops in TCP ratio may indicate UDP/ICMP flood displacing normal traffic.',
  },
  udp_ratio: {
    description: 'UDP traffic as a percentage of all packets.',
    calculation: 'udp_packets * 100 / total_packets',
    unit: '%',
    insight: 'Spikes indicate UDP flood or DNS/NTP amplification attacks.',
  },
  icmp_ratio: {
    description: 'ICMP traffic as a percentage of all packets.',
    calculation: 'icmp_packets * 100 / total_packets',
    unit: '%',
    insight: 'High ICMP ratio suggests ICMP flood or Smurf-style amplification.',
  },
  other_ratio: {
    description: 'Non-TCP/UDP/ICMP protocols as a percentage of all packets.',
    calculation: 'other_packets * 100 / total_packets',
    unit: '%',
    insight: 'Unusual protocol traffic (GRE, ESP, etc.) may indicate tunneling attacks.',
  },
  syn_ack_ratio: {
    description: 'Ratio of SYN packets to ACK packets, scaled by 100.',
    calculation: 'syn_packets * 100 / ack_packets',
    unit: 'ratio x100',
    insight: 'SYN floods cause high ratios (many SYNs, few ACKs). Normal traffic: ~5-20.',
  },
  rst_syn_ratio: {
    description: 'Ratio of RST packets to SYN packets, scaled by 100.',
    calculation: 'rst_packets * 100 / syn_packets',
    unit: 'ratio x100',
    insight: 'High RST/SYN indicates connections being rejected (port scan, blocked IPs).',
  },
  bytes_per_packet: {
    description: 'Average packet size in the current window.',
    calculation: 'bytes_diff / packets_diff',
    unit: 'bytes',
    insight: 'SYN floods: ~60B. DNS amplification: ~512-4096B. Normal mix: ~300-800B.',
  },
  unique_src_ips: {
    description: 'Count of unique source IPs (HyperLogLog estimate).',
    calculation: 'HLL cardinality estimate, clamped to packet count',
    unit: 'count',
    insight: 'Sudden spike = distributed attack (botnet). Very high = spoofed source IPs.',
  },
  unique_dst_ports: {
    description: 'Count of unique destination ports (HyperLogLog estimate).',
    calculation: 'HLL cardinality estimate from dst_port hash',
    unit: 'count',
    insight: 'High port cardinality = port scan. Low (1-2) = targeted service attack.',
  },
  unique_flows: {
    description: 'Count of unique 5-tuple flows (HyperLogLog estimate).',
    calculation: 'HLL cardinality from (src_ip, src_port, dst_ip, dst_port, proto) hash',
    unit: 'count',
    insight: 'Flow explosion with short durations indicates connection exhaustion attack.',
  },
  new_srcip_rate: {
    description: 'Change in unique source IP count from previous window.',
    calculation: 'unique_src_ips_now - unique_src_ips_prev',
    unit: 'count (signed)',
    insight: 'Rapid IP churn = spoofed flooding or botnet IP rotation. Can be negative.',
  },
  max_flow_fraction: {
    description: 'Largest single flow as a percentage of total traffic.',
    calculation: 'max_flow_packets / total_window_packets * 100',
    unit: '%',
    insight: 'High value = single-source volumetric attack. Uses Count-Min Sketch.',
  },
  topk_flow_share: {
    description: 'Top 10 flows combined as a percentage of total traffic.',
    calculation: 'sum(top_10_flows) / total_window_packets * 100',
    unit: '%',
    insight: 'High share with few flows = targeted attack from small botnet.',
  },
  heavy_hitter_count: {
    description: 'Number of flows exceeding 5% of total traffic.',
    calculation: 'count(flows where flow_pkt > 5% of total)',
    unit: 'count',
    insight: 'Many heavy hitters = distributed attack. One heavy hitter = single-source.',
  },
  avg_packets_per_flow: {
    description: 'Average packets per completed flow.',
    calculation: 'total_flow_packets / completed_flow_count',
    unit: 'packets',
    insight: 'Very low (1-2) = SYN flood or UDP one-shot. Normal sessions: 10-100+.',
  },
  flow_duration_avg: {
    description: 'Average duration of completed flows.',
    calculation: 'total_flow_duration_ms / completed_flow_count',
    unit: 'ms',
    insight: 'Short durations (<100ms) = attack traffic. Normal connections: seconds to minutes.',
  },
  syn_tcp_ratio: {
    description: 'SYN packets as a percentage of all TCP packets.',
    calculation: 'syn_packets * 100 / tcp_packets',
    unit: '%',
    insight: 'Normal: 5-15%. SYN flood: >30%. Pure SYN flood: >80%.',
  },
  synack_tcp_ratio: {
    description: 'SYN-ACK packets as a percentage of all TCP packets.',
    calculation: 'synack_packets * 100 / tcp_packets',
    unit: '%',
    insight: 'Should roughly match SYN ratio in normal traffic.',
  },
  ack_tcp_ratio: {
    description: 'ACK packets as a percentage of all TCP packets.',
    calculation: 'ack_packets * 100 / tcp_packets',
    unit: '%',
    insight: 'Normal: 50-70% (most TCP is data+ACK). Low ACK% with high SYN% = SYN flood.',
  },
  rst_tcp_ratio: {
    description: 'RST packets as a percentage of all TCP packets.',
    calculation: 'rst_packets * 100 / tcp_packets',
    unit: '%',
    insight: 'High RST% indicates rejected connections or spoofed traffic getting RSTs.',
  },
  fin_tcp_ratio: {
    description: 'FIN packets as a percentage of all TCP packets.',
    calculation: 'fin_packets * 100 / tcp_packets',
    unit: '%',
    insight: 'Normal: 2-5%. Elevated FIN% may indicate FIN flood or rapid teardown.',
  },
  burst_factor: {
    description: 'Current PPS relative to EWMA baseline, scaled by 100.',
    calculation: 'current_pps / ewma_baseline_pps * 100',
    unit: 'ratio x100',
    insight: '100 = normal. 200 = double baseline (burst). 500+ = likely attack.',
  },
  udp_flow_ratio: {
    description: 'UDP flows per UDP packet ratio, scaled by 100.',
    calculation: 'udp_flows * 100 / udp_pps',
    unit: 'ratio x100',
    insight: 'High ratio = single-packet UDP floods (DNS amplification, NTP monlist).',
  },
  icmp_echo_ratio: {
    description: 'ICMP echo (ping) as a percentage of all ICMP traffic.',
    calculation: 'icmp_echo_packets * 100 / icmp_total_packets',
    unit: '%',
    insight: 'High echo reply ratio = reflected ICMP flood (Smurf attack).',
  },
  dst_port_density: {
    description: 'Unique destination ports per 1000 packets.',
    calculation: 'unique_dst_ports / packets_per_sec * 1000',
    unit: 'ports/1K pps',
    insight: 'High (>100) = port scan. Low (<5) = targeted service attack.',
  },
  src_ip_entropy: {
    description: 'Shannon entropy of source IP distribution.',
    calculation: '-sum(p_i * log2(p_i)) for each unique source IP fraction',
    unit: 'bits (0-32)',
    insight: 'Low (<2) = single-source. High (>6) = distributed/spoofed. Computed globally.',
  },
  small_pkt_ratio: {
    description: 'Percentage of packets with size ≤ 64 bytes.',
    calculation: 'small_packets * 100 / total_packets',
    unit: '%',
    insight: 'High ratio (>80%) indicates SYN floods or small UDP floods (minimum-size packets).',
  },
  fragment_ratio: {
    description: 'Percentage of IP-fragmented packets.',
    calculation: 'fragment_packets * 100 / total_packets',
    unit: '%',
    insight: 'Any significant fragment ratio (>1%) is suspicious. Fragment floods evade stateless filters.',
  },
  ttl_mean: {
    description: 'Average IP Time-To-Live across all packets.',
    calculation: 'sum(ttl) / total_packets',
    unit: '0-255',
    insight: 'Uniform TTL (very low variance) suggests single-host spoofed flood. Normal traffic has diverse TTLs.',
  },
  tcp_completion_rate: {
    description: 'Ratio of completed TCP handshakes (SYN-ACK responses per SYN).',
    calculation: 'min(synack_count * 100 / syn_count, 100)',
    unit: '%',
    insight: 'Low rate (<20%) during high SYN volume = SYN flood. Healthy traffic has >90% completion.',
  },
  src_port_entropy: {
    description: 'Entropy of source port distribution (HyperLogLog-based).',
    calculation: 'log2(unique_src_ports) / 16.0 * 255',
    unit: '0-255 (scaled bits)',
    insight: 'Very high entropy = random spoofed ports. Very low = fixed-port scanner or single application.',
  },
};

export function qualityColor(score: number | null): string {
  if (score === null) return 'bg-slate-400';
  if (score >= 0.5) return 'bg-green-500';
  if (score >= 0.05) return 'bg-amber-500';
  return 'bg-red-500';
}

export function qualityLabel(score: number | null): string {
  if (score === null) return 'No baseline data yet';
  if (score >= 0.5) return 'Strong signal';
  if (score >= 0.05) return 'Moderate signal';
  return 'Low signal';
}
