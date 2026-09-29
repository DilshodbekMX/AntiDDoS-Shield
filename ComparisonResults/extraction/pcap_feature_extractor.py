"""
CIC-DDoS2019 pcap -> per-destination-IP per-second feature extractor.

Reads pcap files chronologically, groups packets by destination IP and
1-second windows, computes the same 11 features as the CESNET harness
plus additional features available from packet headers (TCP flag rates,
entropy, packet characteristics). Output matches the row schema consumed
by experiment/pipeline.py.

Ground-truth labels come from the corresponding CIC-DDoS2019 CSV files:
a (src_ip, src_port, dst_ip, dst_port, proto) 5-tuple in pcap is labeled
'attack' if it appears in any attack-row CSV; 'benign' otherwise.

Usage:
    python3 pcap_feature_extractor.py <pcap_dir> <csv_dir> <output_json>
"""
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_sys.path.insert(0, _HERE)                        # sibling extraction modules (tree_io, extractors)
_sys.path.insert(0, _os.path.dirname(_HERE))      # ComparisonResults/: config, loaders, registry
_BASE = _os.environ.get('ANTIDDOS_BASE', _os.path.dirname(_os.path.dirname(_HERE)))  # == config.BASE

import os, sys, json, glob, math, time, csv
import socket
import struct
from collections import defaultdict, Counter
from datetime import datetime, timezone

import dpkt


# CIC-DDoS2019 victim IP (documented in dataset paper)
VICTIM_IP = '192.168.50.4'

# Attack CSVs map to attack types
ATTACK_CSV_FILES = {
    'syn_flood': 'Syn.csv',
    'udp_flood': 'UDP.csv',
    'portmap': 'Portmap.csv',
    'netbios': 'NetBIOS.csv',
    'ldap': 'LDAP.csv',
    'udp_lag': 'UDPLag.csv',
    'mssql': 'MSSQL.csv',
}


def ip_to_str(ip_bytes):
    """Convert 4-byte IP to dotted-decimal string."""
    return socket.inet_ntoa(ip_bytes)


def shannon_entropy(counter):
    """Compute Shannon entropy of a distribution."""
    total = sum(counter.values())
    if total == 0:
        return 0.0
    h = 0.0
    for c in counter.values():
        if c > 0:
            p = c / total
            h -= p * math.log2(p)
    return h


class WindowAggregator:
    """Aggregates per-packet data into per-(dst_ip, 1-second) feature windows."""

    def __init__(self, t0=None):
        self.t0 = t0  # First packet timestamp
        # Per (dst_ip, second_idx) -> accumulator dict
        self.windows = {}
        # Track first-seen source IPs per dst_ip for new_srcip_rate
        self.seen_src_ips = defaultdict(set)
        # Track per-flow state for flows_per_sec, flow_duration_avg, etc.
        self.flows_per_window = defaultdict(set)  # (dst_ip, sec) -> {5-tuple, ...}

    def _new_window(self):
        return {
            'n_packets': 0,
            'n_bytes': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'other_packets': 0,
            'syn_packets': 0,
            'syn_ack_packets': 0,
            'ack_packets': 0,
            'rst_packets': 0,
            'fin_packets': 0,
            'src_ips': Counter(),
            'src_ports': Counter(),
            'dst_ports': Counter(),
            'flows': set(),  # 5-tuples observed
            'attack_flows': set(),  # 5-tuples labeled attack
            'small_pkts': 0,  # packets < 100 bytes
            'fragments': 0,
            'ttl_sum': 0,
            'pkt_size_sum': 0,
            'icmp_echo': 0,
            'syn_no_ack': 0,
            'syn_with_ack': 0,
            'flow_durations_ms': [],  # We approximate flow duration later
        }

    def add_packet(self, ts, pkt_info):
        """pkt_info dict: src_ip, dst_ip, src_port, dst_port, proto, length, tcp_flags, ttl, is_fragment, is_attack."""
        if self.t0 is None:
            self.t0 = ts
        sec_idx = int((ts - self.t0))
        dst_ip = pkt_info['dst_ip']
        key = (dst_ip, sec_idx)

        if key not in self.windows:
            self.windows[key] = self._new_window()
        w = self.windows[key]

        w['n_packets'] += 1
        length = pkt_info['length']
        w['n_bytes'] += length
        w['pkt_size_sum'] += length
        if length < 100:
            w['small_pkts'] += 1
        if pkt_info.get('is_fragment'):
            w['fragments'] += 1
        ttl = pkt_info.get('ttl', 0)
        if ttl:
            w['ttl_sum'] += ttl

        proto = pkt_info['proto']
        if proto == 6:  # TCP
            w['tcp_packets'] += 1
            flags = pkt_info.get('tcp_flags', 0)
            syn = (flags & 0x02) != 0
            ack = (flags & 0x10) != 0
            rst = (flags & 0x04) != 0
            fin = (flags & 0x01) != 0
            if syn and not ack:
                w['syn_packets'] += 1
                w['syn_no_ack'] += 1
            elif syn and ack:
                w['syn_ack_packets'] += 1
                w['syn_with_ack'] += 1
            if ack:
                w['ack_packets'] += 1
            if rst:
                w['rst_packets'] += 1
            if fin:
                w['fin_packets'] += 1
        elif proto == 17:  # UDP
            w['udp_packets'] += 1
        elif proto == 1:  # ICMP
            w['icmp_packets'] += 1
            if pkt_info.get('icmp_type') == 8:  # Echo request
                w['icmp_echo'] += 1
        else:
            w['other_packets'] += 1

        # Cardinality features
        w['src_ips'][pkt_info['src_ip']] += 1
        w['src_ports'][pkt_info.get('src_port', 0)] += 1
        w['dst_ports'][pkt_info.get('dst_port', 0)] += 1

        # Flow tracking (5-tuple)
        flow_tuple = (
            pkt_info['src_ip'], pkt_info.get('src_port', 0),
            pkt_info['dst_ip'], pkt_info.get('dst_port', 0),
            proto,
        )
        w['flows'].add(flow_tuple)
        if pkt_info.get('is_attack'):
            w['attack_flows'].add(flow_tuple)

        # Track new src_ips for new_srcip_rate
        new_seen = pkt_info['src_ip'] not in self.seen_src_ips[dst_ip]
        if new_seen:
            self.seen_src_ips[dst_ip].add(pkt_info['src_ip'])
            w['n_new_src'] = w.get('n_new_src', 0) + 1

    def finalize(self):
        """Compute features for each window and return list of feature dicts grouped by dst_ip."""
        result = defaultdict(list)

        for (dst_ip, sec_idx), w in sorted(self.windows.items()):
            n = w['n_packets']
            if n == 0:
                continue
            total_pkts = max(n, 1)

            # Volume
            packets_per_sec = float(n)
            bytes_per_sec = float(w['n_bytes'])
            flows_per_sec = float(len(w['flows']))

            # Protocol mix
            tcp_ratio = w['tcp_packets'] / total_pkts
            udp_ratio = w['udp_packets'] / total_pkts
            icmp_ratio = w['icmp_packets'] / total_pkts
            other_ratio = w['other_packets'] / total_pkts

            # TCP flag rates (per second since window is 1s)
            syn_per_sec = float(w['syn_packets'])
            syn_ack_per_sec = float(w['syn_ack_packets'])
            ack_per_sec = float(w['ack_packets'])
            rst_per_sec = float(w['rst_packets'])
            fin_per_sec = float(w['fin_packets'])

            # Ratios
            bytes_per_packet = w['n_bytes'] / total_pkts
            syn_ack_ratio = w['syn_ack_packets'] / max(w['syn_packets'], 1)
            rst_syn_ratio = w['rst_packets'] / max(w['syn_packets'], 1)

            # Cardinality
            unique_src_ips = float(len(w['src_ips']))
            unique_dst_ports = float(len(w['dst_ports']))
            unique_flows = flows_per_sec
            # C-canonical formula: unique_dst_ports * 1000 / packets_per_sec
            # (production source: layer1/interlayer/shared_memory.c:577;
            # documented in layer2/layer2.c:1536 and l2_features_export.h field comment).
            # Prior Python lacked the x1000 scale (F-CIC-6); kept consistent within the
            # harness because z-scores are scale-invariant, but the variance-floor at
            # baselines.py:49 (VAR_FLOOR_MEAN_THRESHOLD=50) gates whether the floor
            # is absolute (1.0) or relative (2% of mean), so the scale matters in
            # practice for whether this feature can ever produce z > theta.
            dst_port_density = unique_dst_ports * 1000.0 / max(packets_per_sec, 1e-10)

            # Entropy (Shannon)
            src_ip_entropy = shannon_entropy(w['src_ips'])
            src_port_entropy = shannon_entropy(w['src_ports'])

            # Packet characteristics
            small_pkt_ratio = w['small_pkts'] / total_pkts
            fragment_ratio = w['fragments'] / total_pkts
            ttl_mean = w['ttl_sum'] / total_pkts if total_pkts > 0 else 0.0

            # TCP flag composition (relative to TCP packets)
            tcp_total = max(w['tcp_packets'], 1)
            syn_tcp_ratio = w['syn_packets'] / tcp_total
            synack_tcp_ratio = w['syn_ack_packets'] / tcp_total
            ack_tcp_ratio = w['ack_packets'] / tcp_total
            rst_tcp_ratio = w['rst_packets'] / tcp_total
            fin_tcp_ratio = w['fin_packets'] / tcp_total

            # Flow behavior approximations
            avg_packets_per_flow = total_pkts / max(len(w['flows']), 1)
            flow_duration_avg = 0.0  # Cannot accurately compute from 1-second window

            # Burst features
            burst_factor = packets_per_sec  # Simplified -- compared against baseline later
            udp_flow_ratio = w['udp_packets'] / max(len(w['flows']), 1)

            # ICMP echo ratio
            icmp_echo_ratio = w['icmp_echo'] / max(w['icmp_packets'], 1)

            # Direction ratio (simplified -- set to 0.5 since we don't track direction here)
            dir_ratio = 0.5

            # Churn
            new_srcip_rate = float(w.get('n_new_src', 0))

            # TCP completion rate (ACKs / SYNs) -- high means most SYNs got ACK'd
            tcp_completion_rate = w['ack_packets'] / max(w['syn_packets'], 1)

            # Concentration (simplified): top-1 flow share, top-K (K=10) flow share
            flow_pkt_counts = Counter()
            # Note: we don't have per-flow packet counts stored, so approximate as 1 per flow
            # (this is a known approximation -- for accurate concentration, would need per-flow counters)
            max_flow_fraction = 1.0 / max(len(w['flows']), 1) * 100  # percentage of single flow
            topk_flow_share = min(10, len(w['flows'])) / max(len(w['flows']), 1) * 100
            heavy_hitter_count = float(len(w['flows']) // 10)  # rough approximation

            # Label: attack if any attack flow in this window
            is_attack = len(w['attack_flows']) > 0

            row = {
                # Volume (3)
                'packets_per_sec': packets_per_sec,
                'bytes_per_sec': bytes_per_sec,
                'flows_per_sec': flows_per_sec,
                # TCP Flag Rates (5)
                'syn_per_sec': syn_per_sec,
                'syn_ack_per_sec': syn_ack_per_sec,
                'ack_per_sec': ack_per_sec,
                'rst_per_sec': rst_per_sec,
                'fin_per_sec': fin_per_sec,
                # Protocol Mix (4)
                'tcp_ratio': tcp_ratio,
                'udp_ratio': udp_ratio,
                'icmp_ratio': icmp_ratio,
                'other_ratio': other_ratio,
                # Derived Ratios (3)
                'syn_ack_ratio': syn_ack_ratio,
                'rst_syn_ratio': rst_syn_ratio,
                'bytes_per_packet': bytes_per_packet,
                # Cardinality (3)
                'unique_src_ips': unique_src_ips,
                'unique_dst_ports': unique_dst_ports,
                'unique_flows': unique_flows,
                # Churn (1)
                'new_srcip_rate': new_srcip_rate,
                # Concentration (3)
                'max_flow_fraction': max_flow_fraction,
                'topk_flow_share': topk_flow_share,
                'heavy_hitter_count': heavy_hitter_count,
                # Flow Behavior (2)
                'avg_packets_per_flow': avg_packets_per_flow,
                'flow_duration_avg': flow_duration_avg,
                # TCP Flag Composition (5)
                'syn_tcp_ratio': syn_tcp_ratio,
                'synack_tcp_ratio': synack_tcp_ratio,
                'ack_tcp_ratio': ack_tcp_ratio,
                'rst_tcp_ratio': rst_tcp_ratio,
                'fin_tcp_ratio': fin_tcp_ratio,
                # Burst/Extended (6)
                'burst_factor': burst_factor,
                'udp_flow_ratio': udp_flow_ratio,
                'icmp_echo_ratio': icmp_echo_ratio,
                'dst_port_density': dst_port_density,
                'src_ip_entropy': src_ip_entropy,
                'src_port_entropy': src_port_entropy,
                # Packet Characteristics (3)
                'small_pkt_ratio': small_pkt_ratio,
                'fragment_ratio': fragment_ratio,
                'ttl_mean': ttl_mean,
                # Ratio Extended (1)
                'tcp_completion_rate': tcp_completion_rate,
                # Metadata
                'dir_ratio': dir_ratio,
                '_dt': self.t0 + sec_idx,  # absolute unix timestamp
                '_id_time': sec_idx,
                '_is_attack': is_attack,
                '_n_flows': int(flows_per_sec),
            }
            result[dst_ip].append(row)

        return dict(result)


def load_attack_flows_from_csv(csv_dir):
    """Load 5-tuple -> attack_label mapping from all attack CSV files.

    Returns a dict: (src_ip, src_port, dst_ip, dst_port, proto) -> attack_type or 'BENIGN'.
    """
    flow_labels = {}
    for attack_name, csv_file in ATTACK_CSV_FILES.items():
        path = os.path.join(csv_dir, csv_file)
        if not os.path.exists(path):
            print(f"  Skipping {csv_file} (not found)")
            continue
        print(f"  Loading {csv_file}...")
        n_added = 0
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    src_ip = row.get(' Source IP', '').strip()
                    dst_ip = row.get(' Destination IP', '').strip()
                    src_port = int(float(row.get(' Source Port', 0) or 0))
                    dst_port = int(float(row.get(' Destination Port', 0) or 0))
                    proto = int(float(row.get(' Protocol', 0) or 0))
                    label = row.get(' Label', '').strip()
                    if not src_ip or not dst_ip:
                        continue
                    key = (src_ip, src_port, dst_ip, dst_port, proto)
                    if label == 'BENIGN':
                        # Keep BENIGN only if no attack label exists for this key
                        if key not in flow_labels:
                            flow_labels[key] = 'BENIGN'
                    else:
                        # Attack label always wins
                        flow_labels[key] = label or attack_name.upper()
                        n_added += 1
                except (ValueError, TypeError):
                    continue
        print(f"    Added {n_added} attack flow labels from {csv_file}")
    print(f"  Total flow labels loaded: {len(flow_labels)}")
    return flow_labels


def parse_pcap_file(pcap_path, aggregator, flow_labels=None, max_packets=None):
    """Parse one pcap file, feeding packets into the aggregator."""
    count = 0
    skipped = 0
    with open(pcap_path, 'rb') as f:
        reader = dpkt.pcap.Reader(f)
        for ts, buf in reader:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    skipped += 1
                    continue
                ip = eth.data
                src_ip = ip_to_str(ip.src)
                dst_ip = ip_to_str(ip.dst)
                proto = ip.p
                length = len(buf)
                ttl = ip.ttl
                is_fragment = (ip.off & 0x3fff) != 0

                src_port = 0
                dst_port = 0
                tcp_flags = 0
                icmp_type = -1

                if proto == 6 and isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    tcp_flags = tcp.flags
                elif proto == 17 and isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    src_port = udp.sport
                    dst_port = udp.dport
                elif proto == 1 and isinstance(ip.data, dpkt.icmp.ICMP):
                    icmp_type = ip.data.type

                # Ground-truth label lookup
                is_attack = False
                if flow_labels:
                    key = (src_ip, src_port, dst_ip, dst_port, proto)
                    label = flow_labels.get(key)
                    if label and label != 'BENIGN':
                        is_attack = True

                pkt_info = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'proto': proto,
                    'length': length,
                    'tcp_flags': tcp_flags,
                    'ttl': ttl,
                    'is_fragment': is_fragment,
                    'icmp_type': icmp_type,
                    'is_attack': is_attack,
                }
                aggregator.add_packet(ts, pkt_info)
                count += 1
                if max_packets and count >= max_packets:
                    break
            except Exception:
                skipped += 1
                continue
    return count, skipped


def main():
    if len(sys.argv) < 4:
        print("Usage: pcap_feature_extractor.py <pcap_dir> <csv_dir> <output_json> [max_files]")
        sys.exit(1)

    pcap_dir = sys.argv[1]
    csv_dir = sys.argv[2]
    output_json = sys.argv[3]
    max_files = int(sys.argv[4]) if len(sys.argv) > 4 else None

    print(f"=== PCAP Feature Extraction ===")
    print(f"PCAP dir: {pcap_dir}")
    print(f"CSV dir: {csv_dir}")

    t0_full = time.time()

    # Load ground-truth labels from CSV
    print("\nLoading flow labels from CSV...")
    flow_labels = load_attack_flows_from_csv(csv_dir)

    # Find pcap files chronologically
    pcap_files = sorted(glob.glob(os.path.join(pcap_dir, "SAT-03-11-2018_*")))
    if max_files:
        pcap_files = pcap_files[:max_files]
    print(f"\nProcessing {len(pcap_files)} pcap files...")

    aggregator = WindowAggregator()
    total_pkts = 0
    total_skipped = 0
    for i, pcap_path in enumerate(pcap_files):
        t0 = time.time()
        n, sk = parse_pcap_file(pcap_path, aggregator, flow_labels=flow_labels)
        total_pkts += n
        total_skipped += sk
        elapsed = time.time() - t0
        if (i + 1) % 10 == 0 or i == len(pcap_files) - 1:
            print(f"  [{i+1}/{len(pcap_files)}] {os.path.basename(pcap_path)} "
                  f"-> {n} pkts in {elapsed:.1f}s "
                  f"(cumulative: {total_pkts} pkts, {len(aggregator.windows)} (dst_ip,sec) windows)")

    print(f"\nTotal: {total_pkts} packets parsed, {total_skipped} skipped")
    print(f"Aggregating into per-IP feature time series...")
    per_ip_windows = aggregator.finalize()

    print(f"Per-IP windows produced:")
    for dst_ip, rows in sorted(per_ip_windows.items()):
        n_attack = sum(1 for r in rows if r['_is_attack'])
        print(f"  {dst_ip}: {len(rows)} windows ({n_attack} attack)")

    out_data = {
        'metadata': {
            'source': pcap_dir,
            'total_packets': total_pkts,
            'total_skipped': total_skipped,
            'n_dst_ips': len(per_ip_windows),
            'feature_count': 39,
            'runtime_s': round(time.time() - t0_full, 1),
        },
        'per_ip_windows': per_ip_windows,
    }
    with open(output_json, 'w') as f:
        json.dump(out_data, f, indent=1)
    print(f"\nSaved: {output_json} ({os.path.getsize(output_json) / 1e6:.1f} MB)")


if __name__ == '__main__':
    main()
