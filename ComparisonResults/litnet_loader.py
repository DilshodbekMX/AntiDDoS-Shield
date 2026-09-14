"""
LITNET-2020 dataset loader for anomaly detection evaluation.

LITNET-2020 is a real labeled network-flow dataset from the Lithuanian academic
network (LITNET), spanning 2020-01-25 to 2020-01-31, with 11 real attack types
embedded in benign backbone traffic. The full export (allFlows.csv, 35M flows,
23 GB) is pre-split into ~1.3 GB chunks under datasets/LITNET-2020/parts/.

Because the export is far too large to hold in memory, this loader STREAMS the
chunked CSVs in chronological order and aggregates flows into global 1-second
time windows on the fly (matching the 1 Hz windowing convention of section 5.3 and
the production 1 Hz engine). Individual flows are never retained -- only the
window accumulators, which are flushed once the timeline advances past them.

Each window carries the same feature schema the CESNET harness uses,
plus '_is_attack' (any attack flow present) and '_attack_type' (dominant attack
label among the window's attack flows, or 'none').

Field layout (0-based) in the 85-column CSV:
  1-6  ts_year..ts_second   13 td        14 sa  15 da  16 sp  17 dp  18 pr
  27 ipkt  28 ibyt  29 opkt  30 obyt     83 attack_t   84 attack_a
"""
import os, csv, glob
from datetime import datetime, timezone
from collections import Counter

# Column indices
C_TS = (1, 2, 3, 4, 5, 6)   # year, month, day, hour, min, second
C_TD = 13
C_SA, C_DA, C_SP, C_DP, C_PR = 14, 15, 16, 17, 18
C_IPKT, C_IBYT, C_OPKT, C_OBYT = 27, 28, 29, 30
C_ATTACK_T, C_ATTACK_A = 83, 84

# Map LITNET attack_t labels to readable attack-type names
ATTACK_TYPE_NAMES = {
    'tcp_syn_f':      'syn_flood',
    'tcp_red_w':      'code_red_worm',
    'icmp_smf':       'smurf',
    'tcp_land':       'land_attack',
    'tcp_w32_w':      'win32_worm',
    'http_f':         'http_flood',
    'icmp_f':         'icmp_flood',
    'tcp_udp_win_p':  'win_port_scan',
    'udp_reaper_w':   'reaper_worm',
    'udp_0':          'udp_flood',
}

def _f(x):
    try:
        return float(x)
    except (ValueError, TypeError):
        return 0.0


class _WindowAcc:
    """Streaming accumulator for one 1-second global window."""
    __slots__ = ('n_flows', 'n_packets', 'n_bytes', 'tcp_pkts', 'udp_pkts',
                 'icmp_pkts', 'src_ips', 'dst_ips', 'dst_ports', 'dur_sum',
                 'dur_n', 'fwd_only', 'attack_flows', 'attack_types')

    def __init__(self):
        self.n_flows = 0
        self.n_packets = 0.0
        self.n_bytes = 0.0
        self.tcp_pkts = 0.0
        self.udp_pkts = 0.0
        self.icmp_pkts = 0.0
        self.src_ips = set()
        self.dst_ips = set()
        self.dst_ports = set()
        self.dur_sum = 0.0
        self.dur_n = 0
        self.fwd_only = 0          # flows with no return packets (opkt == 0)
        self.attack_flows = 0
        self.attack_types = Counter()


def _finalize(acc, dt, window_sec):
    n_packets = acc.n_packets
    total = max(n_packets, 1.0)
    pps = n_packets / window_sec
    dominant = acc.attack_types.most_common(1)[0][0] if acc.attack_types else 'none'
    return {
        'packets_per_sec': pps,
        'bytes_per_sec':   acc.n_bytes / window_sec,
        'flows_per_sec':   acc.n_flows / window_sec,
        'tcp_ratio':       acc.tcp_pkts / total,
        'udp_ratio':       acc.udp_pkts / total,
        'icmp_ratio':      acc.icmp_pkts / total,
        'unique_dst_ports': float(len(acc.dst_ports)),
        'unique_dst_ips':   float(len(acc.dst_ips)),
        'unique_src_ips':   float(len(acc.src_ips)),
        # x1000 to match C definition. layer2/baselines.h
        # defines dst_port_density = unique_dst_ports * 1000 / pps. The pcap
        # extractor already includes the x1000; LITNET loader
        # was missed in that round.
        'dst_port_density': len(acc.dst_ports) * 1000.0 / max(pps, 1e-10),
        'flow_duration_avg': (acc.dur_sum / acc.dur_n) if acc.dur_n else 0.0,
        # dir_ratio: fraction of flows that are unidirectional (no return traffic),
        # a strong signal for spoofed-source floods and scans.
        'dir_ratio':        acc.fwd_only / max(acc.n_flows, 1),
        'ttl_mean':         64.0,   # LITNET flows carry no TTL; placeholder (1 Hz windowing convention)
        '_dt':              dt,
        '_is_attack':       acc.attack_flows >= 1,
        '_attack_type':     dominant,
        '_n_flows':         acc.n_flows,
        '_n_attack_flows':  acc.attack_flows,
    }


def stream_windows(parts_dir, window_sec=1, max_files=None, progress_every=2_000_000):
    """Stream all LITNET part files and yield finalized 1-second window dicts.

    IMPORTANT: the LITNET export is NOT globally time-ordered -- flows from
    multiple capture sessions (e.g. Oct 2019, Dec 2019, Jan 2020) are
    interleaved across chunks. Windows are therefore keyed by ABSOLUTE
    epoch-second (floored), not by an offset from the first flow, so flows
    from different sessions never collide. Individual flows are not retained;
    only one accumulator per distinct second is kept (bounded by the number of
    distinct captured seconds, not by the 35M flow count)."""
    part_files = sorted(glob.glob(os.path.join(parts_dir, "allFlows_part_*.csv")))
    if not part_files:
        mono = os.path.join(parts_dir, "allFlows.csv")
        if os.path.exists(mono):
            part_files = [mono]
    if max_files:
        part_files = part_files[:max_files]

    windows = {}          # epoch_second (int) -> _WindowAcc
    n_rows = 0

    for path in part_files:
        with open(path, 'r', encoding='utf-8', errors='replace', newline='') as fh:
            reader = csv.reader(fh)
            next(reader, None)   # skip per-chunk header
            for row in reader:
                if len(row) < 85:
                    continue
                try:
                    y, mo, d, h, mi, s = (int(row[C_TS[0]]), int(row[C_TS[1]]),
                                          int(row[C_TS[2]]), int(row[C_TS[3]]),
                                          int(row[C_TS[4]]), int(float(row[C_TS[5]])))
                    dt = datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc)
                except (ValueError, TypeError):
                    continue

                key = int(dt.timestamp()) // window_sec   # absolute second bucket
                acc = windows.get(key)
                if acc is None:
                    acc = _WindowAcc()
                    windows[key] = acc

                ipkt = _f(row[C_IPKT]); opkt = _f(row[C_OPKT])
                ibyt = _f(row[C_IBYT]); obyt = _f(row[C_OBYT])
                pkts = ipkt + opkt
                acc.n_flows += 1
                acc.n_packets += pkts
                acc.n_bytes += ibyt + obyt
                pr = row[C_PR]
                if pr == 'TCP':
                    acc.tcp_pkts += pkts
                elif pr == 'UDP':
                    acc.udp_pkts += pkts
                elif pr == 'ICMP' or pr == 'ICMP6':
                    acc.icmp_pkts += pkts
                acc.src_ips.add(row[C_SA])
                acc.dst_ips.add(row[C_DA])
                dp = row[C_DP]
                if dp:
                    acc.dst_ports.add(dp)
                td = _f(row[C_TD])
                if td > 0:
                    acc.dur_sum += td; acc.dur_n += 1
                if opkt == 0:
                    acc.fwd_only += 1
                if row[C_ATTACK_A] == '1':
                    acc.attack_flows += 1
                    at = row[C_ATTACK_T]
                    if at and at != 'none':
                        acc.attack_types[ATTACK_TYPE_NAMES.get(at, at)] += 1

                n_rows += 1
                if progress_every and n_rows % progress_every == 0:
                    print(f"    streamed {n_rows:,} flows, "
                          f"{len(windows)} distinct-second windows, "
                          f"t={dt:%Y-%m-%d %H:%M:%S}")

    # Emit all windows in chronological order
    for key in sorted(windows.keys()):
        dt = datetime.fromtimestamp(key * window_sec, tz=timezone.utc)
        yield _finalize(windows[key], dt, window_sec)


def load_litnet_windows(parts_dir, window_sec=1, max_files=None):
    """Materialize all LITNET global 1-second windows (sorted by time) into a list."""
    windows = list(stream_windows(parts_dir, window_sec=window_sec, max_files=max_files))
    windows.sort(key=lambda w: w['_dt'])
    return windows


def load_litnet_per_ip(parts_dir, window_sec=1, max_files=None, min_windows=100,
                       keep_prefixes=None, keep_exact=None,
                       progress_every=4_000_000):
    """Aggregate flows into per-(destination-IP, 1-second) windows -- matching the
    production per-IP architecture and the pcap per-IP evaluations.

    Only destination IPs whose address starts with one of `keep_prefixes` or is in
    `keep_exact` are aggregated. This is essential for LITNET: the export records
    outbound traffic to the entire internet (hundreds of thousands of distinct
    external dst IPs), so without a filter the per-IP dict exhausts memory. The
    filter restricts aggregation to the protected internal network plus any known
    external victims, matching the deployment model (the system protects a fixed
    set of internal/served addresses).

    Returns dict {dst_ip: [windows sorted by time]} for every kept destination IP
    that reaches at least `min_windows` distinct 1-second windows."""
    keep_prefixes = tuple(keep_prefixes) if keep_prefixes else ()
    keep_exact = set(keep_exact) if keep_exact else set()

    def _keep(dst):
        return dst in keep_exact or (keep_prefixes and dst.startswith(keep_prefixes))
    part_files = sorted(glob.glob(os.path.join(parts_dir, "allFlows_part_*.csv")))
    if not part_files:
        mono = os.path.join(parts_dir, "allFlows.csv")
        if os.path.exists(mono):
            part_files = [mono]
    if max_files:
        part_files = part_files[:max_files]

    # dst_ip -> {epoch_second: _WindowAcc}
    per_ip = {}
    n_rows = 0

    for path in part_files:
        with open(path, 'r', encoding='utf-8', errors='replace', newline='') as fh:
            reader = csv.reader(fh)
            next(reader, None)
            for row in reader:
                if len(row) < 85:
                    continue
                try:
                    y, mo, d, h, mi, s = (int(row[C_TS[0]]), int(row[C_TS[1]]),
                                          int(row[C_TS[2]]), int(row[C_TS[3]]),
                                          int(row[C_TS[4]]), int(float(row[C_TS[5]])))
                    dt = datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc)
                except (ValueError, TypeError):
                    continue

                dst = row[C_DA]
                if not _keep(dst):
                    continue
                key = int(dt.timestamp()) // window_sec
                ipw = per_ip.get(dst)
                if ipw is None:
                    ipw = {}
                    per_ip[dst] = ipw
                acc = ipw.get(key)
                if acc is None:
                    acc = _WindowAcc()
                    ipw[key] = acc

                ipkt = _f(row[C_IPKT]); opkt = _f(row[C_OPKT])
                ibyt = _f(row[C_IBYT]); obyt = _f(row[C_OBYT])
                pkts = ipkt + opkt
                acc.n_flows += 1
                acc.n_packets += pkts
                acc.n_bytes += ibyt + obyt
                pr = row[C_PR]
                if pr == 'TCP':
                    acc.tcp_pkts += pkts
                elif pr == 'UDP':
                    acc.udp_pkts += pkts
                elif pr == 'ICMP' or pr == 'ICMP6':
                    acc.icmp_pkts += pkts
                acc.src_ips.add(row[C_SA])
                acc.dst_ips.add(dst)
                dp = row[C_DP]
                if dp:
                    acc.dst_ports.add(dp)
                td = _f(row[C_TD])
                if td > 0:
                    acc.dur_sum += td; acc.dur_n += 1
                if opkt == 0:
                    acc.fwd_only += 1
                if row[C_ATTACK_A] == '1':
                    acc.attack_flows += 1
                    at = row[C_ATTACK_T]
                    if at and at != 'none':
                        acc.attack_types[ATTACK_TYPE_NAMES.get(at, at)] += 1

                n_rows += 1
                if progress_every and n_rows % progress_every == 0:
                    print(f"    streamed {n_rows:,} flows, "
                          f"{len(per_ip)} dst IPs, t={dt:%Y-%m-%d %H:%M:%S}")

    # Finalize: keep only dst IPs with >= min_windows distinct seconds
    result = {}
    for dst, ipw in per_ip.items():
        if len(ipw) < min_windows:
            continue
        rows = []
        for key in sorted(ipw.keys()):
            dt = datetime.fromtimestamp(key * window_sec, tz=timezone.utc)
            rows.append(_finalize(ipw[key], dt, window_sec))
        result[dst] = rows
    return result


def _subnet_for(dst_ip, prefix_bits):
    """Map an IPv4 dotted-quad to its /prefix_bits network address (also dotted-quad).
    Returns None if dst_ip isn't a parseable IPv4 string."""
    try:
        parts = dst_ip.split('.')
        if len(parts) != 4:
            return None
        a, b, c, d = (int(p) for p in parts)
        ip_int = (a << 24) | (b << 16) | (c << 8) | d
    except (ValueError, TypeError):
        return None
    if not 0 < prefix_bits <= 32:
        return None
    mask = (0xFFFFFFFF << (32 - prefix_bits)) & 0xFFFFFFFF
    net = ip_int & mask
    return f"{(net >> 24) & 0xFF}.{(net >> 16) & 0xFF}.{(net >> 8) & 0xFF}.{net & 0xFF}/{prefix_bits}"


def load_litnet_per_subnet(parts_dir, prefix_bits=24, window_sec=1, max_files=None,
                           min_windows=100, keep_prefixes=None, keep_exact=None,
                           progress_every=4_000_000):
    """L1 protected-subnet aggregation semantic -- one accumulator per (subnet, second).

    Unlike load_litnet_per_ip, which groups flows by destination IP, this loader
    keys windows by (dst_ip & /prefix_bits, second). The `_WindowAcc.src_ips` set
    becomes a TRUE-UNION HLL over every source IP that contributed traffic to ANY
    destination within the subnet in that second -- exactly the property the
    Layer-1 keying policy `l1_resolve_track_key()` produces at the data plane
    (`layer1/layer1.c:1925-1932`): one per-IP feature slot keyed by the subnet
    network, collecting packets from every IP in the CIDR. The single HLL at the
    slot sees the union of sources, not the per-destination sum.

    This is statistically distinct from `experiment/run_litnet_zone.py`, which
    post-hoc sums per-(dst_ip, sec) HLL counts. For one source B hitting N
    destinations once each in /prefix_bits within one second:
       - This function (L1-equivalent): unique_src_ips = 1 (HLL sees {B}).
       - run_litnet_zone (L2-zone-equivalent): unique_src_ips ~= N (sum of N HLLs
         each seeing {B}).

    Returns dict {subnet_str: [windows sorted by time]} for every subnet that
    reaches at least `min_windows` distinct 1-second windows."""
    keep_prefixes = tuple(keep_prefixes) if keep_prefixes else ()
    keep_exact = set(keep_exact) if keep_exact else set()

    def _keep(dst):
        return dst in keep_exact or (keep_prefixes and dst.startswith(keep_prefixes))

    part_files = sorted(glob.glob(os.path.join(parts_dir, "allFlows_part_*.csv")))
    if not part_files:
        mono = os.path.join(parts_dir, "allFlows.csv")
        if os.path.exists(mono):
            part_files = [mono]
    if max_files:
        part_files = part_files[:max_files]

    # subnet_str -> {epoch_second: _WindowAcc}
    per_subnet = {}
    n_rows = 0

    for path in part_files:
        with open(path, 'r', encoding='utf-8', errors='replace', newline='') as fh:
            reader = csv.reader(fh)
            next(reader, None)
            for row in reader:
                if len(row) < 85:
                    continue
                try:
                    y, mo, d, h, mi, s = (int(row[C_TS[0]]), int(row[C_TS[1]]),
                                          int(row[C_TS[2]]), int(row[C_TS[3]]),
                                          int(row[C_TS[4]]), int(float(row[C_TS[5]])))
                    dt = datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc)
                except (ValueError, TypeError):
                    continue

                dst = row[C_DA]
                if not _keep(dst):
                    continue
                subnet = _subnet_for(dst, prefix_bits)
                if subnet is None:
                    continue
                key = int(dt.timestamp()) // window_sec
                sw = per_subnet.get(subnet)
                if sw is None:
                    sw = {}
                    per_subnet[subnet] = sw
                acc = sw.get(key)
                if acc is None:
                    acc = _WindowAcc()
                    sw[key] = acc

                ipkt = _f(row[C_IPKT]); opkt = _f(row[C_OPKT])
                ibyt = _f(row[C_IBYT]); obyt = _f(row[C_OBYT])
                pkts = ipkt + opkt
                acc.n_flows += 1
                acc.n_packets += pkts
                acc.n_bytes += ibyt + obyt
                pr = row[C_PR]
                if pr == 'TCP':
                    acc.tcp_pkts += pkts
                elif pr == 'UDP':
                    acc.udp_pkts += pkts
                elif pr == 'ICMP' or pr == 'ICMP6':
                    acc.icmp_pkts += pkts
                # CRITICAL: src_ips collects the true union across all destinations
                # in the subnet -- this is the L1 semantic, not a per-dst sum.
                acc.src_ips.add(row[C_SA])
                acc.dst_ips.add(dst)
                dp = row[C_DP]
                if dp:
                    acc.dst_ports.add(dp)
                td = _f(row[C_TD])
                if td > 0:
                    acc.dur_sum += td; acc.dur_n += 1
                if opkt == 0:
                    acc.fwd_only += 1
                if row[C_ATTACK_A] == '1':
                    acc.attack_flows += 1
                    at = row[C_ATTACK_T]
                    if at and at != 'none':
                        acc.attack_types[ATTACK_TYPE_NAMES.get(at, at)] += 1

                n_rows += 1
                if progress_every and n_rows % progress_every == 0:
                    print(f"    streamed {n_rows:,} flows, "
                          f"{len(per_subnet)} subnets, t={dt:%Y-%m-%d %H:%M:%S}")

    # Finalize: keep only subnets with >= min_windows distinct seconds
    result = {}
    for subnet, sw in per_subnet.items():
        if len(sw) < min_windows:
            continue
        rows = []
        for key in sorted(sw.keys()):
            dt = datetime.fromtimestamp(key * window_sec, tz=timezone.utc)
            rows.append(_finalize(sw[key], dt, window_sec))
        result[subnet] = rows
    return result
