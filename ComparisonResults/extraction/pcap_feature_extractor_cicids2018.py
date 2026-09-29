"""
CIC-IDS-2018 per-(destination-IP, 1-second) feature extractor.

Two structural facts about this dataset force a different design from the
CIC-DDoS2019 / CIC-IDS-2017 extractors:

 1. CIC-IDS-2018 is captured PER HOST -- each `cap<hostname>-<ip>` pcap is the
    tcpdump output of a single workstation/server's own NIC. A packet between
    two internal hosts appears in BOTH endpoints' pcaps. Naively merging all
    pcaps double-counts internal-to-internal traffic on every (dst_ip, sec)
    window where both endpoints are internal hosts.
    => We process each pcap independently and only keep windows where
       `dst_ip == the file's host IP`. Each pcap is then the canonical source
       for the one IP it captures. No double-counting by construction. Attack
       traffic (external attacker -> internal victim) appears only in the
       victim's pcap, so victim DR is single-counted naturally.

 2. The public CIC-IDS-2018 CSVs are SANITIZED: no Src IP / Dst IP columns.
    Per-5-tuple label join (used by the other pcap extractors) is impossible.
    What is available: clean per-attack-type Timestamp ranges in the CSVs and
    a documented per-day victim (confirmed empirically via pcap-size
    dominance).
    => Label per-(dst_ip, sec) windows by (time-window, victim-IP):
       _is_attack = True iff dst_ip == victim_for_day AND timestamp falls in
       any documented attack window for the day.

Attack-window time interpretation (validated empirically against the pcap clock):
    Labeling uses the documented Table-2 attack-window bounds (one row per
    attack), not per-flow CSV timestamps. CIC's Table-2 times are New Brunswick
    Atlantic Standard Time (AST, UTC-4 in February); `_csv_time_to_utc_epoch`
    converts them to UTC by adding 4 h. The +4 h offset is validated against the
    per-victim pps bursts: each documented window's traffic spike lands within
    ~5 min of the converted window on the victim pcap.

Day-wide pcap coverage (verified): each day captures ~12:30 UTC to ~02:30 UTC
the next day (~14 h), so all 6 documented attack windows fall in range.

Output: experiment/cache/cicids2018_pcap_<day>.json, one file per day, with
        {'metadata': {...}, 'per_ip_windows': {dst_ip: [row, ...]}}
Schema matches the other pcap-extractor outputs (23 active features).

Usage:
    python3 pcap_feature_extractor_cicids2018.py <pcap_dir> <day_tag> <output_json>
    where <day_tag> ∈ {wed, thu, fri}.
"""
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_sys.path.insert(0, _HERE)                        # sibling extraction modules (tree_io, extractors)
_sys.path.insert(0, _os.path.dirname(_HERE))      # ComparisonResults/: config, loaders, registry
_BASE = _os.environ.get('ANTIDDOS_BASE', _os.path.dirname(_os.path.dirname(_HERE)))  # == config.BASE

import os, sys, json, glob, time, gc, random
import socket
from datetime import datetime, timezone, timedelta
from collections import defaultdict, Counter

import dpkt

sys.path.insert(0, os.path.dirname(__file__))
# Reuse the WindowAggregator (it already emits the right 23-active-feature schema)
from pcap_feature_extractor import WindowAggregator, ip_to_str


# ─────────────────────────────────────────────────────────────────────────────
# Memory-bounded substitutes for Counter and set inside the per-window state.
# Under HOIC-class spoofed-source floods, each 1-second window can see tens of
# millions of distinct (src_ip, src_port, 5-tuple). The default Counter()/set()
# grow unboundedly and OOM the process. These capped variants saturate the
# cardinality at MAX (default 50k) -- which for detection purposes is fine,
# since 50k unique sources in one second is already "extremely anomalous".
# ─────────────────────────────────────────────────────────────────────────────
COUNTER_CAP = 50_000
SET_CAP = 50_000


class CappedCounter(dict):
    """Counter-like dict with a size cap (saturates beyond CAP)."""
    __slots__ = ()
    def __missing__(self, k):
        return 0
    def __setitem__(self, k, v):
        if k in self or dict.__len__(self) < COUNTER_CAP:
            dict.__setitem__(self, k, v)


class CappedSet:
    """set-like with a size cap (silently drops new items beyond CAP)."""
    __slots__ = ('_s',)
    def __init__(self):
        self._s = set()
    def add(self, item):
        if len(self._s) < SET_CAP or item in self._s:
            self._s.add(item)
    def __len__(self):     return len(self._s)
    def __iter__(self):    return iter(self._s)
    def __contains__(self, item): return item in self._s


class CappedWindowAggregator(WindowAggregator):
    """WindowAggregator with bounded per-window Counter/set sizes."""
    def _new_window(self):
        return {
            'n_packets': 0, 'n_bytes': 0,
            'tcp_packets': 0, 'udp_packets': 0, 'icmp_packets': 0, 'other_packets': 0,
            'syn_packets': 0, 'syn_ack_packets': 0, 'ack_packets': 0,
            'rst_packets': 0, 'fin_packets': 0,
            'src_ips': CappedCounter(),
            'src_ports': CappedCounter(),
            'dst_ports': CappedCounter(),
            'flows': CappedSet(),
            'attack_flows': CappedSet(),
            'small_pkts': 0, 'fragments': 0, 'ttl_sum': 0, 'pkt_size_sum': 0,
            'icmp_echo': 0, 'syn_no_ack': 0, 'syn_with_ack': 0,
            'flow_durations_ms': [],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Per-day attack windows + victims (empirically validated; see module docstring)
# ─────────────────────────────────────────────────────────────────────────────
# Documented Table-2 window times are AST (UTC-4); converted to UTC by adding 4 h.
# Each entry: (attack_name, day_date, csv_start_hms, csv_end_hms, victim_ip).
# Victim IP confirmed by pcap-size dominance: Wed UCAP172.31.69.28 is 11.2 GB
# (next UCAP is 13 MB), Fri UCAP172.31.69.25-part1.pcap is 4.1 GB (next 4 MB),
# Thu UCAP172.31.69.25 is 181 MB (next UCAP 3.3 MB).
ATTACKS_PER_DAY = {
    # Times taken from the CIC-IDS-2018 dataset documentation (Table 2,
    # "List of daily attacks, Machine IPs, Start and finish time of attack(s)").
    # These are CIC New Brunswick Atlantic Standard Time (AST, UTC-4 in Feb).
    # _csv_time_to_utc_epoch adds 4 h to convert to UTC.
    # We use the DOCUMENTED attack-window bounds (1 row per attack), not the
    # per-flow CSV timestamps, because the per-flow times only cover the first
    # and last flow of each attack and miss much of the active window.
    'wed': {
        'date': '2018-02-21',
        'victim': '172.31.69.28',
        'attacks': [
            ('LOIC-UDP', '10:09:00', '10:43:00'),
            ('HOIC',     '14:05:00', '15:05:00'),
        ],
    },
    'thu': {
        'date': '2018-02-15',
        'victim': '172.31.69.25',
        'attacks': [
            ('GoldenEye', '09:26:00', '10:09:00'),
            ('Slowloris', '10:59:00', '11:40:00'),
        ],
    },
    'fri': {
        'date': '2018-02-16',
        'victim': '172.31.69.25',
        'attacks': [
            ('SlowHTTPTest', '10:12:00', '11:08:00'),
            ('Hulk',         '13:45:00', '14:19:00'),
        ],
    },
}


def _csv_time_to_utc_epoch(date_str, hms):
    """Convert documented attack-window (date, "HH:MM:SS") from AST (UTC-4)
    to UTC epoch seconds. CIC is in New Brunswick, Canada, which observes
    Atlantic Standard Time (UTC-4) in winter -- so the times in CIC's official
    Table 2 are in AST. Empirically validated against the per-victim pps
    bursts found in the extracted pcap caches: every one of the 6 attacks
    matches within ~5 minutes when interpreted as AST->UTC = +4h. (EST/+5h
    was off by 1 h for Thu and Fri and gave wrong labels on Wed.)"""
    dt = datetime.strptime(f"{date_str} {hms}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    dt += timedelta(hours=4)
    return dt.timestamp()


def _attack_windows_for_day(day_tag):
    """Return list of (name, start_epoch, end_epoch, victim_ip) for the day."""
    info = ATTACKS_PER_DAY[day_tag]
    return [
        (name,
         _csv_time_to_utc_epoch(info['date'], t0),
         _csv_time_to_utc_epoch(info['date'], t1),
         info['victim'])
        for (name, t0, t1) in info['attacks']
    ], info['victim']


def _host_ip_from_filename(path):
    """Extract the IP that this pcap belongs to (the host that captured it).

    Naming conventions in CIC-IDS-2018:
        capDESKTOP-AN3U28N-172.31.64.111
        capWIN-J6GMIG1DQE5-172.31.65.104
        capPC1-172.31.66.111
        capEC2AMAZ-O4EL3NG-172.31.66.109
        UCAP172.31.69.28                     (Ubuntu/Linux server)
        UCAP172.31.69.25-part1.pcap          (split capture)
    The last dotted-decimal IP in the basename is always the host IP.
    """
    name = os.path.basename(path)
    # find the last 'X.X.X.X' substring. No leading \b -- CIC's UCAP captures
    # ('UCAP172.31.69.28 part 1', 'UCAP172.31.69.25-part1.pcap') have NO
    # separator between the host prefix and the IP digits, so a leading word
    # boundary would refuse to match them.
    import re
    matches = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', name)
    return matches[-1] if matches else None


def _open_pcap_reader(f):
    """Try libpcap, fall back to pcapng. CIC-IDS-2018 mixes both formats:
    Fri's UCAP172.31.69.25-part1.pcap is pcapng (magic 0a0d0d0a) while most
    other captures are libpcap (magic d4c3b2a1). dpkt's pcap.Reader silently
    raises ValueError on pcapng, so we explicitly detect-and-fallback."""
    head = f.read(4)
    f.seek(0)
    # pcapng magic = 0a0d0d0a (Section Header Block)
    if head == b'\x0a\x0d\x0d\x0a':
        return dpkt.pcapng.Reader(f)
    return dpkt.pcap.Reader(f)


def parse_pcap_for_one_host(pcap_path, host_ip, attack_windows, aggregator):
    """Stream one pcap; keep only packets whose dst_ip == host_ip.

    Labels the resulting window as attack iff host_ip == an attack-window's
    victim AND packet timestamp falls in that attack window.

    The aggregator is shared across files belonging to the SAME host (e.g.
    Wed's UCAP172.31.69.28 has two files: 9.2 GB + 2.0 GB).
    """
    n_kept = 0
    n_skipped = 0
    try:
        with open(pcap_path, 'rb') as f:
            try:
                reader = _open_pcap_reader(f)
            except Exception:
                return 0, 0
            for ts, buf in reader:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        n_skipped += 1
                        continue
                    ip = eth.data
                    dst_ip = ip_to_str(ip.dst)
                    # KEY restriction: only count packets whose destination is the host
                    if dst_ip != host_ip:
                        n_skipped += 1
                        continue
                    src_ip = ip_to_str(ip.src)
                    proto = ip.p
                    length = len(buf)
                    ttl = ip.ttl
                    is_fragment = (ip.off & 0x3fff) != 0

                    src_port = 0; dst_port = 0; tcp_flags = 0; icmp_type = -1
                    if proto == 6 and isinstance(ip.data, dpkt.tcp.TCP):
                        tcp = ip.data
                        src_port = tcp.sport; dst_port = tcp.dport; tcp_flags = tcp.flags
                    elif proto == 17 and isinstance(ip.data, dpkt.udp.UDP):
                        udp = ip.data
                        src_port = udp.sport; dst_port = udp.dport
                    elif proto == 1 and isinstance(ip.data, dpkt.icmp.ICMP):
                        icmp_type = ip.data.type

                    # Time-window attack label (only meaningful if host_ip is the victim)
                    is_attack = False
                    for _name, t0, t1, victim in attack_windows:
                        if host_ip == victim and t0 <= ts <= t1:
                            is_attack = True
                            break

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
                    n_kept += 1
                except Exception:
                    n_skipped += 1
                    continue
    except Exception:
        return n_kept, n_skipped
    return n_kept, n_skipped


def main():
    if len(sys.argv) < 4:
        print("Usage: pcap_feature_extractor_cicids2018.py <pcap_dir> <day_tag> <output_json>")
        print("       <day_tag> ∈ {wed, thu, fri}")
        sys.exit(1)

    pcap_dir = sys.argv[1]
    day_tag = sys.argv[2].lower()
    output_json = sys.argv[3]

    if day_tag not in ATTACKS_PER_DAY:
        print(f"ERROR: unknown day_tag {day_tag!r}; must be one of {list(ATTACKS_PER_DAY)}")
        sys.exit(1)

    attack_windows, victim_ip = _attack_windows_for_day(day_tag)
    print(f"=== CIC-IDS-2018 {day_tag.upper()} per-host pcap extraction ===")
    print(f"Pcap dir: {pcap_dir}")
    print(f"Day victim: {victim_ip}")
    print(f"Attack windows (UTC):")
    for name, t0, t1, _v in attack_windows:
        a = datetime.fromtimestamp(t0, tz=timezone.utc)
        b = datetime.fromtimestamp(t1, tz=timezone.utc)
        print(f"  {name:14s}  {a}  ->  {b}  ({(b - a).total_seconds():.0f} s)")

    # Optional --max-uninvolved arg: sub-sample uninvolved hosts to bound time
    # and memory. The victim is always kept. 100 uninvolved IP clusters is
    # plenty for an IP-clustered bootstrap FPR (CIC-IDS-2017 used 530).
    MAX_UNINVOLVED = 100
    for arg in sys.argv[4:]:
        if arg.startswith('--max-uninvolved='):
            MAX_UNINVOLVED = int(arg.split('=', 1)[1])

    # Group pcap files by host IP (UCAP172.31.69.28 may have multiple files)
    pcap_files = sorted(glob.glob(os.path.join(pcap_dir, 'cap*')) +
                        glob.glob(os.path.join(pcap_dir, 'UCAP*')))
    by_host = defaultdict(list)
    for fn in pcap_files:
        ip = _host_ip_from_filename(fn)
        if ip:
            by_host[ip].append(fn)
    print(f"\nDistinct hosts: {len(by_host)}; total pcap files: {len(pcap_files)}")

    # Build the host list: victim always first; uninvolved hosts deterministically
    # sub-sampled (seeded random.sample) to at most MAX_UNINVOLVED.
    all_hosts = sorted(by_host.keys())
    uninvolved = [ip for ip in all_hosts if ip != victim_ip]
    rng = random.Random(20260601)
    if MAX_UNINVOLVED is not None and MAX_UNINVOLVED > 0 and len(uninvolved) > MAX_UNINVOLVED:
        chosen = sorted(rng.sample(uninvolved, MAX_UNINVOLVED))
        print(f"Sub-sampling uninvolved hosts: {len(uninvolved)} eligible -> {MAX_UNINVOLVED} "
              f"(seed=20260601)")
    else:
        chosen = uninvolved
    if victim_ip in by_host:
        host_order = [victim_ip] + chosen        # victim FIRST so any OOM still leaves victim data
    else:
        print(f"WARNING: victim {victim_ip} not found in pcap files for {day_tag}")
        host_order = chosen
    print(f"Processing {len(host_order)} hosts (1 victim + {len(host_order)-1 if victim_ip in by_host else len(host_order)} uninvolved)")

    # STREAMING output: write per_ip_windows entries to the JSON file one
    # host at a time, then DROP that host's data from memory immediately. Peak
    # memory is therefore bounded by a single host's aggregator (which is in turn
    # bounded by COUNTER_CAP / SET_CAP), not the cumulative dataset.
    os.makedirs(os.path.dirname(output_json) or '.', exist_ok=True)
    t0_full = time.time()
    total_kept = 0; total_skipped = 0; n_hosts_done = 0
    n_hosts_with_windows = 0
    victim_window_counts = None      # (attack, benign) for the victim row
    metadata_placeholder = {}        # we patch the JSON header at the end

    # Open output file and write the prologue (metadata + open per_ip_windows dict)
    with open(output_json, 'w') as out_f:
        # Write a placeholder metadata; we'll close+rewrite the prologue at the end
        out_f.write('{\n  "metadata": ')
        json.dump({'_placeholder': True}, out_f)
        out_f.write(',\n  "per_ip_windows": {\n')

        first_entry = True
        for host_ip in host_order:
            files = by_host.get(host_ip, [])
            if not files:
                continue
            host_t0 = time.time()
            host_size = sum(os.path.getsize(fn) for fn in files)
            agg = CappedWindowAggregator()
            for fn in sorted(files):
                kept, skipped = parse_pcap_for_one_host(fn, host_ip, attack_windows, agg)
                total_kept += kept
                total_skipped += skipped
            finalized = agg.finalize()
            del agg                       # release per-host aggregator state immediately
            rows = finalized.get(host_ip, [])
            n_hosts_done += 1
            host_dt = time.time() - host_t0

            if rows:
                n_hosts_with_windows += 1
                if not first_entry:
                    out_f.write(',\n')
                first_entry = False
                out_f.write(f'    "{host_ip}": ')
                json.dump(rows, out_f, separators=(',', ':'), default=str)

                if host_ip == victim_ip:
                    va = sum(1 for r in rows if r.get('_is_attack'))
                    vb = sum(1 for r in rows if not r.get('_is_attack'))
                    victim_window_counts = (va, vb)
            # Drop everything related to this host
            del finalized, rows
            gc.collect()

            elapsed = time.time() - t0_full
            print(f"  [{n_hosts_done:>3}/{len(host_order)}] {host_ip:18s} "
                  f"{host_size/1e6:6.0f}MB  in {host_dt:5.1f}s  "
                  f"cumul kept={total_kept:>10,}  elapsed={elapsed:.0f}s",
                  flush=True)

        out_f.write('\n  }\n}')

    runtime = time.time() - t0_full
    print(f"\nRuntime: {runtime:.1f}s  hosts_with_windows={n_hosts_with_windows}")
    if victim_window_counts:
        print(f"Victim {victim_ip}: {victim_window_counts[0]} attack windows, "
              f"{victim_window_counts[1]} benign windows")
    else:
        print(f"WARNING: victim {victim_ip} produced no windows")

    # Now PATCH the metadata: re-read the file, replace the _placeholder, and rewrite.
    # We do this by reading the on-disk content, parsing it, and writing it back
    # with the real metadata. With per-host data on disk and streaming reads via
    # json.load this peaks at the same RAM as a normal final load, which is OK at
    # this point since the aggregator memory is gone.
    real_metadata = {
        'dataset': f'CIC-IDS-2018 ({day_tag}; per-host pcap)',
        'source_dir': pcap_dir,
        'day_tag': day_tag,
        'date': ATTACKS_PER_DAY[day_tag]['date'],
        'victim_ip': victim_ip,
        'attack_windows_utc': [
            (n,
             datetime.fromtimestamp(t0, tz=timezone.utc).isoformat(),
             datetime.fromtimestamp(t1, tz=timezone.utc).isoformat())
            for (n, t0, t1, _) in attack_windows
        ],
        'n_pcap_files': len(pcap_files),
        'n_hosts_total': len(by_host),
        'n_hosts_processed': len(host_order),
        'n_hosts_with_windows': n_hosts_with_windows,
        'max_uninvolved': MAX_UNINVOLVED,
        'counter_cap': COUNTER_CAP,
        'set_cap': SET_CAP,
        'total_packets_kept': total_kept,
        'total_packets_skipped': total_skipped,
        'feature_count': 39,
        'design_note': (
            "Per-host capture model: each pcap = one IP's own NIC view, "
            "restricted to dst_ip == host (no double-counting between internal "
            "endpoints). Labels are time-windowed by victim IP (sanitized CSVs "
            "have no Src/Dst IP columns, so 5-tuple labeling impossible). "
            "Memory bounded by CappedCounter/CappedSet (cardinality saturates "
            "at COUNTER_CAP/SET_CAP) and by per-host streaming output."
        ),
        'runtime_s': round(runtime, 1),
    }

    # Patch metadata in the on-disk JSON. The structure was:
    #   { "metadata": {"_placeholder": true}, "per_ip_windows": { ... } }
    # We rewrite by reading the file as text, finding the placeholder, and
    # substituting the real metadata's JSON. This avoids json.load on the
    # full payload (which may be GBs of per_ip_windows).
    placeholder = '"metadata": {"_placeholder": true}'
    replacement = '"metadata": ' + json.dumps(real_metadata, default=str)
    with open(output_json, 'r') as f:
        head = f.read(len(placeholder) + 200)
    if placeholder not in head:
        # Fallback: just rewrite via json.load/dump (uses more RAM).
        print("WARNING: placeholder not found at head; falling back to full re-dump.")
        with open(output_json) as f:
            payload = json.load(f)
        payload['metadata'] = real_metadata
        with open(output_json, 'w') as f:
            json.dump(payload, f, default=str)
    else:
        # Splice: replace placeholder, then stream the remaining bytes.
        new_head = head.replace(placeholder, replacement, 1)
        tmp = output_json + '.tmp'
        with open(output_json, 'r') as rf, open(tmp, 'w') as wf:
            rf.read(len(head))           # advance past `head`
            wf.write(new_head)
            while True:
                chunk = rf.read(64 * 1024 * 1024)
                if not chunk: break
                wf.write(chunk)
        os.replace(tmp, output_json)

    print(f"\nSaved: {output_json} "
          f"({os.path.getsize(output_json) / 1e6:.1f} MB; runtime {runtime:.1f}s)")


if __name__ == '__main__':
    main()
