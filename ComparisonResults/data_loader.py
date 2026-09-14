import tarfile, io, csv, math
from datetime import datetime, timezone, timedelta
import numpy as np
from config import *

FEATURE_MAP = {
    'n_flows':               'flows_per_sec',
    'n_packets':             'packets_per_sec',
    'n_bytes':               'bytes_per_sec',
    'average_n_dest_ports':  'unique_dst_ports',
    'average_n_dest_ip':     'unique_dst_ips',
    'tcp_udp_ratio_packets': 'tcp_ratio',
    'dir_ratio_packets':     'dir_ratio',
    'avg_duration':          'flow_duration_avg',
    'avg_ttl':               'ttl_mean',
}

AVAILABLE_FEATURES = list(FEATURE_MAP.values()) + ['udp_ratio', 'dst_port_density']

def load_time_index(times_tar_path):
    """Returns dict {id_time(int): datetime_utc}"""
    idx = {}
    with tarfile.open(times_tar_path, 'r:gz') as tf:
        for member in tf.getmembers():
            if '1_hour' in member.name and member.name.endswith('.csv'):
                f = tf.extractfile(member)
                reader = csv.DictReader(io.TextIOWrapper(f, encoding='utf-8'))
                for row in reader:
                    try:
                        t = int(row.get('id_time', -1))
                        if t < 0:
                            continue
                        # Try multiple timestamp column names
                        for col in ['time', 'timestamp', 'datetime', 'date']:
                            if col in row and row[col]:
                                try:
                                    val = row[col].strip().replace('Z', '+00:00')
                                    dt = datetime.fromisoformat(val)
                                    # CONVERT to UTC (do not force tzinfo -- that
                                    # silently shifts +02:00 timestamps by 2h and
                                    # corrupts the hour-of-day / day-of-week binning
                                    # the diurnal tiers depend on). Naive timestamps
                                    # are assumed UTC.
                                    if dt.tzinfo is None:
                                        dt = dt.replace(tzinfo=timezone.utc)
                                    else:
                                        dt = dt.astimezone(timezone.utc)
                                    idx[t] = dt
                                    break
                                except Exception:
                                    pass
                        if t not in idx:
                            # Fallback: base time + t hours
                            base = datetime(2023, 10, 9, 0, 0, tzinfo=timezone.utc)
                            idx[t] = base + timedelta(hours=t)
                    except Exception:
                        pass
                break
    if not idx:
        # Build synthetic index
        base = datetime(2023, 10, 9, 0, 0, tzinfo=timezone.utc)
        for i in range(10000):
            idx[i] = base + timedelta(hours=i)
    return idx

def parse_row(raw, time_index):
    """Convert raw CSV dict to feature dict with mapped names + derived features."""
    r = {}
    for raw_col, feat_name in FEATURE_MAP.items():
        try:
            r[feat_name] = float(raw.get(raw_col, 0) or 0)
        except Exception:
            r[feat_name] = 0.0
    # Derived
    r['udp_ratio'] = max(0.0, min(1.0, 1.0 - r['tcp_ratio']))
    pps = r['packets_per_sec'] + EPS
    # x1000 to match the
    # C definition `dst_port_density = unique_dst_ports * 1000 / pps`
    # (layer2/baselines.h). The pcap extractor and the LITNET loader already
    # apply the x1000; this loader (CESNET hourly CSV) was previously missed.
    r['dst_port_density'] = r['unique_dst_ports'] * 1000.0 / pps
    # Timestamp
    try:
        t = int(raw.get('id_time', 0))
        base = datetime(2023, 10, 9, tzinfo=timezone.utc)
        r['_dt'] = time_index.get(t, base + timedelta(hours=t))
        r['_id_time'] = t
    except Exception:
        r['_dt'] = datetime(2023, 10, 9, tzinfo=timezone.utc)
        r['_id_time'] = 0
    return r

def load_corpus(tar_path, times_tar_path):
    """Load top IPs by row count, return sorted list of feature dicts."""
    print("Loading time index...")
    time_index = load_time_index(times_tar_path)
    print(f"  Time index entries: {len(time_index)}")

    print("Scanning IP files...")
    ip_data = {}  # filename -> list of rows

    with tarfile.open(tar_path, 'r:gz') as tf:
        members = [m for m in tf.getmembers()
                   if 'agg_1_hour' in m.name and m.name.endswith('.csv') and m.size > 0]
        print(f"  Found {len(members)} hourly IP files")

        for member in members:
            try:
                f = tf.extractfile(member)
                if f is None:
                    continue
                reader = csv.DictReader(io.TextIOWrapper(f, encoding='utf-8'))
                rows = [parse_row(r, time_index) for r in reader]
                rows = [r for r in rows if r['packets_per_sec'] > 0]
                if len(rows) >= MIN_IP_ROWS:
                    ip_data[member.name] = rows
            except Exception:
                pass

    print(f"  IPs with >= {MIN_IP_ROWS} rows: {len(ip_data)}")

    # Sort by row count descending, take top N
    sorted_ips = sorted(ip_data.items(), key=lambda x: len(x[1]), reverse=True)[:TOP_N_IPS]
    top_count = len(sorted_ips[0][1]) if sorted_ips else 0
    bot_count = len(sorted_ips[-1][1]) if sorted_ips else 0
    print(f"  Using top {len(sorted_ips)} IPs, row counts: {top_count} to {bot_count}")

    # Concatenate all rows sorted by id_time
    all_rows = []
    for _, rows in sorted_ips:
        all_rows.extend(rows)
    all_rows.sort(key=lambda r: r['_id_time'])

    print(f"  Total rows available: {len(all_rows)}")
    return all_rows

def build_split(all_rows):
    """Split into train, test_normal."""
    needed = TRAIN_NORMAL + TEST_NORMAL
    if len(all_rows) < needed:
        raise ValueError(f"Need {needed} rows, only have {len(all_rows)}")
    train = all_rows[:TRAIN_NORMAL]
    test_normal = all_rows[TRAIN_NORMAL:TRAIN_NORMAL + TEST_NORMAL]
    return train, test_normal


def load_per_ip(tar_path, times_tar_path, min_rows=None):
    """Load data grouped per IP.

    Returns a dict {ip_id: [rows]} where each IP's rows are sorted by id_time.
    Only IPs with >= min_rows rows are included.
    ip_id is derived from the member filename (basename without extension).
    """
    if min_rows is None:
        min_rows = MIN_IP_ROWS_PER_IP

    print("Loading time index (per-IP)...")
    time_index = load_time_index(times_tar_path)
    print(f"  Time index entries: {len(time_index)}")

    print("Scanning IP files (per-IP mode)...")
    ip_rows_dict = {}

    with tarfile.open(tar_path, 'r:gz') as tf:
        members = [m for m in tf.getmembers()
                   if 'agg_1_hour' in m.name and m.name.endswith('.csv') and m.size > 0]
        print(f"  Found {len(members)} hourly IP files")

        for member in members:
            try:
                f = tf.extractfile(member)
                if f is None:
                    continue
                reader = csv.DictReader(io.TextIOWrapper(f, encoding='utf-8'))
                rows = [parse_row(r, time_index) for r in reader]
                rows = [r for r in rows if r['packets_per_sec'] > 0]
                if len(rows) >= min_rows:
                    # Use member basename (without extension) as IP id
                    ip_id = member.name.split('/')[-1].replace('.csv', '')
                    rows.sort(key=lambda r: r['_id_time'])
                    ip_rows_dict[ip_id] = rows
            except Exception:
                pass

    print(f"  IPs with >= {min_rows} rows: {len(ip_rows_dict)}")
    row_counts = sorted([len(v) for v in ip_rows_dict.values()], reverse=True)
    if row_counts:
        print(f"  Row counts: max={row_counts[0]}, min={row_counts[-1]}, "
              f"median={row_counts[len(row_counts)//2]}")
    return ip_rows_dict
