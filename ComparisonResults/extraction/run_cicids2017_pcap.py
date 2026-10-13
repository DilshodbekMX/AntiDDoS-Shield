"""
CIC-IDS-2017 cross-day pcap-based per-IP evaluation.

Methodology (mirrors CIC-DDoS2019 section 6.X):
  - Monday pcap (~10.8 GB) is benign-only -> per-(dst_ip, 1-second) windows
    train the EWMA baseline per destination IP.
  - Friday pcap (~8.8 GB) contains the documented afternoon DDoS attack ->
    per-(dst_ip, 1-second) windows labeled via 5-tuple matching against
    the GeneratedLabelledFlows CSV.
  - Per-destination-IP evaluation: for each IP with sufficient Monday baseline
    + sufficient Friday windows, compute DR (on attack-labeled Friday windows)
    and FPR (on benign-labeled Friday windows).

Why pcap and not CSV: CIC-IDS-2017's released GeneratedLabelledFlows CSVs have
minute-resolution timestamps only, insufficient for 1-second windowing. Raw
pcaps have microsecond timestamps, enabling true 1-second binning.

Output: cicids2017_pcap_features_<day>.json + cicids2017_pcap_results.json
"""
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_sys.path.insert(0, _HERE)                        # sibling extraction modules (tree_io, extractors)
_sys.path.insert(0, _os.path.dirname(_HERE))      # ComparisonResults/: config, loaders, registry
_BASE = _os.environ.get('ANTIDDOS_BASE', _os.path.dirname(_os.path.dirname(_HERE)))  # == config.BASE

import os, sys, json, time, csv, math, socket, copy
from collections import defaultdict, Counter
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(__file__))

import dpkt

from config import *
from baselines import ThreeTierBaseline
from detectors import CUSUMDetector, LogZDetector, JSDDetector
from pipeline import (detect_row, calibrate_threshold, calibrate_cusum_h, wilson_ci)

# Reuse the WindowAggregator + helpers from the CIC-DDoS2019 extractor
from pcap_feature_extractor import (WindowAggregator, ip_to_str, shannon_entropy)


DATASET_DIR = os.path.join(BASE, "datasets", "CIC-IDS-2017")
MONDAY_PCAP = os.path.join(DATASET_DIR, "PCAPs", "Monday-WorkingHours.pcap")
FRIDAY_PCAP = os.path.join(DATASET_DIR, "PCAPs", "Friday-WorkingHours.pcap")
MONDAY_CSV  = os.path.join(DATASET_DIR, "CSVs", "TimestampedFlows",
                           "Monday-WorkingHours.pcap_ISCX.csv")
FRIDAY_CSV  = os.path.join(DATASET_DIR, "CSVs", "TimestampedFlows",
                           "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

MONDAY_FEATURES_JSON = os.path.join(CACHE_DIR, "cicids2017_pcap_monday.json")
FRIDAY_FEATURES_JSON = os.path.join(CACHE_DIR, "cicids2017_pcap_friday.json")
RESULTS_JSON         = os.path.join(RESULTS_DIR, "cicids2017_pcap_results.json")

MIN_ROWS_PER_IP = 60          # ~1 minute of activity required for an IP to count
MIN_ATTACK_WINDOWS_FOR_DR = 30

# Module-level stash of the most recent evaluate_cross_day() internals so
# auxiliary audit scripts (run_cicids2017_pool_audit.py) can reuse the exact
# per-IP eligibility gates and evaluation output without re-implementing them.
# Reference-only; no serialized output changes.
LAST_PER_IP_RESULTS = None
LAST_T_ATTACK_START = None
LAST_FRIDAY_PER_IP = None


# Active feature subset -- auto-computed at runtime against PRODUCTION_39_FEATURES.
# Populated in main() after the Monday-benign cache loads.
from feature_filter import filter_active, PRODUCTION_39_FEATURES
USED_FEATURES = []


def epoch_to_dt(t):
    return datetime.fromtimestamp(t, tz=timezone.utc)


def load_2017_flow_labels(csv_path):
    """Build 5-tuple -> label dict from CIC-IDS-2017 GeneratedLabelledFlows CSV.

    The 2017 CSV columns use leading spaces (' Source IP', ' Destination IP', etc.)
    and the Label column has values like 'BENIGN', 'DDoS', 'PortScan'.
    """
    labels = {}
    n_attack = n_benign = 0
    with open(csv_path, 'r', encoding='utf-8', errors='replace') as f:
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
                if label.upper() == 'BENIGN':
                    if key not in labels:
                        labels[key] = 'BENIGN'
                    n_benign += 1
                else:
                    labels[key] = label  # attack label always wins
                    n_attack += 1
            except (ValueError, TypeError):
                continue
    return labels, n_attack, n_benign


def _open_pcap_reader(f):
    """Auto-detect pcap vs pcapng format and return appropriate reader."""
    head = f.read(4)
    f.seek(0)
    # pcapng magic: 0x0a0d0d0a; classic pcap magic: 0xa1b2c3d4 or 0xd4c3b2a1
    if head == b'\x0a\x0d\x0d\x0a':
        return dpkt.pcapng.Reader(f)
    return dpkt.pcap.Reader(f)


def parse_pcap(pcap_path, aggregator, flow_labels=None, label_log_every=2_000_000):
    """Parse one pcap or pcapng file packet-by-packet into the aggregator."""
    n = 0
    skipped = 0
    t_start = time.time()
    with open(pcap_path, 'rb') as f:
        reader = _open_pcap_reader(f)
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

                src_port = dst_port = 0
                tcp_flags = 0
                icmp_type = -1
                if proto == 6 and isinstance(ip.data, dpkt.tcp.TCP):
                    src_port, dst_port, tcp_flags = ip.data.sport, ip.data.dport, ip.data.flags
                elif proto == 17 and isinstance(ip.data, dpkt.udp.UDP):
                    src_port, dst_port = ip.data.sport, ip.data.dport
                elif proto == 1 and isinstance(ip.data, dpkt.icmp.ICMP):
                    icmp_type = ip.data.type

                is_attack = False
                if flow_labels:
                    key = (src_ip, src_port, dst_ip, dst_port, proto)
                    lbl = flow_labels.get(key)
                    if lbl and lbl.upper() != 'BENIGN':
                        is_attack = True

                aggregator.add_packet(ts, {
                    'src_ip': src_ip, 'dst_ip': dst_ip,
                    'src_port': src_port, 'dst_port': dst_port,
                    'proto': proto, 'length': length, 'tcp_flags': tcp_flags,
                    'ttl': ttl, 'is_fragment': is_fragment,
                    'icmp_type': icmp_type, 'is_attack': is_attack,
                })
                n += 1
                if n % label_log_every == 0:
                    elapsed = time.time() - t_start
                    rate = n / elapsed
                    print(f"    {n:>12,} packets parsed ({rate/1000:.0f}K pkts/s)")
            except Exception:
                skipped += 1
                continue
    return n, skipped


def parse_day(pcap_path, label_csv_path, out_json):
    print(f"\n=== Parsing {os.path.basename(pcap_path)} ===")
    flow_labels = {}
    if label_csv_path and os.path.exists(label_csv_path):
        print(f"  Loading flow labels from {os.path.basename(label_csv_path)}...")
        flow_labels, na, nb = load_2017_flow_labels(label_csv_path)
        print(f"    {len(flow_labels)} flow labels ({na:,} attack-labeled rows, {nb:,} benign-labeled rows)")

    aggregator = WindowAggregator()
    t0 = time.time()
    n, sk = parse_pcap(pcap_path, aggregator, flow_labels=flow_labels)
    elapsed = time.time() - t0
    print(f"  Total: {n:,} packets parsed, {sk:,} skipped, {elapsed:.1f}s")

    print(f"  Aggregating into per-IP feature time-series...")
    per_ip = aggregator.finalize()
    n_attack_w = sum(sum(1 for r in rows if r.get('_is_attack')) for rows in per_ip.values())
    n_total_w = sum(len(rows) for rows in per_ip.values())
    print(f"  Per-IP windows: {len(per_ip)} dst_ips, {n_total_w:,} windows ({n_attack_w:,} attack)")

    with open(out_json, 'w') as f:
        json.dump({
            'metadata': {
                'source_pcap': pcap_path,
                'source_csv': label_csv_path,
                'total_packets': n,
                'total_skipped': sk,
                'n_dst_ips': len(per_ip),
                'total_windows': n_total_w,
                'total_attack_windows': n_attack_w,
            },
            'per_ip_windows': per_ip,
        }, f, indent=1)
    print(f"  Saved: {out_json} ({os.path.getsize(out_json) / 1e6:.1f} MB)")
    return per_ip


def evaluate_cross_day(monday_per_ip, friday_per_ip):
    """For each dst_ip present in BOTH days, train baseline on Monday windows,
    test on Friday windows (restricted to the labeled DDoS attack time range).

    The Friday pcap covers ~8 hours but the DDoS labels (Friday-Afternoon-DDos.csv)
    only cover ~20 minutes. To compute meaningful DR/FPR we restrict the Friday
    test set to the time window where ground-truth labels are valid -- otherwise
    the morning/evening traffic (which contains OTHER unlabeled attacks like
    PortScan and benign-but-pattern-shifted Friday traffic) inflates FPR.
    """
    print(f"\n=== Cross-Day Per-IP Evaluation ===")

    # Determine attack-time window from the windows that contain attack flows
    all_friday_rows = [r for rows in friday_per_ip.values() for r in rows]
    attack_rows = [r for r in all_friday_rows if r.get('_is_attack')]
    t_attack_start = None
    if attack_rows:
        atk_times = sorted(r['_dt'] for r in attack_rows)
        t_attack_start = atk_times[0]
        t_attack_end = atk_times[-1]
        print(f"  Attack-time range (from labels): {t_attack_start:.0f} .. {t_attack_end:.0f}")
        print(f"  Friday-morning bridging period: pcap-start .. {t_attack_start:.0f} (used for calibration)")
        print(f"  Test set: {t_attack_start:.0f} .. {t_attack_end:.0f}")

    common_ips = set(monday_per_ip.keys()) & set(friday_per_ip.keys())
    print(f"  Destination IPs in both days: {len(common_ips)}")

    eligible = []
    for ip in common_ips:
        m_n = len(monday_per_ip[ip])
        f_n = len(friday_per_ip[ip])
        f_attack = sum(1 for r in friday_per_ip[ip] if r.get('_is_attack'))
        if m_n >= MIN_ROWS_PER_IP and f_n >= MIN_ROWS_PER_IP:
            eligible.append((ip, m_n, f_n, f_attack))
    eligible.sort(key=lambda x: x[3], reverse=True)
    print(f"  IPs with >= {MIN_ROWS_PER_IP} windows on both days: {len(eligible)}")
    print(f"  Top 10 by Friday attack windows:")
    for ip, mn, fn, fa in eligible[:10]:
        print(f"    {ip}: Monday={mn} Friday={fn} (attack={fa})")

    results = []
    for ip, mn, fn, fa in eligible:
        m_rows = list(monday_per_ip[ip])
        f_rows = list(friday_per_ip[ip])
        for r in m_rows + f_rows:
            if isinstance(r.get('_dt'), (int, float)):
                r['_dt'] = epoch_to_dt(r['_dt'])
        m_rows.sort(key=lambda r: r.get('_id_time', 0))
        f_rows.sort(key=lambda r: r.get('_id_time', 0))

        # Split Friday into (a) bridging period BEFORE the attack starts (benign only,
        # used to acclimate the Monday-trained baseline to Friday distribution), and
        # (b) test period DURING the attack (everything from attack-start onwards).
        if t_attack_start is not None:
            # Bridging = Friday-morning windows up to attack start; must be benign-labeled
            t_atk_dt = epoch_to_dt(t_attack_start) if isinstance(t_attack_start, (int, float)) else t_attack_start
            bridge_rows = [r for r in f_rows if r['_dt'] < t_atk_dt and not r.get('_is_attack', False)]
            test_rows = [r for r in f_rows if r['_dt'] >= t_atk_dt]
        else:
            bridge_rows = []
            test_rows = f_rows
        if len(test_rows) < 5:
            continue

        # Train baseline on Monday (full) + bridging Friday-morning benign windows
        bl = ThreeTierBaseline(USED_FEATURES)
        for row in m_rows:
            bl.update(row, row['_dt'])
        for row in bridge_rows:
            bl.update(row, row['_dt'])

        cusum = CUSUMDetector(USED_FEATURES)
        logz = LogZDetector(USED_FEATURES)
        jsd_d = JSDDetector()
        for row in m_rows:
            cusum.update(row, bl, row['_dt'])
            logz.update(row, THETA_INIT)
            jsd_d.update_and_check(row)
        for row in bridge_rows:
            cusum.update(row, bl, row['_dt'])
            logz.update(row, THETA_INIT)
            jsd_d.update_and_check(row)
        for ff in cusum.s_high:
            cusum.s_high[ff] = 0.0
            cusum.s_low[ff] = 0.0

        # Calibrate on bridging rows (Friday-morning benign -- represents test-time distribution)
        cal_source = bridge_rows if len(bridge_rows) >= 10 else m_rows[-50:]
        theta = calibrate_threshold(cal_source, bl) if len(cal_source) >= 5 else THETA_INIT
        h_mult = calibrate_cusum_h(cal_source, bl, cusum) if len(cal_source) >= 5 else CUSUM_H_MULT
        cusum.h_mult = h_mult

        # Snapshot post-train state for an independent fixed-theta=4.0 pass
        # (the shipped production operating point: fixed theta=4.0 + h=5sigma, no
        # per-IP percentile calibration) -- reported alongside
        # the calibrated number, which on uninvolved IPs uses high theta that
        # suppresses their FPR.
        bl_p = copy.deepcopy(bl)
        cusum_p = copy.deepcopy(cusum); cusum_p.h_mult = CUSUM_H_MULT
        logz_p = copy.deepcopy(logz); jsd_p = copy.deepcopy(jsd_d)

        # Test on Friday-attack-period windows
        tp = fp = fn_c = tn = 0
        tp_p = fp_p = fn_p = tn_p = 0
        for row in test_rows:
            is_atk = row.get('_is_attack', False)
            det, _, _, _ = detect_row(row, bl, cusum, logz, jsd_d, theta, row['_dt'])
            if is_atk and det: tp += 1
            elif is_atk and not det: fn_c += 1
            elif not is_atk and det: fp += 1
            else: tn += 1
            if not det and not is_atk:  # C-faithful: freeze on own FP detection AND throughout the attack episode (state machine stays frozen, paper 4.7.3) -- avoids both FPR deflation and victim self-poisoning
                bl.update(row, row['_dt'])

            # Fixed theta=4.0 production operating point (independent baseline)
            det_p, _, _, _ = detect_row(row, bl_p, cusum_p, logz_p, jsd_p, THETA_INIT, row['_dt'])
            if is_atk and det_p: tp_p += 1
            elif is_atk and not det_p: fn_p += 1
            elif not is_atk and det_p: fp_p += 1
            else: tn_p += 1
            if not det_p and not is_atk:
                bl_p.update(row, row['_dt'])

        n_a = tp + fn_c
        n_b = fp + tn
        results.append({
            'dst_ip': ip,
            'monday_windows': mn, 'friday_windows': fn,
            'bridge_windows': len(bridge_rows),
            'test_windows': len(test_rows),
            'theta': theta, 'h_mult': h_mult,
            'tp': tp, 'fp': fp, 'fn': fn_c, 'tn': tn,
            'tp_p': tp_p, 'fp_p': fp_p, 'fn_p': fn_p, 'tn_p': tn_p,
            'n_attack': n_a, 'n_benign': n_b,
        })

    # Stash internals for auxiliary audit scripts (serialized output unchanged)
    global LAST_PER_IP_RESULTS, LAST_T_ATTACK_START, LAST_FRIDAY_PER_IP
    LAST_PER_IP_RESULTS = results
    LAST_T_ATTACK_START = t_attack_start
    LAST_FRIDAY_PER_IP = friday_per_ip

    # Split DR (victim IPs only) vs FPR (uninvolved IPs)
    victims = [r for r in results if r['n_attack'] >= MIN_ATTACK_WINDOWS_FOR_DR]
    uninvolved = [r for r in results if r['n_attack'] == 0 and r['n_benign'] >= 30]

    v_tp = sum(r['tp'] for r in victims)
    v_fn = sum(r['fn'] for r in victims)
    v_dr = v_tp / max(v_tp + v_fn, 1) * 100
    v_dr_ci = wilson_ci(v_tp, v_tp + v_fn)

    u_fp = sum(r['fp'] for r in uninvolved)
    u_tn = sum(r['tn'] for r in uninvolved)
    u_fpr = u_fp / max(u_fp + u_tn, 1) * 100
    u_fpr_ci = wilson_ci(u_fp, u_fp + u_tn)

    # Fixed-theta=4.0 production operating point
    v_tp_p = sum(r['tp_p'] for r in victims); v_fn_p = sum(r['fn_p'] for r in victims)
    v_dr_p = v_tp_p / max(v_tp_p + v_fn_p, 1) * 100
    u_fp_p = sum(r['fp_p'] for r in uninvolved); u_tn_p = sum(r['tn_p'] for r in uninvolved)
    u_fpr_p = u_fp_p / max(u_fp_p + u_tn_p, 1) * 100

    # IP-clustered bootstrap CI for uninvolved FPR (window-Wilson is pseudoreplicated)
    import random as _rnd
    def _cluster_ci(units, nb=2000, seed=7):
        if not units: return [0.0, 0.0]
        rng = _rnd.Random(seed); m = len(units); rates = []
        for _ in range(nb):
            fp = tot = 0
            for _ in range(m):
                a, b = units[rng.randrange(m)]; fp += a; tot += b
            if tot: rates.append(fp / tot * 100)
        rates.sort()
        return [round(rates[int(0.025*len(rates))], 1), round(rates[int(0.975*len(rates))], 1)]
    u_units = [(r['fp'], r['fp'] + r['tn']) for r in uninvolved]
    u_fpr_cluster = _cluster_ci(u_units)
    # IP-clustered bootstrap CI for the SHIPPED fixed-theta=4.0 floor (M1: headline number needs a CI)
    u_units_p = [(r['fp_p'], r['fp_p'] + r['tn_p']) for r in uninvolved]
    u_fpr_p_cluster = _cluster_ci(u_units_p)

    # Overall (across all IPs incl. victims contributing fps from benign Friday)
    total_tp = sum(r['tp'] for r in results)
    total_fp = sum(r['fp'] for r in results)
    total_fn = sum(r['fn'] for r in results)
    total_tn = sum(r['tn'] for r in results)
    n_a_t = total_tp + total_fn
    n_b_t = total_fp + total_tn
    o_dr = total_tp / max(n_a_t, 1) * 100
    o_fpr = total_fp / max(n_b_t, 1) * 100
    o_prec = total_tp / max(total_tp + total_fp, 1) * 100
    o_f1 = 2 * o_prec * o_dr / max(o_prec + o_dr, 1) if (o_prec + o_dr) > 0 else 0

    print(f"\n  ====== AGGREGATE ======")
    print(f"  Evaluated IPs:           {len(results)}")
    print(f"  Victim IPs (>={MIN_ATTACK_WINDOWS_FOR_DR} atk): {len(victims)}")
    print(f"  Uninvolved IPs (0 atk):  {len(uninvolved)}")
    print(f"  DR on victims:           {v_dr:.1f}% [{v_dr_ci[0]*100:.1f}, {v_dr_ci[1]*100:.1f}]   ({v_tp}/{v_tp+v_fn})")
    print(f"  FPR on uninvolved:       {u_fpr:.1f}% [{u_fpr_ci[0]*100:.1f}, {u_fpr_ci[1]*100:.1f}] (IP-cluster {u_fpr_cluster})  ({u_fp}/{u_fp+u_tn})")
    print(f"  --- fixed-θ=4.0 (shipped production operating point) ---")
    print(f"  DR on victims (fixed-θ):  {v_dr_p:.1f}%   ({v_tp_p}/{v_tp_p+v_fn_p})")
    print(f"  FPR on uninvolved (fixed-θ): {u_fpr_p:.1f}%   ({u_fp_p}/{u_fp_p+u_tn_p})")
    print(f"  Overall DR:              {o_dr:.1f}%   Overall FPR: {o_fpr:.1f}%   Prec: {o_prec:.1f}%   F1: {o_f1:.1f}%")

    out = {
        'metadata': {
            'dataset': 'CIC-IDS-2017 (pcap-based, per-IP, cross-day Monday->Friday)',
            'monday_pcap': MONDAY_PCAP,
            'friday_pcap': FRIDAY_PCAP,
            'feature_count': len(USED_FEATURES),
            'features_used': list(USED_FEATURES),
            'features': list(USED_FEATURES),
            'features_inert_auto_excluded': globals().get('_INERT_FEATURES', []),
            'production_feature_set_size': len(PRODUCTION_39_FEATURES),
            'n_ips_evaluated': len(results),
            'n_victim_ips': len(victims),
            'n_uninvolved_ips': len(uninvolved),
        },
        'aggregate': {
            'dr_on_victims_pct': round(v_dr, 1),
            'dr_on_victims_ci': [round(c * 100, 1) for c in v_dr_ci],
            'fpr_on_uninvolved_pct': round(u_fpr, 1),
            'fpr_on_uninvolved_ci': [round(c * 100, 1) for c in u_fpr_ci],
            'fpr_on_uninvolved_cluster_ci': u_fpr_cluster,
            'dr_on_victims_fixed_theta_pct': round(v_dr_p, 1),
            'fpr_on_uninvolved_fixed_theta_pct': round(u_fpr_p, 1),
            'fpr_on_uninvolved_fixed_theta_cluster_ci': u_fpr_p_cluster,
            'fixed_theta_note': 'fixed theta=4.0 + h=5sigma = shipped production operating point (no per-IP calibration); per-IP-calibrated uninvolved IPs use higher theta which suppresses their FPR',
            'overall_dr_pct': round(o_dr, 1),
            'overall_fpr_pct': round(o_fpr, 1),
            'overall_precision_pct': round(o_prec, 1),
            'overall_f1_pct': round(o_f1, 1),
            'tp': total_tp, 'fp': total_fp, 'fn': total_fn, 'tn': total_tn,
            'n_attack_windows': n_a_t, 'n_benign_windows': n_b_t,
        },
        'top10_victims': [{
            'dst_ip': r['dst_ip'],
            'monday_windows': r['monday_windows'],
            'friday_attack': r['n_attack'], 'friday_benign': r['n_benign'],
            'theta': r['theta'],
            'dr': round(r['tp'] / max(r['n_attack'], 1) * 100, 1),
            'fpr': round(r['fp'] / max(r['n_benign'], 1) * 100, 1),
            'precision': round(r['tp'] / max(r['tp'] + r['fp'], 1) * 100, 1),
            'tp': r['tp'], 'fp': r['fp'], 'fn': r['fn'], 'tn': r['tn'],
        } for r in sorted(victims, key=lambda x: x['n_attack'], reverse=True)[:10]],
    }
    with open(RESULTS_JSON, 'w') as f:
        json.dump(out, f, indent=2)
    print(f"\n  Saved: {RESULTS_JSON}")
    return out


def main():
    print(f"=== CIC-IDS-2017 Cross-Day PCAP Per-IP Evaluation ===\n")
    t0 = time.time()

    # Step 1: parse Monday (benign-only day, label CSV optional)
    if os.path.exists(MONDAY_FEATURES_JSON):
        print(f"Loading cached Monday features: {MONDAY_FEATURES_JSON}")
        monday_per_ip = json.load(open(MONDAY_FEATURES_JSON))['per_ip_windows']
    else:
        monday_per_ip = parse_day(MONDAY_PCAP, MONDAY_CSV, MONDAY_FEATURES_JSON)

    # Step 2: parse Friday (with attack labels via 5-tuple match)
    if os.path.exists(FRIDAY_FEATURES_JSON):
        print(f"Loading cached Friday features: {FRIDAY_FEATURES_JSON}")
        friday_per_ip = json.load(open(FRIDAY_FEATURES_JSON))['per_ip_windows']
    else:
        friday_per_ip = parse_day(FRIDAY_PCAP, FRIDAY_CSV, FRIDAY_FEATURES_JSON)

    # F-CIC-6 cache upgrade: dst_port_density x1000 to match shared_memory.c:577
    from pipeline import upgrade_dst_port_density_inplace
    upgrade_dst_port_density_inplace(monday_per_ip, 'monday')
    upgrade_dst_port_density_inplace(friday_per_ip, 'friday')

    # Auto-detect active features against PRODUCTION_39_FEATURES on
    # Monday benign-only windows. Assigned to module-level USED_FEATURES so
    # evaluate_cross_day's downstream baselines/detectors pick it up.
    global USED_FEATURES
    sample_rows = []
    for ip, rows in monday_per_ip.items():
        sample_rows.extend(rows[:50])
        if len(sample_rows) >= 5000: break
    USED_FEATURES_NEW, inert = filter_active(PRODUCTION_39_FEATURES, sample_rows)
    USED_FEATURES.clear(); USED_FEATURES.extend(USED_FEATURES_NEW)
    print(f"Feature filter: {len(USED_FEATURES)} active of {len(PRODUCTION_39_FEATURES)}; "
          f"inert: {inert}")
    globals()['_INERT_FEATURES'] = inert

    # Step 3: cross-day per-IP evaluation
    evaluate_cross_day(monday_per_ip, friday_per_ip)

    print(f"\nTotal runtime: {time.time() - t0:.1f}s")


if __name__ == '__main__':
    main()
