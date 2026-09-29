"""
CIC-IDS-2017 uninvolved-pool characterization + label-cleanliness cross-check.

Companion audit for the cross-day pcap evaluation (run_cicids2017_pcap.py).
It does NOT re-implement any eligibility or evaluation logic: it drives
run_cicids2017_pcap.main() end-to-end (same caches, same feature filter, same
gates, same detection loop) and reads the per-IP result rows the runner
stashes in LAST_PER_IP_RESULTS, so the uninvolved pool audited here is
selected by the exact code path that produced the committed
results/cicids2017_pcap_results.json.

Three products, all written to results/cicids2017_pool_characterization.json:
  1. Parity check: regenerated aggregate vs the committed results JSON.
  2. Pool composition: per-IP test-window counts, traffic-rate and
     protocol-mix distributions, per-IP fixed-theta FPR distribution, and
     FP-concentration (share of total FP windows from the top 10% of IPs).
  3. Label cross-check: stream ALL EIGHT CIC-IDS-2017 labeled flow CSVs
     (TrafficLabelling variant, the one with Source/Destination IP columns;
     the Friday DDoS file is byte-identical to the TimestampedFlows copy the
     runner labels from) and report every non-BENIGN flow in which a pool IP
     appears as Source IP or Destination IP, including whether such flows
     fall inside the Friday test slice used for FPR accounting.

The regenerated cross-day results are written to a scratch file
(_poolaudit_regen_cicids2017_pcap_results.json); the committed
cicids2017_pcap_results.json is never overwritten.
"""
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_sys.path.insert(0, _HERE)                        # sibling extraction modules (tree_io, extractors)
_sys.path.insert(0, _os.path.dirname(_HERE))      # ComparisonResults/: config, loaders, registry
_BASE = _os.environ.get('ANTIDDOS_BASE', _os.path.dirname(_os.path.dirname(_HERE)))  # == config.BASE

import os, sys, csv, gc, json, math, time
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import run_cicids2017_pcap as base
from config import RESULTS_DIR

HERE = os.path.dirname(os.path.abspath(__file__))
ARTIFACT_JSON = os.path.join(RESULTS_DIR, "cicids2017_pool_characterization.json")
REGEN_RESULTS_JSON = os.path.join(HERE, "_poolaudit_regen_cicids2017_pcap_results.json")
COMMITTED_RESULTS_JSON = os.path.join(RESULTS_DIR, "cicids2017_pcap_results.json")

# GeneratedLabelledFlows CSVs (Flow ID / Source IP / Destination IP / Timestamp
# / Label columns). NOTE: the directory name ends with a space in the released
# dataset archive.
TRAFFIC_LABELLING_DIR = os.path.join(base.DATASET_DIR, "CSVs", "TrafficLabelling ")
WEEK_CSVS = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]
FRIDAY_CSVS = set(WEEK_CSVS[-3:])

EXPECTED_POOL_SIZE = 530
EXPECTED_VICTIM_IP = "192.168.10.50"

# Capture-site local clock (UNB Fredericton, July 2017 = ADT, UTC-3). The pcap
# epoch <-> local wall-clock mapping is sanity-checked below against the last
# DDoS-labeled flow timestamp in the CSV vs the last attack-labeled window.
LOCAL_TZ = timezone(timedelta(hours=-3))
FRIDAY_DATE = (2017, 7, 7)


def pctl(sorted_vals, q):
    """Percentile with linear interpolation on an already-sorted list."""
    if not sorted_vals:
        return None
    n = len(sorted_vals)
    if n == 1:
        return float(sorted_vals[0])
    pos = (q / 100.0) * (n - 1)
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return float(sorted_vals[lo])
    frac = pos - lo
    return float(sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac)


def dist_summary(values, ndigits=3, full=False):
    sv = sorted(values)
    out = {
        "n": len(sv),
        "p10": round(pctl(sv, 10), ndigits),
        "p50": round(pctl(sv, 50), ndigits),
        "p90": round(pctl(sv, 90), ndigits),
    }
    if full:
        out.update({
            "min": round(float(sv[0]), ndigits),
            "p25": round(pctl(sv, 25), ndigits),
            "p75": round(pctl(sv, 75), ndigits),
            "max": round(float(sv[-1]), ndigits),
            "iqr": round(pctl(sv, 75) - pctl(sv, 25), ndigits),
        })
    return out


def classify_pool_ip(ip):
    """Network class of a pool IP within the CIC-IDS-2017 testbed topology."""
    if ip.startswith("192.168.10."):
        return "internal_victim_lan"
    if ip.startswith("205.174.165."):
        return "testbed_infrastructure"
    if ip.startswith("172.16."):
        return "internal_nat"
    return "external_internet"


def row_epoch(w):
    """Window row _dt as epoch float (rows of eligible IPs were converted to
    datetime in place by evaluate_cross_day; others are still floats)."""
    dt = w["_dt"]
    return dt.timestamp() if isinstance(dt, datetime) else float(dt)


def parse_friday_ts(s):
    """Parse a Friday GeneratedLabelledFlows timestamp ('D/M/YYYY H:MM[:SS]',
    12-hour clock with no AM/PM marker) to a UTC epoch.

    The Friday capture runs ~08:59-17:04 local, so hour values 1-7 can only be
    PM (observed hour sets: Morning={8..12}, PortScan={1,2,3}, DDoS={3,4,5}).
    Returns None if unparseable or not dated 7/7/2017.
    """
    s = s.strip()
    try:
        date_part, time_part = s.split(" ", 1)
        if date_part not in ("7/7/2017", "07/07/2017"):
            return None
        parts = time_part.strip().split(":")
        h = int(parts[0]); m = int(parts[1])
        sec = int(parts[2]) if len(parts) > 2 else 0
        if h < 8:
            h += 12
        y, mo, d = FRIDAY_DATE
        return datetime(y, mo, d, h, m, sec, tzinfo=LOCAL_TZ).timestamp()
    except (ValueError, IndexError):
        return None


def scan_labelled_csv(path, pool_ips, is_friday, t_attack_start):
    """Stream one GeneratedLabelledFlows CSV; report non-BENIGN flows whose
    Source IP or Destination IP is in the uninvolved pool."""
    stats = {
        "csv": os.path.basename(path),
        "size_bytes": os.path.getsize(path),
        "n_rows": 0,
        "n_nonbenign_rows": 0,
        "nonbenign_labels": {},
        "pool_hits": {
            "n_flows": 0,
            "n_flows_pool_as_src": 0,
            "n_flows_pool_as_dst": 0,
            "n_pool_ips_as_src": 0,
            "n_pool_ips_as_dst": 0,
            "labels": {},
        },
    }
    per_pool_ip = defaultdict(lambda: {"n_flows": 0, "as_src": 0, "as_dst": 0,
                                       "n_in_test_slice": 0, "labels": Counter()})
    if is_friday:
        stats["pool_hits"]["n_in_test_slice_start_based"] = 0
        stats["pool_hits"]["n_in_test_slice_duration_extended"] = 0
        stats["n_friday_ts_unparsed_on_hits"] = 0
    label_counter = Counter()
    hit_labels = Counter()
    src_ips, dst_ips = set(), set()
    hit_details = []
    ddos_ts_min = ddos_ts_max = None  # tz sanity check (DDoS CSV only)
    n_garbled = 0

    csv.field_size_limit(10_000_000)
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        # Some released CIC CSVs contain stray NUL bytes; strip them so the
        # csv module does not abort mid-file.
        reader = csv.reader(line.replace("\0", "") for line in f)
        header = next(reader)
        n_cols = len(header)
        idx = {name.strip(): i for i, name in enumerate(header)}
        src_i = idx["Source IP"]; dst_i = idx["Destination IP"]
        ts_i = idx["Timestamp"]; dur_i = idx["Flow Duration"]
        lbl_i = idx["Label"]
        need = max(src_i, dst_i, ts_i, dur_i, lbl_i)
        for row in reader:
            if len(row) <= need:
                continue
            stats["n_rows"] += 1
            # Label is the last header column; on ragged rows (a known CIC CSV
            # corruption) fall back to the final field.
            lbl = (row[lbl_i] if len(row) == n_cols else row[-1]).strip()
            if not lbl or lbl.upper() == "BENIGN":
                continue
            if any(c.isdigit() for c in lbl):
                # No CIC-IDS-2017 attack label contains a digit; a numeric
                # "label" means a column-shifted/garbled row, not an attack.
                n_garbled += 1
                continue
            stats["n_nonbenign_rows"] += 1
            label_counter[lbl] += 1
            if is_friday and lbl.upper() == "DDOS":
                ts_e = parse_friday_ts(row[ts_i])
                if ts_e is not None:
                    ddos_ts_min = ts_e if ddos_ts_min is None else min(ddos_ts_min, ts_e)
                    ddos_ts_max = ts_e if ddos_ts_max is None else max(ddos_ts_max, ts_e)
            src = row[src_i].strip()
            dst = row[dst_i].strip()
            s_hit = src in pool_ips
            d_hit = dst in pool_ips
            if not (s_hit or d_hit):
                continue
            ph = stats["pool_hits"]
            ph["n_flows"] += 1
            hit_labels[lbl] += 1
            hit_pool_ips = []
            if s_hit:
                ph["n_flows_pool_as_src"] += 1
                src_ips.add(src)
                hit_pool_ips.append(src)
                per_pool_ip[src]["as_src"] += 1
            if d_hit:
                ph["n_flows_pool_as_dst"] += 1
                dst_ips.add(dst)
                if dst not in hit_pool_ips:
                    hit_pool_ips.append(dst)
                per_pool_ip[dst]["as_dst"] += 1
            for hip in hit_pool_ips:
                per_pool_ip[hip]["n_flows"] += 1
                per_pool_ip[hip]["labels"][lbl] += 1
            detail = {
                "pool_ip": dst if d_hit else src,
                "role": "src+dst" if (s_hit and d_hit) else ("dst" if d_hit else "src"),
                "src_ip": src, "dst_ip": dst, "label": lbl,
                "timestamp_raw": row[ts_i].strip(),
            }
            if is_friday:
                ts_e = parse_friday_ts(row[ts_i])
                if ts_e is None:
                    stats["n_friday_ts_unparsed_on_hits"] += 1
                else:
                    try:
                        dur_s = max(float(row[dur_i]), 0.0) / 1e6
                    except ValueError:
                        dur_s = 0.0
                    in_start = ts_e >= t_attack_start
                    in_ext = (ts_e + dur_s) >= t_attack_start
                    detail["flow_start_epoch_est"] = round(ts_e, 1)
                    detail["in_test_slice_start_based"] = in_start
                    detail["in_test_slice_duration_extended"] = in_ext
                    if in_start:
                        ph["n_in_test_slice_start_based"] += 1
                    if in_ext:
                        ph["n_in_test_slice_duration_extended"] += 1
                        for hip in hit_pool_ips:
                            per_pool_ip[hip]["n_in_test_slice"] += 1
            if len(hit_details) < 200:
                hit_details.append(detail)

    stats["nonbenign_labels"] = dict(label_counter)
    stats["n_garbled_label_rows_skipped"] = n_garbled
    stats["per_pool_ip"] = {
        ip: {"n_flows": v["n_flows"], "as_src": v["as_src"], "as_dst": v["as_dst"],
             "n_in_test_slice": v["n_in_test_slice"], "labels": dict(v["labels"])}
        for ip, v in sorted(per_pool_ip.items(),
                            key=lambda kv: kv[1]["n_flows"], reverse=True)[:50]
    }
    ph = stats["pool_hits"]
    ph["labels"] = dict(hit_labels)
    ph["n_pool_ips_as_src"] = len(src_ips)
    ph["n_pool_ips_as_dst"] = len(dst_ips)
    ph["pool_ips_as_src"] = sorted(src_ips)
    ph["pool_ips_as_dst"] = sorted(dst_ips)
    if hit_details:
        stats["hit_flow_details_first200"] = hit_details
    if ddos_ts_min is not None:
        stats["_ddos_ts_min_epoch_est"] = ddos_ts_min
        stats["_ddos_ts_max_epoch_est"] = ddos_ts_max
    return stats


def main():
    t0 = time.time()
    print("=== CIC-IDS-2017 uninvolved-pool audit ===\n")

    # ---- Phase 1: regenerate the cross-day evaluation via the runner itself.
    # Redirect its output so the committed results JSON is not overwritten.
    base.RESULTS_JSON = REGEN_RESULTS_JSON
    base.main()

    results = base.LAST_PER_IP_RESULTS
    t_attack_start = float(base.LAST_T_ATTACK_START)
    friday_per_ip = base.LAST_FRIDAY_PER_IP
    if results is None or friday_per_ip is None:
        print("ERROR: runner did not stash per-IP results; aborting.")
        sys.exit(1)

    # Pool/victim split -- same expressions evaluate_cross_day applies.
    victims = [r for r in results if r["n_attack"] >= base.MIN_ATTACK_WINDOWS_FOR_DR]
    pool = [r for r in results if r["n_attack"] == 0 and r["n_benign"] >= 30]

    print(f"\n[audit] evaluated IPs: {len(results)}, victims: {len(victims)}, "
          f"uninvolved pool: {len(pool)}")
    if len(pool) != EXPECTED_POOL_SIZE or len(victims) != 1 or \
            victims[0]["dst_ip"] != EXPECTED_VICTIM_IP:
        print(f"ERROR: pool/victim mismatch -- expected {EXPECTED_POOL_SIZE} pool IPs "
              f"and single victim {EXPECTED_VICTIM_IP}; got {len(pool)} pool IPs, "
              f"victims={[v['dst_ip'] for v in victims]}. STOPPING (no artifact written).")
        sys.exit(2)

    # Attack-labeled window range (for the artifact + tz sanity check).
    atk_epochs = [row_epoch(w) for rows in friday_per_ip.values()
                  for w in rows if w.get("_is_attack")]
    t_attack_end = max(atk_epochs)
    if abs(min(atk_epochs) - t_attack_start) > 1e-3:
        print("ERROR: recomputed attack start disagrees with runner stash; aborting.")
        sys.exit(3)

    # Parity: regenerated aggregate vs committed results JSON.
    committed = json.load(open(COMMITTED_RESULTS_JSON))
    regen = json.load(open(REGEN_RESULTS_JSON))
    headline_keys = [
        "dr_on_victims_pct", "fpr_on_uninvolved_pct",
        "dr_on_victims_fixed_theta_pct", "fpr_on_uninvolved_fixed_theta_pct",
        "tp", "fp", "fn", "tn", "n_attack_windows", "n_benign_windows",
    ]
    parity = {
        "committed_results_json": os.path.relpath(COMMITTED_RESULTS_JSON, HERE),
        "regenerated_results_json": os.path.basename(REGEN_RESULTS_JSON),
        "aggregate_identical": committed["aggregate"] == regen["aggregate"],
        "non_headline_diffs": {
            k: ({"committed": committed["aggregate"][k],
                 "regenerated": regen["aggregate"].get(k)}
                if not isinstance(committed["aggregate"][k], str)
                else "documentation string differs (content omitted)")
            for k in committed["aggregate"]
            if committed["aggregate"][k] != regen["aggregate"].get(k)
        },
        "non_headline_diff_note": "the IP-clustered bootstrap CIs resample per-IP "
                                  "units in list order, which depends on set-"
                                  "iteration order (PYTHONHASHSEED) and can move "
                                  "the CI bounds by ~0.1-0.2pp run-to-run; point "
                                  "estimates and counts are order-invariant. "
                                  "Documentation-string keys may also differ from "
                                  "the committed (release-scrubbed) JSON.",
        "headline": {k: {"committed": committed["aggregate"].get(k),
                         "regenerated": regen["aggregate"].get(k),
                         "match": committed["aggregate"].get(k) == regen["aggregate"].get(k)}
                     for k in headline_keys},
        "n_uninvolved_ips": {"committed": committed["metadata"]["n_uninvolved_ips"],
                             "regenerated": len(pool)},
        "n_victim_ips": {"committed": committed["metadata"]["n_victim_ips"],
                         "regenerated": len(victims)},
    }
    print(f"[audit] parity: aggregate identical to committed = {parity['aggregate_identical']}")

    # ---- Phase 2: pool composition over the Friday test slice.
    t_atk_dt = base.epoch_to_dt(t_attack_start)
    per_ip_rows = []
    n_window_mismatch = 0
    for r in pool:
        ip = r["dst_ip"]
        rows = friday_per_ip[ip]
        test = [w for w in rows if w["_dt"] >= t_atk_dt]
        n_atk = sum(1 for w in test if w.get("_is_attack"))
        if len(test) != r["test_windows"] or n_atk != 0 or \
                r["fp_p"] + r["tn_p"] != r["test_windows"]:
            n_window_mismatch += 1
        nt = max(len(test), 1)
        mean_pps = sum(w.get("packets_per_sec", 0.0) for w in test) / nt
        mean_bps = sum(w.get("bytes_per_sec", 0.0) for w in test) / nt
        mean_tcp = sum(w.get("tcp_ratio", 0.0) for w in test) / nt
        mean_udp = sum(w.get("udp_ratio", 0.0) for w in test) / nt
        mean_udp_ports = sum(w.get("unique_dst_ports", 0.0) for w in test) / nt
        if mean_tcp > 0.6:
            mix = "tcp_dominant"
        elif mean_udp > 0.6:
            mix = "udp_dominant"
        else:
            mix = "mixed"
        fpr_p = r["fp_p"] / max(r["fp_p"] + r["tn_p"], 1) * 100.0
        fpr_cal = r["fp"] / max(r["fp"] + r["tn"], 1) * 100.0
        per_ip_rows.append({
            "dst_ip": ip,
            "network_class": classify_pool_ip(ip),
            "monday_windows": r["monday_windows"],
            "test_windows": r["test_windows"],
            "mean_packets_per_sec": round(mean_pps, 3),
            "mean_bytes_per_sec": round(mean_bps, 1),
            "mean_tcp_ratio": round(mean_tcp, 4),
            "mean_udp_ratio": round(mean_udp, 4),
            "mean_unique_dst_ports": round(mean_udp_ports, 3),
            "protocol_mix": mix,
            "fp_fixed_theta": r["fp_p"],
            "fpr_fixed_theta_pct": round(fpr_p, 2),
            "fp_calibrated": r["fp"],
            "fpr_calibrated_pct": round(fpr_cal, 2),
        })
    if n_window_mismatch:
        print(f"ERROR: {n_window_mismatch} pool IPs failed test-window reconciliation; aborting.")
        sys.exit(4)

    tw = [p["test_windows"] for p in per_ip_rows]
    fprs_p = [p["fpr_fixed_theta_pct"] for p in per_ip_rows]
    mix_counts = Counter(p["protocol_mix"] for p in per_ip_rows)
    n_pool = len(per_ip_rows)

    total_fp_p = sum(p["fp_fixed_theta"] for p in per_ip_rows)
    total_fp_cal = sum(p["fp_calibrated"] for p in per_ip_rows)
    total_benign_w = sum(tw)
    n_top = int(math.ceil(0.10 * n_pool))
    top_fp_p = sum(p["fp_fixed_theta"]
                   for p in sorted(per_ip_rows, key=lambda x: x["fp_fixed_theta"],
                                   reverse=True)[:n_top])
    top_fp_cal = sum(p["fp_calibrated"]
                     for p in sorted(per_ip_rows, key=lambda x: x["fp_calibrated"],
                                     reverse=True)[:n_top])

    net_counts = Counter(p["network_class"] for p in per_ip_rows)
    pool_composition = {
        "basis": "all statistics computed over each pool IP's Friday test-slice "
                 "windows (the exact windows used for FPR accounting)",
        "n_pool_ips": n_pool,
        "total_benign_test_windows": total_benign_w,
        "network_split": {
            "n_external_internet": net_counts.get("external_internet", 0),
            "n_internal_victim_lan": net_counts.get("internal_victim_lan", 0),
            "n_testbed_infrastructure": net_counts.get("testbed_infrastructure", 0),
            "n_internal_nat": net_counts.get("internal_nat", 0),
            "non_external_pool_ips": sorted(
                p["dst_ip"] for p in per_ip_rows
                if p["network_class"] != "external_internet"),
        },
        "test_windows_per_ip": dist_summary(tw, ndigits=1, full=True),
        "mean_packets_per_sec_per_ip": dist_summary(
            [p["mean_packets_per_sec"] for p in per_ip_rows]),
        "mean_bytes_per_sec_per_ip": dist_summary(
            [p["mean_bytes_per_sec"] for p in per_ip_rows], ndigits=1),
        "protocol_mix": {
            "rule": "per-IP mean tcp_ratio > 0.6 => tcp_dominant; else mean "
                    "udp_ratio > 0.6 => udp_dominant; else mixed",
            "n_tcp_dominant": mix_counts.get("tcp_dominant", 0),
            "n_udp_dominant": mix_counts.get("udp_dominant", 0),
            "n_mixed": mix_counts.get("mixed", 0),
            "share_tcp_dominant": round(mix_counts.get("tcp_dominant", 0) / n_pool, 4),
            "share_udp_dominant": round(mix_counts.get("udp_dominant", 0) / n_pool, 4),
            "share_mixed": round(mix_counts.get("mixed", 0) / n_pool, 4),
        },
        "mean_unique_dst_ports_per_ip": dist_summary(
            [p["mean_unique_dst_ports"] for p in per_ip_rows]),
        "fixed_theta_fpr_per_ip_pct": dict(
            dist_summary(fprs_p, ndigits=2),
            n_ips_fpr_gt_50pct=sum(1 for v in fprs_p if v > 50.0),
            share_ips_fpr_gt_50pct=round(sum(1 for v in fprs_p if v > 50.0) / n_pool, 4),
            n_ips_zero_fp=sum(1 for p in per_ip_rows if p["fp_fixed_theta"] == 0),
            share_ips_zero_fp=round(
                sum(1 for p in per_ip_rows if p["fp_fixed_theta"] == 0) / n_pool, 4),
        ),
        "fp_concentration": {
            "definition": "share of total pool FP windows contributed by the top "
                          "10% of pool IPs ranked by FP-window count",
            "n_top_ips": n_top,
            "total_fp_windows_fixed_theta": total_fp_p,
            "top10pct_share_fixed_theta": round(top_fp_p / max(total_fp_p, 1), 4),
            "total_fp_windows_calibrated": total_fp_cal,
            "top10pct_share_calibrated": round(top_fp_cal / max(total_fp_cal, 1), 4),
        },
        "pooled_fixed_theta_fpr_pct_recomputed": round(
            total_fp_p / max(total_benign_w, 1) * 100.0, 1),
        "per_ip": sorted(per_ip_rows, key=lambda x: x["fp_fixed_theta"], reverse=True),
    }
    print(f"[audit] pool composition done: {n_pool} IPs, "
          f"{total_benign_w} benign test windows, "
          f"pooled fixed-theta FPR recomputed = "
          f"{pool_composition['pooled_fixed_theta_fpr_pct_recomputed']}%")

    pool_ips = frozenset(p["dst_ip"] for p in per_ip_rows)

    # Free the big caches before streaming ~1.2 GB of CSVs.
    base.LAST_FRIDAY_PER_IP = None
    base.LAST_PER_IP_RESULTS = None
    friday_per_ip = None
    results = None
    victims = None
    pool = None
    gc.collect()

    # ---- Phase 3: label cross-check over all eight labeled flow CSVs.
    csv_reports = []
    for name in WEEK_CSVS:
        path = os.path.join(TRAFFIC_LABELLING_DIR, name)
        print(f"[audit] scanning {name} ...")
        rep = scan_labelled_csv(path, pool_ips, name in FRIDAY_CSVS, t_attack_start)
        print(f"         rows={rep['n_rows']:,} nonbenign={rep['n_nonbenign_rows']:,} "
              f"pool-hit flows={rep['pool_hits']['n_flows']}")
        csv_reports.append(rep)

    # Timezone sanity: last DDoS-labeled CSV flow start vs last attack-labeled
    # pcap window. Both should coincide (LOIC stops at the same instant).
    ddos_rep = next(r for r in csv_reports
                    if r["csv"].endswith("DDos.pcap_ISCX.csv"))
    tz_check = {
        "assumed_local_clock": "ADT (UTC-3); CSV hours 1-7 normalized to PM",
        "ddos_csv_first_attack_flow_local": datetime.fromtimestamp(
            ddos_rep["_ddos_ts_min_epoch_est"], LOCAL_TZ).isoformat(),
        "ddos_csv_last_attack_flow_local": datetime.fromtimestamp(
            ddos_rep["_ddos_ts_max_epoch_est"], LOCAL_TZ).isoformat(),
        "last_attack_window_epoch": t_attack_end,
        "last_ddos_csv_flow_epoch_est": ddos_rep["_ddos_ts_max_epoch_est"],
        "offset_last_flow_vs_last_window_sec": round(
            t_attack_end - ddos_rep["_ddos_ts_max_epoch_est"], 1),
    }
    for r in csv_reports:
        r.pop("_ddos_ts_min_epoch_est", None)
        r.pop("_ddos_ts_max_epoch_est", None)
    if abs(tz_check["offset_last_flow_vs_last_window_sec"]) > 120:
        print(f"ERROR: timezone sanity check failed "
              f"({tz_check['offset_last_flow_vs_last_window_sec']}s); aborting.")
        sys.exit(5)

    friday_reports = [r for r in csv_reports if r["csv"] in FRIDAY_CSVS]
    all_hit_src = set()
    all_hit_dst = set()
    for r in csv_reports:
        all_hit_src.update(r["pool_hits"]["pool_ips_as_src"])
        all_hit_dst.update(r["pool_hits"]["pool_ips_as_dst"])
    cross_totals = {
        "n_pool_ips_with_any_nonbenign_appearance_all8": len(all_hit_src | all_hit_dst),
        "n_pool_ips_with_any_nonbenign_appearance_friday": len(
            set().union(*[set(r["pool_hits"]["pool_ips_as_src"])
                          | set(r["pool_hits"]["pool_ips_as_dst"])
                          for r in friday_reports])),
        "n_nonbenign_pool_flows_all8": sum(
            r["pool_hits"]["n_flows"] for r in csv_reports),
        "n_nonbenign_pool_flows_friday": sum(
            r["pool_hits"]["n_flows"] for r in friday_reports),
        "n_in_friday_test_slice_start_based": sum(
            r["pool_hits"].get("n_in_test_slice_start_based", 0)
            for r in friday_reports),
        "n_in_friday_test_slice_duration_extended": sum(
            r["pool_hits"].get("n_in_test_slice_duration_extended", 0)
            for r in friday_reports),
        "pool_ips_with_nonbenign_appearance": sorted(all_hit_src | all_hit_dst),
    }

    # Impact of the flagged IPs on the pooled fixed-theta FPR floor: does the
    # 530-IP headline move if the (potentially label-contaminated) IPs are
    # excluded from FPR accounting entirely?
    per_ip_by_ip = {p["dst_ip"]: p for p in per_ip_rows}
    friday_affected = set()
    for r in friday_reports:
        for ip, v in r.get("per_pool_ip", {}).items():
            if v["n_in_test_slice"] > 0:
                friday_affected.add(ip)

    def exclusion_impact(subset_ips):
        sub = [per_ip_by_ip[ip] for ip in subset_ips if ip in per_ip_by_ip]
        fp = sum(p["fp_fixed_theta"] for p in sub)
        bw = sum(p["test_windows"] for p in sub)
        rest_fp = total_fp_p - fp
        rest_w = total_benign_w - bw
        return {
            "n_ips_excluded": len(sub),
            "ips_excluded": sorted(p["dst_ip"] for p in sub),
            "their_benign_test_windows": bw,
            "their_fp_windows_fixed_theta": fp,
            "their_share_of_pool_fp_fixed_theta": round(fp / max(total_fp_p, 1), 4),
            "pool_fpr_fixed_theta_pct_after_exclusion": round(
                rest_fp / max(rest_w, 1) * 100.0, 1),
        }

    contamination_impact = {
        "definition": "pooled fixed-theta FPR over the remaining pool IPs after "
                      "removing flagged IPs (their FP and benign-window counts "
                      "subtracted from both numerator and denominator)",
        "pool_fpr_fixed_theta_pct_all_pool_ips": round(
            total_fp_p / max(total_benign_w, 1) * 100.0, 1),
        "excluding_ips_with_in_slice_nonbenign_friday_flows": exclusion_impact(
            friday_affected),
        "excluding_ips_with_any_nonbenign_appearance_all8": exclusion_impact(
            all_hit_src | all_hit_dst),
    }

    # ---- Assemble + write the artifact.
    artifact = {
        "metadata": {
            "artifact": "cicids2017_pool_characterization",
            "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "generator_script": "run_cicids2017_pool_audit.py",
            "runner_reused": "run_cicids2017_pcap.py (driven end-to-end; "
                             "pool selected by its own eligibility code, not a fork)",
            "dataset": "CIC-IDS-2017 (pcap-based, per-IP, cross-day Monday->Friday)",
            "parent_results_json": "results/cicids2017_pcap_results.json",
            "pool_gates_verbatim": {
                "eligible": "dst_ip present in BOTH Monday and Friday caches AND "
                            ">= 60 windows on Monday AND >= 60 windows on Friday "
                            "(MIN_ROWS_PER_IP = 60)",
                "evaluated": ">= 5 Friday test windows, where test windows are all "
                             "windows with epoch >= first attack-labeled window",
                "uninvolved_pool": "0 attack-labeled test windows AND >= 30 benign "
                                   "test windows",
                "victim": ">= 30 attack-labeled test windows "
                          "(MIN_ATTACK_WINDOWS_FOR_DR = 30)",
            },
            "n_victim_ips": 1,
            "victim_ip": EXPECTED_VICTIM_IP,
            "n_uninvolved_pool_ips": n_pool,
            "window_label_source": "CSVs/TimestampedFlows/Friday-WorkingHours-"
                                   "Afternoon-DDos.pcap_ISCX.csv, 5-tuple-matched to "
                                   "Friday pcap packets; the Friday PortScan and "
                                   "Friday-Morning (Botnet) CSVs are never consulted "
                                   "for window labels (that gap is what the label "
                                   "cross-check below closes)",
            "ddos_csv_variants_note": "TimestampedFlows/ and 'TrafficLabelling /' "
                                      "copies of the Friday DDoS CSV are byte-"
                                      "identical (sha256 1f779b4f0d78f9225554c4de53b"
                                      "5a2c07912b60dcd136ee4c5c1d0d2496b7cc4)",
            "pool_provenance_note": "Pool membership is generator-driven: the pool "
                                    "is predominantly external Internet destinations "
                                    "contacted by the CIC-IDS-2017 B-Profile benign "
                                    "traffic generator, plus a minority of internal "
                                    "testbed hosts that also receive traffic on both "
                                    "days (measured breakdown in pool_composition."
                                    "network_split). The corpus ships no per-IP "
                                    "generator metadata, so composition can only be "
                                    "characterized empirically, as done here; the "
                                    "generator-driven character of B-Profile "
                                    "destinations is a documented property of the "
                                    "dataset, not a measurement.",
            "test_slice": {
                "t_attack_start_epoch": t_attack_start,
                "t_attack_end_epoch": t_attack_end,
                "definition": "test windows = all Friday windows with epoch >= "
                              "t_attack_start (first attack-labeled window); FPR is "
                              "accounted over benign test windows only",
                "note": "t_attack_start precedes the documented LOIC start because "
                        "5-tuple label matching marks every packet of any 5-tuple "
                        "that ever carried an attack-labeled flow; see tz_sanity for "
                        "the wall-clock anchoring",
            },
            "percentile_method": "linear interpolation between order statistics",
        },
        "parity_check": parity,
        "pool_composition": pool_composition,
        "label_cross_check": {
            "method": "streamed all eight GeneratedLabelledFlows CSVs "
                      "(TrafficLabelling variant: the only released CSVs carrying "
                      "Source IP / Destination IP columns); every row with a "
                      "non-BENIGN Label was tested for a pool IP in the Source IP "
                      "or Destination IP field; for Friday CSVs each hit was also "
                      "placed relative to the Friday test slice (start-based: flow "
                      "start >= t_attack_start; duration-extended: flow start + "
                      "Flow Duration >= t_attack_start)",
            "role_note": "flow-level src/dst role is reported for completeness; "
                         "packets of a bidirectional flow land in the per-dst_ip "
                         "windows of BOTH endpoints, so any flagged flow can "
                         "contaminate the pool IP's windows regardless of role",
            "tz_sanity": tz_check,
            "csvs_scanned": csv_reports,
            "totals": cross_totals,
            "contamination_impact": contamination_impact,
        },
        "runtime_sec": round(time.time() - t0, 1),
    }
    with open(ARTIFACT_JSON, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"\n[audit] saved: {ARTIFACT_JSON}")
    print(f"[audit] total runtime: {artifact['runtime_sec']}s")


if __name__ == "__main__":
    main()
