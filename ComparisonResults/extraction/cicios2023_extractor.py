"""CIC-IoT-2023 pcap -> per-(dst_ip, 1-second) feature extractor.

Reuses the canonical `WindowAggregator` + `parse_pcap_file` from
pcap_feature_extractor.py. Labels are inferred from the pcap's parent
directory (monothematic-pcap convention: every packet in `PCAP/<family>/*.pcap`
is attack-class `<family>`; every packet in `PCAP/Benign_Final/*.pcap` is
benign). No CSV 5-tuple join -- the CSVs ship without IPs or timestamps, so
they cannot be reconciled to pcap packets; we use the canonical CIC-IoT-2023
labeling convention instead.

Usage:
    python3 cicios2023_extractor.py <pcap_dir> <label> <output_json>

    <label> = 'benign' for Benign_Final, or the attack family name
              (e.g. 'DDoS-SYN_Flood') for any attack pcap directory.

Output schema (per (dst_ip, 1-second)):
    Same 23-feature row schema produced by pcap_feature_extractor.py,
    plus `_is_attack` (bool) and `_attack_type` (str) for every row.
"""
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_sys.path.insert(0, _HERE)                        # sibling extraction modules (tree_io, extractors)
_sys.path.insert(0, _os.path.dirname(_HERE))      # ComparisonResults/: config, loaders, registry
_BASE = _os.environ.get('ANTIDDOS_BASE', _os.path.dirname(_os.path.dirname(_HERE)))  # == config.BASE

import os, sys, json, glob, time
sys.path.insert(0, os.path.dirname(__file__))

# Optional CIC_IOS_CAP env var to tighten the per-window Counter/set caps before
# importing CappedWindowAggregator. CIC-IoT-2023's TCP-flag attack families
# (PSHACK_Flood, RSTFINFlood, SYN_Flood, SynonymousIP_Flood, TCP_Flood) emit
# random source ports -> highly diverse 5-tuple flows -> ~5,000 unique flows per
# (dst_ip, sec) window. At the default 50K cap, the `flows` set holds ~50K x 120B
# tuples x 35K windows ~= 200 GB worst case. CIC_IOS_CAP=5000 saturates at 5K
# entries per container, keeping RAM tractable while still recording cardinality
# >> normal benign rates.
_CAP_OVERRIDE = int(os.environ.get('CIC_IOS_CAP', '0'))
if _CAP_OVERRIDE > 0:
    import pcap_feature_extractor_cicids2018 as _cicids
    _cicids.COUNTER_CAP = _CAP_OVERRIDE
    _cicids.SET_CAP = _CAP_OVERRIDE

# Use the CIC-IDS-2018 capped variant: bounds per-window src_ips / src_ports /
# dst_ports / flows at COUNTER_CAP / SET_CAP unique entries.
from pcap_feature_extractor import parse_pcap_file
from pcap_feature_extractor_cicids2018 import CappedWindowAggregator as WindowAggregator
from pcap_feature_extractor_cicids2018 import COUNTER_CAP, SET_CAP


def main():
    if len(sys.argv) < 4:
        print("Usage: cicios2023_extractor.py <pcap_dir> <label> <output_json> [max_files]")
        print("  <label> = 'benign' or attack family name (e.g. 'DDoS-SYN_Flood')")
        sys.exit(1)

    pcap_dir = sys.argv[1]
    label = sys.argv[2]
    output_json = sys.argv[3]
    max_files = int(sys.argv[4]) if len(sys.argv) > 4 else None

    is_attack = (label != 'benign')

    print(f"=== CIC-IoT-2023 Feature Extraction ===")
    print(f"PCAP dir: {pcap_dir}")
    print(f"Label:    {label}  (is_attack={is_attack})")
    print(f"Output:   {output_json}")
    print(f"Caps:     COUNTER_CAP={COUNTER_CAP}, SET_CAP={SET_CAP}  "
          f"(CIC_IOS_CAP env: {os.environ.get('CIC_IOS_CAP', '(unset → default 50000)')})")

    t0_full = time.time()

    pcap_files = sorted(glob.glob(os.path.join(pcap_dir, "*.pcap")))
    if max_files:
        pcap_files = pcap_files[:max_files]
    print(f"\nFound {len(pcap_files)} pcap files")
    if not pcap_files:
        print("  ERROR: no pcap files found")
        sys.exit(1)

    aggregator = WindowAggregator()
    total_pkts = 0
    total_skipped = 0
    n_pcaps_failed = 0
    for i, pcap_path in enumerate(pcap_files):
        t0 = time.time()
        # parse_pcap_file with flow_labels=None -> every packet is_attack=False
        # at the aggregator level; we override after finalize() so all windows
        # get the directory-derived label.
        try:
            n, sk = parse_pcap_file(pcap_path, aggregator, flow_labels=None)
        except Exception as e:
            # Skip pcaps that dpkt can't parse (e.g. malformed TCP options in
            # CIC-IoT-2023's TCP-flag attack families). Logged + counted but
            # does not crash the whole family extraction.
            n_pcaps_failed += 1
            print(f"  [{i+1}/{len(pcap_files)}] FAIL {os.path.basename(pcap_path)} "
                  f"-> {type(e).__name__}: {e}", flush=True)
            continue
        total_pkts += n
        total_skipped += sk
        elapsed = time.time() - t0
        cumul_pcap_size_mb = sum(os.path.getsize(p) for p in pcap_files[:i+1]) / 1e6
        print(f"  [{i+1}/{len(pcap_files)}] {os.path.basename(pcap_path)} "
              f"-> {n:,} pkts in {elapsed:.1f}s "
              f"(cumul: {total_pkts:,} pkts, {len(aggregator.windows):,} (dst_ip,sec) windows, "
              f"{cumul_pcap_size_mb:.0f} MB pcap read)", flush=True)

    print(f"\nTotal: {total_pkts:,} packets parsed, {total_skipped:,} skipped")
    print(f"Finalizing aggregator (computing 23 features per window)...")
    per_ip_windows = aggregator.finalize()

    # Apply directory-derived label to every window
    n_windows_total = 0
    for dst_ip, rows in per_ip_windows.items():
        for r in rows:
            r['_is_attack'] = is_attack
            r['_attack_type'] = label
            n_windows_total += 1

    # Concise per-IP summary
    print(f"\nProduced {len(per_ip_windows)} dst_ips, {n_windows_total} total windows:")
    top = sorted(per_ip_windows.items(), key=lambda kv: -len(kv[1]))[:10]
    for dst_ip, rows in top:
        print(f"  {dst_ip:18s}: {len(rows):>7,} windows")
    if len(per_ip_windows) > 10:
        print(f"  ... ({len(per_ip_windows) - 10} more IPs)")

    out = {
        'metadata': {
            'source': pcap_dir,
            'label': label,
            'is_attack': is_attack,
            'pcap_files': len(pcap_files),
            'total_packets': total_pkts,
            'total_skipped': total_skipped,
            'n_dst_ips': len(per_ip_windows),
            'n_windows': n_windows_total,
            'runtime_s': round(time.time() - t0_full, 1),
            'feature_count': 23,
        },
        'per_ip_windows': per_ip_windows,
    }

    os.makedirs(os.path.dirname(output_json), exist_ok=True)
    with open(output_json, 'w') as f:
        json.dump(out, f, indent=None, default=str)
    print(f"\nSaved: {output_json}  (runtime: {time.time()-t0_full:.0f}s)")


if __name__ == '__main__':
    main()
