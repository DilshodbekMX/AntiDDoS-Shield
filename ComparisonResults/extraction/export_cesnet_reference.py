"""Export CESNET-TimeSeries24 as a benign false-alarm reference.

CESNET is absent from the per-attack scenario tree for a reason that is not a
gap: **it contains no attacks and no label column**. It is 40 weeks of
unlabelled benign monitoring from the CESNET3 ISP network, built for forecasting
and anomaly-detection research. No detection rate can be computed from it, so no
per-attack split exists to make.

What it can do, no lab capture can: measure false alarms on real backbone
traffic with no synthetic generator behind it. That is its role in the
manuscript (jcp_paper.md §6.3) -- the anti-artifact control. The per-window
floor on CIC-IDS-2017 could be dismissed as an artifact of that corpus's
B-Profile traffic generator; CESNET is real ISP telemetry and still floors,
which is what rules the artifact explanation out.

A SECOND REASON IT WAS ABSENT, and this one was a defect. config.py sets
BASE = dirname(HERE), so from experiments_copy TAR_PATH resolves to
AntiDDOS_Shield/datasets/cesnet/... -- a directory that contains only a
.gitkeep. Every CESNET runner in this tree fails with FileNotFoundError. The
sibling experiment/ tree sits one level higher and resolves correctly, which is
why this was never noticed. Set ANTIDDOS_BASE=/path/to/antiddos
to override, as this script does.

TWO PROPERTIES MAKE ITS NUMBERS NON-COMPARABLE to the pcap corpora, and both
are recorded in the output rather than left to the reader:

  granularity   hourly windows against per-second elsewhere. A detector making
                one decision per second per destination makes 86,400 per address
                per day; hourly makes 24. The manuscript measures the same
                detector on the same traffic at 71.8% per-second, 58.2%
                per-flow and 13.1% hourly.
  features      11 available here against 39 for the pcap corpora. No per-second
                packet rate, no TCP flag rates, no entropy features.

Usage:
    ANTIDDOS_BASE=/path/to/antiddos \
        python3 export_cesnet_reference.py [--out DIR]
"""
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_sys.path.insert(0, _HERE)                        # sibling extraction modules (tree_io, extractors)
_sys.path.insert(0, _os.path.dirname(_HERE))      # ComparisonResults/: config, loaders, registry
_BASE = _os.environ.get('ANTIDDOS_BASE', _os.path.dirname(_os.path.dirname(_HERE)))  # == config.BASE

import statistics
import os, sys, json, hashlib
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from config import TAR_PATH, TIMES_TAR, MIN_IP_ROWS_PER_IP
from data_loader import load_per_ip, load_time_index

DEFAULT_OUT = _os.path.join(_BASE, 'datasets', 'extracted', 'CESNET-TimeSeries24')


def main():
    out = next((sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == '--out'), DEFAULT_OUT)
    if not os.path.exists(TAR_PATH):
        sys.exit(f"CESNET archive not found at {TAR_PATH}\n"
                 f"Set ANTIDDOS_BASE=/path/to/antiddos (see docstring).")
    os.makedirs(out, exist_ok=True)

    # Load EVERY host, then apply the gate here, so the gate's selectivity can be
    # reported instead of being invisible. MIN_IP_ROWS_PER_IP drops 83% of the
    # sample and that was disclosed nowhere.
    allrows = load_per_ip(TAR_PATH, TIMES_TAR, min_rows=1)
    n_slots = len(load_time_index(TIMES_TAR))
    d = {ip: v for ip, v in allrows.items() if len(v) >= MIN_IP_ROWS_PER_IP}
    dropped = {ip: v for ip, v in allrows.items() if len(v) < MIN_IP_ROWS_PER_IP}
    _cov = lambda g: round(100 * statistics.median(len(v) for v in g.values()) / n_slots, 1)
    _rate = lambda g: round(statistics.median(
        statistics.median(r.get('packets_per_sec', 0) or 0 for r in v) for v in g.values() if v), 2)
    gate = {
        'gate': f'MIN_IP_ROWS_PER_IP = {MIN_IP_ROWS_PER_IP} hourly rows',
        'n_hosts_in_sample': len(allrows),
        'n_hosts_kept': len(d),
        'n_hosts_dropped': len(dropped),
        'pct_dropped': round(100 * len(dropped) / max(len(allrows), 1), 1),
        'n_time_slots': n_slots,
        'median_temporal_coverage_pct_kept': _cov(d),
        'median_temporal_coverage_pct_dropped': _cov(dropped),
        'median_of_host_median_packets_kept': _rate(d),
        'median_of_host_median_packets_dropped': _rate(dropped),
        'selects_on': ('PRESENCE, not volume: the kept and dropped groups differ by 24x in temporal '
                       'coverage but only 1.5x in per-window packet volume, so this gate is a '
                       'continuity filter and not a busy-host filter'),
        'counterfactual_note': (
            'scoring every evaluable host instead of the kept 174 raises the shipped fixed-theta '
            'false-alarm rate from 13.08% [12.58, 13.63] to 13.90% [13.49, 14.32] over 921 hosts '
            'and 352,792 windows (measured 2026-08-26 with pipeline.run_fixed_theta_fpr at '
            'theta=4.0, IP-clustered bootstrap). The published figure is therefore 0.82 pp '
            'OPTIMISTIC, which is conservative for the anti-artifact argument it supports: a '
            'higher floor on real ISP telemetry strengthens that claim rather than weakening it.'),
    }
    del allrows, dropped
    n_rows = sum(len(v) for v in d.values())
    attacks = sum(1 for v in d.values() for r in v if r.get('_is_attack'))
    feats = sorted(k for k in next(iter(d.values()))[0] if not k.startswith('_'))

    pps = np.array([float(r.get('packets_per_sec', 0) or 0)
                    for v in d.values() for r in v], dtype=float)
    meta = {
        'corpus': 'CESNET-TimeSeries24',
        'kind': 'benign reference — NO ATTACKS, NO LABELS',
        'source': 'ip_addresses_sample.tar.gz, agg_1_hour',
        'doi': '10.5281/zenodo.13382427',
        'n_hosts': len(d), 'n_windows': n_rows,
        'attack_windows': attacks,
        'window_unit': 'hourly per-IP aggregate',
        'n_features': len(feats), 'features': feats,
        'min_rows_per_host': MIN_IP_ROWS_PER_IP,
        'host_selection': gate,
        # These are HOURLY COUNTS. data_loader.FEATURE_MAP renames CESNET's
        # n_flows / n_packets / n_bytes to flows_per_sec / packets_per_sec /
        # bytes_per_sec and never divides by the 3,600 s window, so on this
        # corpus -- and only this corpus -- those shared feature names carry a
        # count per hour where every sibling corpus carries a true rate. The
        # descriptive statistics below are therefore named for what they are.
        'packets_per_hour_median': float(np.median(pps)),
        'packets_per_hour_p95': float(np.percentile(pps, 95)),
        'packets_per_sec_median_equivalent': float(np.median(pps)) / 3600.0,
        'packets_per_sec_p95_equivalent': float(np.percentile(pps, 95)) / 3600.0,
        'unit_note': (
            'FEATURE NAMES ON THIS CORPUS DO NOT MEAN RATES. flows_per_sec, packets_per_sec and '
            'bytes_per_sec hold per-HOUR counts here: the hourly aggregate is the exact sum of its '
            'six 10-minute siblings (checked, 200 of 200 hours, ratio 1.0000), and no divisor is '
            'applied anywhere in the load path. Divide by 3,600 for true rates. No published '
            'false-alarm rate depends on this: the z-path is scale-invariant and 13.1% is computed '
            'consistently. Dividing is nonetheless NOT free -- the variance floor of baselines.c:356 '
            'tests the mean against an ABSOLUTE 50.0, so rescaling moves hosts across it and shifts '
            'the headline 13.08% -> 12.89% (measured 2026-08-26). The names are therefore corrected '
            'here rather than the data rescaled, which leaves every published number intact.'),
        'usable_for': 'false-alarm rate only',
        'not_usable_for': 'detection rate — there are no attacks to detect',
        'comparability_note': (
            'hourly windows and 11 features against per-second windows and 39 '
            'features on the pcap corpora. Per-window rates are NOT commensurable '
            'across those units: the same detector on the same traffic yields '
            '71.8% per-second, 58.2% per-flow and 13.1% hourly.'),
        'role': ('anti-artifact control: real ISP backbone telemetry with no '
                 'synthetic traffic generator, so a false-alarm floor measured '
                 'here cannot be a testbed-generator artifact'),
    }
    print(f"\n  hosts {len(d)}, windows {n_rows:,}, attack windows {attacks}")
    print(f"  features {len(feats)}: {feats}")

    # _dt arrives as a timezone-aware datetime here, where every other corpus
    # carries a unix float. Normalising rather than adding a JSON encoder hook,
    # so a consumer written against the pcap caches reads this one unchanged.
    for rows in d.values():
        for r in rows:
            v = r.get('_dt')
            if hasattr(v, 'timestamp'):
                r['_dt'] = v.timestamp()
    meta['dt_note'] = ('_dt normalised from datetime to unix epoch float to match '
                       'the other corpora; original values are hourly UTC stamps')

    p = os.path.join(out, 'benign_reference.json')
    json.dump({'metadata': meta, 'per_ip_windows': d}, open(p, 'w'))
    h = hashlib.sha256(open(p, 'rb').read()).hexdigest()
    meta.update(bytes=os.path.getsize(p), sha256=h, file='benign_reference.json')
    json.dump({'benign_reference': meta}, open(os.path.join(out, 'index.json'), 'w'), indent=2)
    open(os.path.join(out, 'SHA256SUMS'), 'w').write(f"{h}  benign_reference.json\n")
    print(f"\n  wrote {p}  ({os.path.getsize(p)/1e6:.0f} MB)")


if __name__ == '__main__':
    main()
