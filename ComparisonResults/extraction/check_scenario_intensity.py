"""Flag per-attack scenarios whose 'attack' traffic is not actually a flood.

This check exists because the same defect has now been shipped twice.

In CIC-IoT-2023 a victim was chosen by attack-window COUNT. Because that corpus
labels every window of a family capture as attack, the most-attacked host was
one receiving 2 packets/s, and a claimed +72.9 pp win over every baseline
became +2.1 pp on the correct host (CHANGE 168).

In CIC-DDoS2019 the same thing happened for a different reason: labels run
wall-to-wall, so 172.16.0.5 accumulated 7,025 "attack" windows at 12-16 pkt/s
p95 -- statistically identical to its own benign traffic. Six of twelve
published slices sat on it, and the reported mean showed a lead that reversed
once the non-floods were removed (CHANGE 184).

Both times the fix was the same p95 test. The second time, the test already
existed and simply was not run on new data. So it lives here now, corpus-
agnostic, and should be run over every new set of slices before any number is
quoted from them.

A DDoS scenario is only meaningful if the victim actually receives flood-rate
traffic. p95 rather than max, because a single burst passes a max threshold
while the host sits at background rate for the rest of the attack -- exactly
how the CIC-IoT non-victims cleared a max>=100 gate.

BUT AN ABSOLUTE RATE GATE ALONE IS WRONG, and running it over the other corpora
proved it: Slowloris and SlowHTTPTest are deliberately LOW-rate application-layer
attacks. CIC-IDS-2018 SlowHTTPTest sits at p95 40 pkt/s -- far under any flood
threshold -- but that is 5.7x its own benign p95 of 7, and it is a perfectly
real attack. Condemning it as "not a flood" would be descriptively true and
practically wrong.

So two numbers, not one:
    absolute p95      -- is this volumetric?
    p95 / benign p95  -- is it distinguishable from this host's own traffic?

VOLUMETRIC   p95 >= threshold                     a flood
LOW-RATE     p95 < threshold but >= 2x benign     real, non-volumetric (slow HTTP)
INDISTINCT   p95 < 2x benign                      unusable regardless of label

INDISTINCT is the failure that matters. CIC-DDoS2019's 172.16.0.5 sits at
1.0-1.3x its own benign p95 across all seven of its attacks; CIC-IDS-2017
Slowloris is at 0.83x -- its "attack" traffic is quieter than the host's normal
traffic. Neither can support a detection claim.

Usage:
    python3 check_scenario_intensity.py <cache-or-dir> [--p95 100]
"""
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_sys.path.insert(0, _HERE)                        # sibling extraction modules (tree_io, extractors)
_sys.path.insert(0, _os.path.dirname(_HERE))      # ComparisonResults/: config, loaders, registry
_BASE = _os.environ.get('ANTIDDOS_BASE', _os.path.dirname(_os.path.dirname(_HERE)))  # == config.BASE

import os, sys, json, glob
import numpy as np

DEFAULT_P95 = 100.0


def profile(rows):
    a = np.array([float(r.get('packets_per_sec', 0) or 0)
                  for r in rows if r.get('_is_attack')], dtype=float)
    b = np.array([float(r.get('packets_per_sec', 0) or 0)
                  for r in rows if not r.get('_is_attack')], dtype=float)
    if not a.size:
        return None
    return {'n_attack': int(a.size), 'n_benign': int(b.size),
            'atk_median': float(np.median(a)), 'atk_p95': float(np.percentile(a, 95)),
            'atk_max': float(a.max()),
            'ben_p95': float(np.percentile(b, 95)) if b.size else None}


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    target = sys.argv[1]
    thr = float(sys.argv[sys.argv.index('--p95') + 1]) if '--p95' in sys.argv else DEFAULT_P95
    files = ([target] if os.path.isfile(target)
             else sorted(glob.glob(os.path.join(target, '*.json'))))

    print(f"flood gate: attack p95 >= {thr:.0f} pkt/s\n")
    print(f"  {'scenario':40s} {'n_atk':>6s} {'med':>8s} {'p95':>10s} "
          f"{'ben p95':>8s} {'ratio':>8s}  verdict")
    print("  " + "-" * 104)
    counts = {'volumetric': 0, 'lowrate': 0, 'indistinct': 0}
    for f in files:
        base = os.path.basename(f)
        if base in ('index.json', 'SHA256SUMS'):
            continue
        try:
            d = json.load(open(f))
        except Exception:
            continue
        pw = d.get('per_ip_windows', d if isinstance(d, dict) else {})
        for victim, rows in pw.items():
            if not isinstance(rows, list):
                continue
            p = profile(rows)
            if not p:
                continue
            ratio = (p['atk_p95'] / p['ben_p95']) if p['ben_p95'] else float('inf')
            if ratio < 2.0:
                note, cls = 'INDISTINCT -- unusable', 'indistinct'
            elif p['atk_p95'] >= thr:
                note, cls = 'VOLUMETRIC', 'volumetric'
            else:
                note, cls = 'LOW-RATE (real, non-volumetric)', 'lowrate'
            counts[cls] += 1
            print(f"  {base.replace('.json',''):40s} {p['n_attack']:6d} "
                  f"{p['atk_median']:8.1f} {p['atk_p95']:10.1f} "
                  f"{(p['ben_p95'] if p['ben_p95'] is not None else -1):8.1f} "
                  f"{ratio:7.1f}x  {note}")
    print("  " + "-" * 104)
    print(f"  {counts['volumetric']} volumetric, {counts['lowrate']} low-rate, "
          f"{counts['indistinct']} INDISTINCT")
    if counts['indistinct']:
        print(f"\n  INDISTINCT scenarios carry attack traffic under 2x the SAME HOST's")
        print(f"  benign p95. They cannot support a detection claim and must not be")
        print(f"  averaged into any mean. The host is often a NAT, gateway or")
        print(f"  attacker-side address the corpus labels as attack-involved without")
        print(f"  it ever receiving the attack.")
    return 1 if counts['indistinct'] else 0


if __name__ == '__main__':
    sys.exit(main())
