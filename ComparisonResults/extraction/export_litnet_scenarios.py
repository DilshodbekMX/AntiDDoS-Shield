"""Export LITNET-2020 per-attack scenarios.

No extraction and no schedule: litnet_loader.py already records _attack_type per
window from the corpus's own flow labels, so this is selection only.

WHAT LITNET ACTUALLY CONTAINS, which is less than its three-scenario presence in
the panel suggests. Four attack types have any host with >= 30 attack windows:

    http_flood      1 host    360 windows
    code_red_worm   1 host    345
    smurf           1 host    299
    syn_flood   15,335 hosts  ~175 each

syn_flood is DISTRIBUTED -- it is the carpet-bomb case. No single host carries
enough of it to evaluate, which is why it has never appeared in the panel
despite being the corpus's largest attack by far.

It is not recoverable by aggregating either. At /24 the attack is QUIETER than
the zone's own benign traffic: p95 1,060 against 51,370 packets/s, a ratio of
0.02. That was checked across all 39 features, not just volume, in case flag
composition carried the signal instead -- the most discriminative feature is
icmp_ratio at 1.6x, still under the 2x distinguishability bar. At /16 it is
0.3-0.5x. So the dilution is complete at every aggregation scale available here.

Of the three concentrated attacks, one is cleanly usable:

    code_red_worm   volumetric, 798.8x its own benign p95        USABLE
    smurf           volumetric, 89.6x, but n_test_benign = 0     DR ONLY
    http_flood      1.1x -- indistinguishable from benign        UNUSABLE

smurf's attack runs to the end of the capture, so no benign traffic follows the
onset and its false-positive rate is undefined rather than zero -- the same
failure mode as CIC-IDS-2018 Tuesday LOIC-UDP.

Usage: python3 export_litnet_scenarios.py [--out DIR] [--dry-run]
"""
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_sys.path.insert(0, _HERE)                        # sibling extraction modules (tree_io, extractors)
_sys.path.insert(0, _os.path.dirname(_HERE))      # ComparisonResults/: config, loaders, registry
_BASE = _os.environ.get('ANTIDDOS_BASE', _os.path.dirname(_os.path.dirname(_HERE)))  # == config.BASE

import os, sys, json, gc, hashlib
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, 'negatives'))
from config import CACHE_DIR
from tree_io import within_split

DEFAULT_OUT = _os.path.join(_BASE, 'datasets', 'extracted', 'LITNET-2020')
# udp_f was absent from every previous LITNET analysis: allFlows.csv had been
# extracted 11.5% short and that attack type lay entirely in the missing tail
# (CHANGE 188). Rebuilt from the complete file it is the corpus's fourth
# concentrated attack, 301 windows on 193.219.81.137.
VICTIMS = {'code_red_worm': '193.219.81.138',
           'smurf':         '193.219.88.36',
           'http_flood':    '23.32.104.60',
           'udp_f':         '193.219.81.137'}


def p95(rows, f='packets_per_sec'):
    v = [float(r.get(f, 0) or 0) for r in rows]
    return float(np.percentile(v, 95)) if v else 0.0


def main():
    dry = '--dry-run' in sys.argv
    out = next((sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == '--out'), DEFAULT_OUT)
    d = json.load(open(os.path.join(CACHE_DIR, 'litnet_per_ip_cache.json')))
    d = d.get('per_ip_windows', d)
    if not dry:
        os.makedirs(out, exist_ok=True)
    idx, lines = {}, []
    print(f"  {'attack':16s} {'victim':17s} {'n_atk':>6s} {'n_cal':>6s} {'n_ben_t':>8s} "
          f"{'ratio':>8s}  verdict")
    print("  " + "-" * 86)
    for atk, v in VICTIMS.items():
        rows = sorted(d.get(v, []), key=lambda r: r.get('_dt', 0))
        # this attack's windows plus every fully-benign window of the same host
        sel = [r for r in rows
               if (not r.get('_is_attack')) or r.get('_attack_type') == atk]
        a = [r for r in sel if r.get('_is_attack')]
        b = [r for r in sel if not r.get('_is_attack')]
        if not a or not b:
            print(f"  {atk:16s} {v:17s} no rows"); continue
        ap, bp = p95(a), p95(b)
        ratio = ap / bp if bp else float('inf')
        cls = 'INDISTINCT' if ratio < 2 else ('VOLUMETRIC' if ap >= 100 else 'LOW-RATE')
        fit, cal, tb, ta = within_split(sel)
        n_cal = len(cal) if cal else 0
        n_tb = len(tb) if tb else 0
        fpr_ok = n_tb >= 5
        usable = (cls != 'INDISTINCT') and fpr_ok
        note = cls if fpr_ok else f'{cls}, FPR UNDEFINED (n_test_benign=0)'
        print(f"  {atk:16s} {v:17s} {len(a):6d} {n_cal:6d} {n_tb:8d} {ratio:7.1f}x  "
              f"{'USABLE -- ' if usable else ''}{note}")
        if dry:
            continue
        name = f"{atk}.json"
        meta = {'corpus': 'LITNET-2020', 'attack_type': atk, 'victim': v,
                'derived_from': 'litnet_per_ip_cache.json',
                'label_source': 'corpus flow labels via litnet_loader.py (no schedule)',
                'n_attack_windows': len(a), 'n_benign_windows': len(b),
                'n_calib': n_cal, 'n_benign_test': n_tb,
                'p95_packets_per_sec': ap, 'benign_p95_packets_per_sec': bp,
                'attack_to_benign_p95_ratio': round(ratio, 2), 'intensity_class': cls,
                'fpr_measurable': bool(fpr_ok),
                'usable_as_ddos_scenario': bool(usable)}
        if not fpr_ok:
            meta['fpr_note'] = ('attack runs to capture end, so no benign traffic '
                                'follows onset: FPR is undefined, not zero')
        p = os.path.join(out, name)
        json.dump({'metadata': meta,
                   'per_ip_windows': {v: sorted(b + a, key=lambda r: r.get('_dt', 0))}},
                  open(p, 'w'))
        h = hashlib.sha256(open(p, 'rb').read()).hexdigest()
        meta.update(bytes=os.path.getsize(p), sha256=h, file=name)
        idx[atk] = meta
        lines.append(f"{h}  {name}")
    del d; gc.collect()
    if dry:
        print("\nDRY RUN"); return
    open(os.path.join(out, 'SHA256SUMS'), 'w').write('\n'.join(sorted(lines)) + '\n')
    json.dump(idx, open(os.path.join(out, 'index.json'), 'w'), indent=2)
    n = sum(1 for m in idx.values() if m['usable_as_ddos_scenario'])
    print(f"\n  wrote {len(idx)} scenarios to {out}; {n} usable as DDoS scenarios")


if __name__ == '__main__':
    main()
