"""Materialise the CIC-IoT-2023 per-family scenarios as standalone caches.

The other corpora needed splitting because one cache held several attacks.
CIC-IoT is the opposite: each family already has its own capture and its own
cache, but a cache holds every destination IP in the testbed, and the scenario
is one victim. So the work here is selection and materialisation rather than
splitting -- pull the chosen victim's benign windows from the shared benign
cache and its attack windows from the family cache, and write the pair as one
self-contained file.

VICTIM RULE (same as PANEL.json, and it is not optional). CIC-IoT labels every
window of a family capture as attack -- cicios2023_extractor.py:107-112 applies
a directory-derived label -- so ranking candidates by attack-window count picks
whichever host merely appears most often. That selects 8.8.8.8, AWS and GCP
addresses, whose "attack" rows are ordinary traffic captured during an attack
window. The victim is instead the testbed device in 192.168.137.0/24, excluding
the gateway .1, with the most attack windows, clearing the split gates and a
max-rate floor. That rule reproduces all five of the manuscript's hand-picked
victims exactly, and matches the gate already implemented independently in
run_crosscorpus_auc.py:315.

INTENSITY IS RECORDED PER SCENARIO, because the rule above is necessary but not
sufficient. Five of the thirteen families select a victim whose attack traffic
never reaches flood rate -- p95 of 14 to 44 packets/s. They are not mislabelled;
the device simply was not meaningfully attacked in that capture. Their high
reported detection rates (58%, 62.8%, 76%) measure discrimination between two
capture sessions rather than detection of a flood, so every file carries
p95_packets_per_sec and usable_as_ddos_scenario.

MEMORY. The benign cache is 1.6 GB. It is loaded once, reduced to the victims'
rows, and freed before any family cache is opened. Do not parallelise: this
host has been OOM-killed by concurrent cache reads.

Usage: python3 export_cicios2023_scenarios.py [--out DIR] [--dry-run]
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
from config import CACHE_DIR, RESULTS_DIR
import tree_io as R

DEFAULT_OUT = _os.path.join(_BASE, 'datasets', 'extracted', 'CIC_IOT_Dataset2023')
PANEL = os.path.join(RESULTS_DIR, 'panel_inventory', 'PANEL.json')
FLOOD_P95 = 100.0


def tkey(r):
    return r.get('_id_time', r.get('_dt', 0))


def pps_stats(rows):
    v = sorted(float(r.get('packets_per_sec', 0) or 0) for r in rows)
    if not v:
        return {'median': 0.0, 'p95': 0.0, 'max': 0.0}
    return {'median': v[len(v) // 2],
            'p95': v[min(len(v) - 1, int(0.95 * len(v)))], 'max': v[-1]}


def main():
    dry = '--dry-run' in sys.argv
    out = next((sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == '--out'), DEFAULT_OUT)
    entries = [p for p in json.load(open(PANEL))['panel'] if p['mode'] == 'crossfile']
    if not entries:
        sys.exit("no crossfile scenarios in PANEL.json")
    if not dry:
        os.makedirs(out, exist_ok=True)

    victims = sorted({e['victim'] for e in entries})
    print(f"{len(entries)} families, {len(victims)} distinct victims")
    ben = R.load_perip('cicios2023_benign.json')
    ben_rows = {v: sorted([r for r in ben.get(v, []) if not r.get('_is_attack')], key=tkey)
                for v in victims}
    del ben
    gc.collect()
    print(f"benign cache reduced to {sum(len(v) for v in ben_rows.values()):,} windows and freed\n")

    idx, lines = {}, []
    print(f"  {'family':26s} {'victim':16s} {'n_atk':>6s} {'n_ben':>6s} {'p95':>8s}  verdict")
    print("  " + "-" * 80)
    for e in sorted(entries, key=lambda e: e['label']):
        fam = e['label'].replace('CIC-IoT ', '')
        v = e['victim']
        b = ben_rows.get(v, [])
        try:
            d = R.load_perip(e['cache'])
        except Exception as ex:
            print(f"  {fam:26s} cache load failed: {ex}"); continue
        a = sorted([r for r in d.get(v, []) if r.get('_is_attack')], key=tkey)
        del d
        gc.collect()
        if not a or not b:
            print(f"  {fam:26s} {v:16s} no rows"); continue
        st = pps_stats(a)
        flood = st['p95'] >= FLOOD_P95
        name = f"{fam}.json"
        meta = {'corpus': 'CIC-IoT-2023', 'attack_family': fam, 'victim': v,
                'benign_cache': 'cicios2023_benign.json', 'attack_cache': e['cache'],
                'n_attack_windows': len(a), 'n_benign_windows': len(b),
                'pps_median': st['median'], 'p95_packets_per_sec': st['p95'],
                'pps_max': st['max'], 'is_flood': bool(flood),
                'usable_as_ddos_scenario': bool(flood),
                'label_note': ('CIC-IoT labels every window of a family capture as attack '
                               '(directory-derived, cicios2023_extractor.py:107-112). '
                               '_is_attack here means "captured during this attack", not '
                               '"this window contains attack traffic".'),
                'split_note': ('benign drawn from a SEPARATE benign capture, so the '
                               'train/calibration set is not temporally adjacent to the '
                               'attack; FPR is measured within the benign capture.')}
        print(f"  {fam:26s} {v:16s} {len(a):6d} {len(b):6d} {st['p95']:8.0f}  "
              f"{'USABLE' if flood else 'NOT A FLOOD -- do not use as a DDoS scenario'}")
        if dry:
            continue
        p = os.path.join(out, name)
        json.dump({'metadata': meta,
                   'per_ip_windows': {v: sorted(b + a, key=tkey)}}, open(p, 'w'))
        h = hashlib.sha256(open(p, 'rb').read()).hexdigest()
        meta.update(bytes=os.path.getsize(p), sha256=h, file=name)
        idx[fam] = meta
        lines.append(f"{h}  {name}")

    if dry:
        print("\nDRY RUN"); return
    open(os.path.join(out, 'SHA256SUMS'), 'w').write('\n'.join(sorted(lines)) + '\n')
    json.dump(idx, open(os.path.join(out, 'index.json'), 'w'), indent=2)
    n_ok = sum(1 for m in idx.values() if m['usable_as_ddos_scenario'])
    print(f"\n  wrote {len(idx)} scenarios to {out}")
    print(f"  {n_ok} usable as DDoS scenarios, {len(idx) - n_ok} not floods")


if __name__ == '__main__':
    main()
