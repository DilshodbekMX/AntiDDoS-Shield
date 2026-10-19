"""Script the CIC-DDoS2019 slice metadata that was written by hand.

split_cicddos_by_type.py writes ten metadata keys. The tree's twelve
CIC-DDoS2019 payloads carry more, and three groups of them had no writer:

  intensity      p95_packets_per_sec, benign_p95_packets_per_sec,
                 attack_to_benign_p95_ratio, intensity_class, floor_limited,
                 usable_as_ddos_scenario -- put into index.json by hand when the
                 p95 intensity check was first run on this corpus, and copied
                 into the payloads by hand when the tree was re-verified;
  floor reason   unusable_reason on the two floor-limited victim slices
                 (MSSQL, NetBIOS): "conformal floor exceeds alpha=0.01 (n_calib
                 too small)";
  role           on the six attacker_side/ slices: role, ground_truth_source,
                 and a first unusable_reason, typed in when the slices were
                 moved into attacker_side/.

This script writes those keys from the slices themselves, in the position the
tree has them (straight after the splitter's keys). It does not move files:
`split_cicddos_by_type.py --attacker-side` writes the attacker slices into
attacker_side/ directly. It does move any 172.16.0.5 slice it finds in the
corpus root there, which is where a count-selected split would have put them.

Later steps own some of these values and overwrite them in place, so the
result does not depend on the provisional values written here:
  - write_extracted_index.py recomputes the four intensity keys (same rule:
    check_scenario_intensity.profile + write_extracted_index.classify);
  - classify_scenarios.py --write rewrites floor_limited and
    usable_as_ddos_scenario (verdict == USABLE);
  - stamp_cicddos_roles.py replaces the attacker slices' unusable_reason with
    the direction counts it measures over all seven 03-11 CSVs.
The first attacker unusable_reason typed into the tree quoted a Syn.csv-only
count from a truncated read (see stamp_cicddos_roles.py). It is not reproduced
here; the provisional text below carries no count.

Byte-for-byte checksums of the tree's payloads still cannot be reproduced:
their key order also reflects the run order of the later writers.

    python3 stamp_cicddos_slice_metadata.py [<corpus-dir>] [--alpha 0.01] [--dry-run]

Run it after split_cicddos_by_type.py (both runs) and before
stamp_cicddos_roles.py and the first write_extracted_index.py.
"""
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_sys.path.insert(0, _HERE)                        # sibling extraction modules (tree_io, extractors)
_sys.path.insert(0, _os.path.dirname(_HERE))      # ComparisonResults/: config, loaders, registry
_BASE = _os.environ.get('ANTIDDOS_BASE', _os.path.dirname(_os.path.dirname(_HERE)))  # == config.BASE

import os, sys, json, glob

from check_scenario_intensity import profile
from write_extracted_index import classify
from tree_io import within_split
from split_cicddos_by_type import CSV_ATTACKERS

TREE = _os.path.join(_BASE, 'datasets', 'extracted', 'CICDDoS2019')
ROLE = 'ATTACKER-SIDE HOST, not a victim'
GROUND_TRUTH_SOURCE = 'CICDDoS2019/03-11/*.csv Source IP / Destination IP'


def provisional_attacker_reason(host):
    return (f"{host} is the SOURCE of the attack traffic on this day, not a target: the "
            f"03-11 CSVs give it as the Source IP, and the victim as the Destination IP, of "
            f"the attack flows. Provisional text, replaced by stamp_cicddos_roles.py with the "
            f"direction counts it measures over all seven CSVs.")


def stamp(md, rows, host, alpha):
    """Add the hand-written keys to one payload's metadata, in tree order."""
    p = profile(rows)
    if p is None:
        return False
    cls, ratio = classify(p)
    md['p95_packets_per_sec'] = p['atk_p95']
    md['benign_p95_packets_per_sec'] = p['ben_p95']
    md['attack_to_benign_p95_ratio'] = round(ratio, 2) if ratio != float('inf') else None
    md['intensity_class'] = cls
    # Same floor rule as classify_scenarios.analyse(); that script rewrites both
    # values in place when it runs with --write.
    _fit, cal, _tb, _ta = within_split(rows)
    n_cal = len(cal) if cal else 0
    floor = 1.0 / (n_cal + 1) if n_cal else 1.0
    floor_limited = bool(floor > alpha)
    attacker = host in CSV_ATTACKERS
    md.setdefault('floor_limited', floor_limited)
    md.setdefault('usable_as_ddos_scenario',
                  bool(cls != 'INDISTINCT' and not floor_limited and not attacker))
    if attacker:
        md.setdefault('unusable_reason', provisional_attacker_reason(host))
        md['role'] = ROLE
        md['ground_truth_source'] = GROUND_TRUTH_SOURCE
    elif floor_limited:
        md.setdefault('unusable_reason',
                      f'conformal floor exceeds alpha={alpha:g} (n_calib too small)')
    return True


def main():
    args = sys.argv[1:]
    skip = {i + 1 for i, a in enumerate(args) if a == '--alpha'}
    corpus = next((a for i, a in enumerate(args) if not a.startswith('--') and i not in skip), TREE)
    alpha = float(args[args.index('--alpha') + 1]) if '--alpha' in args else 0.01
    dry = '--dry-run' in args
    side = os.path.join(corpus, 'attacker_side')

    # The move CHANGE 191 made by hand: attacker slices out of the corpus root.
    for host in CSV_ATTACKERS:
        for f in sorted(glob.glob(os.path.join(corpus, f"cicddos_*_{host.replace('.', '-')}_*.json"))):
            dst = os.path.join(side, os.path.basename(f))
            print(f"  move {os.path.relpath(f, corpus)} -> {os.path.relpath(dst, corpus)}"
                  f"{'  (dry run)' if dry else ''}")
            if not dry:
                os.makedirs(side, exist_ok=True)
                os.replace(f, dst)

    files = (sorted(glob.glob(os.path.join(corpus, 'cicddos_*.json')))
             + sorted(glob.glob(os.path.join(side, 'cicddos_*.json'))))
    n = 0
    for f in files:
        js = json.load(open(f))
        md = js.get('metadata') or {}
        pw = js.get('per_ip_windows') or {}
        host = md.get('victim') or next(iter(pw), None)
        if host not in pw:
            print(f"  {os.path.relpath(f, corpus)}: no rows for {host} -- skipped")
            continue
        rows = sorted(pw[host], key=lambda r: r.get('_dt', 0))
        if not stamp(md, rows, host, alpha):
            print(f"  {os.path.relpath(f, corpus)}: no attack rows -- skipped")
            continue
        md.pop('bytes', None)
        md.pop('sha256', None)
        js['metadata'] = md
        print(f"  {os.path.relpath(f, corpus):48s} {md['intensity_class']:10s} "
              f"floor_limited={md['floor_limited']!s:5s} "
              f"{'role=' + md['role'] if 'role' in md else ''}")
        if not dry:
            json.dump(js, open(f, 'w'))
        n += 1
    print(f"{'DRY RUN: ' if dry else ''}stamped {n} CIC-DDoS2019 payloads under {corpus}")


if __name__ == '__main__':
    main()
