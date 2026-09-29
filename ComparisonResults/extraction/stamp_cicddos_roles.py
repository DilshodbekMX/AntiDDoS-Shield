"""Measure CIC-DDoS2019 03-11 host roles from the CSVs and stamp the result.

The quarantine of 172.16.0.5 rests on a direction count, and that count was
typed into the tree by hand -- README, index.json and all six attacker_side/
payloads -- with no script producing it. It was wrong: "192.168.50.4 as
Destination of 2,966,708 flows, as Source of 2,232" is Syn.csv alone, and only
its first 3,000,000 of 4,320,541 rows. Both printed numbers reproduce
simultaneously at that row, so it was a truncated read rather than a different
counting rule; no variant (distinct Flow IDs, Protocol==6, Inbound==1)
reproduces the pair. The conclusion was right, which is exactly why it survived.

So the number is now MEASURED here and written from the measurement. Nothing
about the role verdict is typed.

    python3 stamp_cicddos_roles.py [--dry-run]
"""
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_sys.path.insert(0, _HERE)                        # sibling extraction modules (tree_io, extractors)
_sys.path.insert(0, _os.path.dirname(_HERE))      # ComparisonResults/: config, loaders, registry
_BASE = _os.environ.get('ANTIDDOS_BASE', _os.path.dirname(_os.path.dirname(_HERE)))  # == config.BASE

import os, sys, json, glob

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from config import BASE, RESULTS_DIR

CSV_DIR = os.path.join(BASE, 'datasets', 'CICDDoS2019', '03-11')
TREE = _os.path.join(_BASE, 'datasets', 'extracted', 'CICDDoS2019')
ATTACKER, VICTIM = '172.16.0.5', '192.168.50.4'
OUT = os.path.join(RESULTS_DIR, 'cicddos2019_role_ground_truth.json')
SRC_COL, DST_COL = 2, 4          # 0-based: Unnamed, Flow ID, Source IP, Source Port, Destination IP


def measure():
    """Stream every 03-11 CSV once. Never load one -- MSSQL.csv alone is 2.2 GB."""
    tot = a2v = v2a = 0
    per_file = {}
    for path in sorted(glob.glob(os.path.join(CSV_DIR, '*.csv'))):
        f_tot = f_a2v = f_v2a = 0
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            fh.readline()
            for line in fh:
                p = line.split(',', DST_COL + 1)
                if len(p) <= DST_COL:
                    continue
                s, d = p[SRC_COL].strip(), p[DST_COL].strip()
                f_tot += 1
                if s == ATTACKER and d == VICTIM:
                    f_a2v += 1
                elif s == VICTIM and d == ATTACKER:
                    f_v2a += 1
        per_file[os.path.basename(path)] = {'rows': f_tot, 'attacker_to_victim': f_a2v,
                                            'victim_to_attacker': f_v2a}
        tot += f_tot; a2v += f_a2v; v2a += f_v2a
        print(f"  {os.path.basename(path):16s} rows={f_tot:>10,d}  "
              f"{ATTACKER}->{VICTIM}={f_a2v:>10,d}  reverse={f_v2a:>6,d}")
    return {'csv_dir': CSV_DIR, 'n_csv_files': len(per_file), 'data_rows': tot,
            'attacker': ATTACKER, 'victim': VICTIM,
            'attacker_to_victim_flows': a2v, 'victim_to_attacker_flows': v2a,
            'ratio': round(a2v / v2a, 1) if v2a else None, 'per_file': per_file}


def reason(m):
    return (f"{m['attacker']} is the SOURCE of the attack traffic on this day, not a "
            f"target. Ground truth measured over all {m['n_csv_files']} 03-11 CSVs "
            f"({m['data_rows']:,} data rows): {m['attacker']} -> {m['victim']} carries "
            f"{m['attacker_to_victim_flows']:,} flows against {m['victim_to_attacker_flows']:,} "
            f"in reverse, a ratio of {m['ratio']:,.0f}:1. The reverse flows are SYN-ACK and "
            f"RST-ACK replies from the victim -- backscatter. These slices are kept as a "
            f"negative control, not deleted: a detector that alarms on them is alarming on "
            f"the attack source, which is a different and much easier problem than "
            f"protecting the target. Excluded from every usable count.")


def main():
    print(f"measuring {CSV_DIR}\n")
    m = measure()
    print(f"\n  TOTAL rows={m['data_rows']:,}  "
          f"{m['attacker']}->{m['victim']}={m['attacker_to_victim_flows']:,}  "
          f"reverse={m['victim_to_attacker_flows']:,}  ratio={m['ratio']:,.0f}:1")
    if '--dry-run' in sys.argv:
        print("\nDRY RUN -- nothing written"); return
    json.dump(m, open(OUT, 'w'), indent=2)
    print(f"\nwrote {OUT}")
    r = reason(m)
    n = 0
    for f in sorted(glob.glob(os.path.join(TREE, 'attacker_side', '*.json'))):
        js = json.load(open(f))
        js['metadata']['unusable_reason'] = r
        js['metadata']['role_ground_truth'] = {
            k: m[k] for k in ('data_rows', 'attacker_to_victim_flows',
                              'victim_to_attacker_flows', 'ratio', 'n_csv_files')}
        js['metadata'].pop('bytes', None)
        js['metadata'].pop('sha256', None)
        json.dump(js, open(f, 'w'))
        n += 1
    print(f"stamped {n} attacker_side payloads")


if __name__ == '__main__':
    main()
