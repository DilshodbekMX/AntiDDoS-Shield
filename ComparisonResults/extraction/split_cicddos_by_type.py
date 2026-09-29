"""Split CIC-DDoS2019 into per-attack-type scenarios using the CSV ground truth.

CIC-DDoS2019 contributes ZERO scenarios to the panel: its causal split finds
n_pre_benign=1 because the labels run wall-to-wall. pcap_feature_extractor.py
marks a window as attack when ANY flow in it is one, and these floods produce
enormous flow counts, so nearly every second at the victim reads as attack.
There IS a benign prologue in the capture; there is none in the day-level label.

Splitting by attack type recovers it. Each attack starts at a different time,
so the windows preceding a given attack -- benign ones, with no attack flow at
all -- become that attack's calibration set. Measured on 03-11: six of seven
attacks per victim gain a usable prologue, turning 0 scenarios into 12.

Unlike the CIC-IDS-2017/2018 splitters this uses NO published schedule and NO
timezone derivation. The attack type comes from the dataset's own per-flow CSV
labels, carried through the existing 5-tuple join (see CHANGE 180). That
matters: the two corpora split so far needed different offsets (2018 UTC-4,
2017 UTC-3, neither matching the calendar) and this one would have needed a
third.

WHAT A SLICE IS. Attacks here are NOT cleanly time-separated. _attack_type is
the DOMINANT label in a window, and residual flows from an earlier attack
persist into later ones, so MSSQL-dominant windows on 03-11 span 08:44-11:38
and overlap NetBIOS, LDAP and UDP. A slice therefore means "windows where this
attack dominates", plus every fully-benign window, and excludes windows
dominated by a different attack. It is not a claim that the attack ran
continuously across that span.

Usage: python3 split_cicddos_by_type.py <typed_cache> <day-tag> [--out DIR] [--dry-run]
"""
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_sys.path.insert(0, _HERE)                        # sibling extraction modules (tree_io, extractors)
_sys.path.insert(0, _os.path.dirname(_HERE))      # ComparisonResults/: config, loaders, registry
_BASE = _os.environ.get('ANTIDDOS_BASE', _os.path.dirname(_os.path.dirname(_HERE)))  # == config.BASE

import os, sys, json, gc
from datetime import datetime, timezone, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from config import CACHE_DIR

TREE_DIR = _os.path.join(_BASE, 'datasets', 'extracted', 'CICDDoS2019')

MIN_PRE = 30

# Victims established from the per-attack CSVs' Destination IP field, verified
# unanimous across all seven 03-11 files (LDAP, MSSQL, NetBIOS, Portmap, Syn,
# UDP, UDPLag). Extend this when adding the 01-12 day, whose documented victim
# is 192.168.50.1.
CSV_VICTIMS = ['192.168.50.4']
TZ = timezone(timedelta(hours=-4))   # display only; no labelling depends on it


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    if len(args) < 2:
        sys.exit(__doc__)
    cache, tag = args[0], args[1]
    dry = '--dry-run' in sys.argv
    # Defaults to the extracted tree, like every other exporter. It used to
    # default to CACHE_DIR -- alone among the five -- so following the README's
    # recipe wrote the six victim slices into experiments_copy/cache/ under
    # filenames identical to the tree's and left the tree untouched. Same defect
    # the CIC-IDS-2017 audit found in the sibling splitter; fixed there in
    # CHANGE 199 and missed here.
    outdir = next((sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == '--out'),
                  TREE_DIR)

    path = cache if os.path.exists(cache) else os.path.join(CACHE_DIR, cache)
    d = json.load(open(path))
    d = d.get('per_ip_windows', d)
    loc = lambda t: datetime.fromtimestamp(t, TZ).strftime('%H:%M:%S')
    written = []

    # Victims come from the CSV's Destination IP field, NOT from attack-window
    # count. Counting alone selects the ATTACKER: the cache is keyed by
    # destination but a host also accumulates attack-labelled windows from the
    # backscatter it receives, and 172.16.0.5 -- the source of every attack on
    # this day -- carried 7,025 such windows.
    #
    # Ground truth, ALL SEVEN 03-11 CSVs, 20,364,525 data rows:
    #
    #   172.16.0.5 -> 192.168.50.4   20,299,481 flows
    #   192.168.50.4 -> 172.16.0.5        8,079 flows      2,513 : 1
    #
    # An earlier revision cited "2,966,708 and 2,232" here and in the README,
    # index and every attacker_side payload. Those are Syn.csv alone, and only
    # its first 3,000,000 of 4,320,541 rows: the full file is 4,281,316 / 3,435,
    # and both printed numbers reproduce simultaneously at that row. It was a
    # truncated read, not a different counting rule -- no variant (distinct Flow
    # IDs, Protocol==6, Inbound==1) reproduces the pair. The conclusion was
    # right, which is why it survived; the evidence for it was not.
    #
    # The 8,079 inbound flows are SYN-ACK replies from the victim -- backscatter.
    # Selecting on count produced six scenarios on the attacker's own host,
    # every one of which the intensity gate later flagged at 1.0-1.3x its own
    # benign traffic.
    victims = [ip for ip in CSV_VICTIMS if ip in d]
    if not victims:
        victims = sorted((ip for ip, rows in d.items()
                          if sum(1 for r in rows if r.get('_is_attack')) >= 100),
                         key=lambda ip: -sum(1 for r in d[ip] if r.get('_is_attack')))
        print("  WARNING: no known CSV victim present; falling back to "
              "attack-window count, which can select the attacker -- verify "
              "direction against the CSV Destination IP field before using.")
    print(f"{path}\n  victims with >=100 attack windows: {victims}\n")

    for v in victims:
        rows = sorted(d[v], key=lambda r: r.get('_dt', 0))
        benign = [r for r in rows if not r.get('_is_attack')]
        types = {}
        for r in rows:
            if r.get('_is_attack') and r.get('_attack_type'):
                types.setdefault(r['_attack_type'], []).append(r)
        print(f"  === {v}: {len(rows)} windows, {len(benign)} fully benign ===")
        for atk, arows in sorted(types.items(), key=lambda kv: -len(kv[1])):
            first = min(r['_dt'] for r in arows)
            pre = [r for r in benign if r['_dt'] < first]
            ok = len(pre) >= MIN_PRE
            print(f"    {atk:10s} {len(arows):6d} windows  [{loc(first)}-"
                  f"{loc(max(r['_dt'] for r in arows))}]  n_pre_benign={len(pre):5d}"
                  f"  {'->' if ok else 'SKIP: no prologue'}", end='')
            if not ok:
                print(); continue
            name = f"cicddos_{tag}_{v.replace('.', '-')}_{atk}.json"
            print(f" {name}")
            if not dry:
                os.makedirs(outdir, exist_ok=True)
                json.dump({'metadata': {
                    'corpus': 'CIC-DDoS2019', 'day': tag, 'victim': v, 'attack_type': atk,
                    'derived_from': os.path.basename(path),
                    'label_source': 'per-flow CSV labels via 5-tuple join (no schedule used)',
                    'n_attack_windows': len(arows), 'n_benign_windows': len(benign),
                    'n_pre_benign': len(pre),
                    'note': ('windows where this attack DOMINATES, plus all fully-benign '
                             'windows; windows dominated by another attack are excluded. '
                             'Attacks overlap in this capture -- see the script docstring.'),
                }, 'per_ip_windows': {v: sorted(benign + arows, key=lambda r: r['_dt'])}},
                    open(os.path.join(outdir, name), 'w'))
                written.append(name)
        print()
        del rows, benign, types; gc.collect()
    print(f"{'DRY RUN' if dry else f'wrote {len(written)} slices to {outdir}'}")


if __name__ == '__main__':
    main()
