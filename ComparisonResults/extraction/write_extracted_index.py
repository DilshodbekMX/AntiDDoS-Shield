"""Write index.json and SHA256SUMS for an extracted-scenario directory.

CIC-IDS-2017, CIC-IDS-2018 and CIC-DDoS2019 shipped without one. Their
index.json and SHA256SUMS were assembled by hand after the slices were
emitted, so re-running the producer regenerated correct per_ip_windows
payloads that matched zero of the recorded hashes: a third party got usable
data, a manifest that failed `sha256sum -c`, and verify_extracted_tree.py
exiting 1. LITNET, CIC-IoT and CESNET each had a writer; these three did not.

Everything here is derived from the files on disk. Nothing is carried over
from a previous index, because a stale `bytes`/`sha256` pair surviving a
re-emit is exactly the failure this replaces.

    python3 write_extracted_index.py <corpus-dir> [<corpus-dir> ...]
"""
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_sys.path.insert(0, _HERE)                        # sibling extraction modules (tree_io, extractors)
_sys.path.insert(0, _os.path.dirname(_HERE))      # ComparisonResults/: config, loaders, registry
_BASE = _os.environ.get('ANTIDDOS_BASE', _os.path.dirname(_os.path.dirname(_HERE)))  # == config.BASE

import os, sys, json, glob, hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from check_scenario_intensity import profile, DEFAULT_P95

SKIP = {'index.json'}
# Sub-directories that hold scenarios and must appear in the index. Quarantined
# slices stay in the record -- CIC-DDoS2019's six 172.16.0.5 files were moved to
# attacker_side/ once the corpus CSVs showed that host is the attack SOURCE, and
# dropping them from the index would erase the finding rather than record it.
# benign_pools/ is excluded: those are host pools, not scenarios, and carry
# their own SHA256SUMS.
SUBDIRS = ('attacker_side',)


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def classify(p, thr=DEFAULT_P95):
    """Same two-number rule as check_scenario_intensity.py -- absolute rate
    answers 'is it volumetric', ratio answers 'is it distinguishable from this
    host's own traffic'. Duplicated as a call, not a copy, so the two artifacts
    can never drift apart."""
    ratio = (p['atk_p95'] / p['ben_p95']) if p['ben_p95'] else float('inf')
    if ratio < 2.0:
        return 'INDISTINCT', ratio
    return ('VOLUMETRIC' if p['atk_p95'] >= thr else 'LOW-RATE'), ratio


def build(d):
    idx, sums = {}, []
    files = sorted(glob.glob(os.path.join(d, '*.json')))
    for sub in SUBDIRS:
        files += sorted(glob.glob(os.path.join(d, sub, '*.json')))
    for f in files:
        base = os.path.relpath(f, d)
        if os.path.basename(f) in SKIP:
            continue
        js = json.load(open(f))
        pw = js.get('per_ip_windows')
        if not isinstance(pw, dict) or not pw:
            print(f"  {base}: no per_ip_windows -- skipped")
            continue
        md = dict(js.get('metadata') or {})
        # Never trust a size or digest embedded in the payload: it describes
        # whatever the file was BEFORE this emit.
        md.pop('bytes', None)
        md.pop('sha256', None)
        rows = next(iter(pw.values()))
        p = profile(rows)
        if p:
            cls, ratio = classify(p)
            md.update({
                'p95_packets_per_sec': p['atk_p95'],
                'benign_p95_packets_per_sec': p['ben_p95'],
                'attack_to_benign_p95_ratio': (round(ratio, 2)
                                               if ratio != float('inf') else None),
                'intensity_class': cls,
                'n_attack': p['n_attack'], 'n_benign': p['n_benign'],
            })
        # Stamp the derived stats back into the payload as well as the index.
        # verify_extracted_tree.py reads intensity_class from the FILE, so a
        # scenario that only carries it in the manifest verifies as "NO CLASS",
        # and a third party holding one file alone can still tell what it is.
        # Written before hashing, so the digest describes the final bytes.
        js['metadata'] = {k: v for k, v in md.items()
                          if k not in ('file', 'bytes', 'sha256')}
        json.dump(js, open(f, 'w'))
        md.update({'file': base, 'bytes': os.path.getsize(f), 'sha256': sha256(f)})
        idx[os.path.basename(base).replace('.json', '')] = md
        sums.append(f"{md['sha256']}  {base}")
        print(f"  {base:44s} {md['bytes']:>10,d} B  {md.get('intensity_class','?')}")
    json.dump(idx, open(os.path.join(d, 'index.json'), 'w'), indent=2)
    open(os.path.join(d, 'SHA256SUMS'), 'w').write('\n'.join(sorted(sums)) + '\n')
    return len(idx)


def main():
    dirs = [a for a in sys.argv[1:] if not a.startswith('-')]
    if not dirs:
        sys.exit(__doc__)
    for d in dirs:
        print(f"\n=== {d} ===")
        n = build(d)
        print(f"  index.json + SHA256SUMS written, {n} scenarios")


if __name__ == '__main__':
    main()
