#!/usr/bin/env python3
"""Drop the two placeholder columns of the old offline extractor, burst_factor (a copy of packets_per_sec) and
unique_flows (a copy of flows_per_sec), from the per-window rows of the four-corpus feature tree, then update every stored
hash of the rewritten files: tree SHA256SUMS (scenario files and benign_pools), each corpus index.json, the deposited
copies under ComparisonResults/extraction/tree_manifest/, and payload_sha256 in admissibility_inputs.json.
Safety: a file is rewritten only if, in every one of its rows, burst_factor equals packets_per_sec and unique_flows equals
flows_per_sec; a file in which either column differs from its twin in any row, or is missing from any row, is left as
it is. Both must be copies because the old extractor wrote both. The current extractors compute burst_factor from a
per-destination EWMA and unique_flows from (source, protocol) pairs; on a small benign file the latter can equal
flows_per_sec in every row, and it is then kept. A file is also rewritten only if
json.dumps(json.loads(raw)) == raw (the tree's own serialisation), and only if every row after the rewrite equals the
old row minus the two keys. Writes hash_map.tsv (old -> new) beside itself; a hash list is written only if it changes.
It was run once, on 2026-10-13, when the deposit was prepared, on a tree whose 34 files carrying the two columns held
the copies in every row; the deposited copy differs from the one that ran in its paths, this docstring, a main()
wrapper and the copy test. On a tree built by the current extractors no file holds the copies, so it rewrites no file
and writes a header-only hash_map.tsv.
Usage: python3 drop_duplicate_columns.py   (ANTIDDOS_BASE selects the repository root, as for the other scripts)"""
import json, glob, hashlib, os, sys
_HERE = os.path.dirname(os.path.abspath(__file__))
SH = os.environ.get('ANTIDDOS_BASE', os.path.dirname(os.path.dirname(_HERE)))
TREE = SH + '/datasets/extracted'; MAN = SH + '/ComparisonResults/extraction/tree_manifest'
DUP = ('burst_factor', 'unique_flows'); CORPORA = ['CIC-IDS-2017', 'CIC-IDS2018', 'CICDDoS2019', 'LITNET-2020']
INPUTS = [SH + '/ComparisonResults/results/admissibility_inputs.json']
TWIN = {'burst_factor': 'packets_per_sec', 'unique_flows': 'flows_per_sec'}


def all_copies(d):
    """True if every row carries both columns and each equals its twin, as the old extractor wrote them."""
    rows = [r for rs in d['per_ip_windows'].values() for r in rs]
    return bool(rows) and all(k in r and r[k] == r.get(t) for r in rows for k, t in TWIN.items())


def main():
    sha = lambda b: hashlib.sha256(b).hexdigest()
    hmap = {}; nrows = 0
    for c in CORPORA:
        for f in sorted(glob.glob(f'{TREE}/{c}/**/*.json', recursive=True)):
            if os.path.basename(f) == 'index.json' or f.endswith('.meta.json'): continue
            raw = open(f, 'rb').read()
            if b'burst_factor' not in raw and b'unique_flows' not in raw: continue
            d = json.loads(raw)
            if not all_copies(d):
                print(f'kept, not copies in every row: {os.path.relpath(f, TREE)}'); continue
            assert json.dumps(d).encode() == raw, f'not the tree serialisation: {f}'
            old_rows = {v: [dict(r) for r in rows] for v, rows in d['per_ip_windows'].items()}
            for v, rows in d['per_ip_windows'].items():
                for r in rows:
                    for k in DUP: r.pop(k, None)
            new = json.dumps(d).encode()
            chk = json.loads(new)
            for v, rows in chk['per_ip_windows'].items():
                assert len(rows) == len(old_rows[v])
                for a, b in zip(old_rows[v], rows):
                    assert b == {k: x for k, x in a.items() if k not in DUP}, f'row changed beyond the two keys: {f}'
                    nrows += 1
            assert b'burst_factor' not in new and b'unique_flows' not in new
            open(f, 'wb').write(new); hmap[sha(raw)] = (sha(new), os.path.relpath(f, TREE))
    print(f'rewrote {len(hmap)} files, {nrows} rows verified')
    def remap_text(p):
        t0 = t = open(p).read()
        for o, (nw, _) in hmap.items():
            if o in t: t = t.replace(o, nw)
        if t != t0: open(p, 'w').write(t)
        return t != t0
    touched = []
    if hmap:
        for c in CORPORA:
            for p in glob.glob(f'{TREE}/{c}/**/SHA256SUMS', recursive=True) + [f'{TREE}/{c}/index.json']:
                if remap_text(p): touched.append(os.path.relpath(p, SH))
                mp = p.replace(TREE, MAN)
                if os.path.exists(mp) and remap_text(mp): touched.append(os.path.relpath(mp, SH))
        for p in INPUTS:
            if remap_text(p): touched.append(os.path.relpath(p, SH))
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'hash_map.tsv'), 'w') as fh:
        fh.write('old_sha256\tnew_sha256\tfile\n'); [fh.write(f'{o}\t{n}\t{f}\n') for o, (n, f) in sorted(hmap.items(), key=lambda x: x[1][1])]
    print('hash references updated in', len(touched), 'files:'); [print('  ', t) for t in touched]


if __name__ == '__main__':
    main()
