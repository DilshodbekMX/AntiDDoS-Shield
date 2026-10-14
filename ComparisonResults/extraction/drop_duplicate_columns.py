#!/usr/bin/env python3
"""Drop the two duplicated offline-extractor columns, burst_factor (= packets_per_sec) and unique_flows
(= flows_per_sec), from every per-window row of the four-corpus feature tree, then update every stored hash of the
rewritten files: tree SHA256SUMS (scenario files and benign_pools), each corpus index.json, the deposited copies
under ComparisonResults/extraction/tree_manifest/, and payload_sha256 in admissibility_inputs.json.
Safety: a file is rewritten only if json.dumps(json.loads(raw)) == raw (the tree's own serialisation), and only if
every row after the rewrite equals the old row minus the two keys. Writes hash_map.tsv (old -> new) beside itself.
It was run once, on 2026-10-13, when the deposit was prepared; the deposited copy differs from the one that ran only in
its paths, this docstring and a main() wrapper. On the tree that tree_manifest/ pins it finds neither column, so it rewrites no file and writes a header-only hash_map.tsv.
Usage: python3 drop_duplicate_columns.py   (ANTIDDOS_BASE selects the repository root, as for the other scripts)"""
import json, glob, hashlib, os, sys
_HERE = os.path.dirname(os.path.abspath(__file__))
SH = os.environ.get('ANTIDDOS_BASE', os.path.dirname(os.path.dirname(_HERE)))
TREE = SH + '/datasets/extracted'; MAN = SH + '/ComparisonResults/extraction/tree_manifest'
DUP = ('burst_factor', 'unique_flows'); CORPORA = ['CIC-IDS-2017', 'CIC-IDS2018', 'CICDDoS2019', 'LITNET-2020']
INPUTS = [SH + '/ComparisonResults/results/admissibility_inputs.json']


def main():
    sha = lambda b: hashlib.sha256(b).hexdigest()
    hmap = {}; nrows = 0
    for c in CORPORA:
        for f in sorted(glob.glob(f'{TREE}/{c}/**/*.json', recursive=True)):
            if os.path.basename(f) == 'index.json' or f.endswith('.meta.json'): continue
            raw = open(f, 'rb').read()
            if b'burst_factor' not in raw and b'unique_flows' not in raw: continue
            d = json.loads(raw)
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
        t = open(p).read(); n = 0
        for o, (nw, _) in hmap.items():
            if o in t: t = t.replace(o, nw); n += t.count(nw)
        open(p, 'w').write(t); return n
    touched = []
    for c in CORPORA:
        for p in glob.glob(f'{TREE}/{c}/**/SHA256SUMS', recursive=True) + [f'{TREE}/{c}/index.json']:
            before = open(p).read(); remap_text(p)
            if open(p).read() != before: touched.append(os.path.relpath(p, SH))
            mp = p.replace(TREE, MAN)
            if os.path.exists(mp):
                mb = open(mp).read(); remap_text(mp)
                if open(mp).read() != mb: touched.append(os.path.relpath(mp, SH))
    for p in INPUTS:
        before = open(p).read(); remap_text(p)
        if open(p).read() != before: touched.append(os.path.relpath(p, SH))
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'hash_map.tsv'), 'w') as fh:
        fh.write('old_sha256\tnew_sha256\tfile\n'); [fh.write(f'{o}\t{n}\t{f}\n') for o, (n, f) in sorted(hmap.items(), key=lambda x: x[1][1])]
    print('hash references updated in', len(touched), 'files:'); [print('  ', t) for t in touched]


if __name__ == '__main__':
    main()
