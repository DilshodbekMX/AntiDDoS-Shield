"""Write results/admissibility_inputs.json, the admissibility ledger's input, from the tree.

classify_scenarios.py --write stores each candidate's admissibility statistics in the
index.json of its corpus directory, and runners/run_admissibility_ledger.py reads them from
results/admissibility_inputs.json. That record had no writer. Its content equals a projection
of the index files, and its payload_sha256 values were updated when the scenario files changed,
once by drop_duplicate_columns.py and once by a scripted hand edit (ComparisonResults/README.md).
This projects it instead. For every scenario in the index.json of the four
corpora, each field is copied from the scenario's index entry, and payload_sha256 is the
entry's sha256, the checksum of the file the statistics were measured on. Nothing is
carried over from an earlier record, so no field can outlive the file it describes.

Run it after step 3 of extraction/README.md (classify_scenarios.py --write, then
write_extracted_index.py). It reads the index files and changes nothing in the tree.

    python3 write_admissibility_inputs.py [tree] [--out FILE] [--check FILE]

tree defaults to datasets/extracted under ANTIDDOS_BASE, --out to
results/admissibility_inputs.json. --check FILE compares the projection with FILE, field by
field and by JSON type, writes nothing, and exits 1 on any difference.
"""
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_sys.path.insert(0, _HERE)                        # sibling extraction modules (tree_io, extractors)
_sys.path.insert(0, _os.path.dirname(_HERE))      # ComparisonResults/: config, loaders, registry
_BASE = _os.environ.get('ANTIDDOS_BASE', _os.path.dirname(_os.path.dirname(_HERE)))  # == config.BASE

import os, sys, json

from corpus_names import in_scope

TREE = _os.path.join(_BASE, 'datasets', 'extracted')

NOTE = ("Per-candidate admissibility statistics, one entry per extracted candidate scenario (31). "
        "Read from the index.json of each corpus directory of the derived per-window feature tree, "
        "where the scenario classifier wrote them; no verdict is carried. best_feature / best_auc / "
        "best_dr_at_5pct_fpr: over every non-constant feature, the feature maximising (detection "
        "rate, rank-AUC) lexicographically, rank-AUC two-sided max(AUC, 1-AUC) with ties averaged, "
        "detection rate the larger of the attack shares above the benign 95th and below the benign "
        "5th percentile, over the labelled slice. inbound_*_share: SYN, ACK, RST and SYN-ACK counts "
        "over attack windows divided by their packet count. n_calib / n_test_benign: the causal "
        "scenario split (with fewer than 30 pre-attack benign windows yields n_calib = 0 and "
        "n_test_benign = 0). payload_sha256: the scenario file the numbers were measured on.")

# (record field, index.json key), in the record's order, after corpus_dir and scenario.
FIELDS = [('file', 'file'), ('victim', 'victim'), ('split_mode', 'split_mode'),
          ('n_attack_windows', 'n_attack_windows'), ('best_feature', 'best_feature'),
          ('best_auc', 'best_auc'), ('best_dr_at_5pct_fpr', 'best_dr_at_5pct_fpr'),
          ('inbound_syn_share', 'inbound_syn_share'), ('inbound_ack_share', 'inbound_ack_share'),
          ('inbound_rst_share', 'inbound_rst_share'),
          ('inbound_syn_ack_share', 'inbound_syn_ack_share'),
          ('n_calib', 'n_calib'), ('n_test_benign', 'n_test_benign'),
          ('payload_sha256', 'sha256')]


def project(tree):
    cands = []
    for corpus in sorted(os.listdir(tree)):
        p = os.path.join(tree, corpus, 'index.json')
        if not in_scope(corpus) or not os.path.isfile(p):
            continue
        idx = json.load(open(p))
        for scenario in sorted(idx):
            m = idx[scenario]
            missing = [k for _, k in FIELDS if k not in m]
            if missing:
                sys.exit(f"{corpus}/{scenario}: index entry lacks {missing}; "
                         f"run classify_scenarios.py --write and write_extracted_index.py first")
            c = {'corpus_dir': corpus, 'scenario': scenario}
            c.update({f: m[k] for f, k in FIELDS})
            cands.append(c)
    return {'note': NOTE, 'n_candidates': len(cands), 'candidates': cands}


def same(a, b):
    # by value and by JSON type: 0 and 0.0 differ, as they do in the file
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def differences(new, old):
    out = [f"{k}: {old.get(k)!r} -> {new.get(k)!r}" for k in ('note', 'n_candidates')
           if not same(new.get(k), old.get(k))]
    key = lambda c: (c['corpus_dir'], c['scenario'])
    a = {key(c): c for c in new['candidates']}
    b = {key(c): c for c in old.get('candidates', [])}
    out += [f"{k[0]}/{k[1]}: only in the projection" for k in sorted(set(a) - set(b))]
    out += [f"{k[0]}/{k[1]}: only in the file" for k in sorted(set(b) - set(a))]
    if [key(c) for c in new['candidates']] != [key(c) for c in old.get('candidates', [])] \
            and set(a) == set(b):
        out.append("candidate order differs")
    for k in sorted(set(a) & set(b)):
        for f in sorted(set(a[k]) | set(b[k])):
            if not same(a[k].get(f), b[k].get(f)):
                out.append(f"{k[0]}/{k[1]} {f}: {b[k].get(f)!r} -> {a[k].get(f)!r}")
    return out


def main():
    args = sys.argv[1:]
    opt = {}
    for flag in ('--out', '--check'):
        if flag in args:
            i = args.index(flag)
            opt[flag] = args[i + 1]
            del args[i:i + 2]
    tree = args[0] if args else TREE
    rec = project(tree)
    per = {}
    for c in rec['candidates']:
        per[c['corpus_dir']] = per.get(c['corpus_dir'], 0) + 1
    print(f"{rec['n_candidates']} candidates from {tree}: "
          + ", ".join(f"{k} {v}" for k, v in per.items()))
    if '--check' in opt:
        diffs = differences(rec, json.load(open(opt['--check'])))
        for d in diffs:
            print("  " + d)
        print(f"{len(diffs)} differences against {opt['--check']}")
        sys.exit(1 if diffs else 0)
    if '--out' in opt:
        out = opt['--out']
    else:
        from config import RESULTS_DIR
        out = os.path.join(RESULTS_DIR, 'admissibility_inputs.json')
    if os.path.exists(out):
        diffs = differences(rec, json.load(open(out)))
        print(f"{len(diffs)} fields differ from the record being replaced")
        for d in diffs:
            print("  " + d)
    with open(out, 'w') as fh:
        fh.write(json.dumps(rec, indent=1))
    print(f"wrote {out}")


if __name__ == '__main__':
    main()
