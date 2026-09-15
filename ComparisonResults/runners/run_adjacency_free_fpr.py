"""Stream-realized vs adjacency-free false-alarm rate, for every arm.

The published realized FPR (run_29_scenarios_corrected.py) scores ONE array: the
calibration prefix followed by the timestamp-merged benign-test and attack rows. Arms
that carry state across that array -- ours, through its EWMA accumulator; DSPOT, through
its drift window -- let a benign window that directly follows an attack window inherit
part of that attack window's surprise. Memoryless arms inherit nothing.

Comparing a stateful arm's realized FPR against a memoryless arm's is therefore not a
calibration comparison. This runner reports both quantities:

  stream-realized : attack rows present in the scored array (what the paper published)
  adjacency-free  : the same benign rows scored with the attack rows excised

Only the second compares like with like across stateful and stateless arms. Neither is
"the" right number -- a streaming detector really does carry state, and a benign window
just after a flood really would score high -- but they answer different questions and
must not be differenced.

Threshold control: thresholds come from the calibration prefix in both passes and are
asserted equal, so any movement is test-side, not threshold-side.

Writes results/adjacency_free_fpr.json.
"""
import json, os, sys, time
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
for p in (HERE, os.path.abspath(os.path.join(HERE, '..'))):
    sys.path.insert(0, p)

from config import RESULTS_DIR
import competitors_fixed as C
import run_crosscorpus_auc as R
import run_29_scenarios_corrected as R29
from run_post2023_benchmark import tkey

TARGETS = (0.01, 0.02, 0.05)


def main():
    t0 = time.time()
    cases = R29.collect()
    print(f"{len(cases)} scenarios with verdict in (USABLE, ROLE-UNVERIFIED)\n")
    per_scen, nthr, nbad = [], 0, 0

    for corp, fn, path, e in cases:
        fit, cal, tb, atk = R29.load_case_tree(path, e.get('victim'), e.get('split_mode'))
        if fit is None or len(fit) < 10 or len(cal) < 5 or len(tb) < 5 or len(atk) < 10:
            print(f"  SKIP {corp} {fn[:40]}"); continue
        feats = R.active_features(fit)
        A = C.mat(fit, feats)
        tagged = sorted([(tkey(r), 0, r) for r in tb] + [(tkey(r), 1, r) for r in atk],
                        key=lambda x: x[0])
        y = np.array([t[1] for t in tagged])
        nc = len(cal)
        stream = C.mat(cal + [t[2] for t in tagged], feats)          # as published
        benign_only = C.mat(cal + [t[2] for t in tagged if t[1] == 0], feats)  # excised

        # how often does a benign test row directly follow an attack row?
        adj = float(np.mean([y[i - 1] == 1 for i in range(1, len(y)) if y[i] == 0])) if len(y) > 1 else 0.0

        rec = {'corpus': corp, 'file': fn, 'label': f"{corp} {fn.replace('.json','')}",
               'verdict': e.get('verdict'), 'split_mode': e.get('split_mode'),
               'causal': e.get('split_mode') not in ('treefile', 'crossfile'),
               'adjacency': round(adj, 4), 'attack_frac': round(float(y.mean()), 4), 'arms': {}}

        for name, (fnc, _) in C.DETECTORS.items():
            s_all = np.asarray(fnc(A, stream), dtype=float)
            s_ben = np.asarray(fnc(A, benign_only), dtype=float)
            cs_a, ts_a = s_all[:nc], s_all[nc:]
            cs_b, ts_b = s_ben[:nc], s_ben[nc:]
            a = {}
            for t in TARGETS:
                k = int(t * 100)
                th_a = np.percentile(cs_a, (1 - t) * 100)
                th_b = np.percentile(cs_b, (1 - t) * 100)
                nthr += 1
                if not np.isclose(th_a, th_b, rtol=0, atol=1e-12):
                    nbad += 1
                a[f'stream_fpr@{k}'] = round(float((ts_a[y == 0] > th_a).mean() * 100), 2)
                # adjacency-free: same benign rows, attack rows absent, SAME prefix threshold
                a[f'free_fpr@{k}'] = round(float((ts_b > th_a).mean() * 100), 2)
            rec['arms'][name] = a
        per_scen.append(rec)
        print(f"  {rec['label'][:52]:52s} adj={adj:.3f} ({time.time()-t0:.0f}s)", flush=True)

    def summarise(rows):
        out = {}
        for name in C.DETECTORS:
            o = {}
            for k in (1, 2, 5):
                o[f'stream_fpr@{k}'] = round(float(np.mean([r['arms'][name][f'stream_fpr@{k}'] for r in rows])), 2)
                o[f'free_fpr@{k}'] = round(float(np.mean([r['arms'][name][f'free_fpr@{k}'] for r in rows])), 2)
            o['moved'] = sum(1 for r in rows
                             if r['arms'][name]['stream_fpr@1'] != r['arms'][name]['free_fpr@1'])
            out[name] = o
        return out

    usable = [r for r in per_scen if r['verdict'] == 'USABLE']
    cross = [r for r in usable if not r['causal']]
    res = {'note': __doc__.strip(),
           'threshold_control': {'compared': nthr, 'unequal': nbad},
           'summary': {'ALL-29': summarise(per_scen), 'USABLE-22': summarise(usable),
                       'crossfile-admissible': summarise(cross)},
           'n': {'ALL-29': len(per_scen), 'USABLE-22': len(usable), 'crossfile-admissible': len(cross)},
           'per_scenario': per_scen}
    dst = os.path.join(RESULTS_DIR, 'adjacency_free_fpr.json')
    json.dump(res, open(dst, 'w'), indent=1)
    print(f"\n  thresholds compared {nthr}, unequal {nbad}")
    u = res['summary']['USABLE-22']
    print(f"  {'arm':26s}{'stream 1/2/5':>22s}{'adjacency-free 1/2/5':>26s}{'moved':>7s}")
    for name, o in u.items():
        print(f"  {name:26s}{o['stream_fpr@1']:>7.2f}{o['stream_fpr@2']:>7.2f}{o['stream_fpr@5']:>8.2f}"
              f"{o['free_fpr@1']:>10.2f}{o['free_fpr@2']:>8.2f}{o['free_fpr@5']:>8.2f}{o['moved']:>7d}")
    print(f"  wrote {dst}")


if __name__ == '__main__':
    main()
