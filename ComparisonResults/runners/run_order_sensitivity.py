"""Order sensitivity of the stateful arms on USABLE-16.

Every scenario is re-derived under two orders: interleaved (as published, both classes
merged on the shared index) and appended (each class sorted on its own index, benign
block then attack block). On the four corpora both classes come from one capture, so
the index is monotone in time. ROC AUC is order-invariant for a memoryless scorer, so
the memoryless arms are the control and any movement in ours or DSPOT is order
dependence; LODA moves only by reseeding. Reports AUC and realized FPR for every arm
under both.

Writes results/order_sensitivity.json.
"""
import json, os, sys, time
import numpy as np
from sklearn.metrics import roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
for p in (HERE, os.path.abspath(os.path.join(HERE, '..'))):
    sys.path.insert(0, p)

from config import RESULTS_DIR
import safe_out
import competitors_fixed as C
import run_crosscorpus_auc as R
import run_29_scenarios_corrected as R29
from run_post2023_benchmark import tkey
from corpus_names import spelling_census

TARGETS = (0.01, 0.02, 0.05)


def score(A, cal, rows, y, feats, nc):
    out = {}
    stream = C.mat(cal + rows, feats)
    for name, (fnc, _) in C.DETECTORS.items():
        s = np.asarray(fnc(A, stream), dtype=float)
        cs, ts = s[:nc], s[nc:]
        a = {'auc': round(float(roc_auc_score(y, ts)), 6)}
        for t in TARGETS:
            k = int(t * 100)
            th = np.percentile(cs, (1 - t) * 100)
            a[f'fpr@{k}'] = round(float((ts[y == 0] > th).mean() * 100), 2)
            a[f'dr@{k}'] = round(float((ts[y == 1] > th).mean() * 100), 2)
        out[name] = a
    return out


def main():
    t0 = time.time()
    per = []
    for corp, fn, path, e in R29.collect():
        fit, cal, tb, atk = R29.load_case_tree(path, e.get('victim'), e.get('split_mode'))
        if fit is None or len(fit) < 10 or len(cal) < 5 or len(tb) < 5 or len(atk) < 10:
            continue
        feats = R.active_features(fit)
        A = C.mat(fit, feats)
        nc = len(cal)

        tagged = sorted([(tkey(r), 0, r) for r in tb] + [(tkey(r), 1, r) for r in atk],
                        key=lambda x: x[0])
        y_i = np.array([t[1] for t in tagged])
        rows_i = [t[2] for t in tagged]

        rows_a = sorted(tb, key=tkey) + sorted(atk, key=tkey)
        y_a = np.array([0] * len(tb) + [1] * len(atk))

        # index diagnostics. tkey is numeric on the CIC corpora (a per-file window index) and an
        # ISO-8601 string on LITNET-2020, which carries real timestamps; only the numeric case has
        # a meaningful step, so the string case reports None rather than crashing.
        def _steps(rs):
            try:
                t = np.sort(np.array([float(tkey(r)) for r in rs], dtype=float))
            except (TypeError, ValueError):
                return None
            return float(np.median(np.diff(t))) if len(t) > 1 else 0.0
        step_a = _steps(atk)
        step_b = _steps(tb)

        rec = {'corpus': corp, 'file': fn, 'label': f"{corp} {fn.replace('.json','')}",
               'verdict': e.get('verdict'), 'split_mode': e.get('split_mode'),
               'median_step_attack': step_a, 'median_step_benign': step_b,
               'step_ratio': round(step_b / step_a, 2) if (step_a and step_b) else None,
               'key_is_numeric': step_a is not None,
               'interleaved': score(A, cal, rows_i, y_i, feats, nc),
               'appended': score(A, cal, rows_a, y_a, feats, nc)}
        per.append(rec)
        o = rec['interleaved']['Subspace-Q + EWMA (ours)']['auc']
        a = rec['appended']['Subspace-Q + EWMA (ours)']['auc']
        print(f"  {rec['label'][:50]:52s} ours {o:.4f} -> {a:.4f}  ({time.time()-t0:.0f}s)", flush=True)

    def agg(rows, arm, key):
        return round(float(np.mean([r[key][arm]['auc'] for r in rows])), 6)

    summary = {}
    for tag, rows in ((f'USABLE-{len(per)}', per),):
        if not rows: continue
        summary[tag] = {arm: {'interleaved_mean_auc': agg(rows, arm, 'interleaved'),
                              'appended_mean_auc': agg(rows, arm, 'appended'),
                              'delta': round(agg(rows, arm, 'appended') - agg(rows, arm, 'interleaved'), 6),
                              'rows_moved': sum(1 for r in rows
                                                if r['interleaved'][arm]['auc'] != r['appended'][arm]['auc'])}
                        for arm in C.DETECTORS}
        summary[tag]['n'] = len(rows)

    out = {'note': __doc__.strip(),
           'corpus_spelling_census': spelling_census([r['corpus'] for r in per]),
           'summary': summary, 'per_scenario': per}
    dst = safe_out.resolve(RESULTS_DIR, 'order_sensitivity.json', 'OS')
    json.dump(out, open(dst, 'w'), indent=1)
    for tag, blk in summary.items():
        print(f"\n  == {tag} (n={blk['n']})")
        print(f"  {'arm':26s}{'interleaved':>13s}{'appended':>11s}{'delta':>10s}{'moved':>7s}")
        for arm in C.DETECTORS:
            b = blk[arm]
            print(f"  {arm:26s}{b['interleaved_mean_auc']:>13.4f}{b['appended_mean_auc']:>11.4f}"
                  f"{b['delta']:>+10.4f}{b['rows_moved']:>7d}")
    print(f"\n  wrote {dst}")


if __name__ == '__main__':
    main()
