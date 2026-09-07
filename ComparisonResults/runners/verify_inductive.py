"""Acceptance test: every arm must score a row independently of its batch.

The 2026-08-27 audit found four arms whose score for a FIXED row changed with the
composition of the test batch. That invalidated the comparison, because the panel
is 67% attack. This scores the SAME benign rows in batches padded with 0, 16 and
all available attack rows and requires the benign scores to be identical.

An arm that fails this is not a scoring function and cannot appear in a table.
"""
import json, os, sys
import numpy as np
from scipy import stats as st

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, 'negatives'))

from config import RESULTS_DIR
import run_crosscorpus_auc as R
import competitors_fixed as C
from run_post2023_benchmark import load_case, tkey

LABEL = 'CIC-IDS-2018 Tue-20-02_DDoS-LOIC-HTTP'   # 92.6% attack: worst case


def main():
    panel = json.load(open(os.path.join(RESULTS_DIR, 'panel_inventory', 'PANEL.json')))['panel']
    e = next(x for x in panel if x['label'] == LABEL)
    fit, cal, tb, atk = load_case(e)
    feats = R.active_features(fit)
    A = C.mat(fit, feats)
    B_ben = C.mat(tb, feats)
    B_atk = C.mat(atk, feats)
    nb = len(B_ben)
    print(f"{LABEL}\n  train={A.shape}  benign={nb}  attack={len(B_atk)}\n")

    pads = [0, 16, len(B_atk)]
    print(f"  {'arm':26s}{'pad=0':>12s}{'pad=16':>12s}{'pad=all':>12s}   {'max drift':>10s}  verdict")
    fails = []
    for name, (fn, _) in C.DETECTORS.items():
        runs = []
        for p in pads:
            batch = np.vstack([B_ben, B_atk[:p]]) if p else B_ben
            s = np.asarray(fn(A, batch), dtype=float)[:nb]
            runs.append(s)
        drift = max(float(np.max(np.abs(runs[0] - r))) for r in runs[1:])
        rho = min(st.spearmanr(runs[0], r).statistic for r in runs[1:])
        ok = drift < 1e-9
        if not ok:
            fails.append((name, drift, rho))
        print(f"  {name:26s}{runs[0].mean():>12.4f}{runs[1].mean():>12.4f}{runs[2].mean():>12.4f}"
              f"   {drift:>10.2e}  {'PASS' if ok else f'FAIL rho={rho:.4f}'}")

    print()
    if fails:
        print(f"  {len(fails)} arm(s) still batch-dependent: {[f[0] for f in fails]}")
        return 1
    print(f"  all {len(C.DETECTORS)} arms are inductive (benign scores bit-identical across batches)")
    return 0


if __name__ == '__main__':
    sys.exit(main())
