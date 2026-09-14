"""CESNET-TimeSeries24 anti-artifact control for the universal-EWMA tournament.

The panel leaderboard lives in run_universal_ewma_tournament.py. That script does
NOT touch CESNET, so the real-ISP false-alarm table had no code behind it. This
supplies it.

CESNET is benign-only -- no attacks, no labels, no synthetic generator -- so it
yields a false-alarm rate and nothing else. That is precisely its value: a floor
measured here cannot be dismissed as a testbed artifact.

Protocol, per host: fit on the train slice, take the threshold at the target
quantile of the HELD-OUT calibration slice, measure the realized FPR on the test
slice. Same causal EWMA (alpha = 0.5) applied to every smoothed arm.

NOTE: on CESNET the *_per_sec feature names carry HOURLY COUNTS, not rates
(data_loader.FEATURE_MAP applies no divisor). Scale-invariant scores are
unaffected; do not compare these magnitudes against the pcap corpora.

Writes to this tree's results/ directory only.
"""
import json
import os
import statistics
import sys
import time

import numpy as np
from scipy import stats as st

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..')))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..', '..', 'experiment')))
sys.path.insert(0, os.path.join(HERE, 'negatives'))

from config import RESULTS_DIR, TAR_PATH, TIMES_TAR, MIN_IP_ROWS_PER_IP
from data_loader import load_per_ip, AVAILABLE_FEATURES
from pipeline import split_ip_rows
import post2023_competitors as C

OUT = os.path.join(RESULTS_DIR, 'cesnet_ewma_control.json')
TARGETS = (0.01, 0.02, 0.05, 0.10)
ALPHA = 0.5
K = 8


def ewma(s, alpha=ALPHA):
    """Causal exponentially weighted mean; no lookahead."""
    out = np.zeros(len(s))
    cur = 0.0
    for i, v in enumerate(s):
        cur = alpha * v + (1.0 - alpha) * cur
        out[i] = cur
    return out


def subspace_q_ewma(train_mat, test_mat, k=K):
    """EWMA-smoothed ECOD surprise of the Lakhina orthogonal subspace residual.

    No SPOT term: dropping it measured better than fusing it on the panel
    (0.9936 vs 0.9928 mean AUC, 95.66% vs 90.45% DR at a matched 2% FPR).
    Falls back to SPOT when the training slice cannot support an SVD.
    """
    N, D = train_mat.shape
    if N < 2 * D:
        return C.spot_baseline_scores(train_mat, test_mat)
    mu = train_mat.mean(axis=0)
    sd = train_mat.std(axis=0)
    sd[sd < 1e-9] = 1.0
    Z_tr, Z_te = (train_mat - mu) / sd, (test_mat - mu) / sd
    _, _, Vt = np.linalg.svd(Z_tr, full_matrices=False)
    ke = min(k, Vt.shape[0])
    P = np.eye(D) - Vt[:ke].T @ Vt[:ke]
    Q_tr = np.sum((Z_tr @ P) ** 2, axis=1)
    Q_te = np.sum((Z_te @ P) ** 2, axis=1)
    Q_te_adj = Q_te - 1e-12 * np.maximum(1.0, Q_te)
    ge = N - np.searchsorted(np.sort(Q_tr), Q_te_adj, side='left')
    return ewma(-np.log(np.maximum(ge + 1.0, 1.0) / (N + 1.0)))


ARMS = {
    'SPOT': lambda a, b: C.spot_baseline_scores(a, b),
    'INNE + EWMA': lambda a, b: ewma(C.inne_scores(a, b)),
    'Subspace-Q + EWMA (ours)': subspace_q_ewma,
}


def main():
    t0 = time.time()
    ip_rows = load_per_ip(TAR_PATH, TIMES_TAR, min_rows=MIN_IP_ROWS_PER_IP)
    fpr = {n: {t: [] for t in TARGETS} for n in ARMS}
    n_hosts = n_test = 0

    for _, rows in ip_rows.items():
        tr, cal, te = split_ip_rows(rows)
        if len(te) < 20 or len(cal) < 20 or len(tr) < 40:
            continue
        A = C.mat(tr, AVAILABLE_FEATURES)
        B = C.mat(cal + te, AVAILABLE_FEATURES)
        nc = len(cal)
        n_hosts += 1
        n_test += len(te)
        for name, fn in ARMS.items():
            s = np.asarray(fn(A, B), dtype=float)
            cal_s, test_s = s[:nc], s[nc:]
            for t in TARGETS:
                th = np.percentile(cal_s, (1.0 - t) * 100.0)
                fpr[name][t].append(float((test_s > th).mean()))
        if n_hosts % 40 == 0:
            print(f"  {n_hosts} hosts ({time.time()-t0:.0f}s)", flush=True)

    summary = {}
    for name in ARMS:
        summary[name] = {}
        for t in TARGETS:
            v = fpr[name][t]
            summary[name][f'target_{int(t*100)}pct'] = {
                'realized_fpr_pct': round(100 * statistics.mean(v), 2),
                'std_pct': round(100 * statistics.pstdev(v), 2),
                'mean_abs_error_pp': round(100 * statistics.mean([abs(x - t) for x in v]), 2),
            }
    for t in TARGETS:
        a = [abs(x - t) for x in fpr['SPOT'][t]]
        for name in ('INNE + EWMA', 'Subspace-Q + EWMA (ours)'):
            b = [abs(x - t) for x in fpr[name][t]]
            p = 1.0 if np.allclose(a, b) else float(st.wilcoxon(b, a, zero_method='wilcox')[1])
            summary[name][f'target_{int(t*100)}pct']['vs_spot_p'] = round(p, 5)

    json.dump({'n_hosts': n_hosts, 'n_benign_test_windows': n_test,
               'alpha': ALPHA, 'k': K, 'summary': summary,
               'elapsed_sec': round(time.time() - t0, 1)}, open(OUT, 'w'), indent=1)

    print(f"\n{n_hosts} hosts, {n_test:,} benign test windows\n")
    print(f"  {'target':>7s} {'arm':26s} {'realized FPR':>13s} {'mean|err| pp':>13s} {'p vs SPOT':>10s}")
    for t in TARGETS:
        for name in ARMS:
            e = summary[name][f'target_{int(t*100)}pct']
            p = e.get('vs_spot_p')
            print(f"  {t*100:>6.0f}% {name:26s} {e['realized_fpr_pct']:>12.2f}% "
                  f"{e['mean_abs_error_pp']:>13.2f} {('-' if p is None else f'{p:.4f}'):>10s}")
        print()
    print(f"-> {OUT}  ({time.time()-t0:.0f}s)")


if __name__ == '__main__':
    main()
