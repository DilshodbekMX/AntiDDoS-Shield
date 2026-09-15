"""CESNET-TimeSeries24 benign control, re-scored through the corrected competitor registry.

Re-scores the three-arm benign control of run_cesnet_ewma_control.py and the seven-arm
CESNET summary of run_final_evaluation.py through competitors_fixed, with the same hosts,
splits, threshold rule and targets as those two runners, which import the uncorrected
post2023_competitors. Per host: split the hourly rows 60/15/25 in time order
(pipeline.split_ip_rows), fit on the train slice, take each threshold at the target
quantile of the held-out calibration slice, count alarms on the test slice. Rates are
host means. Our arm is the registry's subspace_q_ewma (k = 8, alpha = 0.5); the reference
is POT; every other arm gets the same causal EWMA.

Not re-scored: the pooled validation measurement of the unsmoothed k = 4 variant. Its
runner is not deposited and that variant is not in the registry.

CESNET carries no labels, so every window counts as benign and each rate bounds a
false-alarm rate from above. The *_per_sec names carry hourly counts (data_loader applies
no divisor); scale-invariant scores are unaffected.

Needs the CESNET export under $ANTIDDOS_BASE/datasets/cesnet. Writes
results/cesnet_corrected.json, including per-host alarm counts, so every rate and test
statistic in it can be recomputed from the record.
"""
import inspect
import json
import os
import platform
import statistics
import sys
import time

import numpy as np
import scipy
from scipy import stats as st

HERE = os.path.dirname(os.path.abspath(__file__))
for p in (HERE, os.path.abspath(os.path.join(HERE, '..'))):
    sys.path.insert(0, p)

from config import (BASE, RESULTS_DIR, TAR_PATH, TIMES_TAR, MIN_IP_ROWS_PER_IP,
                    TRAIN_FRAC, CALIB_FRAC)
from data_loader import load_per_ip, AVAILABLE_FEATURES
from pipeline import split_ip_rows
import competitors_fixed as C

OUT = os.path.join(RESULTS_DIR, 'cesnet_corrected.json')
SEED = 20260827
TARGETS = (0.01, 0.02, 0.05, 0.10)
PANEL_B_TARGETS = (0.01, 0.02, 0.05)
MIN_TRAIN, MIN_CALIB, MIN_TEST = 40, 20, 20
OURS = 'Subspace-Q + EWMA (ours)'
REF = 'POT'

ARMS = {
    OURS: C.subspace_q_ewma,
    'POT': C.pot_scores,
    'INNE + EWMA': lambda a, b: C.ewma(C.inne_scores(a, b)),
    'HBOS + EWMA': lambda a, b: C.ewma(C.hbos_scores(a, b)),
    'ECOD + EWMA': lambda a, b: C.ewma(C.ecod_scores(a, b)),
    'COPOD + EWMA': lambda a, b: C.ewma(C.copod_scores(a, b)),
    'LODA + EWMA': lambda a, b: C.ewma(C.loda_scores(a, b)),
}
PANEL_A_ARMS = (OURS, 'POT', 'INNE + EWMA')


def tkey(t):
    return f'target_{int(t * 100)}pct'


def main():
    t0 = time.time()
    np.random.seed(SEED)
    ip_rows = load_per_ip(TAR_PATH, TIMES_TAR, min_rows=MIN_IP_ROWS_PER_IP)

    hosts, n_train, n_calib, n_test = [], [], [], []
    alarms = {n: {t: [] for t in TARGETS} for n in ARMS}
    for ip, rows in ip_rows.items():
        tr, cal, te = split_ip_rows(rows)
        if len(te) < MIN_TEST or len(cal) < MIN_CALIB or len(tr) < MIN_TRAIN:
            continue
        A = C.mat(tr, AVAILABLE_FEATURES)
        B = C.mat(cal + te, AVAILABLE_FEATURES)
        nc = len(cal)
        hosts.append(ip)
        n_train.append(len(tr)); n_calib.append(nc); n_test.append(len(te))
        for name, fn in ARMS.items():
            s = np.asarray(fn(A, B), dtype=float)
            if s.shape[0] != len(B) or not np.all(np.isfinite(s)):
                raise SystemExit(f"{name}: bad scores on host {ip}")
            cal_s, test_s = s[:nc], s[nc:]
            for t in TARGETS:
                th = np.percentile(cal_s, (1.0 - t) * 100.0)
                alarms[name][t].append(int(np.sum(test_s > th)))
        if len(hosts) % 40 == 0:
            print(f"  {len(hosts)} hosts ({time.time()-t0:.0f}s)", flush=True)

    fpr = {n: {t: [a / m for a, m in zip(alarms[n][t], n_test)] for t in TARGETS} for n in ARMS}
    arms = {}
    for name in ARMS:
        arms[name] = {}
        for t in TARGETS:
            v = fpr[name][t]
            e = {'realized_fpr_pct': round(100 * statistics.mean(v), 2),
                 'std_pct': round(100 * statistics.pstdev(v), 2),
                 'mean_abs_error_pp': round(100 * statistics.mean([abs(x - t) for x in v]), 2)}
            if name != REF:
                a = [abs(x - t) for x in fpr[REF][t]]
                b = [abs(x - t) for x in v]
                p = 1.0 if np.allclose(a, b) else float(st.wilcoxon(b, a, zero_method='wilcox')[1])
                e['vs_pot_p'] = round(p, 5)
            arms[name][tkey(t)] = e

    panel_a = {n: {tkey(t): arms[n][tkey(t)] for t in TARGETS} for n in PANEL_A_ARMS}
    panel_b = {n: {tkey(t): arms[n][tkey(t)]['realized_fpr_pct'] for t in PANEL_B_TARGETS}
               for n in ARMS}

    record = {
        'note': ('CESNET-TimeSeries24 benign control re-scored through competitors_fixed. Same hosts, '
                 'splits, threshold rule and targets as cesnet_ewma_control.json (three arms) and '
                 'final_evaluation.json results.cesnet (seven arms), which were scored through '
                 'post2023_competitors; those records are left unchanged. Per host: time-ordered '
                 '60/15/25 split, threshold at the (1 - target) percentile of the calibration-slice '
                 'scores, alarm iff test score > threshold. realized_fpr_pct and std_pct are the mean '
                 'and population SD over hosts of the per-host test false-alarm rate; mean_abs_error_pp '
                 'is the host mean of |realized - nominal|; vs_pot_p is scipy.stats.wilcoxon(arm, POT, '
                 "zero_method='wilcox') on the per-host absolute calibration errors, 1.0 when the two are "
                 'allclose. Unlabelled corpus: every window is counted benign, so the rates bound a '
                 'false-alarm rate from above. Hourly counts under *_per_sec names. The pooled, unsmoothed '
                 'k = 4 validation measurement is not re-scored here.'),
        'inputs': [os.path.relpath(TAR_PATH, BASE), os.path.relpath(TIMES_TAR, BASE)],
        'uncorrected_counterparts': ['cesnet_ewma_control.json', 'final_evaluation.json'],
        'registry': 'competitors_fixed',
        'seed': SEED,
        'arm_random_state': {'INNE + EWMA': inspect.signature(C.inne_scores).parameters['random_state'].default,
                             'LODA + EWMA': inspect.signature(C.loda_scores).parameters['random_state'].default},
        'alpha': C.ALPHA, 'k': C.K, 'reference_arm': REF,
        'split': {'train_frac': TRAIN_FRAC, 'calib_frac': CALIB_FRAC, 'order': 'time'},
        'host_gate': {'min_rows': MIN_IP_ROWS_PER_IP, 'min_train': MIN_TRAIN,
                      'min_calib': MIN_CALIB, 'min_test': MIN_TEST},
        'targets_pct': [int(t * 100) for t in TARGETS],
        'n_hosts': len(hosts),
        'n_benign_test_windows': int(sum(n_test)),
        'versions': {'python': platform.python_version(), 'numpy': np.__version__,
                     'scipy': scipy.__version__, 'sklearn': __import__('sklearn').__version__,
                     'pyod': __import__('pyod').__version__},
        'arms': arms,
        'panel_a_three_arm': panel_a,
        'panel_b_seven_arm': panel_b,
        'per_host': {'host_ids': hosts, 'n_train': n_train, 'n_calib': n_calib, 'n_test': n_test,
                     'test_alarms': {n: {tkey(t): alarms[n][t] for t in TARGETS} for n in ARMS}},
        'elapsed_sec': round(time.time() - t0, 1),
    }
    with open(OUT, 'w') as fh:
        json.dump(record, fh, indent=1)

    print(f"\n{len(hosts)} hosts, {sum(n_test):,} benign test windows\n")
    print(f"  {'target':>7s} {'arm':26s} {'realized FPR':>13s} {'mean|err| pp':>13s} {'p vs POT':>10s}")
    for t in TARGETS:
        for name in ARMS:
            e = arms[name][tkey(t)]
            p = e.get('vs_pot_p')
            print(f"  {t*100:>6.0f}% {name:26s} {e['realized_fpr_pct']:>12.2f}% "
                  f"{e['mean_abs_error_pp']:>13.2f} {('-' if p is None else f'{p:.5f}'):>10s}")
        print()
    print(f"-> {OUT}  ({time.time()-t0:.0f}s)")


if __name__ == '__main__':
    main()
