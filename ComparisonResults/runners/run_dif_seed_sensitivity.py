#!/usr/bin/env python3
"""DIF seed sensitivity on PANEL-23: both competitor modules, random_state 42 against 7.

Writes results/dif_seed_sensitivity.json. Reconstructed on 2026-09-24 from the deposited
record's own structure (the record had been deposited without its runner); before the
feature-schedule change it reproduced the deposited record bit-exactly, and it was then
re-run with the two placeholder names excluded (README, CHANGE 2026-09-24).

Per scenario: the panel split of run_corrected_benchmark.py (load_case, R.active_features),
DIF scored by the archived module (post2023_competitors) and the corrected module
(competitors_fixed) at random_state 42 and 7. Summary: per-module means and seed deltas,
and the corrected-minus-archived panel delta at each seed -- the number Section 3.2 of the
main article attributes to the inductive correction.
"""
import json
import os
import statistics
import sys
import time

import numpy as np
from sklearn.metrics import roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..')))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..', '..', 'experiment')))

from config import RESULTS_DIR
from run_post2023_benchmark import load_case, tkey
import run_crosscorpus_auc as R
import post2023_competitors as ARCH
import competitors_fixed as CORR

SEEDS = (42, 7)
OUT = os.path.join(RESULTS_DIR, 'dif_seed_sensitivity.json')


def main():
    t0 = time.time()
    panel = json.load(open(os.path.join(RESULTS_DIR, 'panel_inventory', 'PANEL.json')))['panel']
    per = []
    for e in panel:
        fit, cal, tb, atk = load_case(e)
        if fit is None or len(fit) < 10 or len(atk) < 10:
            continue
        feats = R.active_features(fit)
        tg = sorted([(tkey(r), 0, r) for r in tb] + [(tkey(r), 1, r) for r in atk], key=lambda x: x[0])
        y = np.array([t[1] for t in tg])
        A = CORR.mat(fit, feats); B = CORR.mat([t[2] for t in tg], feats)
        row = {'label': e['label']}
        for tag, mod in (('archived', ARCH), ('corrected', CORR)):
            for seed in SEEDS:
                s = np.asarray(mod.dif_scores(A, B, random_state=seed), dtype=float)
                row[f'{tag}_{seed}'] = float(roc_auc_score(y, s))
        per.append(row)
        print(f"  {e['label'][:54]:54s} arch {row['archived_42']:.4f}/{row['archived_7']:.4f}"
              f"  corr {row['corrected_42']:.4f}/{row['corrected_7']:.4f} ({time.time()-t0:.0f}s)", flush=True)

    summary = {}
    for tag in ('archived', 'corrected'):
        a42 = [r[f'{tag}_42'] for r in per]; a7 = [r[f'{tag}_7'] for r in per]
        d = [abs(x - z) for x, z in zip(a42, a7)]
        i = int(np.argmax(d))
        summary[tag] = {
            'mean_auc_seed42': round(statistics.mean(a42), 6),
            'mean_auc_seed7': round(statistics.mean(a7), 6),
            'abs_delta_of_means': round(abs(statistics.mean(a42) - statistics.mean(a7)), 6),
            'per_scenario_abs_delta_mean': round(statistics.mean(d), 6),
            'per_scenario_abs_delta_median': round(statistics.median(d), 6),
            'per_scenario_abs_delta_max': round(max(d), 6),
            'max_scenario': per[i]['label'],
        }
    summary['panel_delta_corrected_minus_archived'] = {
        f'at_seed_{s}': round(statistics.mean(r[f'corrected_{s}'] for r in per)
                             - statistics.mean(r[f'archived_{s}'] for r in per), 6) for s in SEEDS}
    out = {
        'note': ('DIF seed sensitivity on PANEL-23, both competitor modules, random_state 42 against 7. '
                 'Supports the seed-robustness sentence in Section 2.5 and the attribution in Section 3.2. '
                 'The corrected-minus-archived attribution rests on both archived and corrected runs having '
                 'used seed 42, not on either module being seed-insensitive.'),
        'arm': 'DIF (Deep Isolation Forest)', 'population': 'PANEL-23', 'seeds': list(SEEDS),
        'modules': {'archived': 'post2023_competitors.py', 'corrected': 'competitors_fixed.py'},
        'per_scenario': per, 'summary': summary,
    }
    json.dump(out, open(OUT, 'w'), indent=1)
    print(json.dumps(summary, indent=1))
    print(f"wrote {OUT}  WALL_SECONDS={time.time()-t0:.2f}")


if __name__ == '__main__':
    main()
