"""Benchmark every detector in post2023_competitors.DETECTORS on the 23-scenario panel.

Protocol, identical for every detector:
  * chronological order -- eval rows are sorted by timestamp, never
    benign-block-then-attack-block, because a stateful detector's score depends
    on array order and that ordering is backwards for this panel (31,020 of
    34,894 benign test windows fall AFTER the first attack window).
  * fit on training rows only.
  * two aggregations are reported because they answer different questions:
      per-scenario -- each scenario gets its own threshold; what a
                      per-host-tuned deployment achieves.
      pooled       -- ONE global threshold over every window; what a single
                      deployed threshold across all hosts achieves.

Writes to this tree's results/ directory only.
"""
import json
import os
import statistics
import sys
import time

import numpy as np
from sklearn.metrics import roc_auc_score
from scipy import stats as st

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..')))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..', '..', 'experiment')))
sys.path.insert(0, os.path.join(HERE, 'negatives'))

from config import RESULTS_DIR
import run_crosscorpus_auc as R
import post2023_competitors as C

OUT = os.path.join(RESULTS_DIR, 'post2023_benchmark_results.json')
TARGETS = (0.01, 0.02, 0.05)
REF = 'SPOT'


def dr_at(scores, y, fpr_target):
    th = np.percentile(scores[y == 0], (1.0 - fpr_target) * 100.0)
    return float(np.mean(scores[y == 1] > th) * 100.0)


def tkey(r):
    return r.get('_id_time', r.get('_dt', 0))


def load_case(entry):
    """Return (fit, calib, test_benign, test_attack) for a panel entry.

    Modes:
      within (default) -- causal split on the attack day: fit on pre-attack
                          benign, calib on trailing 20% of pre-attack, test on
                          post-attack benign + attack interleaved.
      treefile         -- file-based 60/20/20 benign split. Used where the
                          pre-attack benign window is too short (<300 s).
      crossfile        -- benign from an explicit benign file. Used where the
                          attack scenario has no pre-attack benign slice (e.g.
                          CIC-IoT-2023 DDoS-ICMP_Flood). The benign file is a
                          separate capture and so has no pre-attack history.
      crossday         -- fit on the training day, test on the attack day.
    """
    from config import CACHE_DIR, BASE
    mode = entry.get('mode', 'within')
    victim = entry.get('victim')

    def _load(p):
        actual_p = p
        if not os.path.exists(actual_p):
            candidates = [
                os.path.join(CACHE_DIR, p),
                os.path.join(CACHE_DIR, os.path.basename(p)),
                os.path.join(BASE, 'datasets', 'feature_caches', os.path.basename(p)),
                os.path.join(BASE, p.lstrip('./')),   # scrubbed records store './datasets/...'
                os.path.join(BASE, 'datasets', 'extracted', p.lstrip('./')),
                os.path.join(BASE, 'experiment', 'cache', os.path.basename(p)),
                os.path.join(HERE, '..', 'datasets', 'feature_caches', os.path.basename(p)),
                os.path.join(HERE, '..', '..', 'datasets', 'feature_caches', os.path.basename(p)),
            ]
            for c in candidates:
                if os.path.exists(c):
                    actual_p = c
                    break
        d = json.load(open(actual_p))
        return d.get('per_ip_windows', d)

    if mode == 'crossday':
        mon = _load(entry['train_cache']); day = _load(entry['cache'])
        if victim not in mon or victim not in day:
            return None, None, None, None
        mben = sorted([r for r in mon[victim] if not r.get('_is_attack')], key=tkey)
        cut = int(len(mben) * 0.8)
        test = sorted(day[victim], key=tkey)
        return (mben[:cut], mben[cut:],
                [r for r in test if not r.get('_is_attack')],
                [r for r in test if r.get('_is_attack')])

    per_ip = _load(entry['cache'])
    if victim not in per_ip and per_ip:
        victim = next(iter(per_ip))
    rows = sorted(per_ip.get(victim, []), key=tkey)

    if mode == 'treefile':
        ben = [r for r in rows if not r.get('_is_attack')]
        atk = [r for r in rows if r.get('_is_attack')]
        a, b = int(len(ben) * 0.6), int(len(ben) * 0.8)
        return ben[:a], ben[a:b], ben[b:], atk

    atk_idx = [i for i, r in enumerate(rows) if r.get('_is_attack')]
    if not atk_idx:
        return None, None, None, None
    first = atk_idx[0]
    pre = rows[:first]
    cut = int(len(pre) * 0.6)
    post = rows[first:]
    return (pre[:cut], pre[cut:],
            [r for r in post if not r.get('_is_attack')],
            [r for r in post if r.get('_is_attack')])


def main():
    load_case_from_entry = load_case
    panel = json.load(open(os.path.join(RESULTS_DIR, 'panel_inventory', 'PANEL.json')))['panel']

    names = list(C.DETECTORS)
    per_scen = {n: [] for n in names}
    aucs = {n: [] for n in names}
    pooled_b = {n: [] for n in names}
    pooled_a = {n: [] for n in names}
    failed = {n: 0 for n in names}
    rows, t0 = [], time.time()

    for e in panel:
        fit, cal, tb, atk = load_case_from_entry(e)
        if fit is None or len(fit) < 10 or len(atk) < 10:
            continue
        feats = R.active_features(fit)
        tagged = sorted([(tkey(r), 0, r) for r in tb] + [(tkey(r), 1, r) for r in atk],
                        key=lambda x: x[0])
        ev = [t[2] for t in tagged]
        y = np.array([t[1] for t in tagged])
        Xtr, Xev = C.mat(fit, feats), C.mat(ev, feats)

        rec = {'label': e['label'], 'n_attack': int(y.sum()), 'n_benign': int((y == 0).sum()),
               'scores': {}}
        for n in names:
            fn = C.DETECTORS[n][0]
            try:
                s = np.asarray(fn(Xtr, Xev), dtype=float)
                if s.shape[0] != len(y) or not np.all(np.isfinite(s)):
                    raise ValueError('bad score vector')
                aucs[n].append(roc_auc_score(y, s))
                per_scen[n].append({t: dr_at(s, y, t) for t in TARGETS})
                pooled_b[n].append(s[y == 0])
                pooled_a[n].append(s[y == 1])
                rec['scores'][n] = {'auc': round(float(roc_auc_score(y, s)), 4),
                                    **{f'dr@{int(t*100)}pct': round(dr_at(s, y, t), 2)
                                       for t in TARGETS}}
            except Exception as ex:
                failed[n] += 1
                rec['scores'][n] = {'error': str(ex)[:120]}
        rows.append(rec)
        print(f"  {e['label'][:52]:52s} done ({time.time()-t0:.0f}s)", flush=True)

    summary = {}
    for n in names:
        if not aucs[n]:
            summary[n] = {'status': f'FAILED on all scenarios ({failed[n]})',
                          'citation': C.DETECTORS[n][1]}
            continue
        b = np.concatenate(pooled_b[n])
        a = np.concatenate(pooled_a[n])
        pooled = {}
        for t in TARGETS:
            best = 0.0
            for th in np.unique(np.percentile(b, np.linspace(80, 100, 4001))):
                if (b > th).mean() <= t:
                    best = max(best, float((a > th).mean() * 100.0))
            pooled[f'dr@{int(t*100)}pct'] = round(best, 2)
        summary[n] = {
            'citation': C.DETECTORS[n][1],
            'n_scenarios': len(aucs[n]), 'n_failed': failed[n],
            'mean_auc': round(statistics.mean(aucs[n]), 4),
            'median_auc': round(statistics.median(aucs[n]), 4),
            'min_auc': round(min(aucs[n]), 4),
            'per_scenario': {f'dr@{int(t*100)}pct':
                             round(statistics.mean(d[t] for d in per_scen[n]), 2) for t in TARGETS},
            'pooled': pooled,
        }
    base = aucs.get('SPOT')
    for n in names:
        if aucs[n] and base and len(aucs[n]) == len(base) and n != 'SPOT':
            d = np.array(aucs[n]) - np.array(base)
            summary[n]['vs_spot_auc'] = round(float(np.mean(d)), 4)
            summary[n]['vs_spot_p'] = (1.0 if np.allclose(aucs[n], base)
                                       else round(float(st.wilcoxon(aucs[n], base,
                                                  zero_method='wilcox')[1]), 5))

    json.dump({'summary': summary, 'per_scenario': rows,
               'elapsed_sec': round(time.time() - t0, 1)}, open(OUT, 'w'), indent=1)

    order = sorted([n for n in names if aucs[n]], key=lambda n: -summary[n]['mean_auc'])
    print(f"\n{'detector':22s} {'meanAUC':>8s} {'medAUC':>8s} {'vsSPOT':>8s} {'p':>8s} | "
          f"{'per-scenario DR':^24s} | {'pooled DR':^24s}")
    print(f"{'':22s} {'':>8s} {'':>8s} {'':>8s} {'':>8s} | "
          f"{'@1%':>7s}{'@2%':>8s}{'@5%':>8s} | {'@1%':>7s}{'@2%':>8s}{'@5%':>8s}")
    print('-' * 118)
    for n in order:
        s = summary[n]
        print(f"{n:22s} {s['mean_auc']:>8.4f} {s['median_auc']:>8.4f} "
              f"{s.get('vs_spot_auc', 0.0):>+8.4f} {str(s.get('vs_spot_p', '-')):>8s} | "
              f"{s['per_scenario']['dr@1pct']:>7.2f}{s['per_scenario']['dr@2pct']:>8.2f}"
              f"{s['per_scenario']['dr@5pct']:>8.2f} | "
              f"{s['pooled']['dr@1pct']:>7.2f}{s['pooled']['dr@2pct']:>8.2f}"
              f"{s['pooled']['dr@5pct']:>8.2f}")
    for n in names:
        if not aucs[n]:
            print(f"{n:22s} {summary[n]['status']}")
    print(f"\n-> {OUT}  ({time.time()-t0:.0f}s)")


if __name__ == '__main__':
    main()
