"""Fifth admissibility check: what does a detector that reads NO traffic score?

score_i = -(window index). A label that is a step function of the clock is separated
perfectly by this null, and whatever AUC it earns is unavailable to the traffic.
Label-only: uses y alone, never a feature value.
"""
import os, sys, json
import numpy as np
from sklearn.metrics import roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
for p in (HERE, os.path.abspath(os.path.join(HERE, '..'))):
    sys.path.insert(0, p)

from config import RESULTS_DIR
import run_29_scenarios_corrected as R29

def label_runs(y):
    return 1 + int(np.sum(np.asarray(y)[1:] != np.asarray(y)[:-1])) if len(y) else 0

def main():
    EXTRACTED = R29.EXTRACTED
    out = []
    for corp in sorted(os.listdir(EXTRACTED)):
        ix = os.path.join(EXTRACTED, corp, 'index.json')
        if not os.path.exists(ix):
            continue
        d = json.load(open(ix))
        # exactly collect()'s extraction (run_29_scenarios_corrected.py:80-83), minus the verdict filter
        items = d if isinstance(d, list) else (list(d.values())[0] if len(d) == 1 else list(d.values()))
        if isinstance(items, dict):
            items = list(items.values())
        for e in items:
            if not isinstance(e, dict):
                continue
            fn = e.get('file') or (str(e.get('attack_type')) + '.json')
            verdict = e.get('verdict')
            rec = {'corpus': corp, 'file': fn, 'verdict': verdict,
                   'victim': e.get('victim'), 'clock_auc': None, 'label_runs': None,
                   'n': None, 'attack_frac': None, 'note': ''}
            try:
                path = os.path.join(EXTRACTED, corp, fn)
                fit, cal, tb, atk = R29.load_case_tree(path, e.get('victim'), e.get('split_mode'))
                if fit is None or not tb or not atk:
                    rec['note'] = 'no scorable stream'
                else:
                    tagged = sorted([(R29.tkey(r), 0, r) for r in tb] +
                                    [(R29.tkey(r), 1, r) for r in atk], key=lambda x: x[0])
                    y = np.array([t[1] for t in tagged])
                    clock = -np.arange(len(y), dtype=float)
                    a = float(roc_auc_score(y, clock))
                    rec['clock_auc'] = round(a, 4)
                    rec['clock_separability'] = round(max(a, 1 - a), 4)
                    rec['label_runs'] = label_runs(y)
                    rec['n'] = int(len(y))
                    rec['attack_frac'] = round(float(y.mean()), 4)
            except Exception as ex:
                rec['note'] = f'{type(ex).__name__}: {str(ex)[:60]}'
            out.append(rec)
            print(f"  {corp:22s} {fn[:40]:42s} {str(verdict):16s} "
                  f"clock={rec['clock_auc']} runs={rec['label_runs']} {rec['note']}", flush=True)

    # PANEL-23 scores one scenario under a second split (cross-day). That variant has its own
    # stream and its own label vector, so it needs its own clock score: inheriting the within-day
    # value would be wrong, and by a margin that crosses the 0.95 cut.
    try:
        from run_post2023_benchmark import load_case
        panel = json.load(open(os.path.join(RESULTS_DIR, 'panel_inventory', 'PANEL.json')))['panel']
        for e in panel:
            if e.get('mode') != 'crossday':
                continue
            fit, cal, tb, atk = load_case(e)
            if not tb or not atk:
                continue
            tagged = sorted([(R29.tkey(r), 0, r) for r in tb] + [(R29.tkey(r), 1, r) for r in atk],
                            key=lambda x: x[0])
            y = np.array([t[1] for t in tagged])
            a = float(roc_auc_score(y, -np.arange(len(y), dtype=float)))
            out.append({'corpus': e['corpus'], 'file': e['label'], 'verdict': 'USABLE',
                        'victim': e.get('victim'), 'clock_auc': round(a, 4),
                        'label_runs': label_runs(y), 'n': int(len(y)),
                        'attack_frac': round(float(y.mean()), 4),
                        'clock_separability': round(max(a, 1 - a), 4),
                        'note': 'PANEL-23 cross-day split of an already-listed scenario; scored on its own stream'})
            print(f"  {e['corpus']:22s} {e['label'][:40]:42s} {'crossday':16s} "
                  f"clock={round(a,4)} runs={label_runs(y)}", flush=True)
    except Exception as ex:
        print(f"  cross-day variant not scored: {type(ex).__name__}: {ex}")

    scored = [r for r in out if r['clock_auc'] is not None]
    print(f"\n  {len(out)} candidates, {len(scored)} with a scorable stream")
    summary = None
    if scored:
        a = [r['clock_separability'] for r in scored]
        summary = {'n_candidates': len(out), 'n_scored': len(scored),
                   'mean_separability': round(float(np.mean(a)), 4),
                   'perfect_1_0': sum(1 for x in a if x >= 0.9999),
                   'ge_0_95': sum(1 for x in a if x >= 0.95),
                   'le_0_6': sum(1 for x in a if x <= 0.6),
                   'two_label_runs': sum(1 for r in scored if r.get('label_runs') == 2)}
        print(f"  clock separability max(AUC,1-AUC): mean {summary['mean_separability']:.4f}"
              f"  perfect {summary['perfect_1_0']}  >=0.95 {summary['ge_0_95']}  <=0.6 {summary['le_0_6']}")
        two = [r for r in scored if r['label_runs'] == 2]
        print(f"  exactly two label runs: {len(two)} -> {[r['file'][:30] for r in two]}")
    dst = os.path.join(RESULTS_DIR, 'clock_null.json')
    json.dump({'note': ('clock-only null, score = -(window index); label-only, reads no traffic. '
                        'clock_separability = max(AUC, 1-AUC): an AUC of 0.0 is perfect separation '
                        'with the sign reversed and disqualifies a scenario exactly as much as 1.0.'),
               'summary': summary, 'candidates': out}, open(dst, 'w'), indent=1)
    print(f"  wrote {dst}")

if __name__ == '__main__':
    main()
