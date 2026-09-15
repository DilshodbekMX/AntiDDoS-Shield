"""Joint filter: the clock-only null crossed with session provenance over PANEL-23.

Joins each PANEL-23 row's AUC difference, ours minus the peaks-over-threshold reference
(panel_auc_matrix.json, per_population), to that row's clock separability max(AUC, 1-AUC)
(clock_null.json). A row is clock-clean below the cut. A row is session-clean unless its
benign traffic is a separate capture from its attack traffic, which holds for every
CIC-IoT-2023 row and no other. Reads three deposited records (the two above and
panel_inventory/PANEL.json, which joins them); scores no detector.
"""
import os, sys, json
import numpy as np
import scipy
from scipy.stats import wilcoxon

HERE = os.path.dirname(os.path.abspath(__file__))
for p in (HERE, os.path.abspath(os.path.join(HERE, '..'))):
    sys.path.insert(0, p)

from config import RESULTS_DIR

OURS = 'Subspace-Q + EWMA (ours)'
REF = 'POT'
CUTS = (0.94, 0.95)
SEPARATE_CAPTURE_CORPORA = ('CIC-IoT-2023',)


def exact_p(x):
    """Exact two-sided signed-rank p; zero differences dropped (zero_method='wilcox')."""
    x = np.asarray(x, dtype=float)
    n = int(np.sum(x != 0))
    if n == 0:
        return None, 0, None
    p = float(wilcoxon(x, zero_method='wilcox', alternative='two-sided', method='exact').pvalue)
    return p, n, 2.0 / 2 ** n


def cluster_means(rows):
    by = {}
    for r in rows:
        by.setdefault(r['victim'], []).append(r['_delta'])
    return {v: float(np.mean(d)) for v, d in sorted(by.items())}


def stratum(rows, full_mean):
    if not rows:
        return {'n': 0}
    d = np.array([r['_delta'] for r in rows])
    p, n_inf, floor = exact_p(d)
    cm = cluster_means(rows)
    cp, c_inf, c_floor = exact_p(list(cm.values()))
    return {'n': len(rows),
            'rows': [r['label'] for r in rows],
            'mean_delta_auc': round(float(d.mean()), 6),
            'share_of_full_panel_pct': round(100.0 * float(d.mean()) / full_mean, 1),
            'wins': int(np.sum(d > 0)), 'losses': int(np.sum(d < 0)), 'ties': int(np.sum(d == 0)),
            'scenario_wilcoxon_p': p, 'scenario_informative_pairs': n_inf,
            'scenario_exact_floor': floor,
            'n_victim_clusters': len(cm),
            'cluster_mean_delta_auc': {v: round(m, 6) for v, m in cm.items()},
            'victim_cluster_mean': round(float(np.mean(list(cm.values()))), 6),
            'cluster_informative_pairs': c_inf,
            'cluster_wilcoxon_p': cp,
            'cluster_exact_floor': c_floor}


def main():
    matrix = json.load(open(os.path.join(RESULTS_DIR, 'panel_auc_matrix.json')))
    clock = json.load(open(os.path.join(RESULTS_DIR, 'clock_null.json')))['candidates']
    panel = json.load(open(os.path.join(RESULTS_DIR, 'panel_inventory', 'PANEL.json')))['panel']
    auc_rows = matrix['per_population']['PANEL-23']

    rows = []
    for e in panel:
        m = [r for r in auc_rows if r['label'] == e['label']]
        if e.get('mode') == 'crossday':
            c = [r for r in clock if r['file'] == e['label']]
        else:
            corp = os.path.basename(os.path.dirname(e['cache']))
            fn = os.path.basename(e['cache'])
            c = [r for r in clock if r['corpus'] == corp and r['file'] == fn
                 and r['victim'] == e['victim']]
        if len(m) != 1 or len(c) != 1:
            raise SystemExit(f"join failed for {e['label']}: {len(m)} AUC rows, {len(c)} clock rows")
        m, c = m[0], c[0]
        delta = m['auc'][OURS] - m['auc'][REF]
        rows.append({'label': e['label'], 'corpus': m['corpus'], 'victim': m['victim'],
                     'mode': e.get('mode'), 'delta_auc': round(delta, 6), '_delta': delta,
                     'clock_separability': c['clock_separability'], 'label_runs': c['label_runs'],
                     'separate_benign_capture': m['corpus'] in SEPARATE_CAPTURE_CORPORA})
    if len(rows) != len(auc_rows):
        raise SystemExit(f"joined {len(rows)} rows, PANEL-23 holds {len(auc_rows)}")

    full = stratum(rows, float(np.mean([r['_delta'] for r in rows])))
    full_mean = float(np.mean([r['_delta'] for r in rows]))
    print(f"  PANEL-23: {len(rows)} rows, mean delta {full['mean_delta_auc']:+.6f}, "
          f"victim-cluster mean {full['victim_cluster_mean']:+.6f}")

    cuts = {}
    for cut in CUTS:
        clean = [r for r in rows if r['clock_separability'] < cut]
        sep = [r for r in rows if r['clock_separability'] >= cut]
        both = [r for r in clean if not r['separate_benign_capture']]
        table = {'session_clean': {'clock_clean': len(both), 'clock_separated':
                                   sum(1 for r in sep if not r['separate_benign_capture'])},
                 'separate_benign_capture': {'clock_clean': len(clean) - len(both), 'clock_separated':
                                             sum(1 for r in sep if r['separate_benign_capture'])}}
        cc = stratum(clean, full_mean)
        cs = stratum(sep, full_mean)
        cuts[f'{cut:.2f}'] = {
            'rule': f'clock-clean iff clock_separability < {cut}',
            'contingency': table,
            'survivors_of_both': [{k: r[k] for k in ('label', 'victim', 'delta_auc',
                                                     'clock_separability', 'label_runs')}
                                  for r in both],
            'clock_clean': cc,
            'clock_separated': {k: cs[k] for k in ('n', 'rows', 'mean_delta_auc', 'wins', 'losses',
                                                   'ties', 'n_victim_clusters')}}
        print(f"  cut {cut}: clock-clean {len(clean)}, separated {len(sep)}, "
              f"survivors {[r['label'] for r in both]}")
        print(f"    clock-clean mean {cc['mean_delta_auc']:+.6f}  wins {cc['wins']}/{cc['n']}  "
              f"p {cc['scenario_wilcoxon_p']}  clusters {cc['n_victim_clusters']} "
              f"(informative {cc['cluster_informative_pairs']})  cluster p {cc['cluster_wilcoxon_p']} "
              f"floor {cc['cluster_exact_floor']}  separated-stratum mean {cs['mean_delta_auc']:+.6f}")

    dst = os.path.join(RESULTS_DIR, 'joint_filter.json')
    json.dump({'note': ('Joint filter over PANEL-23: clock-only null (clock_null.json, clock_separability = '
                        'max(AUC, 1-AUC)) crossed with session provenance (benign traffic a separate capture '
                        'from attack traffic: every CIC-IoT-2023 row). delta_auc = ours minus POT, from '
                        'panel_auc_matrix.json per_population PANEL-23. Wilcoxon tests are exact, two-sided, '
                        "zero_method='wilcox'; clusters are victim hosts, a cluster value being the mean delta "
                        'over that victim\'s rows; the exact floor is 2/2^n over n informative pairs. '
                        'Label-only and score-only: reads no traffic and scores no detector.'),
               'inputs': ['panel_auc_matrix.json', 'clock_null.json', 'panel_inventory/PANEL.json'],
               'arms': {'ours': OURS, 'reference': REF},
               'versions': {'numpy': np.__version__, 'scipy': scipy.__version__},
               'full_panel': {k: full[k] for k in ('n', 'mean_delta_auc', 'wins', 'losses', 'ties',
                                                   'n_victim_clusters', 'victim_cluster_mean')},
               'cuts': cuts,
               'rows': [{k: v for k, v in r.items() if k != '_delta'} for r in rows]},
              open(dst, 'w'), indent=1)
    print(f"  wrote {dst}")


if __name__ == '__main__':
    main()
