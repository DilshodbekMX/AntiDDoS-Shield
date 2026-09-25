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
import safe_out

OURS = 'Subspace-Q + EWMA (ours)'
REF = 'POT'
EXPECTED_PANEL_VICTIMS = 9   # stated in the manuscript and recorded in PANEL.json
CUTS = (0.94, 0.95)
# Resolved through corpus_names so both spellings of every corpus map to one name.
# A single literal here silently flipped all six CIC-IoT rows to False whenever this
# runner met a filesystem-spelled record, taking the survivor count from two to eight.
from corpus_names import (is_separate_capture, canon, spelling_census, victim_key,
                          normalise_victim)


def exact_p(x):
    """Exact two-sided signed-rank p; zero differences dropped (zero_method='wilcox')."""
    x = np.asarray(x, dtype=float)
    n = int(np.sum(x != 0))
    if n == 0:
        return None, 0, None
    p = float(wilcoxon(x, zero_method='wilcox', alternative='two-sided', method='exact').pvalue)
    return p, n, 2.0 / 2 ** n


def panel_victims():
    """Canonical victim set of PANEL-23, from the panel inventory alone.

    This is the independent anchor. It is derived from PANEL.json's own corpus paths and
    victim addresses, not from any record being checked, so a missed merge (one victim
    left under two keys) or a wrong merge (two victims collapsed into one) both change
    its size and both raise. Comparing canonical against raw key counts cannot do that:
    canon() is a function, so the canonical count is bounded by the raw count by
    construction and the comparison can never fail.
    """
    panel = json.load(open(os.path.join(RESULTS_DIR, 'panel_inventory', 'PANEL.json')))['panel']
    keys, by_addr = set(), {}
    for e in panel:
        corp = os.path.basename(os.path.dirname(str(e['cache'])))
        k = victim_key(corp, e.get('victim'))
        keys.add(k)
        # no address may sit under two canonical keys inside one corpus
        c, a = k.split('/', 1)
        by_addr.setdefault((c, a), set()).add(k)
    bad = {p: v for p, v in by_addr.items() if len(v) > 1}
    assert not bad, f'an address maps to more than one canonical key: {bad}'
    assert len(keys) == EXPECTED_PANEL_VICTIMS, (
        f'panel victim census is {len(keys)}, expected {EXPECTED_PANEL_VICTIMS}; a merge was '
        f'missed or made wrongly: {sorted(keys)}')
    return keys


def joint_clean_stratum():
    """Joint-clean statistics under both splits, with the cluster count asserted.

    The stratum is the rows passing both of our own criteria: clock-clean and drawing
    benign traffic from the attack capture. Detector deltas come from panel_auc_matrix
    for the deposited split and from split_control_threeway60_matrix for the repaired
    one; a row the repair leaves untouched keeps its deposited delta, which is stated
    per row in carried_rows.

    Every victim passes through normalise_victim first, because the two matrices key
    victims differently, and the runner then asserts that the cluster count equals the
    number of distinct canonical victims. Without that assertion a raw-string join splits
    one victim in two, lowers the exact floor and can make 5% look reachable.
    """
    csp = os.path.join(RESULTS_DIR, 'clock_split_sensitivity.json')
    if not os.path.exists(csp):
        return None
    cs = {r['label']: r for r in json.load(open(csp))['per_scenario']}
    PANEL_VICTIMS = panel_victims()
    dep = {r['scenario']: r for r in json.load(
        open(os.path.join(RESULTS_DIR, 'panel_auc_matrix.json')))['per_population']['PANEL-23']}
    repp = os.path.join(RESULTS_DIR, 'split_control_threeway60_matrix.json')
    rep = {}
    if os.path.exists(repp):
        m = json.load(open(repp))['per_population']
        rep = {r['scenario']: r for r in m.get('PANEL-22', m.get('PANEL-23', []))}

    out = {}
    for split, src_primary in (('deposited_split', None), ('threeway_split', rep)):
        labels = [l for l, r in cs.items()
                  if r[split]['clock_separability'] < 0.95 and not r['separate_benign_capture']]
        if not labels:
            continue
        rows, carried = {}, []
        for l in labels:
            if src_primary and l in src_primary:
                rows[l] = src_primary[l]
            else:
                if src_primary is not None:
                    carried.append(l)
                rows[l] = dep[l]
        d = [rows[l]['auc'][OURS] - rows[l]['auc'][REF] for l in labels]
        raw = [str(rows[l]['victim']) for l in labels]
        vics = [normalise_victim(rows[l]['victim'], cs[l]['corpus']) for l in labels]
        groups = sorted(set(vics))
        n_raw = len(set(raw))            # diagnostic only, see below
        # The canonical count can never exceed the raw count, because canon() is a
        # function, so comparing the two guarantees nothing. Check instead against a count
        # derived independently of these keys: the panel inventory's own victim set.
        assert set(groups) <= PANEL_VICTIMS, (
            f'stratum victims outside the panel set: {sorted(set(groups) - PANEL_VICTIMS)}')
        cmeans = [float(np.mean([d[i] for i, v in enumerate(vics) if v == g])) for g in groups]
        nz = [x for x in cmeans if abs(x) > 1e-12]
        p = 1.0 if not nz else float(wilcoxon(cmeans, zero_method='wilcox')[1])
        out[split] = {'n': len(labels), 'mean_delta_auc': round(float(np.mean(d)), 6),
                      'n_victim_clusters_raw_keys_diagnostic': n_raw,
                      'wins': sum(1 for x in d if x > 0),
                      'n_victim_clusters': len(groups), 'victims': groups,
                      'cluster_wilcoxon_p': round(p, 5),
                      'cluster_informative_pairs': len(nz),
                      'cluster_exact_floor': 2 / 2 ** len(nz) if nz else None,
                      'carried_rows': carried,
                      'reachable_at_5pct': bool(nz) and (2 / 2 ** len(nz)) < 0.05}
    return out or None


def repaired_cross():
    """The same 2x2, recomputed under the repaired split.

    Table 11 needs both panels, and this runner is one of the two that regenerate from the
    deposit alone, so the repaired counts belong here rather than in a second file the
    reader has to join by hand. Reads results/clock_split_sensitivity.json, which carries
    both splits per row; returns None if that record is absent.
    """
    p = os.path.join(RESULTS_DIR, 'clock_split_sensitivity.json')
    if not os.path.exists(p):
        return None
    cs = json.load(open(p))['per_scenario']
    out = {}
    for split in ('deposited_split', 'threeway_split'):
        cell = {}
        for prov, want in (('session_clean', False), ('separate_benign_capture', True)):
            sel = [r for r in cs if r['separate_benign_capture'] is want]
            cell[prov] = {'clock_clean': sum(1 for r in sel if r[split]['clock_separability'] < 0.95),
                          'clock_separates': sum(1 for r in sel if r[split]['clock_separability'] >= 0.95)}
        cell['n'] = len(cs)
        out[split] = cell
    out['note'] = ('The clock reads the test stream labels only, so every row is measurable '
                   'under both splits. The repair is a no-op on the six CIC-IoT-2023 rows '
                   '(index-collision order) and on the cross-day row (test stream is the whole '
                   'attack day, never truncated). Detector re-scoring covers 22 of these 23 '
                   'rows: the cross-day training cache is not in the deposit.')
    return out


def cluster_means(rows):
    # Key on corpus AND address. A bare address would merge two victims silently the day
    # two corpora share a private range; no address currently collides, so this renames
    # the keys and changes no membership and no statistic.
    by = {}
    for r in rows:
        by.setdefault(victim_key(r['corpus'], r['victim']), []).append(r['_delta'])
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
                     'separate_benign_capture': is_separate_capture(m['corpus'])})
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

    dst = safe_out.resolve(RESULTS_DIR, 'joint_filter.json', 'JF')
    json.dump({'note': ('Joint filter over PANEL-23: clock-only null (clock_null.json, clock_separability = '
                        'max(AUC, 1-AUC)) crossed with session provenance (benign traffic a separate capture '
                        'from attack traffic: every CIC-IoT-2023 row). delta_auc = ours minus POT, from '
                        'panel_auc_matrix.json per_population PANEL-23. Wilcoxon tests are exact, two-sided, '
                        "zero_method='wilcox'; clusters are victim hosts, a cluster value being the mean delta "
                        'over that victim\'s rows; the exact floor is 2/2^n over n informative pairs. '
                        'Label-only and score-only: reads no traffic and scores no detector.'),
               'inputs': ['panel_auc_matrix.json', 'clock_null.json', 'panel_inventory/PANEL.json'],
               'corpus_spelling_census': spelling_census([r['corpus'] for r in rows]),
               'repaired_split_cross': repaired_cross(),
               'joint_clean_stratum': joint_clean_stratum(),
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
