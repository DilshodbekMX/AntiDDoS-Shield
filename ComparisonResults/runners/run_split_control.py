"""Corrected competitor benchmark: inductive arms, honest inference.

Replaces run_post2023_benchmark.py / run_final_evaluation.py for the comparison
table. Three things are different, all of them consequences of the 2026-08-27
audit:

  1. Every arm is inductive (verify_inductive.py is the gate).
  2. Significance is reported CORRECTED (Holm and Bonferroni over the arm family)
     and at the CLUSTER level (victim host), because the scenarios are not
     independent -- the 17-scenario population comes from 6 victims.
  3. Benign alarm EPISODES are reported beside AUC, because this project's
     standing rule is that the episode metric is the judge.

No hyperparameter of ours is selected here; k=8 and alpha=0.5 are inherited. That
does NOT make this a held-out test -- see the resubstitution caveat in the
report. This runner measures; it does not license a superiority claim.
"""
import gc, json, os, statistics, sys, time
import numpy as np
from sklearn.metrics import roc_auc_score
from scipy import stats as st

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..')))

from config import RESULTS_DIR
from corpus_names import canon, victim_key, spelling_census
import safe_out
import run_crosscorpus_auc as R
import competitors_fixed as C
from run_post2023_benchmark import load_case, tkey, dr_at

EXTRACTED = os.path.join(os.environ.get('ANTIDDOS_BASE', '/home/detector/Projects/antiddos'),
                         'datasets', 'extracted')
OUT = safe_out.resolve(RESULTS_DIR, 'split_control_benchmark.json', 'SC')
TARGETS = (0.01, 0.02, 0.05)
PER_SCEN = {}
POP = None   # which population is currently being scored
REF = 'POT'
SEED = 20260827


def episodes(flags, cooldown=30):
    idx = np.flatnonzero(flags)
    return 0 if len(idx) == 0 else 1 + int(np.sum(np.diff(idx) > cooldown))


def score_case(A, B, y, acc, meta, key):
    for n, (fn, _) in C.DETECTORS.items():
        try:
            s = np.asarray(fn(A, B), dtype=float)
            if s.shape[0] != len(y) or not np.all(np.isfinite(s)):
                raise ValueError('bad scores')
            nb = int((y == 0).sum())
            rec = {'auc': float(roc_auc_score(y, s)), 'meta': meta}
            for t in TARGETS:
                rec[f'dr{int(t*100)}'] = dr_at(s, y, t)
                th = np.percentile(s[y == 0], (1 - t) * 100)
                rec[f'ep{int(t*100)}'] = 1000.0 * episodes((s > th) & (y == 0)) / max(nb, 1)
            acc[n].append(rec)
            slot = PER_SCEN.setdefault(POP, {}).setdefault(
                key, {'meta': meta, 'auc': {}, 'ep1': {}, 'ep2': {}, 'ep5': {}})
            slot['auc'][n] = rec['auc']
            for t in TARGETS:
                slot[f'ep{int(t*100)}'][n] = rec[f'ep{int(t*100)}']
        except Exception as ex:
            acc[n].append(None)
            print(f"      !! {n} failed on {key}: {str(ex)[:70]}", flush=True)


def boot_ci(d, n=10000, seed=SEED):
    rng = np.random.default_rng(seed)
    d = np.asarray(d)
    m = rng.choice(d, size=(n, len(d)), replace=True).mean(axis=1)
    return float(np.percentile(m, 2.5)), float(np.percentile(m, 97.5))


def cluster_boot_ci(d, groups, n=10000, seed=SEED):
    """Resample CLUSTERS, not scenarios."""
    rng = np.random.default_rng(seed)
    uniq = sorted(set(groups))
    by = {g: np.array([d[i] for i, x in enumerate(groups) if x == g]) for g in uniq}
    out = []
    for _ in range(n):
        pick = rng.choice(len(uniq), size=len(uniq), replace=True)
        out.append(np.concatenate([by[uniq[i]] for i in pick]).mean())
    return float(np.percentile(out, 2.5)), float(np.percentile(out, 97.5))


def summarise(acc, label, out):
    names = [n for n in C.DETECTORS if any(acc[n])]
    base = [r['auc'] for r in acc[REF] if r]
    groups_all = [r['meta']['victim'] for r in acc[REF] if r]
    rows = {}
    raw_p = {}

    for n in names:
        vals = [r for r in acc[n] if r]
        if not vals:
            continue
        e = {'n': len(vals),
             'mean_auc': round(statistics.mean(v['auc'] for v in vals), 4),
             'median_auc': round(statistics.median(v['auc'] for v in vals), 4),
             'min_auc': round(min(v['auc'] for v in vals), 4),
             'citation': C.DETECTORS[n][1]}
        for t in TARGETS:
            k = int(t * 100)
            e[f'dr@{k}pct'] = round(statistics.mean(v[f'dr{k}'] for v in vals), 2)
            e[f'ep@{k}pct'] = round(statistics.mean(v[f'ep{k}'] for v in vals), 2)
        if n != REF and len(vals) == len(base):
            a = np.array([v['auc'] for v in vals]); b = np.array(base)
            d = a - b
            e['vs_ref_auc'] = round(float(d.mean()), 4)
            p = 1.0 if np.allclose(a, b) else float(st.wilcoxon(a, b, zero_method='wilcox')[1])
            e['vs_ref_p_raw'] = round(p, 5); raw_p[n] = p
            e['wins'] = f"{int((d > 0).sum())}/{len(d)}"
            e['boot_ci'] = [round(x, 4) for x in boot_ci(d)]
            e['cluster_boot_ci'] = [round(x, 4) for x in cluster_boot_ci(d, groups_all)]
            # cluster-level paired test: mean per victim
            gs = sorted(set(groups_all))
            ca = [np.mean([a[i] for i, g in enumerate(groups_all) if g == gg]) for gg in gs]
            cb = [np.mean([b[i] for i, g in enumerate(groups_all) if g == gg]) for gg in gs]
            e['n_clusters'] = len(gs)
            e['cluster_p'] = (1.0 if np.allclose(ca, cb)
                              else round(float(st.wilcoxon(ca, cb, zero_method='wilcox')[1]), 5))
        rows[n] = e

    # Holm + Bonferroni over the arm family
    m = len(raw_p)
    order = sorted(raw_p, key=lambda n: raw_p[n]); mx = 0.0
    for i, n in enumerate(order):
        rows[n]['vs_ref_p_bonf'] = round(min(raw_p[n] * m, 1.0), 5)
        adj = min(max(raw_p[n] * (m - i), mx), 1.0); mx = adj
        rows[n]['vs_ref_p_holm'] = round(adj, 5)
    for n in rows:
        if 'vs_ref_p_raw' in rows[n]:
            rows[n]['family_size'] = m

    print(f"\n{label}  (n = {len(base)} scenarios, {len(set(groups_all))} victim clusters)")
    print(f"  {'arm':26s}{'meanAUC':>9s}{'vsPOT':>8s}{'p_raw':>8s}{'p_holm':>8s}"
          f"{'clus_p':>8s}{'wins':>7s}{'DR@2%':>7s}{'ep@2%':>7s}")
    print('  ' + '-' * 88)
    for n in sorted(rows, key=lambda n: -rows[n]['mean_auc']):
        e = rows[n]
        print(f"  {n:26s}{e['mean_auc']:>9.4f}{e.get('vs_ref_auc', 0.0):>+8.4f}"
              f"{str(e.get('vs_ref_p_raw', '-')):>8s}{str(e.get('vs_ref_p_holm', '-')):>8s}"
              f"{str(e.get('cluster_p', '-')):>8s}{e.get('wins', '-'):>7s}"
              f"{e[f'dr@2pct']:>7.2f}{e[f'ep@2pct']:>7.2f}")
    out[label] = rows
    return rows


def diagnostics(by_pop, ours='Subspace-Q + EWMA (ours)'):
    """Concentration, leave-one-victim-out and episode tests, for EVERY population.

    Section 3.4's concentration and leave-one-out figures were USABLE-strict only; PANEL-23,
    the population the abstract leads with, had no equivalent. Section 3.5's episode claim was
    an arm-level mean with no paired or clustered test behind it. Both are computed here.
    """
    out = {}
    for pop, rows in by_pop.items():
        rows = [r for r in rows if ours in r['auc'] and REF in r['auc']]
        if not rows:
            continue
        d = np.array([r['auc'][ours] - r['auc'][REF] for r in rows])
        vic = [r['victim'] for r in rows]
        tot = float(d.sum())
        top = int(np.argmax(d))
        uniq = sorted(set(vic))
        by_v = {g: float(sum(d[i] for i, x in enumerate(vic) if x == g)) for g in uniq}
        top_v = max(by_v, key=lambda g: by_v[g])
        loo = {g: round(float(np.mean([d[i] for i, x in enumerate(vic) if x != g])), 6)
               for g in uniq}
        e = {'n_scenarios': len(rows), 'n_victim_clusters': len(uniq),
             'sum_delta_auc': round(tot, 6), 'mean_delta_auc': round(float(d.mean()), 6),
             'top_scenario': rows[top]['scenario'],
             'top_scenario_delta': round(float(d[top]), 6),
             'top_scenario_share_pct': round(100.0 * d[top] / tot, 1) if tot else None,
             'top_victim': top_v,
             'top_victim_share_pct': round(100.0 * by_v[top_v] / tot, 1) if tot else None,
             'mean_after_deleting_top_scenario':
                 round(float(np.mean(np.delete(d, top))), 6),
             'max_other_single_deletion_shift':
                 round(max(abs(float(np.mean(np.delete(d, i))) - float(d.mean()))
                           for i in range(len(d)) if i != top), 6),
             'victim_cluster_mean': round(float(np.mean([
                 np.mean([d[i] for i, x in enumerate(vic) if x == g]) for g in uniq])), 6),
             'leave_one_victim_out_mean_delta': loo}
        # paired and clustered tests on the DECLARED primary metric: benign episodes
        eps = {}
        for t in TARGETS:
            k = f'ep{int(t * 100)}'
            a = np.array([r[k][ours] for r in rows if ours in r[k] and REF in r[k]])
            b = np.array([r[k][REF] for r in rows if ours in r[k] and REF in r[k]])
            gv = [r['victim'] for r in rows if ours in r[k] and REF in r[k]]
            de = a - b
            ca = [float(np.mean([a[i] for i, x in enumerate(gv) if x == g])) for g in uniq]
            cb = [float(np.mean([b[i] for i, x in enumerate(gv) if x == g])) for g in uniq]
            eps[k] = {
                'mean_ours': round(float(a.mean()), 4), 'mean_ref': round(float(b.mean()), 4),
                'scenarios_ours_fewer': int((de < 0).sum()),
                'scenarios_ours_more': int((de > 0).sum()),
                'scenarios_tied': int((de == 0).sum()),
                'median_delta': round(float(np.median(de)), 4),
                'paired_wilcoxon_p': (1.0 if np.allclose(a, b) else
                                      round(float(st.wilcoxon(a, b,
                                            zero_method='wilcox')[1]), 5)),
                'cluster_mean_ours': [round(x, 4) for x in ca],
                'cluster_mean_ref': [round(x, 4) for x in cb],
                'cluster_wilcoxon_p': (1.0 if np.allclose(ca, cb) else
                                       round(float(st.wilcoxon(ca, cb,
                                             zero_method='wilcox')[1]), 5)),
                'clusters_ours_fewer': int(sum(1 for x, y in zip(ca, cb) if x < y)),
                'n_clusters': len(uniq)}
        e['episodes'] = eps
        out[pop] = e
        print(f"\n  [{pop}] concentration: {e['top_scenario']} = "
              f"{e['top_scenario_share_pct']}% of the summed effect; "
              f"top victim {e['top_victim_share_pct']}%; "
              f"cluster mean {e['victim_cluster_mean']}")
        for k, v in eps.items():
            print(f"    {k}: ours {v['mean_ours']} vs ref {v['mean_ref']}; "
                  f"ours fewer in {v['scenarios_ours_fewer']}/{v['n_scenarios'] if 'n_scenarios' in v else len(rows)}"
                  f" scenarios, {v['clusters_ours_fewer']}/{v['n_clusters']} clusters; "
                  f"paired p={v['paired_wilcoxon_p']}, cluster p={v['cluster_wilcoxon_p']}")
    return out


def main():
    t0 = time.time()
    out = {}
    _raw_corpora = []
    panel = json.load(open(os.path.join(RESULTS_DIR, 'panel_inventory', 'PANEL.json')))['panel']
    if os.environ.get('SC_INTRACK_ONLY', '1') == '1':
        base = os.environ.get('ANTIDDOS_BASE', os.path.dirname(os.path.dirname(HERE)))
        def _intrack(e):
            for fld in ('cache', 'train_cache'):
                q = e.get(fld)
                if not q:
                    continue
                if not (os.path.exists(os.path.join(base, str(q).lstrip('./')))
                        or os.path.exists(str(q))):
                    return False
            return True
        kept = [e for e in panel if _intrack(e)]
        dropped = [e['label'] for e in panel if not _intrack(e)]
        if dropped:
            print('SC_INTRACK_ONLY: dropped %d of %d panel rows whose inputs are not in the '
                  'track: %s' % (len(dropped), len(panel), '; '.join(dropped)), flush=True)
        panel = kept

    global POP
    POP = 'PANEL-23'
    # ---------- PANEL (own splits) ----------
    acc = {n: [] for n in C.DETECTORS}
    for e in panel:
        fit, cal, tb, atk = load_case(e)
        if fit is None or len(fit) < 10 or len(atk) < 10:
            continue
        feats = R.active_features(fit)
        tg = sorted([(tkey(r), 0, r) for r in tb] + [(tkey(r), 1, r) for r in atk], key=lambda x: x[0])
        y = np.array([t[1] for t in tg])
        _corp = os.path.basename(os.path.dirname(str(e['cache'])))
        _raw_corpora.append(_corp)
        meta = {'label': e['label'], 'victim': victim_key(_corp, e.get('victim') or e['label']),
                'corpus': canon(_corp),
                'attack_frac': round(float(y.mean()), 4)}
        score_case(C.mat(fit, feats), C.mat([t[2] for t in tg], feats), y, acc, meta, e['label'])
        print(f"  panel: {e['label'][:54]:54s} ({time.time()-t0:.0f}s)", flush=True)
    summarise(acc, os.environ.get('SC_POPNAME', 'PANEL-23'), out)

    POP = 'USABLE-strict'
    # ---------- FULL TREE, USABLE only, one strict causal split ----------
    accu = {n: [] for n in C.DETECTORS}
    for corp in sorted(os.listdir(EXTRACTED)):
        ix = os.path.join(EXTRACTED, corp, 'index.json')
        if not os.path.isfile(ix) or corp == 'CESNET-TimeSeries24':
            continue
        d = json.load(open(ix))
        items = d if isinstance(d, list) else (list(d.values())[0] if len(d) == 1 else list(d.values()))
        if isinstance(items, dict):
            items = list(items.values())
        for e in items:
            if not isinstance(e, dict) or e.get('verdict') != 'USABLE':
                continue
            fn = e.get('file') or (str(e.get('attack_type')) + '.json')
            p = os.path.join(EXTRACTED, corp, fn)
            if not os.path.exists(p) or os.path.getsize(p) > 120e6:
                continue
            try:
                dd = json.load(open(p)); pi = dd.get('per_ip_windows', {})
                vic = e.get('victim') if e.get('victim') in pi else next(iter(pi), None)
                rr = sorted(pi.get(vic, []), key=tkey)
                ai = [i for i, r in enumerate(rr) if r.get('_is_attack')]
                if not ai:
                    raise ValueError
                pre = [r for r in rr[:ai[0]] if not r.get('_is_attack')]
                if len(pre) < 30:
                    raise ValueError
                post = rr[ai[0]:]
                _m3 = os.environ.get('ANTIDDOS_SPLIT')
                if _m3 in ('threeway', 'threeway40', 'threeway60'):
                    # same three-way rule as load_case
                    _f = 0.6 if _m3 == 'threeway60' else 0.4
                    fit = pre[:int(len(pre) * _f)]
                    post = sorted(pre[int(len(pre) * 0.8):] + post, key=tkey)
                else:
                    fit = pre[:int(len(pre) * 0.6)]
                y = np.array([1 if r.get('_is_attack') else 0 for r in post])
                if y.sum() < 10 or (y == 0).sum() < 5:
                    raise ValueError
                feats = R.active_features(fit)
                _raw_corpora.append(corp)
                meta = {'label': f"{canon(corp)} {fn}", 'victim': victim_key(corp, vic),
                        'corpus': canon(corp),
                        'attack_frac': round(float(y.mean()), 4)}
                score_case(C.mat(fit, feats), C.mat(post, feats), y, accu, meta, fn)
                print(f"  usable: {corp} {fn[:44]:44s} ({time.time()-t0:.0f}s)", flush=True)
            except Exception:
                pass
            finally:
                try: del dd, pi
                except Exception: pass
                gc.collect()
    summarise(accu, 'USABLE-strict', out)

    _m3m = os.environ.get('ANTIDDOS_SPLIT') or 'deposited'
    mp = safe_out.resolve(RESULTS_DIR, 'split_control_matrix.json', 'SC_MATRIX')
    strict_rows = [{'scenario': k, **v['meta'], 'auc': v['auc']}
                   for k, v in PER_SCEN.get('USABLE-strict', {}).items()]
    by_pop = {p: [{'scenario': k, **v['meta'], 'auc': v['auc'],
                   'ep1': v['ep1'], 'ep2': v['ep2'], 'ep5': v['ep5']}
                  for k, v in rows.items()]
              for p, rows in PER_SCEN.items()}
    json.dump({'split_mode': _m3m,
               'note': 'Per-scenario AUC and benign-episode rates behind every inferential '
                       'claim, for BOTH evaluation populations. The victim field is the '
                       'clustering unit for the cluster Wilcoxon and the cluster bootstrap. '
                       'The top-level per_scenario block is USABLE-strict, unchanged; '
                       'per_population carries both.',
               'n_scenarios': len(strict_rows),
               'n_victim_clusters': len({r['victim'] for r in strict_rows}),
               'per_scenario': strict_rows,
               'per_population': by_pop,
               'diagnostics': diagnostics(by_pop)}, open(mp, 'w'), indent=1)
    print(f"-> {mp}  ({', '.join(f'{p}: {len(r)}' for p, r in by_pop.items())})")

    _m3 = os.environ.get('ANTIDDOS_SPLIT') or 'deposited'
    _fit = 0.6 if _m3 in ('deposited', 'threeway60') else 0.4
    _calib_end = 1.0 if _m3 == 'deposited' else 0.8
    _split = {'split_mode': _m3,
              'fit_fraction_of_pre_attack_benign': _fit,
              'calibration_fraction': round(_calib_end - _fit, 2),
              'test_pre_attack_fraction': round(1.0 - _calib_end, 2),
              'description': ('deposited: all pre-attack benign goes to fit and calibration, so the '
                              'test stream opens on attack. threeway40 / threeway60: the last fifth of '
                              'pre-attack benign is returned to the test stream, so it runs benign -> '
                              'attack -> benign. threeway40 holds the calibration size and shrinks fit; '
                              'threeway60 holds the fit size and shrinks calibration, which separates '
                              'the effect of stream order from the effect of training on less data.')}
    json.dump({'seed': SEED, 'alpha': C.ALPHA, 'k': C.K, 'reference_arm': REF,
               'split': _split,
               'corpus_spelling_census': spelling_census(_raw_corpora),
               'versions': {'pyod': __import__('pyod').__version__,
                            'torch': __import__('torch').__version__,
                            'numpy': np.__version__,
                            'sklearn': __import__('sklearn').__version__,
                            'scipy': __import__('scipy').__version__},
               'results': out, 'elapsed_sec': round(time.time() - t0, 1)},
              open(OUT, 'w'), indent=1)
    print(f"\n-> {OUT}  ({time.time()-t0:.0f}s)")


if __name__ == '__main__':
    main()
