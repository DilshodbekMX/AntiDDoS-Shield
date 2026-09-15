"""Component ablation of the proposed arm: the EWMA stage, on and off.

The proposed detector is the subspace residual together with its EWMA stage
(competitors_fixed.subspace_q_ewma). This runner removes that stage and nothing
else, and rescores both evaluated populations, so the arm's discrimination can be
attributed between its two components.

What this runner deliberately does NOT do: it does not modify any competitor arm,
and it does not score the ablated variant against a baseline. Every competitor in
the registry is evaluated only as its authors published it, in
run_corrected_benchmark.py; the variant without the smoothing stage is not a
detector of record and is reported only as a component attribution of our own arm.

Populations, splits, feature selection, k and seed are inherited unchanged from
run_corrected_benchmark.py. The cross-day panel row additionally requires the
CIC-IDS-2017 Monday feature cache to be reachable from config.CACHE_DIR; if it is
absent that row is skipped and the panel is scored on the remaining 22.

Writes results/ewma_ablation.json.
"""
import gc, json, os, sys, time
import numpy as np
from sklearn.metrics import roc_auc_score
from scipy import stats as st

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..')))          # package modules

from config import RESULTS_DIR
import run_crosscorpus_auc as R
import competitors_fixed as C
from run_post2023_benchmark import load_case, tkey

EXTRACTED = os.path.join(os.environ.get('ANTIDDOS_BASE', '/home/detector/Projects/antiddos'),
                         'datasets', 'extracted')
OUT = os.path.join(RESULTS_DIR, 'ewma_ablation.json')
SEED = 20260827


def subspace_q_no_ewma(train_mat, test_mat, k=C.K):
    """competitors_fixed.subspace_q_ewma with the final EWMA stage removed.

    Every other step is identical, including the small-sample guard, which returns
    the unsmoothed reference score in both variants and so contributes no difference.
    """
    N, D = train_mat.shape
    if N < 2 * D:
        return C.pot_scores(train_mat, test_mat)
    mu = train_mat.mean(axis=0); sd = train_mat.std(axis=0); sd[sd < 1e-9] = 1.0
    Ztr, Zte = (train_mat - mu) / sd, (test_mat - mu) / sd
    _, _, Vt = np.linalg.svd(Ztr, full_matrices=False)
    Vk = Vt[:min(k, Vt.shape[0])]
    Qtr = np.sum(Ztr ** 2, axis=1) - np.sum((Ztr @ Vk.T) ** 2, axis=1)
    Qte = np.sum(Zte ** 2, axis=1) - np.sum((Zte @ Vk.T) ** 2, axis=1)
    Qte_adj = Qte - 1e-12 * np.maximum(1.0, Qte)
    ge = N - np.searchsorted(np.sort(Qtr), Qte_adj, side='left')
    return -np.log(np.maximum(ge + 1.0, 1.0) / (N + 1.0))


def score(A, B, y, meta, key, store):
    store[key] = {'meta': meta,
                  'auc_with_ewma':    float(roc_auc_score(y, C.subspace_q_ewma(A, B))),
                  'auc_without_ewma': float(roc_auc_score(y, subspace_q_no_ewma(A, B)))}


def summarise(store, label):
    ks = list(store)
    a = np.array([store[k]['auc_with_ewma'] for k in ks])
    b = np.array([store[k]['auc_without_ewma'] for k in ks])
    vic = [store[k]['meta']['victim'] for k in ks]
    gs = sorted(set(vic))
    ca = np.array([np.mean([a[i] for i, g in enumerate(vic) if g == gg]) for gg in gs])
    cb = np.array([np.mean([b[i] for i, g in enumerate(vic) if g == gg]) for gg in gs])
    d = a - b
    out = {'n_scenarios': len(ks), 'n_victim_clusters': len(gs),
           'mean_auc_with_ewma': round(float(a.mean()), 4),
           'mean_auc_without_ewma': round(float(b.mean()), 4),
           'stage_contribution': round(float(d.mean()), 4),
           'improves': int((d > 0).sum()), 'degrades': int((d < 0).sum()),
           'ties': int((d == 0).sum()),
           'scenario_p': float(st.wilcoxon(a, b, zero_method='wilcox')[1]),
           'cluster_p': float(st.wilcoxon(ca, cb, zero_method='wilcox')[1]),
           'cluster_mean_delta': round(float((ca - cb).mean()), 4),
           'largest_gain': {'scenario': ks[int(np.argmax(d))], 'delta': round(float(d.max()), 4)},
           'largest_loss': {'scenario': ks[int(np.argmin(d))], 'delta': round(float(d.min()), 4)},
           'per_scenario': {k: {'victim': store[k]['meta']['victim'],
                                'with_ewma': store[k]['auc_with_ewma'],
                                'without_ewma': store[k]['auc_without_ewma']} for k in ks}}
    print(f"  {label:14s} n={out['n_scenarios']:2d} with={out['mean_auc_with_ewma']:.4f} "
          f"without={out['mean_auc_without_ewma']:.4f} delta={out['stage_contribution']:+.4f} "
          f"p={out['scenario_p']:.3g} cluster_p={out['cluster_p']:.3g}", flush=True)
    return out


def main():
    t0 = time.time()
    panel_store, strict_store, skipped = {}, {}, []

    panel = json.load(open(os.path.join(RESULTS_DIR, 'panel_inventory', 'PANEL.json')))['panel']
    for e in panel:
        try:
            fit, cal, tb, atk = load_case(e)
        except Exception as ex:
            skipped.append({'row': e['label'], 'reason': str(ex)[:120]}); continue
        if fit is None or len(fit) < 10 or len(atk) < 10:
            skipped.append({'row': e['label'], 'reason': 'below size gate'}); continue
        feats = R.active_features(fit)
        tg = sorted([(tkey(r), 0, r) for r in tb] + [(tkey(r), 1, r) for r in atk], key=lambda x: x[0])
        y = np.array([t[1] for t in tg])
        score(C.mat(fit, feats), C.mat([t[2] for t in tg], feats), y,
              {'label': e['label'], 'victim': e.get('victim') or e['label']},
              e['label'], panel_store)
        print(f"  panel: {e['label'][:52]:52s} ({time.time()-t0:.0f}s)", flush=True)

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
                if not ai: raise ValueError
                pre = [r for r in rr[:ai[0]] if not r.get('_is_attack')]
                if len(pre) < 30: raise ValueError
                fit = pre[:int(len(pre) * 0.6)]; post = rr[ai[0]:]
                y = np.array([1 if r.get('_is_attack') else 0 for r in post])
                if y.sum() < 10 or (y == 0).sum() < 5: raise ValueError
                feats = R.active_features(fit)
                score(C.mat(fit, feats), C.mat(post, feats), y,
                      {'label': f"{corp} {fn}", 'victim': f"{corp}/{vic}"}, fn, strict_store)
                print(f"  usable: {corp} {fn[:42]:42s} ({time.time()-t0:.0f}s)", flush=True)
            except Exception:
                pass
            finally:
                try: del dd, pi
                except Exception: pass
                gc.collect()

    print()
    out = {'note': 'Component ablation of the proposed arm: the EWMA stage on and off, '
                   'nothing else changed. No competitor arm is modified and the ablated '
                   'variant is not scored against any baseline; it is a component '
                   'attribution of our own arm, not a detector of record.',
           'seed': SEED, 'k': C.K, 'alpha': C.ALPHA,
           'skipped_rows': skipped,
           'PANEL-23': summarise(panel_store, 'PANEL-23'),
           'USABLE-strict': summarise(strict_store, 'USABLE-strict')}
    json.dump(out, open(OUT, 'w'), indent=1)
    print(f"\nwrote {OUT} ({time.time()-t0:.0f}s)")


if __name__ == '__main__':
    main()
