"""AUC / DR / FPR for all 10 corrected arms on the 29-scenario population.

POPULATION: verdict in (USABLE, ROLE-UNVERIFIED) = 22 + 7. This is the set
run_29_usable_benchmark.py used. Seven rows are audit-quarantined and 13 use a
non-causal benign 60/20/20 split, so every table below is ALSO broken out by
verdict and by split mode. Read the subgroups, not just the 29-row mean.

FPR IS MEASURED, NOT MATCHED. The other runners report DR at a matched FPR, which
fixes FPR by construction and so cannot show calibration error. Here the
threshold is taken from a HELD-OUT BENIGN CALIBRATION SLICE at the nominal
target, and the realized FPR is then measured on unseen benign test windows.
The gap between nominal and realized is the calibration floor this project
documents. Matched-FPR DR is reported alongside for comparability.

Scoring is one continuous chronological stream (calibration then test) so the
EWMA arms carry state across the boundary exactly as they would in deployment.
"""
import gc, json, os, statistics, sys, time
import numpy as np
from sklearn.metrics import roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..')))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..', '..', 'experiment')))

from config import RESULTS_DIR
from corpus_names import canon, victim_key, is_chronological, spelling_census
import safe_out
import run_crosscorpus_auc as R
import competitors_fixed as C
from run_post2023_benchmark import tkey, dr_at

BASE = os.environ.get('ANTIDDOS_BASE', '/home/detector/Projects/antiddos')
EXTRACTED = os.path.join(BASE, 'datasets', 'extracted')
OUT = safe_out.resolve(RESULTS_DIR, 'scenarios29_corrected_results.json', 'S29')
TARGETS = (0.01, 0.02, 0.05)



def episodes(flags, cooldown=30):
    # Verbatim from runners/run_corrected_benchmark_full.py:42-44 so the held-out
    # episode rate uses the same cooldown definition as the oracle-threshold one.
    idx = np.flatnonzero(flags)
    return 0 if len(idx) == 0 else 1 + int(np.sum(np.diff(idx) > cooldown))

def load_case_tree(fpath, victim, split_mode):
    """Mirrors run_29_usable_benchmark.load_case_tree exactly."""
    with open(fpath) as f:
        d = json.load(f)
    per_ip = d.get('per_ip_windows', {})
    if not per_ip:
        return None, None, None, None
    if victim not in per_ip:
        victim = list(per_ip.keys())[0]
    rows = sorted(per_ip.get(victim, []), key=tkey)
    if split_mode in ('treefile', 'crossfile'):
        ben = [r for r in rows if not r.get('_is_attack')]
        atk = [r for r in rows if r.get('_is_attack')]
        if len(ben) < 10 or len(atk) < 10:
            return None, None, None, None
        a, b = int(len(ben) * 0.6), int(len(ben) * 0.8)
        return ben[:a], ben[a:b], ben[b:], atk
    atk_idx = [i for i, r in enumerate(rows) if r.get('_is_attack')]
    if not atk_idx:
        return None, None, None, None
    pre = rows[:atk_idx[0]]
    if len(pre) < 10:
        ben = [r for r in rows if not r.get('_is_attack')]
        atk = [r for r in rows if r.get('_is_attack')]
        if len(ben) < 10 or len(atk) < 10:
            return None, None, None, None
        a, b = int(len(ben) * 0.6), int(len(ben) * 0.8)
        return ben[:a], ben[a:b], ben[b:], atk
    cut = int(len(pre) * 0.6)
    post = rows[atk_idx[0]:]
    return (pre[:cut], pre[cut:],
            [r for r in post if not r.get('_is_attack')],
            [r for r in post if r.get('_is_attack')])


def collect():
    out = []
    for corp in sorted(os.listdir(EXTRACTED)):
        ix = os.path.join(EXTRACTED, corp, 'index.json')
        if not os.path.isfile(ix):
            continue
        d = json.load(open(ix))
        items = d if isinstance(d, list) else (list(d.values())[0] if len(d) == 1 else list(d.values()))
        if isinstance(items, dict):
            items = list(items.values())
        for e in items:
            if not isinstance(e, dict) or e.get('verdict') not in ('USABLE', 'ROLE-UNVERIFIED'):
                continue
            fn = e.get('file') or (str(e.get('attack_type')) + '.json')
            p = os.path.join(EXTRACTED, corp, fn)
            if os.path.exists(p):
                out.append((corp, fn, p, e))
    return out


def main():
    t0 = time.time()
    cases = collect()
    print(f"{len(cases)} scenarios with verdict in (USABLE, ROLE-UNVERIFIED)\n")

    per_scen = []
    for corp, fn, p, e in cases:
        try:
            fit, cal, tb, atk = load_case_tree(p, e.get('victim'), e.get('split_mode'))
            if fit is None or len(fit) < 10 or len(cal) < 5 or len(tb) < 5 or len(atk) < 10:
                print(f"  SKIP {corp} {fn[:40]} (thin split)"); continue
            feats = R.active_features(fit)
            A = C.mat(fit, feats)
            tagged = sorted([(tkey(r), 0, r) for r in tb] + [(tkey(r), 1, r) for r in atk],
                            key=lambda x: x[0])
            y = np.array([t[1] for t in tagged])
            stream = C.mat(cal + [t[2] for t in tagged], feats)
            nc = len(cal)

            rec = {'corpus': canon(corp), 'file': fn,
                   'label': f"{canon(corp)} {fn.replace('.json','')}",
                   'victim': victim_key(corp, e.get('victim')), 'verdict': e.get('verdict'),
                   '_corpus_raw': corp,
                   'split_mode': e.get('split_mode'),
                   # The causal/crossfile stratum comes from the SPLIT MODE, not from the
                   # corpus name, so it is unaffected by spelling. is_chronological() is
                   # recorded beside it because the two coincide on this tree and a reader
                   # should be able to see that rather than infer it.
                   'causal': e.get('split_mode') not in ('treefile', 'crossfile'),
                   'chronological': is_chronological(corp),
                   'fpr_measurable': e.get('fpr_measurable'),
                   'n_calib': nc, 'n_benign_test': int((y == 0).sum()),
                   'n_attack': int(y.sum()),
                   'attack_frac': round(float(y.mean()), 4), 'arms': {}}

            for name, (fnc, _) in C.DETECTORS.items():
                try:
                    s = np.asarray(fnc(A, stream), dtype=float)
                    if s.shape[0] != nc + len(y) or not np.all(np.isfinite(s)):
                        raise ValueError('bad scores')
                    cs, ts = s[:nc], s[nc:]
                    a = {'auc': round(float(roc_auc_score(y, ts)), 4)}
                    for t in TARGETS:
                        k = int(t * 100)
                        th = np.percentile(cs, (1 - t) * 100)
                        a[f'dr@{k}'] = round(float((ts[y == 1] > th).mean() * 100), 2)
                        a[f'fpr@{k}'] = round(float((ts[y == 0] > th).mean() * 100), 2)
                        a[f'drmatched@{k}'] = round(dr_at(ts, y, t), 2)
                        a[f'ep@{k}'] = round(1000.0 * episodes((ts > th) & (y == 0))
                                             / max(int((y == 0).sum()), 1), 2)
                    rec['arms'][name] = a
                except Exception as ex:
                    rec['arms'][name] = {'error': str(ex)[:90]}
            per_scen.append(rec)
            print(f"  {rec['label'][:56]:56s} atk={rec['attack_frac']:.2f} ({time.time()-t0:.0f}s)", flush=True)
        except Exception as ex:
            print(f"  FAIL {corp} {fn[:40]}: {str(ex)[:70]}")
        finally:
            gc.collect()

    def agg(rows, label, out):
        if not rows:
            return
        names = [n for n in C.DETECTORS]
        tab = {}
        for n in names:
            v = [r['arms'][n] for r in rows if 'auc' in r['arms'].get(n, {})]
            if not v:
                continue
            e = {'n': len(v), 'mean_auc': round(statistics.mean(x['auc'] for x in v), 4),
                 'median_auc': round(statistics.median(x['auc'] for x in v), 4)}
            for t in TARGETS:
                k = int(t * 100)
                e[f'dr@{k}pct'] = round(statistics.mean(x[f'dr@{k}'] for x in v), 2)
                e[f'fpr@{k}pct'] = round(statistics.mean(x[f'fpr@{k}'] for x in v), 2)
                e[f'drmatched@{k}pct'] = round(statistics.mean(x[f'drmatched@{k}'] for x in v), 2)
                if all(f'ep@{k}' in x for x in v):
                    e[f'ep@{k}pct'] = round(statistics.mean(x[f'ep@{k}'] for x in v), 2)
            tab[n] = e
        out[label] = tab
        print(f"\n{label}  (n = {len(rows)})")
        print(f"  {'arm':26s}{'meanAUC':>9s}{'medAUC':>8s} | "
              f"{'DR@1%':>7s}{'DR@2%':>7s}{'DR@5%':>7s} | "
              f"{'FPR@1%':>8s}{'FPR@2%':>8s}{'FPR@5%':>8s}")
        print('  ' + '-' * 88)
        for n in sorted(tab, key=lambda n: -tab[n]['mean_auc']):
            e = tab[n]
            print(f"  {n:26s}{e['mean_auc']:>9.4f}{e['median_auc']:>8.4f} | "
                  f"{e['dr@1pct']:>7.2f}{e['dr@2pct']:>7.2f}{e['dr@5pct']:>7.2f} | "
                  f"{e['fpr@1pct']:>8.2f}{e['fpr@2pct']:>8.2f}{e['fpr@5pct']:>8.2f}")

    res = {}
    agg(per_scen, 'ALL-29', res)
    agg([r for r in per_scen if r['verdict'] == 'USABLE'], 'USABLE-22', res)
    agg([r for r in per_scen if r['verdict'] == 'ROLE-UNVERIFIED'], 'ROLE-UNVERIFIED-7', res)
    agg([r for r in per_scen if r['causal']], 'causal-split-only', res)
    agg([r for r in per_scen if not r['causal']], 'non-causal-split-only', res)

    json.dump({'targets': list(TARGETS), 'alpha': C.ALPHA, 'k': C.K,
               'corpus_spelling_census': spelling_census([r['_corpus_raw'] for r in per_scen]),
               'note': 'FPR is realized on held-out benign test windows at a threshold '
                       'taken from a separate benign calibration slice. Not matched.',
               'versions': {'pyod': __import__('pyod').__version__,
                            'torch': __import__('torch').__version__,
                            'numpy': np.__version__},
               'summary': res,
               'per_scenario': [{k: v for k, v in r.items() if k != '_corpus_raw'}
                                for r in per_scen],
               'elapsed_sec': round(time.time() - t0, 1)}, open(OUT, 'w'), indent=1)
    print(f"\n-> {OUT}  ({time.time()-t0:.0f}s)")


if __name__ == '__main__':
    main()
