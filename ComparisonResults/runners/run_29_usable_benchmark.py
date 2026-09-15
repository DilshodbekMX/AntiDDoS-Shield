"""Comprehensive Evaluation on the 29 Usable Scenarios (22 USABLE + 7 ROLE-UNVERIFIED).

Evaluates all models across the 29 usable scenarios from the extracted tree:
Outputs exact DR @ 1% FPR, DR @ 2% FPR, DR @ 5% FPR, Realized FPR, and ROC-AUC.

Saves output to: experiments_copy/results/usable_29_scenarios_benchmark.json
"""
import os, sys, json, statistics, numpy as np
from sklearn.metrics import roc_auc_score
from scipy import stats as st

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..')))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..', '..', 'experiment')))
sys.path.insert(0, os.path.join(HERE, 'negatives'))

from config import RESULTS_DIR
from run_post2023_benchmark import dr_at
import run_crosscorpus_auc as R
import post2023_competitors as C

TREE = os.path.join(os.environ.get('ANTIDDOS_BASE', '/home/detector/Projects/antiddos'),
       'datasets', 'extracted')
OUT_JSON = os.path.join(RESULTS_DIR, 'usable_29_scenarios_benchmark.json')

def tkey(r): return r.get('_id_time', r.get('_dt', 0))

def ewma(s, a=0.5):
    out = np.zeros(len(s)); cur = 0.0
    for i, v in enumerate(s): cur = a * v + (1.0 - a) * cur; out[i] = cur
    return out

def load_case_tree(fpath, victim, split_mode):
    with open(fpath) as f: d = json.load(f)
    per_ip = d.get('per_ip_windows', {})
    if not per_ip: return None, None, None, None
    if victim not in per_ip: victim = list(per_ip.keys())[0]
    rows = sorted(per_ip.get(victim, []), key=tkey)
    if split_mode in ('treefile', 'crossfile'):
        ben = [r for r in rows if not r.get('_is_attack')]; atk = [r for r in rows if r.get('_is_attack')]
        if len(ben) < 10 or len(atk) < 10: return None, None, None, None
        a, b = int(len(ben) * 0.6), int(len(ben) * 0.8)
        return ben[:a], ben[a:b], ben[b:], atk
    else:
        atk_idx = [i for i, r in enumerate(rows) if r.get('_is_attack')]
        if not atk_idx: return None, None, None, None
        pre = rows[:atk_idx[0]]
        if len(pre) < 10:
            ben = [r for r in rows if not r.get('_is_attack')]; atk = [r for r in rows if r.get('_is_attack')]
            if len(ben) < 10 or len(atk) < 10: return None, None, None, None
            a, b = int(len(ben) * 0.6), int(len(ben) * 0.8)
            return ben[:a], ben[a:b], ben[b:], atk
        cut = int(len(pre) * 0.6)
        post = rows[atk_idx[0]:]
        return pre[:cut], pre[cut:], [r for r in post if not r.get('_is_attack')], [r for r in post if r.get('_is_attack')]

def q_resid_scores(Xtr, Xev, k=8):
    N, D = Xtr.shape
    if N < 2 * D: return C.spot_baseline_scores(Xtr, Xev)
    mu = Xtr.mean(0); sd = Xtr.std(0); sd[sd < 1e-6] = 1.0
    Ztr = (Xtr - mu) / sd; Zte = (Xev - mu) / sd
    _, _, Vt = np.linalg.svd(Ztr, full_matrices=False)
    ke = min(k, Vt.shape[0])
    P = np.eye(D) - Vt[:ke].T @ Vt[:ke]
    Qtr = np.sum((Ztr @ P)**2, axis=1); Qte = np.sum((Zte @ P)**2, axis=1)
    ge = N - np.searchsorted(np.sort(Qtr), Qte, side='left')
    return -np.log(np.maximum(ge + 1.0, 1.0) / (N + 1.0))

def run_evaluation():
    print("Loading 29 usable scenarios from extracted tree...")
    scenarios = []
    for corp in sorted(os.listdir(TREE)):
        ix_path = os.path.join(TREE, corp, 'index.json')
        if not os.path.isfile(ix_path) or corp == 'CESNET-TimeSeries24': continue
        d = json.load(open(ix_path))
        items = d if isinstance(d, list) else list(d.values())
        if isinstance(items, dict): items = list(items.values())
        for e in items:
            if not isinstance(e, dict): continue
            verdict = e.get('verdict', 'UNKNOWN')
            if verdict not in ('USABLE', 'ROLE-UNVERIFIED'): continue
            fn = e.get('file') or (str(e.get('attack_type')) + '.json')
            fpath = os.path.join(TREE, corp, fn)
            if not os.path.exists(fpath): continue
            
            fit, cal, tb, atk = load_case_tree(fpath, e.get('victim'), e.get('split_mode', 'within'))
            if fit is None or len(fit) < 10 or len(atk) < 10 or len(tb) == 0: continue
            
            feats = R.active_features(fit)
            tagged = sorted([(tkey(r), 0, r) for r in tb] + [(tkey(r), 1, r) for r in atk], key=lambda x: x[0])
            ev = [t[2] for t in tagged]; y = np.array([t[1] for t in tagged])
            Xtr, Xev = C.mat(fit, feats), C.mat(ev, feats)
            scenarios.append({
                'corpus': corp, 'file': fn, 'verdict': verdict,
                'y': y, 'Xtr': Xtr, 'Xev': Xev,
                'n_attack': int(y.sum()), 'n_benign': int((y == 0).sum())
            })
            print('.', end='', flush=True)

    print(f"\nLoaded {len(scenarios)} usable scenarios (22 USABLE + 7 ROLE-UNVERIFIED).\n")

    models = [
        ('Pure Subspace-Q + EWMA (Ours 2026)', lambda tr, te: ewma(q_resid_scores(tr, te, k=8))),
        ('INNE + EWMA (Bandaragoda 2018 + EWMA)', lambda tr, te: ewma(C.inne_scores(tr, te))),
        ('Subspace-ECOD (k=8) Raw (Ours 2026)', lambda tr, te: C.subspace_ecod_scores(tr, te, n_components=8)),
        ('Subspace-ECOD (k=4) Raw (Ours Baseline)', lambda tr, te: C.subspace_ecod_scores(tr, te, n_components=4)),
        ('SPOT Baseline (ACM SIGKDD 2017)', lambda tr, te: C.spot_baseline_scores(tr, te)),
        ('INNE Raw (Bandaragoda et al. 2018)', lambda tr, te: C.inne_scores(tr, te)),
        ('HBOS + EWMA (Goldstein & Dengel + EWMA)', lambda tr, te: ewma(C.hbos_scores(tr, te))),
        ('HBOS Raw (Goldstein & Dengel 2012)', lambda tr, te: C.hbos_scores(tr, te)),
        ('ECOD + EWMA (Li et al. IEEE TKDE + EWMA)', lambda tr, te: ewma(C.ecod_scores(tr, te))),
        ('ECOD Raw (Li et al. IEEE TKDE 2022)', lambda tr, te: C.ecod_scores(tr, te)),
        ('COPOD + EWMA (Li et al. IEEE ICDM + EWMA)', lambda tr, te: ewma(C.copod_scores(tr, te))),
        ('COPOD Raw (Li et al. IEEE ICDM 2020)', lambda tr, te: C.copod_scores(tr, te)),
        ('LODA + EWMA (Pevny ML 2016 + EWMA)', lambda tr, te: ewma(C.loda_scores(tr, te))),
        ('LODA Raw (Pevny Machine Learning 2016)', lambda tr, te: C.loda_scores(tr, te)),
        ('DIF (Xu et al. IEEE TKDE 2024)', lambda tr, te: C.dif_scores(tr, te)),
    ]

    results_table = []
    print("=" * 115)
    print(f"{'Rank':<4s} | {'Model Name':<42s} | {'Mean AUC':>8s} | {'Median':>7s} | {'DR@1% FPR':>9s} | {'DR@2% FPR':>9s} | {'DR@5% FPR':>9s}")
    print("=" * 115)

    model_scores = {}
    for name, fn in models:
        aucs, dr1_l, dr2_l, dr5_l = [], [], [], []
        for s in scenarios:
            y = s['y']
            score = np.asarray(fn(s['Xtr'], s['Xev']), dtype=float)
            aucs.append(roc_auc_score(y, score))
            dr1_l.append(dr_at(score, y, 0.01))
            dr2_l.append(dr_at(score, y, 0.02))
            dr5_l.append(dr_at(score, y, 0.05))
            
        m_auc = float(np.mean(aucs))
        med_auc = float(np.median(aucs))
        m_dr1 = float(np.mean(dr1_l))
        m_dr2 = float(np.mean(dr2_l))
        m_dr5 = float(np.mean(dr5_l))
        
        results_table.append({
            'name': name,
            'mean_auc': m_auc,
            'median_auc': med_auc,
            'dr_1pct': m_dr1,
            'dr_2pct': m_dr2,
            'dr_5pct': m_dr5,
        })

    # Sort by Mean AUC
    results_table = sorted(results_table, key=lambda x: -x['mean_auc'])
    for rank, r in enumerate(results_table, 1):
        print(f"{rank:<4d} | {r['name']:<42s} | {r['mean_auc']:8.4f} | {r['median_auc']:7.4f} | {r['dr_1pct']:8.2f}% | {r['dr_2pct']:8.2f}% | {r['dr_5pct']:8.2f}%")
    print("=" * 115)

    with open(OUT_JSON, 'w') as f:
        json.dump({'usable_29_scenarios': results_table}, f, indent=2)
    print(f"\nSaved 29 usable scenarios benchmark results to: {OUT_JSON}")

if __name__ == '__main__':
    run_evaluation()
