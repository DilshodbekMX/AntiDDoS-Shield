"""Systematic Research on Maximizing Detection Rate (DR) and Minimizing False Positive Rate (FPR).

Explores:
1. Subspace rank k in {4, 6, 8}
2. Residual weighting: Standard Orthogonal vs Mahalanobis SPE
3. Temporal smoothing: Raw vs EWMA (alpha=0.5) vs Persistence (P=2, P=3)
4. Fusion rules: max(SPOT, O(Q)) vs Soft-OR vs Shrinkage Gating

Protocol:
- Evaluated on all 23 panel scenarios (chronological order, fit on train only)
- Evaluates ROC-AUC, DR @ 1% FPR, DR @ 2% FPR, DR @ 5% FPR, and Benign Episodes / 1k windows
- Saves complete results to experiments_copy/results/fpr_dr_optimization_results.json
"""
import os, sys, json, statistics, numpy as np
from sklearn.metrics import roc_auc_score
from scipy import stats as st

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, 'negatives'))

from config import RESULTS_DIR
from run_post2023_benchmark import load_case, tkey, dr_at
import run_crosscorpus_auc as R
import post2023_competitors as C

OUT_JSON = os.path.join(RESULTS_DIR, 'fpr_dr_optimization_results.json')

def count_episodes(alarms):
    if len(alarms) == 0: return 0
    diff = np.diff(np.pad(alarms.astype(int), (1, 1), 'constant'))
    starts = np.where(diff == 1)[0]
    return len(starts)

def run_study():
    print("=== RESEARCH STUDY: OPTIMIZING DR AND FPR IN experiments_copy ===")
    panel = json.load(open(os.path.join(RESULTS_DIR, 'panel_inventory', 'PANEL.json')))['panel']
    
    cases = []
    for e in panel:
        fit, cal, tb, atk = load_case(e)
        if fit is None or len(fit) < 10 or len(atk) < 10: continue
        feats = R.active_features(fit)
        tagged = sorted([(tkey(r), 0, r) for r in tb] + [(tkey(r), 1, r) for r in atk], key=lambda x: x[0])
        ev = [t[2] for t in tagged]; y = np.array([t[1] for t in tagged])
        Xtr, Xev = C.mat(fit, feats), C.mat(ev, feats)
        cases.append({'label': e['label'], 'y': y, 'Xtr': Xtr, 'Xev': Xev})
    print(f"Loaded {len(cases)} panel cases.\n")

    def make_detector(k=8, weighting='standard', temporal='raw', alpha=0.5, p_len=2, q_spot=0.98):
        def score_fn(Xtr, Xev):
            N, D = Xtr.shape; M = len(Xev)
            S = C.spot_baseline_scores(Xtr, Xev, q=q_spot)
            if N < 2 * D: return S
            
            mu = np.mean(Xtr, axis=0); std = np.std(Xtr, axis=0); std[std < 1e-6] = 1.0
            Z_tr = (Xtr - mu) / std; Z_te = (Xev - mu) / std
            U, s, Vt = np.linalg.svd(Z_tr, full_matrices=False)
            k_eff = min(k, Vt.shape[0])
            
            if weighting == 'mahalanobis':
                lambdas = np.maximum((s ** 2) / N, 1e-4)
                P_res = Vt[k_eff:]
                var_res = lambdas[k_eff:]
                Q_tr = np.sum(((Z_tr @ P_res.T) ** 2) / var_res, axis=1)
                Q_te = np.sum(((Z_te @ P_res.T) ** 2) / var_res, axis=1)
            else:
                P = np.eye(D) - Vt[:k_eff].T @ Vt[:k_eff]
                Q_tr = np.sum((Z_tr @ P)**2, axis=1)
                Q_te = np.sum((Z_te @ P)**2, axis=1)
                
            sorted_Q = np.sort(Q_tr)
            ge = N - np.searchsorted(sorted_Q, Q_te, side='left')
            O = -np.log(np.maximum(ge + 1.0, 1.0) / (N + 1.0))
            
            if temporal == 'ewma':
                O_sm = np.zeros(M); cur = 0.0
                for i in range(M):
                    cur = alpha * O[i] + (1.0 - alpha) * cur
                    O_sm[i] = cur
                raw_comb = np.maximum(S, O_sm)
                return raw_comb
            elif temporal == 'persistence':
                raw_comb = np.maximum(S, O)
                filt = np.zeros(M)
                for i in range(M):
                    lo = max(0, i - p_len + 1)
                    filt[i] = np.min(raw_comb[lo:i+1])
                return filt
            else:
                return np.maximum(S, O)
        return score_fn

    variants = [
        ('SPOT Baseline (KDD 2017)', C.spot_baseline_scores),
        ('Subspace-ECOD (k=4, Raw)', make_detector(k=4, weighting='standard', temporal='raw')),
        ('Subspace-ECOD (k=8, Raw)', make_detector(k=8, weighting='standard', temporal='raw')),
        ('Subspace-ECOD (k=8, Mahalanobis SPE)', make_detector(k=8, weighting='mahalanobis', temporal='raw')),
        ('Subspace-ECOD (k=8, EWMA alpha=0.5)', make_detector(k=8, weighting='standard', temporal='ewma', alpha=0.5)),
        ('Subspace-ECOD (k=8, Persistence P=2)', make_detector(k=8, weighting='standard', temporal='persistence', p_len=2)),
        ('Subspace-ECOD (k=8, Persistence P=3)', make_detector(k=8, weighting='standard', temporal='persistence', p_len=3)),
        ('Subspace-ECOD (k=8, Mahalanobis + Persistence P=2)', make_detector(k=8, weighting='mahalanobis', temporal='persistence', p_len=2)),
    ]

    results = []
    header = f"{'Variant Name':<46s} | {'Mean AUC':>8s} | {'DR @ 1%':>7s} | {'DR @ 2%':>7s} | {'DR @ 5%':>7s} | {'Ben Ep@1%':>9s} | {'Ben Ep@5%':>9s}"
    print(header)
    print('-' * len(header))

    for name, fn in variants:
        aucs, dr1_l, dr2_l, dr5_l = [], [], [], []
        ep1_l, ep5_l = [], []
        for c in cases:
            y = c['y']
            s = fn(c['Xtr'], c['Xev'])
            aucs.append(roc_auc_score(y, s))
            dr1_l.append(dr_at(s, y, 0.01))
            dr2_l.append(dr_at(s, y, 0.02))
            dr5_l.append(dr_at(s, y, 0.05))
            
            n_ben = sum(y == 0)
            t1 = np.percentile(s[y == 0], 99.0)
            t5 = np.percentile(s[y == 0], 95.0)
            ep1_l.append(count_episodes(s[y == 0] > t1) / max(n_ben, 1) * 1000.0)
            ep5_l.append(count_episodes(s[y == 0] > t5) / max(n_ben, 1) * 1000.0)
            
        m_auc = float(np.mean(aucs))
        m_dr1 = float(np.mean(dr1_l))
        m_dr2 = float(np.mean(dr2_l))
        m_dr5 = float(np.mean(dr5_l))
        m_ep1 = float(np.mean(ep1_l))
        m_ep5 = float(np.mean(ep5_l))
        
        results.append({
            'name': name, 'mean_auc': round(m_auc, 4),
            'dr_1pct': round(m_dr1, 2), 'dr_2pct': round(m_dr2, 2), 'dr_5pct': round(m_dr5, 2),
            'benign_episodes_1pct': round(m_ep1, 2), 'benign_episodes_5pct': round(m_ep5, 2),
        })
        print(f"{name:<46s} | {m_auc:8.4f} | {m_dr1:6.2f}% | {m_dr2:6.2f}% | {m_dr5:6.2f}% | {m_ep1:9.2f} | {m_ep5:9.2f}")

    with open(OUT_JSON, 'w') as f:
        json.dump({'variants': results}, f, indent=2)
    print(f"\nSaved research results to: {OUT_JSON}")

if __name__ == '__main__':
    run_study()
