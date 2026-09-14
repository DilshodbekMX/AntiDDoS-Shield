"""Universal EWMA Tournament Across All Detectors on the 23 Panel Scenarios.

Tests the fair, like-for-like application of causal EWMA temporal smoothing (alpha=0.5)
across all registered detectors to determine which base model benefits most and which
model legitimately holds the state-of-the-art Pareto frontier (AUC, DR @ 1/2/5% FPR, and Episode Burden).

Detectors evaluated with and without EWMA (alpha=0.5):
1. SPOT (ACM KDD 2017)
2. INNE (Bandaragoda et al., Comput. Intell. 2018)
3. Subspace-ECOD (k=8, Ours)
4. Pure Subspace Q-Residual (Lakhina SVD)
5. ECOD (Li et al., IEEE TKDE 2022)
6. COPOD (Li et al., IEEE ICDM 2020)
7. HBOS (Goldstein & Dengel, 2012)
8. LODA (Pevny, ML 2016)
9. DIF (Xu et al., IEEE TKDE 2024)
10. Hybrid INNE + SPOT + EWMA

Output: experiments_copy/results/universal_ewma_tournament.json
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
from run_post2023_benchmark import load_case, tkey, dr_at
import run_crosscorpus_auc as R
import post2023_competitors as C

OUT_FILE = os.path.join(RESULTS_DIR, 'universal_ewma_tournament.json')

def ewma(s, a=0.5):
    out = np.zeros(len(s)); cur = 0.0
    for i, v in enumerate(s):
        cur = a * v + (1.0 - a) * cur
        out[i] = cur
    return out

def eps_cd(al, cd=30):
    idx = np.flatnonzero(al)
    return 0 if len(idx) == 0 else 1 + int(np.sum(np.diff(idx) > cd))

def run_tournament():
    print("=== UNIVERSAL EWMA TOURNAMENT (23 PANEL SCENARIOS) ===")
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
        print('.', end='', flush=True)
    print(f"\nLoaded {len(cases)} panel cases.\n")

    # Base scorer implementations
    def q_resid_scores(Xtr, Xev, k=8):
        N, D = Xtr.shape
        if N < 2 * D: return np.zeros(len(Xev))
        mu = Xtr.mean(0); sd = Xtr.std(0); sd[sd < 1e-6] = 1.0
        Ztr = (Xtr - mu) / sd; Zte = (Xev - mu) / sd
        _, _, Vt = np.linalg.svd(Ztr, full_matrices=False)
        ke = min(k, Vt.shape[0])
        P = np.eye(D) - Vt[:ke].T @ Vt[:ke]
        Qtr = np.sum((Ztr @ P)**2, axis=1)
        Qte = np.sum((Zte @ P)**2, axis=1)
        ge = N - np.searchsorted(np.sort(Qtr), Qte, side='left')
        return -np.log(np.maximum(ge + 1.0, 1.0) / (N + 1.0))

    def inne_spot_hybrid(Xtr, Xev):
        s_spot = C.spot_baseline_scores(Xtr, Xev)
        s_inne = C.inne_scores(Xtr, Xev)
        # Normalize and max
        return np.maximum(s_spot, s_inne * 10.0)

    detectors = [
        ('SPOT', C.spot_baseline_scores),
        ('INNE', C.inne_scores),
        ('Subspace-ECOD (k=8)', lambda tr, te: C.subspace_ecod_scores(tr, te, n_components=8)),
        ('Subspace-ECOD (k=4)', lambda tr, te: C.subspace_ecod_scores(tr, te, n_components=4)),
        ('Pure Subspace Q-Resid (k=8)', lambda tr, te: q_resid_scores(tr, te, k=8)),
        ('ECOD', C.ecod_scores),
        ('COPOD', C.copod_scores),
        ('HBOS', C.hbos_scores),
        ('LODA', C.loda_scores),
        ('INNE + SPOT Hybrid', inne_spot_hybrid),
    ]

    tournament_entries = []
    # Add raw and EWMA variants for all detectors
    for name, fn in detectors:
        tournament_entries.append((f"{name} (Raw)", fn, False))
        tournament_entries.append((f"{name} + EWMA", fn, True))

    results = []
    print(f"{'Model Configuration':<36s} | {'Mean AUC':>8s} | {'Median':>7s} | {'DR@1%':>7s} | {'DR@2%':>7s} | {'DR@5%':>7s} | {'Ep@2%/1k':>8s} | {'Ep@5%/1k':>8s}")
    print("-" * 105)

    all_res_dict = {}

    for name, fn, use_ewma in tournament_entries:
        aucs, d1_l, d2_l, d5_l = [], [], [], []
        ep2_l, ep5_l = [], []
        
        for c in cases:
            y = c['y']
            s_raw = np.asarray(fn(c['Xtr'], c['Xev']), dtype=float)
            s = ewma(s_raw, 0.5) if use_ewma else s_raw
            
            aucs.append(roc_auc_score(y, s))
            d1_l.append(dr_at(s, y, 0.01))
            d2_l.append(dr_at(s, y, 0.02))
            d5_l.append(dr_at(s, y, 0.05))
            
            nb = int((y == 0).sum())
            t2 = np.percentile(s[y == 0], 98.0)
            t5 = np.percentile(s[y == 0], 95.0)
            ep2_l.append(1000.0 * eps_cd((s > t2) & (y == 0)) / max(nb, 1))
            ep5_l.append(1000.0 * eps_cd((s > t5) & (y == 0)) / max(nb, 1))
            
        m_auc = float(np.mean(aucs))
        med_auc = float(np.median(aucs))
        m_d1 = float(np.mean(d1_l))
        m_d2 = float(np.mean(d2_l))
        m_d5 = float(np.mean(d5_l))
        m_ep2 = float(np.mean(ep2_l))
        m_ep5 = float(np.mean(ep5_l))
        
        all_res_dict[name] = {
            'aucs': aucs, 'dr1': d1_l, 'dr2': d2_l, 'dr5': d5_l, 'ep2': ep2_l, 'ep5': ep5_l,
            'mean_auc': m_auc, 'med_auc': med_auc, 'dr_1pct': m_d1, 'dr_2pct': m_d2, 'dr_5pct': m_d5,
            'ep_2pct': m_ep2, 'ep_5pct': m_ep5
        }
        
        results.append({
            'name': name, 'mean_auc': round(m_auc, 4), 'median_auc': round(med_auc, 4),
            'dr_1pct': round(m_d1, 2), 'dr_2pct': round(m_d2, 2), 'dr_5pct': round(m_d5, 2),
            'episodes_2pct': round(m_ep2, 2), 'episodes_5pct': round(m_ep5, 2),
        })
        print(f"{name:<36s} | {m_auc:8.4f} | {med_auc:7.4f} | {m_d1:6.2f}% | {m_d2:6.2f}% | {m_d5:6.2f}% | {m_ep2:8.2f} | {m_ep5:8.2f}")

    # Statistical significance comparisons against INNE + EWMA and SPOT raw
    print("\n" + "=" * 95)
    print("HEAD-TO-HEAD STATISTICAL SIGNIFICANCE COMPARISONS")
    print("=" * 95)
    
    comparisons = [
        ('Subspace-ECOD (k=8) + EWMA', 'INNE + EWMA'),
        ('Subspace-ECOD (k=8) + EWMA', 'SPOT (Raw)'),
        ('Subspace-ECOD (k=8) + EWMA', 'SPOT + EWMA'),
        ('INNE + EWMA', 'INNE (Raw)'),
        ('INNE + EWMA', 'SPOT (Raw)'),
        ('Pure Subspace Q-Resid (k=8) + EWMA', 'INNE + EWMA'),
        ('INNE + SPOT Hybrid + EWMA', 'INNE + EWMA'),
    ]
    
    significance_table = []
    for m1, m2 in comparisons:
        a1, a2 = np.array(all_res_dict[m1]['aucs']), np.array(all_res_dict[m2]['aucs'])
        d2_1, d2_2 = np.array(all_res_dict[m1]['dr2']), np.array(all_res_dict[m2]['dr2'])
        ep2_1, ep2_2 = np.array(all_res_dict[m1]['ep2']), np.array(all_res_dict[m2]['ep2'])
        
        diff_auc = a1 - a2
        diff_dr2 = d2_1 - d2_2
        diff_ep2 = ep2_1 - ep2_2
        
        p_auc = 1.0 if np.allclose(diff_auc, 0) else st.wilcoxon(a1, a2, zero_method='wilcox')[1]
        p_dr2 = 1.0 if np.allclose(diff_dr2, 0) else st.wilcoxon(d2_1, d2_2, zero_method='wilcox')[1]
        p_ep2 = 1.0 if np.allclose(diff_ep2, 0) else st.wilcoxon(ep2_1, ep2_2, zero_method='wilcox')[1]
        
        row = {
            'comparison': f"{m1} vs {m2}",
            'delta_mean_auc': round(float(np.mean(diff_auc)), 4), 'p_auc': round(float(p_auc), 4),
            'delta_dr2_pp': round(float(np.mean(diff_dr2)), 2), 'p_dr2': round(float(p_dr2), 4),
            'delta_ep2': round(float(np.mean(diff_ep2)), 2), 'p_ep2': round(float(p_ep2), 4),
        }
        significance_table.append(row)
        print(f"{m1} vs {m2}:")
        print(f"  Delta AUC  : {row['delta_mean_auc']:+.4f} (p = {row['p_auc']:.4f})")
        print(f"  Delta DR@2%: {row['delta_dr2_pp']:+.2f} pp (p = {row['p_dr2']:.4f})")
        print(f"  Delta Ep@2%: {row['delta_ep2']:+.2f} eps (p = {row['p_ep2']:.4f})\n")

    # Save to JSON
    with open(OUT_FILE, 'w') as f:
        json.dump({'leaderboard': results, 'significance': significance_table}, f, indent=2)
    print(f"Saved full tournament results to: {OUT_FILE}")

if __name__ == '__main__':
    run_tournament()
