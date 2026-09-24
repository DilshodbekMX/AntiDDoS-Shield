"""Comprehensive Pre-Implementation Validation of Subspace-ECOD.

Executes all five validation tasks before any C-engine port:
1. Cross-host threshold transferability (leave-one-scenario-out calibration error)
2. Episode-level false-alarm and attack recall metrics at 1%, 2%, and 5% FPR
3. Nested / leave-one-scenario-out selection and sensitivity grid for subspace rank k
4. Anti-artifact benign control on CESNET-TimeSeries24 (174 hosts / 388k windows)
5. Verdict-stratified full-tree re-run (USABLE vs quarantined slices)

Output: results/subspace_ecod_validation_report.json
Deposited 2026-09-24 with the record it writes: it had been deposited without its generator.
"""
import os, sys, json, statistics, numpy as np
from sklearn.metrics import roc_auc_score
from scipy import stats as st

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..')))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..', '..', 'experiment')))

from config import RESULTS_DIR, TAR_PATH, TIMES_TAR, MIN_IP_ROWS_PER_IP
from run_post2023_benchmark import load_case, tkey
import run_crosscorpus_auc as R
import post2023_competitors as C
from data_loader import load_per_ip

OUT_FILE = os.path.join(RESULTS_DIR, 'subspace_ecod_validation_report.json')

def count_episodes(alarms):
    if len(alarms) == 0: return 0
    diff = np.diff(np.pad(alarms.astype(int), (1, 1), 'constant'))
    starts = np.where(diff == 1)[0]
    return len(starts)

def episode_recall(alarms, y):
    diff = np.diff(np.pad(y.astype(int), (1, 1), 'constant'))
    starts = np.where(diff == 1)[0]
    ends = np.where(diff == -1)[0]
    if len(starts) == 0: return float('nan')
    caught = sum(1 for s, e in zip(starts, ends) if np.any(alarms[s:e] == 1))
    return caught / len(starts)

def run_all_validation():
    print("=== Subspace-ECOD Pre-Implementation Validation ===")
    panel = json.load(open(os.path.join(RESULTS_DIR, 'panel_inventory', 'PANEL.json')))['panel']
    
    # Load 23 panel cases
    cases = []
    for e in panel:
        fit, cal, tb, atk = load_case(e)
        if fit is None or len(fit) < 10 or len(atk) < 10: continue
        feats = R.active_features(fit)
        tagged = sorted([(tkey(r), 0, r) for r in tb] + [(tkey(r), 1, r) for r in atk], key=lambda x: x[0])
        ev = [t[2] for t in tagged]; y = np.array([t[1] for t in tagged])
        Xtr, Xev = C.mat(fit, feats), C.mat(ev, feats)
        s_spot = C.spot_baseline_scores(Xtr, Xev, q=0.98)
        s_ours = C.subspace_ecod_scores(Xtr, Xev, n_components=4, q=0.98)
        cases.append({
            'label': e['label'], 'y': y, 'feats': feats, 'Xtr': Xtr, 'Xev': Xev,
            's_spot': s_spot, 's_ours': s_ours,
            'spot_b': s_spot[y == 0], 'spot_a': s_spot[y == 1],
            'ours_b': s_ours[y == 0], 'ours_a': s_ours[y == 1],
        })
    print(f"Loaded {len(cases)} panel cases.\n")

    # ─────────────────────────────────────────────────────────────
    # TASK 1: Threshold Transfer Across Hosts
    # ─────────────────────────────────────────────────────────────
    print("--- Task 1: Cross-Host Threshold Transfer ---")
    task1_results = {}
    TARGETS = [0.01, 0.02, 0.05]
    for target in TARGETS:
        spot_rfpr, ours_rfpr = [], []
        spot_rec, ours_rec = [], []
        spot_cal_err, ours_cal_err = [], []
        
        for i in range(len(cases)):
            tr_sp_b = np.concatenate([cases[j]['spot_b'] for j in range(len(cases)) if j != i])
            tr_ou_b = np.concatenate([cases[j]['ours_b'] for j in range(len(cases)) if j != i])
            tau_sp = np.percentile(tr_sp_b, (1.0 - target) * 100.0)
            tau_ou = np.percentile(tr_ou_b, (1.0 - target) * 100.0)
            
            c = cases[i]
            rfpr_sp = float(np.mean(c['spot_b'] > tau_sp)) if len(c['spot_b']) > 0 else float('nan')
            rfpr_ou = float(np.mean(c['ours_b'] > tau_ou)) if len(c['ours_b']) > 0 else float('nan')
            rec_sp = float(np.mean(c['spot_a'] > tau_sp)) if len(c['spot_a']) > 0 else float('nan')
            rec_ou = float(np.mean(c['ours_a'] > tau_ou)) if len(c['ours_a']) > 0 else float('nan')
            
            spot_rfpr.append(rfpr_sp); ours_rfpr.append(rfpr_ou)
            spot_rec.append(rec_sp); ours_rec.append(rec_ou)
            spot_cal_err.append(abs(rfpr_sp - target)); ours_cal_err.append(abs(rfpr_ou - target))
            
        p_cal = 1.0 if np.allclose(spot_cal_err, ours_cal_err) else st.wilcoxon(ours_cal_err, spot_cal_err, zero_method='wilcox')[1]
        task1_results[f'target_{int(target*100)}pct'] = {
            'spot_realized_fpr_mean': round(float(np.mean(spot_rfpr)*100), 2),
            'spot_realized_fpr_std': round(float(np.std(spot_rfpr)*100), 2),
            'spot_recall_mean': round(float(np.mean(spot_rec)*100), 2),
            'spot_calib_error_mean': round(float(np.mean(spot_cal_err)*100), 2),
            'ours_realized_fpr_mean': round(float(np.mean(ours_rfpr)*100), 2),
            'ours_realized_fpr_std': round(float(np.std(ours_rfpr)*100), 2),
            'ours_recall_mean': round(float(np.mean(ours_rec)*100), 2),
            'ours_calib_error_mean': round(float(np.mean(ours_cal_err)*100), 2),
            'wilcoxon_p_calib_error': round(float(p_cal), 4),
            'supported': False
        }
        print(f"  Target {target*100:.0f}%: SPOT FPR={np.mean(spot_rfpr)*100:.2f}%, Ours FPR={np.mean(ours_rfpr)*100:.2f}%, p={p_cal:.4f}")

    # ─────────────────────────────────────────────────────────────
    # TASK 2: Episode Metrics at Matched and Transferred FPR
    # ─────────────────────────────────────────────────────────────
    print("\n--- Task 2: Episode Metrics ---")
    task2_results = {'matched_per_window': {}, 'transferred_cross_host': {}}
    for target in TARGETS:
        # Matched per-window
        sp_ep_1k, ou_ep_1k = [], []
        sp_win_rec, ou_win_rec = [], []
        sp_ep_rec, ou_ep_rec = [], []
        for c in cases:
            y = c['y']
            b_sp, b_ou = c['spot_b'], c['ours_b']
            t_sp = np.percentile(b_sp, (1.0 - target) * 100.0) if len(b_sp) > 0 else 0.0
            t_ou = np.percentile(b_ou, (1.0 - target) * 100.0) if len(b_ou) > 0 else 0.0
            alm_sp = (c['s_spot'] > t_sp); alm_ou = (c['s_ours'] > t_ou)
            
            n_ben = len(c['spot_b'])
            sp_ep_1k.append(count_episodes(alm_sp[y == 0]) / max(n_ben, 1) * 1000.0)
            ou_ep_1k.append(count_episodes(alm_ou[y == 0]) / max(n_ben, 1) * 1000.0)
            sp_win_rec.append(float(np.mean(alm_sp[y == 1])*100))
            ou_win_rec.append(float(np.mean(alm_ou[y == 1])*100))
            sp_ep_rec.append(episode_recall(alm_sp, y)*100.0)
            ou_ep_rec.append(episode_recall(alm_ou, y)*100.0)
            
        p_ep_match = st.wilcoxon(ou_ep_1k, sp_ep_1k, zero_method='wilcox')[1]
        p_rec_match = st.wilcoxon(ou_win_rec, sp_win_rec, zero_method='wilcox')[1]
        task2_results['matched_per_window'][f'target_{int(target*100)}pct'] = {
            'spot_episodes_per_1k': round(float(np.mean(sp_ep_1k)), 2),
            'ours_episodes_per_1k': round(float(np.mean(ou_ep_1k)), 2),
            'spot_window_recall': round(float(np.mean(sp_win_rec)), 2),
            'ours_window_recall': round(float(np.mean(ou_win_rec)), 2),
            'spot_episode_recall': round(float(np.mean(sp_ep_rec)), 2),
            'ours_episode_recall': round(float(np.mean(ou_ep_rec)), 2),
            'wilcoxon_p_episodes': round(float(p_ep_match), 4),
            'wilcoxon_p_window_recall': round(float(p_rec_match), 4),
        }
        
        # Transferred cross-host
        sp_ep_tr, ou_ep_tr = [], []
        sp_ep_rec_tr, ou_ep_rec_tr = [], []
        for i in range(len(cases)):
            tr_sp_b = np.concatenate([cases[j]['spot_b'] for j in range(len(cases)) if j != i])
            tr_ou_b = np.concatenate([cases[j]['ours_b'] for j in range(len(cases)) if j != i])
            tau_sp = np.percentile(tr_sp_b, (1.0 - target) * 100.0)
            tau_ou = np.percentile(tr_ou_b, (1.0 - target) * 100.0)
            c = cases[i]; y = c['y']
            alm_sp = (c['s_spot'] > tau_sp); alm_ou = (c['s_ours'] > tau_ou)
            n_ben = len(c['spot_b'])
            sp_ep_tr.append(count_episodes(alm_sp[y == 0]) / max(n_ben, 1) * 1000.0)
            ou_ep_tr.append(count_episodes(alm_ou[y == 0]) / max(n_ben, 1) * 1000.0)
            sp_ep_rec_tr.append(episode_recall(alm_sp, y)*100.0)
            ou_ep_rec_tr.append(episode_recall(alm_ou, y)*100.0)
            
        p_ep_tr = 1.0 if np.allclose(sp_ep_tr, ou_ep_tr) else st.wilcoxon(ou_ep_tr, sp_ep_tr, zero_method='wilcox')[1]
        task2_results['transferred_cross_host'][f'target_{int(target*100)}pct'] = {
            'spot_episodes_per_1k': round(float(np.mean(sp_ep_tr)), 2),
            'ours_episodes_per_1k': round(float(np.mean(ou_ep_tr)), 2),
            'spot_episode_recall': round(float(np.mean(sp_ep_rec_tr)), 2),
            'ours_episode_recall': round(float(np.mean(ou_ep_rec_tr)), 2),
            'wilcoxon_p_episodes': round(float(p_ep_tr), 4),
        }
        print(f"  Target {target*100:.0f}%: Matched Benign Episodes/1k SPOT={np.mean(sp_ep_1k):.2f}, Ours={np.mean(ou_ep_1k):.2f} (p={p_ep_match:.4f})")

    # ─────────────────────────────────────────────────────────────
    # TASK 3: Justify k on Held-Out Data
    # ─────────────────────────────────────────────────────────────
    print("\n--- Task 3: Justify k on Held-Out Data ---")
    K_GRID = [2, 3, 4, 5, 6, 8]
    Q_GRID = [0.95, 0.98, 0.99]
    grid_data = {}
    for k in K_GRID:
        for q in Q_GRID:
            aucs = [roc_auc_score(c['y'], C.subspace_ecod_scores(c['Xtr'], c['Xev'], n_components=k, q=q)) for c in cases]
            grid_data[f"k={k}_q={q}"] = round(float(np.mean(aucs)), 4)
            
    # Nested LOSO selection of k at q=0.98
    nested_ks, nested_aucs = [], []
    for i in range(len(cases)):
        best_k, best_auc = None, -1.0
        for k in K_GRID:
            tr_aucs = [roc_auc_score(cases[j]['y'], C.subspace_ecod_scores(cases[j]['Xtr'], cases[j]['Xev'], n_components=k, q=0.98))
                       for j in range(len(cases)) if j != i]
            m_auc = np.mean(tr_aucs)
            if m_auc > best_auc:
                best_auc = m_auc; best_k = k
        nested_ks.append(best_k)
        held_s = C.subspace_ecod_scores(cases[i]['Xtr'], cases[i]['Xev'], n_components=best_k, q=0.98)
        nested_aucs.append(roc_auc_score(cases[i]['y'], held_s))
        
    spot_aucs = [roc_auc_score(c['y'], c['s_spot']) for c in cases]
    p_nested = st.wilcoxon(nested_aucs, spot_aucs, zero_method='wilcox')[1]
    task3_results = {
        'sensitivity_grid': grid_data,
        'selected_k_counts': {int(k): nested_ks.count(k) for k in set(nested_ks)},
        'nested_heldout_mean_auc': round(float(np.mean(nested_aucs)), 4),
        'nested_heldout_median_auc': round(float(np.median(nested_aucs)), 4),
        'spot_mean_auc': round(float(np.mean(spot_aucs)), 4),
        'heldout_gain_vs_spot': round(float(np.mean(nested_aucs) - np.mean(spot_aucs)), 4),
        'wilcoxon_p': round(float(p_nested), 5),
    }
    print(f"  Nested Selected k: {task3_results['selected_k_counts']}, Held-out Mean AUC = {np.mean(nested_aucs):.4f} vs SPOT {np.mean(spot_aucs):.4f} (p={p_nested:.5f})")

    # ─────────────────────────────────────────────────────────────
    # TASK 4: CESNET-TimeSeries24 Anti-Artifact Control
    # ─────────────────────────────────────────────────────────────
    print("\n--- Task 4: CESNET Anti-Artifact Control ---")
    allrows = load_per_ip(TAR_PATH, TIMES_TAR, min_rows=1)
    ces_d = {ip: v for ip, v in allrows.items() if len(v) >= MIN_IP_ROWS_PER_IP}
    ces_feats = sorted(k for k in next(iter(ces_d.values()))[0] if not k.startswith('_'))
    
    total_ces_test_win = 0
    raw_sp_alms, raw_ou_alms = 0, 0
    ces_calib_stats = {t: {'sp_alms': 0, 'ou_alms': 0, 'sp_host': [], 'ou_host': []} for t in TARGETS}
    
    for ip, rows in ces_d.items():
        rows = sorted(rows, key=tkey)
        cut = int(len(rows) * 0.6)
        tr, te = rows[:cut], rows[cut:]
        if len(tr) < 10 or len(te) < 10: continue
        Xtr, Xte = C.mat(tr, ces_feats), C.mat(te, ces_feats)
        
        s_sp = C.spot_baseline_scores(Xtr, Xte, q=0.98)
        s_ou = C.subspace_ecod_scores(Xtr, Xte, n_components=min(4, len(ces_feats)-1), q=0.98)
        
        raw_sp_alms += int(np.sum(s_sp > 0))
        raw_ou_alms += int(np.sum(s_ou > 0))
        
        s_tr_sp = C.spot_baseline_scores(Xtr, Xtr, q=0.98)
        s_tr_ou = C.subspace_ecod_scores(Xtr, Xtr, n_components=min(4, len(ces_feats)-1), q=0.98)
        for t in TARGETS:
            tau_sp = np.percentile(s_tr_sp, (1.0 - t) * 100.0)
            tau_ou = np.percentile(s_tr_ou, (1.0 - t) * 100.0)
            alm_sp = (s_sp > tau_sp); alm_ou = (s_ou > tau_ou)
            ces_calib_stats[t]['sp_alms'] += int(np.sum(alm_sp))
            ces_calib_stats[t]['ou_alms'] += int(np.sum(alm_ou))
            ces_calib_stats[t]['sp_host'].append(float(np.mean(alm_sp)*100))
            ces_calib_stats[t]['ou_host'].append(float(np.mean(alm_ou)*100))
        total_ces_test_win += len(te)
        
    task4_results = {
        'n_hosts': len(ces_d),
        'n_test_windows': total_ces_test_win,
        'raw_spot_fpr_pct': round(float(raw_sp_alms / total_ces_test_win * 100), 2),
        'raw_ours_fpr_pct': round(float(raw_ou_alms / total_ces_test_win * 100), 2),
        'calibrated': {}
    }
    for t in TARGETS:
        task4_results['calibrated'][f'target_{int(t*100)}pct'] = {
            'spot_pooled_fpr_pct': round(float(ces_calib_stats[t]['sp_alms'] / total_ces_test_win * 100), 2),
            'spot_host_mean_fpr_pct': round(float(np.mean(ces_calib_stats[t]['sp_host'])), 2),
            'ours_pooled_fpr_pct': round(float(ces_calib_stats[t]['ou_alms'] / total_ces_test_win * 100), 2),
            'ours_host_mean_fpr_pct': round(float(np.mean(ces_calib_stats[t]['ou_host'])), 2),
        }
    print(f"  CESNET: Calibrated @ 5% target: SPOT Pooled FPR = {task4_results['calibrated']['target_5pct']['spot_pooled_fpr_pct']}%, Ours = {task4_results['calibrated']['target_5pct']['ours_pooled_fpr_pct']}%")

    # ─────────────────────────────────────────────────────────────
    # TASK 5: Full-Tree Stratified Re-Run by Verdict
    # ─────────────────────────────────────────────────────────────
    print("\n--- Task 5: Full-Tree Stratified Evaluation ---")
    TREE = os.path.join(os.environ.get('ANTIDDOS_BASE', '/home/detector/Projects/antiddos'),
                        'datasets', 'extracted')
    tree_scenarios = []
    
    def load_tree_entry(fpath, victim, split_mode):
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

    for corp in sorted(os.listdir(TREE)):
        ix_path = os.path.join(TREE, corp, 'index.json')
        if not os.path.isfile(ix_path) or corp == 'CESNET-TimeSeries24': continue
        d = json.load(open(ix_path))
        items = d if isinstance(d, list) else (list(d.values())[0] if len(d) == 1 else list(d.values()))
        if isinstance(items, dict): items = list(items.values())
        for e in items:
            if not isinstance(e, dict): continue
            fn = e.get('file') or (str(e.get('attack_type')) + '.json')
            fpath = os.path.join(TREE, corp, fn)
            if not os.path.exists(fpath): continue
            fit, cal, tb, atk = load_tree_entry(fpath, e.get('victim'), e.get('split_mode', 'within'))
            if fit is None or len(fit) < 10 or len(atk) < 10 or len(tb) == 0: continue
            
            feats = R.active_features(fit)
            tagged = sorted([(tkey(r), 0, r) for r in tb] + [(tkey(r), 1, r) for r in atk], key=lambda x: x[0])
            ev = [t[2] for t in tagged]; y = np.array([t[1] for t in tagged])
            Xtr, Xev = C.mat(fit, feats), C.mat(ev, feats)
            s_sp = C.spot_baseline_scores(Xtr, Xev)
            s_ou = C.subspace_ecod_scores(Xtr, Xev)
            tree_scenarios.append({
                'corpus': corp, 'file': fn, 'verdict': e.get('verdict', 'UNKNOWN'),
                'auc_spot': float(roc_auc_score(y, s_sp)),
                'auc_ours': float(roc_auc_score(y, s_ou)),
            })
            
    task5_results = {}
    verdicts = sorted(list(set(s['verdict'] for s in tree_scenarios)))
    for v in verdicts:
        sub = [s for s in tree_scenarios if s['verdict'] == v]
        s_aucs = [s['auc_spot'] for s in sub]; o_aucs = [s['auc_ours'] for s in sub]
        d_arr = np.array(o_aucs) - np.array(s_aucs)
        p_v = 1.0 if np.allclose(d_arr, 0) else st.wilcoxon(o_aucs, s_aucs, zero_method='wilcox')[1]
        task5_results[v] = {
            'count': len(sub),
            'spot_mean_auc': round(float(np.mean(s_aucs)), 4),
            'ours_mean_auc': round(float(np.mean(o_aucs)), 4),
            'delta_auc': round(float(np.mean(d_arr)), 4),
            'wilcoxon_p': round(float(p_v), 4),
            'wins': sum(1 for x in d_arr if x > 0),
            'ties': sum(1 for x in d_arr if x == 0),
            'losses': sum(1 for x in d_arr if x < 0),
        }
        print(f"  Verdict {v:16s} (n={len(sub):2d}): SPOT={np.mean(s_aucs):.4f}, Ours={np.mean(o_aucs):.4f}, Delta={np.mean(d_arr):+.4f} (p={p_v:.4f})")
        
    s_all = [s['auc_spot'] for s in tree_scenarios]; o_all = [s['auc_ours'] for s in tree_scenarios]
    d_all = np.array(o_all) - np.array(s_all)
    p_all = st.wilcoxon(o_all, s_all, zero_method='wilcox')[1]
    task5_results['ALL_42_SCENARIOS'] = {
        'count': len(tree_scenarios),
        'spot_mean_auc': round(float(np.mean(s_all)), 4),
        'ours_mean_auc': round(float(np.mean(o_all)), 4),
        'delta_auc': round(float(np.mean(d_all)), 4),
        'wilcoxon_p': round(float(p_all), 5),
        'wins': sum(1 for x in d_all if x > 0),
        'ties': sum(1 for x in d_all if x == 0),
        'losses': sum(1 for x in d_all if x < 0),
    }

    # Assemble and write final JSON
    report = {
        'task1_threshold_transfer': task1_results,
        'task2_episode_metrics': task2_results,
        'task3_justify_k': task3_results,
        'task4_cesnet_control': task4_results,
        'task5_full_tree_stratified': task5_results,
    }
    with open(OUT_FILE, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\nSuccessfully wrote validation report to: {OUT_FILE}")

if __name__ == '__main__':
    run_all_validation()
