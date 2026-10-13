#!/usr/bin/env python3
"""Second-tier quantities the manuscript prose quotes, recomputed for the four-corpus, 16-row population
from the deposited per-scenario records (read-only). Writes extra.json and prints a digest.
Usage: extra_numbers.py <results_dir> <out_dir>"""
import json, sys, os, collections, statistics
import numpy as np, scipy.stats as st
RES, OUT = sys.argv[1], sys.argv[2]
J = lambda n: json.load(open(f'{RES}/{n}.json'))
PANEL_POP = f"PANEL-{len(json.load(open(f'{RES}/panel_inventory/PANEL.json'))['panel'])}"
OURS = 'Subspace-Q + EWMA (ours)'; REF = 'POT'
SURV = ['CIC-IDS-2017 Wed-05-07_DoS-Slowhttptest', 'CIC-IDS-2017 Wed-05-07_DoS-Slowloris', 'CIC-DDoS2019 cicddos_03-11_192-168-50-4_UDP']
def vk(r): return f"{r['corpus']}/{str(r['victim']).split('/')[-1]}"
def exact_p(x):
    x = np.asarray(x, float); n = int((x != 0).sum())
    return (None, 0, None) if n == 0 else (round(float(st.wilcoxon(x, zero_method='wilcox', method='exact').pvalue), 5), n, round(2 / 2 ** n, 5))
def cl(vals, groups):
    gs = sorted(set(groups)); return np.array([np.mean([v for v, g in zip(vals, groups) if g == gg]) for gg in gs])
X = {}
# ---- benchmark matrix, 16 rows ----
rows = J('panel_auc_matrix')['per_population'][PANEL_POP]; assert len(rows) == 16
groups = [vk(r) for r in rows]; arms = list(rows[0]['auc'].keys())
d = np.array([r['auc'][OURS] - r['auc'][REF] for r in rows]); S = d.sum()
lab = [r['label'] for r in rows]
X['concentration'] = {'sum_delta': round(float(S), 6), 'mean': round(float(d.mean()), 6), 'cluster_mean': round(float(cl(d, groups).mean()), 6),
    'five_largest': sorted([(l, round(float(x), 6)) for l, x in zip(lab, d)], key=lambda t: -t[1])[:5],
    'five_largest_share_pct': round(100 * sum(sorted(d)[-5:]) / S, 1), 'others_sum': round(float(sum(x for x in d if x > 0) - sum(sorted(d)[-5:])), 6),
    'n_others': int(sum(1 for x in d if x > 0) - 5), 'losses': sorted([(l, round(float(x), 6)) for l, x in zip(lab, d) if x < 0], key=lambda t: t[1]),
    'wins': int((d > 0).sum()), 'top_share_pct': round(100 * d.max() / S, 1), 'top_victim_share_pct': round(100 * sum(x for x, g in zip(d, groups) if g == 'CIC-IDS-2017/192.168.10.50') / S, 1),
    'mean_without_top': round(float(np.delete(d, int(np.argmax(d))).mean()), 6), 'max_other_deletion_shift': round(max(abs(np.delete(d, i).mean() - d.mean()) for i in range(16) if i != int(np.argmax(d))), 6),
    'lovo': {g: round(float(np.mean([x for x, gg in zip(d, groups) if gg != g])), 6) for g in sorted(set(groups))},
    'cluster_deltas': {g: round(float(np.mean([x for x, gg in zip(d, groups) if gg == g])), 6) for g in sorted(set(groups))}, 'cluster_sizes': dict(collections.Counter(groups))}
# ---- clock null vs detector on the 16 rows ----
jf = {r['label']: r for r in J('joint_filter')['rows']}; assert len(jf) == 16
clock = np.array([jf[l]['clock_separability'] for l in lab]); ours = np.array([r['auc'][OURS] for r in rows])
X['clock_vs_ours'] = {'clock_wins': int((clock > ours).sum()), 'ties': int((clock == ours).sum()), 'scenario_p': round(float(st.wilcoxon(clock, ours, zero_method='wilcox')[1]), 4),
    'cluster_wins': int((cl(clock, groups) > cl(ours, groups)).sum()), 'cluster_p': round(float(st.wilcoxon(cl(clock, groups), cl(ours, groups), zero_method='wilcox')[1]), 4),
    'n_ge_095': int((clock >= 0.95).sum()), 'n_perfect': int((clock >= 0.99995).sum()), 'clean_rows': [(l, round(float(jf[l]['clock_separability']), 4), round(float(x), 6)) for l, x in zip(lab, d) if jf[l]['clock_separability'] < 0.95],
    'sum_delta_on_separated': round(float(sum(x for l, x in zip(lab, d) if jf[l]['clock_separability'] >= 0.95)), 6), 'label_runs_2018': [jf[l]['label_runs'] for l in lab if 'IDS-2018' in l], 'slowhttptest_clock': jf['CIC-IDS-2017 Wed-05-07_DoS-Slowhttptest']['clock_separability']}
# ---- clock-null census over scorable four-corpus candidates ----
cn = [c for c in J('clock_null')['candidates'] if c['clock_auc'] is not None and 'monday' not in str(c['file']).lower() and 'cross' not in str(c['file']).lower()]
sep = np.array([max(c['clock_auc'], 1 - c['clock_auc']) for c in cn])
X['clock_census'] = {'n_scorable': len(cn), 'mean_separability': round(float(sep.mean()), 4), 'n_perfect': int((sep >= 0.99995).sum()), 'n_ge_095': int((sep >= 0.95).sum()), 'files': [c['file'] for c in cn]}
# ---- three clock-surviving rows' share under each split ----
X['surviving_rows_share'] = {}
for var in ('deposited', 'threeway40', 'threeway60'):
    m = J(f'split_control_{var}_matrix')['per_population'][PANEL_POP]; dd = {r['label']: r['auc'][OURS] - r['auc'][REF] for r in m}; s = sum(dd.values())
    X['surviving_rows_share'][var] = {'n': len(m), 'slowhttptest_pct': round(100 * dd[SURV[0]] / s, 1), 'three_rows_pct': round(100 * sum(dd[k] for k in SURV) / s, 1), 'sum_delta': round(s, 6), 'mean_auc_ours': round(float(np.mean([r['auc'][OURS] for r in m])), 4), 'margin': round(float(np.mean(list(dd.values()))), 4)}
# ---- DSPOT on the 16 rows ----
ds = np.array([r['auc']['DSPOT'] for r in rows])
X['dspot'] = {'mean': round(float(ds.mean()), 4), 'median': round(float(np.median(ds)), 4), 'min': round(float(ds.min()), 4), 'min_row': lab[int(np.argmin(ds))], 'below_05': int((ds < 0.5).sum()), 'wins_vs_ref': int((ds > np.array([r['auc'][REF] for r in rows])).sum()),
    'zero_ep2_rows': int(sum(1 for r in rows if r['ep2']['DSPOT'] == 0))}
X['zero_ep2_cells'] = {a: int(sum(1 for r in rows if r['ep2'][a] == 0)) for a in arms}; X['zero_ep2_total'] = sum(X['zero_ep2_cells'].values())
# ---- oracle episode ranks and ours-vs-POT tallies ----
def ep_block(rows_, name):
    out = {}
    for k in ('1', '2', '5'):
        means = {a: float(np.mean([r[f'ep{k}'][a] for r in rows_])) for a in arms}; order = sorted(means, key=means.get)
        xa = [r[f'ep{k}'][OURS] for r in rows_]; xb = [r[f'ep{k}'][REF] for r in rows_]; dd = np.array(xa) - np.array(xb); g = [vk(r) for r in rows_]
        p, ninf, floor = exact_p(cl(dd, g))
        out[f'ep@{k}'] = {'means': {a: round(v, 2) for a, v in means.items()}, 'rank_ours': order.index(OURS) + 1, 'rank_ref': order.index(REF) + 1, 'best': order[0], 'worst': order[-1],
            'ours_fewer': int((dd < 0).sum()), 'ours_more': int((dd > 0).sum()), 'ties': int((dd == 0).sum()), 'scenario_p': round(float(st.wilcoxon(xa, xb, zero_method='wilcox')[1]), 4) if not np.allclose(xa, xb) else 1.0, 'cluster_p': p, 'floor': floor}
    return out
X['oracle_episodes'] = ep_block(rows, 'benchmark')
mrows = J('matched_smoothing_matrix')['per_population'][PANEL_POP]; X['matched_episodes'] = ep_block(mrows, 'matched')
md = np.array([r['auc'][OURS] - r['auc'][REF] for r in mrows]); rng = np.random.default_rng(20260827)
# one bootstrap draw for both quantiles, as run_matched_smoothing.boot_ci does
bm = rng.choice(md, size=(10000, len(md)), replace=True).mean(axis=1)
X['matched'] = {'ref_smoothed_mean': round(float(np.mean([r['auc'][REF] for r in mrows])), 4), 'means': {a: round(float(np.mean([r['auc'][a] for r in mrows])), 4) for a in arms},
    'ours_iid_ci': [round(float(np.percentile(bm, q)), 4) for q in (2.5, 97.5)], 'ours_minus_dif': round(float(np.mean([r['auc'][OURS] - r['auc']['DIF'] for r in mrows])), 6)}
# ---- leakage on the 16 rows ----
arch = {r['label']: r['scores'] for r in J('post2023_benchmark_results')['per_scenario']}; amap = {'Subspace-ECOD (ours)': OURS, 'SPOT': REF}
X['leakage'] = {}
for a_old, sc in arch[lab[0]].items():
    a = amap.get(a_old, a_old)
    if a in arms: X['leakage'][a] = {'uncorrected': round(float(np.mean([arch[l][a_old]['auc'] for l in lab])), 4), 'corrected': round(float(np.mean([r['auc'][a] for r in rows])), 4)}
band = sorted([X['leakage'][a]['corrected'] if a in X['leakage'] else float(np.mean([r['auc'][a] for r in rows])) for a in ('DIF', 'INNE', 'IForest', 'POT', 'ECOD', 'COPOD')])
X['band_six_arms'] = {'low': band[0], 'high': band[-1], 'width': round(band[-1] - band[0], 4)}
X['margin_over_ecod'] = {'corrected': round(float(np.mean(ours)) - X['leakage']['ECOD']['corrected'], 4), 'counterfactual': round(float(np.mean(ours)) - X['leakage']['ECOD']['uncorrected'], 4)}
# ---- exact vs approximate Wilcoxon per arm (16 pairs) ----
X['wilcoxon_method'] = {}
ref = np.array([r['auc'][REF] for r in rows])
for a in arms:
    if a == REF: continue
    x = np.array([r['auc'][a] for r in rows]); dd = x - ref; nz = dd[dd != 0]
    p_auto = float(st.wilcoxon(x, ref, zero_method='wilcox')[1]); p_ex = float(st.wilcoxon(x, ref, zero_method='wilcox', method='exact')[1])
    X['wilcoxon_method'][a] = {'p_auto': round(p_auto, 5), 'p_exact': round(p_ex, 5), 'exact_used': abs(p_auto - p_ex) < 1e-9, 'n_nonzero': int(len(nz)), 'ties_in_abs': int(len(nz) - len(set(np.round(np.abs(nz), 12))))}
# ---- DIF seed sensitivity, 16 rows ----
D = J('dif_seed_sensitivity')['per_scenario']
for k in ('corrected', 'archived'):
    a42 = np.array([r[f'{k}_42'] for r in D]); a7 = np.array([r[f'{k}_7'] for r in D]); i = int(np.argmax(np.abs(a42 - a7)))
    X[f'dif_seed_{k}'] = {'n': len(D), 'mean_42': round(float(a42.mean()), 6), 'mean_7': round(float(a7.mean()), 6), 'mean_shift': round(float(abs(a42.mean() - a7.mean())), 6), 'worst_row': D[i]['label'], 'worst_shift': round(float(abs(a42 - a7)[i]), 6)}
X['dif_correction_seed7'] = round(float(X['dif_seed_corrected']['mean_7'] - X['dif_seed_archived']['mean_7']), 4); X['dif_correction_seed42'] = round(float(X['dif_seed_corrected']['mean_42'] - X['dif_seed_archived']['mean_42']), 4)
# ---- engine verification, 16 rows ----
E = J('c_engine_verification_report')['scenarios']
X['engine'] = {'n': len(E), 'min_n_train': min(r['n_train'] for r in E), 'max_d': max(r['d_features'] for r in E), 'max_abs': max(r['max_absolute_error'] for r in E), 'max_rel': max(r['max_relative_error'] for r in E), 'mean_auc': round(float(np.mean([r['auc_python'] for r in E])), 6), 'all_pass': all(r['pass'] for r in E)}
# ---- held-out run: adjacency correlation, DSPOT movement, ties ----
F = [r for r in J('adjacency_free_fpr')['per_scenario'] if r['verdict'] == 'USABLE']; assert len(F) == 16
X['adjacency'] = {'mean_adjacency_pct': round(100 * float(np.mean([r['adjacency'] for r in F])), 1)}
for k in ('1', '2', '5'):
    infl = [r['arms'][OURS][f'stream_fpr@{k}'] - r['arms'][OURS][f'free_fpr@{k}'] for r in F]; adj = [r['adjacency'] for r in F]; af = [r['attack_frac'] for r in F]
    rho, p = st.spearmanr(infl, adj); rho2, p2 = st.spearmanr(infl, af)
    X['adjacency'][f'spearman_inflation_vs_adjacency@{k}'] = (round(float(rho), 2), round(float(p), 3)); X['adjacency'][f'spearman_inflation_vs_attackfrac@{k}'] = (round(float(rho2), 2), round(float(p2), 3))
    X['adjacency'][f'dspot_stream_free@{k}'] = (round(float(np.mean([r['arms']['DSPOT'][f'stream_fpr@{k}'] for r in F])), 2), round(float(np.mean([r['arms']['DSPOT'][f'free_fpr@{k}'] for r in F])), 2))
    moved = {a: int(sum(1 for r in F if abs(r['arms'][a][f'stream_fpr@{k}'] - r['arms'][a][f'free_fpr@{k}']) > 1e-9)) for a in arms}; X['adjacency'][f'arms_moved@{k}'] = {a: n for a, n in moved.items() if n}
S29 = [r for r in J('scenarios29_corrected_results')['per_scenario'] if r['verdict'] == 'USABLE']; assert len(S29) == 16
X['heldout_ties'] = {k: [r['label'] for r in S29 if r['arms'][OURS][f'dr@{k}'] == r['arms'][REF][f'dr@{k}']] for k in ('1', '2', '5')}
X['heldout_n'] = {'n_calib_min': min(r['n_calib'] for r in S29), 'n_benign_test_sum': sum(r['n_benign_test'] for r in S29), 'n_attack_sum': sum(r['n_attack'] for r in S29)}
AE = [r for r in J('adjacency_free_episodes')['per_scenario'] if r['verdict'] == 'USABLE']
for k in ('1', '2', '5'):
    so = sum(r['arms'][OURS][f'ep_starts@{k}'] for r in AE); sn = sum(r['arms'][OURS][f'ep_starts_near_attack@{k}'] for r in AE); ro = sum(r['arms'][REF][f'ep_starts@{k}'] for r in AE); rn = sum(r['arms'][REF][f'ep_starts_near_attack@{k}'] for r in AE)
    X[f'ep_starts_near_attack@{k}'] = {'ours_pct': round(100 * sn / so, 1) if so else None, 'ref_pct': round(100 * rn / ro, 1) if ro else None}
# ---- ledger checks on the 31 candidates ----
L = J('admissibility_ledger')['ledger']; assert len(L) == 31
X['ledger'] = {'n': 31, 'fail_separability': [(e['corpus'], e['scenario'], e['verdict']) for e in L if not e['separable']], 'n_fail_separability': sum(1 for e in L if not e['separable']),
    'direction_rounding_sensitive': [(e['corpus'], e['scenario']) for e in L if e['direction_rounding_sensitive']], 'floor_limited': [(e['corpus'], e['scenario'], e['n_calib'], e['p_floor']) for e in L if e['verdict'] == 'FLOOR-LIMITED'],
    'usable_min_calib': min(e['n_calib'] for e in L if e['verdict'] == 'USABLE'), 'http_flood_best_auc': [e['best_auc'] for e in L if e['scenario'] == 'http_flood'], 'checks_failed_multi': [(e['scenario'], e['checks_failed']) for e in L if len(e['checks_failed']) > 1]}
json.dump(X, open(f'{OUT}/extra.json', 'w'), indent=1, default=str)
for k, v in X.items(): print(f'== {k}: {json.dumps(v, default=str)[:900]}')
