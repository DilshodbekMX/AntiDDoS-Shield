#!/usr/bin/env python3
"""Recompute every aggregate the manuscript prints from the per-scenario records of the four-corpus deposit,
and validate the recomputation against the aggregates those records store. Read-only on <results_dir>.
Usage: four_corpus_tables.py <results_dir> <out_dir>"""
import json, sys, os, statistics, collections
import numpy as np, scipy.stats as st
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'ComparisonResults'))
from corpus_names import canon  # the one corpus-name mapping; raises on an unmapped spelling
RES, OUT = sys.argv[1], sys.argv[2]; os.makedirs(OUT, exist_ok=True)
J = lambda n: json.load(open(f'{RES}/{n}.json'))
PANEL_POP = f"PANEL-{len(json.load(open(f'{RES}/panel_inventory/PANEL.json'))['panel'])}"
SEED = 20260827; OURS = 'Subspace-Q + EWMA (ours)'; REF = 'POT'
vkey = lambda r: f"{canon(r['corpus'])}/{str(r['victim']).split('/')[-1]}"
# ---------------- statistics, as in the deposited runners ----------------
def boot_ci(d, n=10000, seed=SEED):
    rng = np.random.default_rng(seed); d = np.asarray(d, float)
    m = rng.choice(d, size=(n, len(d)), replace=True).mean(axis=1)
    return [round(float(np.percentile(m, 2.5)), 4), round(float(np.percentile(m, 97.5)), 4)]
def cluster_boot_ci(d, groups, n=10000, seed=SEED):
    rng = np.random.default_rng(seed); uniq = sorted(set(groups))
    by = {g: np.array([d[i] for i, x in enumerate(groups) if x == g]) for g in uniq}; out = []
    for _ in range(n):
        pick = rng.choice(len(uniq), size=len(uniq), replace=True)
        out.append(np.concatenate([by[uniq[i]] for i in pick]).mean())
    return [round(float(np.percentile(out, 2.5)), 4), round(float(np.percentile(out, 97.5)), 4)]
def wp_exact(a, b):
    a, b = np.asarray(a, float), np.asarray(b, float)
    return 1.0 if np.allclose(a, b) else float(st.wilcoxon(a, b, zero_method='wilcox')[1])
def wp(a, b):
    return round(wp_exact(a, b), 5)
def exact_p(x):
    x = np.asarray(x, float); n = int(np.sum(x != 0))
    if n == 0: return None, 0, None
    return round(float(st.wilcoxon(x, zero_method='wilcox', alternative='two-sided', method='exact').pvalue), 5), n, round(2.0 / 2 ** n, 5)
def holm(pd):
    """pd: {arm: p_raw}; returns {arm: p_holm}"""
    items = sorted(pd.items(), key=lambda kv: kv[1]); m = len(items); out = {}; run = 0.0
    for i, (k, p) in enumerate(items):
        run = max(run, (m - i) * p); out[k] = round(min(1.0, run), 5)
    return out
def cl_means(vals, groups):
    gs = sorted(set(groups)); return gs, np.array([np.mean([vals[i] for i, g in enumerate(groups) if g == gg]) for gg in gs])
# ---------------- A. admissibility ----------------
def admissibility():
    A = J('admissibility_ledger'); L = A['ledger']
    order = ['NOT-DDOS', 'ATTACKER-SIDE', 'FLOOR-LIMITED', 'NO-FPR', 'INSEPARABLE']
    census = {v: {'n': sum(1 for r in L if r['verdict'] == v), 'corpora': dict(collections.Counter(canon(r['corpus']) for r in L if r['verdict'] == v))} for v in ['USABLE'] + order}
    funnel = [len(L)]; left = list(L)
    for v in order:
        left = [r for r in left if r['verdict'] != v]; funnel.append(len(left))
    corp = collections.Counter(canon(r['corpus']) for r in L); us = collections.Counter(canon(r['corpus']) for r in L if r['verdict'] == 'USABLE')
    fails = collections.Counter(c for r in L for c in r['checks_failed'])
    sep_fail = [r for r in L if 'INSEPARABLE' in r['checks_failed'] or not r['separable']]
    multi = [r for r in L if len(r['checks_failed']) > 1]
    usable = [r for r in L if r['verdict'] == 'USABLE']
    return {'n_candidates': len(L), 'census': census, 'funnel': funnel, 'usable_fraction': {c: f'{us[c]}/{corp[c]}' for c in corp},
            'checks_failed_counts': dict(fails), 'separability_failures': [(canon(r['corpus']), r['scenario'], r['verdict']) for r in sep_fail],
            'multiple_check_failures': [(canon(r['corpus']), r['scenario'], r['checks_failed']) for r in multi],
            'n_usable_victims': len({vkey(r) for r in usable}), 'n_usable_benign_pools': None,
            'highest_surviving_floor': max(({'scenario': r['scenario'], 'p_floor': r['p_floor'], 'n_calib': r['n_calib']} for r in usable), key=lambda d: d['p_floor']),
            'floor_limited_calib': sorted(r['n_calib'] for r in L if r['verdict'] == 'FLOOR-LIMITED'),
            'smallest_admitted_calib': min(r['n_calib'] for r in usable),
            'alpha_conf_sensitivity_changed': list(A['alpha_conf_sensitivity']['changed']),
            'alpha_conf_counts_deposited': A['alpha_conf_sensitivity']['counts']}
# ---------------- C. discrimination (benchmark-style summary over a row list) ----------------
def bench(rows, arms=None, ref=REF, fam_exclude=(REF,)):
    arms = arms or list(rows[0]['auc'].keys()); groups = [str(r['victim']) for r in rows]; out = {}  # raw victim strings, as the runners group
    ref_auc = np.array([r['auc'][ref] for r in rows]); p_exact = {}
    for a in arms:
        x = np.array([r['auc'][a] for r in rows]); e = {'n': len(rows), 'mean_auc': round(float(x.mean()), 4), 'median_auc': round(float(np.median(x)), 4), 'min_auc': round(float(x.min()), 4)}
        for k in ('1', '2', '5'):
            if f'ep{k}' in rows[0] and a in rows[0][f'ep{k}']: e[f'ep@{k}pct'] = round(float(np.mean([r[f'ep{k}'][a] for r in rows])), 2)
        if a != ref:
            d = x - ref_auc; e['vs_ref_auc'] = round(float(d.mean()), 4); p_exact[a] = wp_exact(x, ref_auc); e['vs_ref_p_raw'] = round(p_exact[a], 5)
            e['wins'] = f'{int((d > 0).sum())}/{len(d)}'; e['boot_ci'] = boot_ci(d); e['cluster_boot_ci'] = cluster_boot_ci(d, groups)
            gs, ca = cl_means(x, groups); _, cb = cl_means(ref_auc, groups); e['n_clusters'] = len(gs); e['cluster_p'] = wp(ca, cb)
            e['cluster_mean_delta'] = round(float((ca - cb).mean()), 6)
        out[a] = e
    # Holm and Bonferroni from the unrounded p, as the runners compute them (rounding first moved fifth decimals)
    fam = {a: p_exact[a] for a in arms if a not in fam_exclude}
    hp = holm(fam)
    for a in fam: out[a]['vs_ref_p_holm'] = hp[a]; out[a]['vs_ref_p_bonf'] = round(min(1.0, fam[a] * len(fam)), 5); out[a]['family_size'] = len(fam)
    return out
def concentration(rows, ours=OURS, ref=REF):
    d = np.array([r['auc'][ours] - r['auc'][ref] for r in rows]); groups = [vkey(r) for r in rows]; uniq = sorted(set(groups))
    top = int(np.argmax(d)); vm = {g: float(np.mean([d[i] for i, x in enumerate(groups) if x == g])) for g in uniq}
    vsum = {g: float(sum(d[i] for i, x in enumerate(groups) if x == g)) for g in uniq}; tv = max(vsum, key=vsum.get)
    loo = {g: round(float(np.mean([d[i] for i, x in enumerate(groups) if x != g])), 6) for g in uniq}
    dele = [float(np.mean(np.delete(d, i))) for i in range(len(d))]
    return {'n_scenarios': len(d), 'n_victim_clusters': len(uniq), 'sum_delta_auc': round(float(d.sum()), 6), 'mean_delta_auc': round(float(d.mean()), 6),
            'top_scenario': rows[top]['label'], 'top_scenario_delta': round(float(d[top]), 6), 'top_scenario_share_pct': round(100 * float(d[top] / d.sum()), 1),
            'top_victim': tv, 'top_victim_share_pct': round(100 * vsum[tv] / float(d.sum()), 1), 'victim_cluster_mean': round(float(np.mean(list(vm.values()))), 6),
            'mean_after_deleting_top_scenario': round(float(np.mean(np.delete(d, top))), 6), 'max_other_single_deletion_shift': round(max(abs(dele[i] - d.mean()) for i in range(len(d)) if i != top), 6),
            'leave_one_victim_out_mean_delta': loo, 'wins': int((d > 0).sum()), 'losses': int((d < 0).sum()), 'ties': int((d == 0).sum()),
            'five_largest': sorted([(r['label'], round(float(x), 4)) for r, x in zip(rows, d)], key=lambda t: -t[1])[:5], 'negative': [(r['label'], round(float(x), 4)) for r, x in zip(rows, d) if x < 0]}
# ---------------- populations from the matrix-type records ----------------
def matrix_pops(name):
    return J(name)['per_population']
# ---------------- E. clock filter ----------------
def clockjoint():
    Jf = J('joint_filter'); Cs = J('clock_split_sensitivity')
    rows = Jf['rows']; cs = {r['label']: r for r in Cs['per_scenario']}
    rep = {r['scenario']: r for r in J('split_control_threeway60_matrix')['per_population'][PANEL_POP]}
    def delta(r, split):
        if split == 'threeway' and r['label'] in rep: return rep[r['label']]['auc'][OURS] - rep[r['label']]['auc'][REF]
        return r['delta_auc']
    out = {'n': len(rows)}
    for cut in (0.95, 0.94):
        sep_d = [r for r in rows if r['clock_separability'] >= cut]; clean_d = [r for r in rows if r['clock_separability'] < cut]
        sep_t = [r for r in rows if cs[r['label']]['threeway_split']['clock_separability'] >= cut]
        fixed = {sp: sum(1 for r in rows if cs[r['label']][f'{sp}_split']['clock_auc'] >= cut) for sp in ('deposited', 'threeway')}
        clean_t = [r for r in rows if cs[r['label']]['threeway_split']['clock_separability'] < cut]
        cell = {}
        for split, clean, sep in (('deposited', clean_d, sep_d), ('threeway', clean_t, sep_t)):
            both = clean
            d = np.array([delta(r, split) for r in both]); groups = [vkey(r) for r in both]
            gs, cm = (sorted(set(groups)), np.array([np.mean([d[i] for i, g in enumerate(groups) if g == gg]) for gg in sorted(set(groups))])) if both else ([], np.array([]))
            p, ninf, floor = exact_p(cm) if len(cm) else (None, 0, None)
            cell[split] = {'clock_clean': {'n': len(both), 'mean_delta_auc': round(float(d.mean()), 6) if len(d) else None, 'wins': int((d > 0).sum()) if len(d) else 0,
                                           'n_victim_clusters': len(gs), 'cluster_wilcoxon_p': p, 'cluster_informative_pairs': ninf, 'cluster_exact_floor': floor,
                                           'reachable_at_5pct': (floor is not None and floor < 0.05), 'rows': [r['label'] for r in both], 'carried_rows': [r['label'] for r in both if split == 'threeway' and r['label'] not in rep]},
                           'fixed_sign_ge_cut': fixed[split], 'separability_ge_cut': len(sep), 'oracle_signed_ge_cut': sum(1 for r in rows if max(cs[r['label']][f'{split}_split']['clock_auc'], 1 - cs[r['label']][f'{split}_split']['clock_auc']) >= cut)}
        out[f'cut_{cut:.2f}'] = cell
    d = np.array([r['delta_auc'] for r in rows]); groups = [vkey(r) for r in rows]; gs, cm = cl_means(d, groups)
    out['full_panel'] = {'n': len(rows), 'mean_delta_auc': round(float(d.mean()), 6), 'wins': int((d > 0).sum()), 'losses': int((d < 0).sum()), 'ties': int((d == 0).sum()), 'n_victim_clusters': len(gs), 'victim_cluster_mean': round(float(cm.mean()), 6)}
    return out
# ---------------- F/G/H. held-out operating point, episodes, clustered tests ----------------
def heldout(S=None, F=None, E=None):
    S = S or J('scenarios29_corrected_results'); F = F or J('adjacency_free_fpr'); E = E or J('adjacency_free_episodes')
    rows = S['per_scenario']
    # join the three held-out records on (canonical corpus, scenario file), never on the label: the corpus
    # spelling differs between records (CSE-CIC-IDS2018 / CIC-IDS2018, CIC-DDoS2019 / CICDDoS2019, ...)
    fk = lambda r: (canon(r['corpus']), r['file'])
    fr = {fk(r): r for r in F['per_scenario']}; er = {fk(r): r for r in E['per_scenario']}
    for r in rows: r['_k'] = fk(r)
    U = [r for r in rows if r['verdict'] == 'USABLE']
    pops = {'ALL': rows, 'USABLE': U, 'causal': [r for r in U if r['causal']]}
    arms = list(U[0]['arms'].keys()); out = {}
    for pn, rs in pops.items():
        if not rs: continue
        e = {'n': len(rs), 'n_victim_clusters': len({vkey(r) for r in rs}), 'arms': {}}
        for a in arms:
            v = [r['arms'][a] for r in rs if a in r['arms']]; fv = [fr[r['_k']]['arms'][a] for r in rs if r['_k'] in fr and a in fr[r['_k']]['arms']]
            ev = [er[r['_k']]['arms'][a] for r in rs if r['_k'] in er and a in er[r['_k']]['arms']]
            assert len(fv) == len(v) == len(ev), (pn, a, len(v), len(fv), len(ev))
            ent = {'n': len(v), 'mean_auc': round(statistics.mean(x['auc'] for x in v), 4)}
            for k in ('1', '2', '5'):
                ent[f'dr@{k}pct'] = round(statistics.mean(x[f'dr@{k}'] for x in v), 2); ent[f'fpr@{k}pct'] = round(statistics.mean(x[f'fpr@{k}'] for x in v), 2)
                if ev: ent[f'stream_ep@{k}pct'] = round(statistics.mean(x[f'stream_ep@{k}'] for x in ev), 2); ent[f'free_ep@{k}pct'] = round(statistics.mean(x[f'free_ep@{k}'] for x in ev), 2)
                if fv: ent[f'free_fpr@{k}pct'] = round(statistics.mean(x[f'free_fpr@{k}'] for x in fv), 2)
            e['arms'][a] = ent
        # clustered tests ours vs POT on dr, stream_ep, free_ep
        groups = [vkey(r) for r in rs]; tests = {}
        for k in ('1', '2', '5'):
            for field, src in ((f'dr@{k}', 'S'), (f'stream_ep@{k}', 'E'), (f'free_ep@{k}', 'E'), (f'fpr@{k}', 'S')):
                get = (lambda r, a: r['arms'][a][field]) if src == 'S' else (lambda r, a: er[r['_k']]['arms'][a][field])
                try: xa = [get(r, OURS) for r in rs]; xb = [get(r, REF) for r in rs]
                except KeyError: continue
                gs, ca = cl_means(xa, groups); _, cb = cl_means(xb, groups); dd = ca - cb; p, ninf, floor = exact_p(dd)
                tests[field] = {'clusters': len(gs), 'informative': ninf, 'mean_delta': round(float(dd.mean()), 3), 'cluster_p': p, 'floor': floor, 'ours_higher': int((dd > 0).sum()), 'ours_lower': int((dd < 0).sum()),
                                'scenario_p': wp(xa, xb), 'scenario_mean_delta': round(float(np.mean(np.array(xa) - np.array(xb))), 3)}
        e['tests_ours_vs_POT'] = tests
        # rank of ours among arms on episodes / dr
        for k in ('1', '2', '5'):
            for f in (f'stream_ep@{k}pct', f'free_ep@{k}pct'):
                if f in e['arms'][OURS]: o = sorted(e['arms'], key=lambda a: e['arms'][a][f]); e[f'rank_ours_{f}'] = f'{o.index(OURS)+1}/{len(o)} (best {o[0]} {e["arms"][o[0]][f]})'
            o = sorted(e['arms'], key=lambda a: -e['arms'][a][f'dr@{k}pct']); e[f'rank_ours_dr@{k}pct'] = f'{o.index(OURS)+1}/{len(o)}'
        out[pn] = e
    return out
# ---------------- I. ablation ----------------
def ablation():
    E = J('ewma_ablation'); out = {}
    for pop in (PANEL_POP, 'USABLE-strict'):
        ks = list(E[pop]['per_scenario'])
        a = np.array([E[pop]['per_scenario'][k]['with_ewma'] for k in ks]); b = np.array([E[pop]['per_scenario'][k]['without_ewma'] for k in ks]); d = a - b
        vic = [E[pop]['per_scenario'][k]['victim'] for k in ks]; gs, ca = cl_means(a, vic); _, cb = cl_means(b, vic)
        out[pop] = {'n': len(ks), 'mean_auc_with_ewma': round(float(a.mean()), 4), 'mean_auc_without_ewma': round(float(b.mean()), 4), 'stage_contribution': round(float(d.mean()), 4),
                    'improves': int((d > 0).sum()), 'degrades': int((d < 0).sum()), 'scenario_p': wp(a, b), 'n_clusters': len(gs), 'cluster_p': wp(ca, cb), 'cluster_mean_delta': round(float((ca - cb).mean()), 4)}
    return out
# ---------------- M/N. order sensitivity, DIF seeds, engine ----------------
def order_sens():
    O = J('order_sensitivity'); rows = O['per_scenario']; out = {}
    for grp, sel in ((f'USABLE-{len(rows)}', rows),):
        arms = list(sel[0]['interleaved'].keys()); out[grp] = {'n': len(sel)}
        for a in arms:
            i = np.array([r['interleaved'][a]['auc'] for r in sel]); p = np.array([r['appended'][a]['auc'] for r in sel])
            out[grp][a] = {'interleaved_mean_auc': round(float(i.mean()), 6), 'appended_mean_auc': round(float(p.mean()), 6), 'delta': round(float((p - i).mean()), 6), 'rows_moved': int((np.abs(p - i) > 1e-9).sum()), 'max_row_move': round(float(np.abs(p - i).max()), 6)}
    return out
def dif_seed():
    D = J('dif_seed_sensitivity'); rows = D['per_scenario']
    return {'n': len(rows), **{k: round(float(np.mean([r[k] for r in rows])), 4) for k in ('archived_42', 'archived_7', 'corrected_42', 'corrected_7')},
            'max_abs_seed_shift_corrected': round(float(max(abs(r['corrected_42'] - r['corrected_7']) for r in rows)), 6), 'max_abs_seed_shift_archived': round(float(max(abs(r['archived_42'] - r['archived_7']) for r in rows)), 6)}
def engine():
    V = J('c_engine_verification_report'); rows = V['scenarios']
    return {'n': len(rows), 'max_absolute_error': max(r['max_absolute_error'] for r in rows), 'mean_auc_c': round(float(np.mean([r['auc_c'] for r in rows])), 6), 'mean_auc_python': round(float(np.mean([r['auc_python'] for r in rows])), 6)}
# ---------------- D. leakage ----------------
def leakage(panel_rows):
    P = J('post2023_benchmark_results'); arch = {r['label']: r['scores'] for r in P['per_scenario']}
    amap = {'Subspace-ECOD (ours)': OURS, 'SPOT': REF}; labels = [r['label'] for r in panel_rows]; out = {}
    for a_old, sc in arch[labels[0]].items():
        a_new = amap.get(a_old, a_old)
        if a_new not in panel_rows[0]['auc']: continue
        old = np.mean([arch[l][a_old]['auc'] for l in labels]); new = np.mean([r['auc'][a_new] for r in panel_rows])
        out[a_new] = {'uncorrected': round(float(old), 4), 'corrected': round(float(new), 4), 'change': round(float(new - old), 4)}
    return out
# ---------------- main ----------------
R40DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results')
JR = lambda n: json.load(open(f'{R40DIR}/{n}.json'))
def run():
    N = {}; N['admissibility'] = admissibility()
    pm = matrix_pops('panel_auc_matrix'); N['populations'] = {p: {'n': len(rs), 'victims': len({vkey(r) for r in rs}), 'corpora': dict(collections.Counter(canon(r['corpus']) for r in rs))} for p, rs in pm.items()}
    N['discrimination'] = {p: bench(rs) for p, rs in pm.items()}
    N['concentration'] = {p: concentration(rs) for p, rs in pm.items()}
    N['leakage'] = leakage(pm[PANEL_POP])
    N['clock'] = clockjoint(); N['heldout'] = heldout(); N['ablation'] = ablation()
    # the held-out operating point re-scored under the repaired 40/40/20 split (post hoc; records in recompute/results/)
    if os.path.exists(f'{R40DIR}/scenarios29_corrected_results_threeway40.json'):
        N['heldout_threeway40'] = heldout(JR('scenarios29_corrected_results_threeway40'), JR('adjacency_free_fpr_threeway40'), JR('adjacency_free_episodes_threeway40'))
    mm = matrix_pops('matched_smoothing_matrix'); N['matched'] = {p: bench(rs) for p, rs in mm.items()}; N['matched_concentration'] = {p: concentration(rs) for p, rs in mm.items()}
    N['split_control'] = {}
    for var in ('deposited', 'threeway40', 'threeway60'):
        sm = matrix_pops(f'split_control_{var}_matrix'); N['split_control'][var] = {p: bench(rs) for p, rs in sm.items()}
        for p, rs in sm.items():  # clustered benign-episode comparison ours vs POT at each target
            groups = [vkey(r) for r in rs]; t = {}
            for k in ('1', '2', '5'):
                xa = [r[f'ep{k}'][OURS] for r in rs]; xb = [r[f'ep{k}'][REF] for r in rs]; gs, ca = cl_means(xa, groups); _, cb = cl_means(xb, groups); p_, ninf, floor = exact_p(ca - cb)
                t[f'ep@{k}pct'] = {'ours': round(float(np.mean(xa)), 2), 'POT': round(float(np.mean(xb)), 2), 'cluster_p': p_, 'informative': ninf, 'floor': floor, 'clusters': len(gs), 'scenario_p': wp(xa, xb)}
            N['split_control'][var][p]['_episodes_ours_vs_POT'] = t
    N['order_sensitivity'] = order_sens(); N['dif_seed'] = dif_seed(); N['engine_verification'] = engine()
    return N
N = run()
json.dump({'four': N, 'scope': 'the four-corpus deposit: CIC-IDS-2017, CSE-CIC-IDS2018, CIC-DDoS2019, LITNET-2020'},
          open(f'{OUT}/numbers.json', 'w'), indent=1, default=str)
# ---------------- validation of the recomputation against the aggregates the records store ----------------
bad = []; ok = 0
def cmp(name, a, b, tol=0.0):
    global ok
    try:
        if isinstance(a, (list, tuple)) and all(isinstance(x, str) for x in a): good = list(a) == list(b)
        elif isinstance(a, (list, tuple)): good = all(abs(float(x) - float(y)) <= tol for x, y in zip(a, b)) and len(a) == len(b)
        elif isinstance(a, str) or isinstance(b, str): good = str(a) == str(b)
        else: good = abs(float(a) - float(b)) <= tol
    except Exception: good = False
    if good: ok += 1
    else: bad.append((name, a, b))
C = J('corrected_benchmark_results')['results']
for pop in (PANEL_POP, 'USABLE-strict'):
    for arm, e in C[pop].items():
        m = N['discrimination'][pop][arm]
        for k in ('mean_auc', 'median_auc', 'min_auc', 'vs_ref_auc', 'vs_ref_p_raw', 'vs_ref_p_holm', 'vs_ref_p_bonf', 'cluster_p', 'n_clusters', 'wins', 'boot_ci', 'cluster_boot_ci', 'ep@1pct', 'ep@2pct', 'ep@5pct'):
            if k in e: cmp(f'corrected_benchmark/{pop}/{arm}/{k}', e[k], m.get(k), 0.00006 if 'p' in k and 'ep' not in k else 0.0)
Mb = J('matched_smoothing_benchmark')['results']
for pop in Mb:
    for arm, e in Mb[pop].items():
        m = N['matched'][pop].get(arm, {})
        for k in ('mean_auc', 'vs_ref_auc', 'vs_ref_p_raw', 'vs_ref_p_holm', 'cluster_p', 'boot_ci', 'cluster_boot_ci', 'ep@1pct', 'ep@5pct'):
            if k in e: cmp(f'matched/{pop}/{arm}/{k}', e[k], m.get(k), 0.00006 if k.endswith('p') or '_p_' in k else 0.0)
Md = J('matched_smoothing_matrix')['diagnostics']
for pop in Md:
    for k in ('sum_delta_auc', 'mean_delta_auc', 'top_scenario_share_pct', 'top_victim_share_pct', 'victim_cluster_mean', 'mean_after_deleting_top_scenario', 'max_other_single_deletion_shift'):
        if k in Md[pop]: cmp(f'matched_diag/{pop}/{k}', Md[pop][k], N['matched_concentration'][pop].get(k), 0.0000015)
Pd = J('panel_auc_matrix')['diagnostics']
for pop in Pd:
    for k in ('sum_delta_auc', 'mean_delta_auc', 'top_scenario_share_pct', 'top_victim_share_pct', 'victim_cluster_mean', 'mean_after_deleting_top_scenario', 'max_other_single_deletion_shift'):
        if k in Pd[pop]: cmp(f'panel_diag/{pop}/{k}', Pd[pop][k], N['concentration'][pop].get(k), 0.0000015)
for var in ('deposited', 'threeway40', 'threeway60'):
    B = J(f'split_control_{var}_benchmark')['results']
    for pop in B:
        for arm, e in B[pop].items():
            m = N['split_control'][var][pop].get(arm, {})
            for k in ('mean_auc', 'vs_ref_auc', 'vs_ref_p_raw', 'cluster_p', 'ep@1pct', 'ep@5pct', 'boot_ci', 'cluster_boot_ci'):
                if k in e: cmp(f'split_{var}/{pop}/{arm}/{k}', e[k], m.get(k), 0.00006 if 'p' in k and 'ep' not in k else 0.0)
    Dg = J(f'split_control_{var}_matrix')['diagnostics']
    for pop in Dg:
        ep = Dg[pop]['episodes']
        for k, v in ep.items():
            if isinstance(v, dict) and 'cluster_wilcoxon_p' in v: cmp(f'split_{var}_episodes/{pop}/{k}/cluster_p', v['cluster_wilcoxon_p'], N['split_control'][var][pop]['_episodes_ours_vs_POT'].get(k.replace('ep', 'ep@') + 'pct' if not k.startswith('ep@') else k, {}).get('cluster_p'), 0.00006)
Jf = J('joint_filter'); jc = N['clock']['cut_0.95']
for split in ('deposited', 'threeway'):
    r = Jf['clock_clean_stratum'][f'{split}_split']; m = jc[split]['clock_clean']
    for k in ('n', 'mean_delta_auc', 'wins', 'n_victim_clusters', 'cluster_wilcoxon_p', 'cluster_informative_pairs', 'cluster_exact_floor', 'reachable_at_5pct', 'carried_rows'): cmp(f'joint/{split}/{k}', r[k], m.get(k), 0.00006)
for k in ('n', 'mean_delta_auc', 'wins', 'losses', 'n_victim_clusters', 'victim_cluster_mean'): cmp(f'joint/full_panel/{k}', Jf['full_panel'][k], N['clock']['full_panel'][k], 0.0000015)
Cs = J('clock_split_sensitivity')['summary']
for split in ('deposited', 'threeway'):
    for cut in ('0.95', '0.94'):
        r = Cs[f'{split}_split'][f'cut_{cut}']; m = N['clock'][f'cut_{cut}'][split]
        cmp(f'clocksplit/{split}/{cut}/fixed', r['fixed_sign_ge_cut'], m['fixed_sign_ge_cut']); cmp(f'clocksplit/{split}/{cut}/oracle', r['oracle_signed_ge_cut'], m['oracle_signed_ge_cut']); cmp(f'clocksplit/{split}/{cut}/clock_clean', r['clock_clean'], m['clock_clean']['n'])
def check_heldout(tag, S, E, Fs, H):
    global ok
    ALL_KEY = f"ALL-{H['ALL']['n']}"; USABLE_KEY = f"USABLE-{H['USABLE']['n']}"
    for pop, mine in ((ALL_KEY, 'ALL'), (USABLE_KEY, 'USABLE'), ('causal-split-only', 'causal')):
        for arm, e in S[pop].items():
            m = H[mine]['arms'].get(arm, {})
            for k in ('n', 'mean_auc', 'dr@1pct', 'fpr@1pct', 'dr@2pct', 'fpr@2pct', 'dr@5pct', 'fpr@5pct'): cmp(f'{tag}scen29/{pop}/{arm}/{k}', e[k], m.get(k))
    for pop, mine in ((USABLE_KEY, 'USABLE'), (f"USABLE-{H['causal']['n']}-causal", 'causal')):
        for arm, e in E[pop].items():
            if not isinstance(e, dict): continue
            m = H[mine]['arms'].get(arm, {})
            for k in ('stream_ep@1pct', 'free_ep@1pct', 'stream_ep@5pct', 'free_ep@5pct', 'stream_fpr@2pct'): 
                if k in e: cmp(f'{tag}afe/{pop}/{arm}/{k}', e[k], m.get(k.replace('stream_fpr', 'fpr')))
    for pop, mine in ((ALL_KEY, 'ALL'), (USABLE_KEY, 'USABLE')):
        for arm, e in Fs[pop].items():
            m = H[mine]['arms'].get(arm, {})
            for k in ('1', '2', '5'): cmp(f'{tag}aff/{pop}/{arm}/free_fpr@{k}', e[f'free_fpr@{k}'], m.get(f'free_fpr@{k}pct')); cmp(f'{tag}aff/{pop}/{arm}/stream_fpr@{k}', e[f'stream_fpr@{k}'], m.get(f'fpr@{k}pct'))
check_heldout('', J('scenarios29_corrected_results')['summary'], J('adjacency_free_episodes')['summary'], J('adjacency_free_fpr')['summary'], N['heldout'])
if 'heldout_threeway40' in N:
    check_heldout('r40/', JR('scenarios29_corrected_results_threeway40')['summary'], JR('adjacency_free_episodes_threeway40')['summary'], JR('adjacency_free_fpr_threeway40')['summary'], N['heldout_threeway40'])
A = J('admissibility_ledger')
for v, e in A['census'].items(): cmp(f'ledger/census/{v}', e['n'], N['admissibility']['census'][v]['n'])
cmp('ledger/n_usable_victims', A['n_usable_victims'], N['admissibility']['n_usable_victims']); cmp('ledger/floor', A['highest_surviving_floor']['p_floor'], N['admissibility']['highest_surviving_floor']['p_floor'])
Eb = J('ewma_ablation')
for pop in (PANEL_POP, 'USABLE-strict'):
    for k in ('n_victim_clusters', 'mean_auc_with_ewma', 'mean_auc_without_ewma', 'stage_contribution', 'cluster_mean_delta', 'improves', 'degrades'): cmp(f'ablation/{pop}/{k}', Eb[pop][k], N['ablation'][pop][k.replace('n_victim_clusters', 'n_clusters')])
    cmp(f'ablation/{pop}/cluster_p', Eb[pop]['cluster_p'], N['ablation'][pop]['cluster_p'], 0.00006); cmp(f'ablation/{pop}/scenario_p', Eb[pop]['scenario_p'], N['ablation'][pop]['scenario_p'], 0.00006)
O = J('order_sensitivity')['summary']
for grp, e in O.items():
    m = N['order_sensitivity'][grp]  # direct lookup: a group tag the recomputation does not produce raises
    for arm, v in e.items():
        if isinstance(v, dict):
            for kk in ('interleaved_mean_auc', 'appended_mean_auc', 'delta', 'rows_moved'): cmp(f'order/{grp[:12]}/{arm}/{kk}', v[kk], m[arm][kk], 0.0000015)
print(f'VALIDATION: {ok} aggregates reproduced, {len(bad)} mismatches')
for name, a, b in bad[:40]: print(f'  MISMATCH {name}: deposited {a} vs recomputed {b}')
json.dump({'ok': ok, 'mismatches': bad}, open(f'{OUT}/validation.json', 'w'), indent=1, default=str)
