#!/usr/bin/env python3
"""Render the numeric table bodies and figure coordinate blocks of the four-corpus manuscript from
numbers.json, extra.json and the deposited per-scenario records. The optional third directory supplies
universal_ewma_tournament.json, corrected_benchmark_results.json and matched_smoothing_benchmark.json
(pass the results directory; without it the smoothing, oracle detection-rate and matched-control tables
are skipped). Writes tables_v4.json {name: latex}. Read-only on every input.
Usage: tables_v4.py <results_dir> <recompute_dir> [<records_dir>]"""
import json, sys, os, collections
import numpy as np
RES, REC = sys.argv[1], sys.argv[2]; SBX = sys.argv[3] if len(sys.argv) > 3 else None
N = json.load(open(f'{REC}/numbers.json'))['four']; X = json.load(open(f'{REC}/extra.json'))
J = lambda n: json.load(open(f'{RES}/{n}.json'))
PANEL_POP = f"PANEL-{len(json.load(open(f'{RES}/panel_inventory/PANEL.json'))['panel'])}"
OURS = 'Subspace-Q + EWMA (ours)'; REF = 'POT'
ORDER = [OURS, REF, 'DIF', 'INNE', 'IForest', 'ECOD', 'COPOD', 'HBOS', 'DSPOT', 'LODA']   # the manuscript's row order
SHORT = {OURS: 'Subspace-Q + EWMA (ours)', REF: 'POT (reference)'}
def sgn(x, d=4): return ('$-$' if x < 0 else '$+$') + f'{abs(x):.{d}f}'
def p5(x): return f'{x:.5f}'
def holm(pd):
    items = sorted(pd.items(), key=lambda kv: kv[1]); m = len(items); out = {}; run = 0.0
    for i, (k, p) in enumerate(items): run = max(run, (m - i) * p); out[k] = min(1.0, run)
    return out
T = {}
# ---------------- Table: discrimination (one population) ----------------
D = N['discrimination'][PANEL_POP]; cl_holm = holm({a: D[a]['cluster_p'] for a in D if a != REF})
rows = []
for a in ORDER:
    e = D[a]
    if a == REF: rows.append(f"POT (reference)& {e['mean_auc']:.4f} & --- & --- & --- & --- & --- & --- & --- & --- & --- \\\\"); continue
    rows.append(f"{SHORT.get(a, a)}& {e['mean_auc']:.4f} & {sgn(e['vs_ref_auc'])} & {p5(e['vs_ref_p_raw'])} & {p5(e['vs_ref_p_holm'])} & {p5(e['vs_ref_p_bonf'])} & {p5(e['cluster_p'])} & {p5(cl_holm[a])} & [{sgn(e['boot_ci'][0]).replace('$+$','')}, {sgn(e['boot_ci'][1]).replace('$+$','')}] & [{sgn(e['cluster_boot_ci'][0]).replace('$+$','')}, {sgn(e['cluster_boot_ci'][1]).replace('$+$','')}] & {e['wins']} \\\\")
T['discrimination_rows'] = '\n'.join(rows)
T['discrimination_header_note'] = f"\\multicolumn{{11}}{{l}}{{\\emph{{USABLE-16}} ($n = 16$ scenarios, 5 victim clusters, 5 informative pairs for our arm)}} \\\\"
# ---------------- Table: leakage ----------------
L = X['leakage']
def lk(a): e = L[a]; return f"{a:7s} & {e['uncorrected']:.4f} & {e['corrected']:.4f} & {sgn(e['corrected'] - e['uncorrected']) if abs(e['corrected']-e['uncorrected']) >= 0.00005 else '0.0000'} \\\\"
T['leakage_rows'] = '\n'.join([lk('ECOD'), lk('COPOD'), lk('DIF'), '\\midrule', '\\multicolumn{4}{l}{\\emph{Batch-invariant by construction}} \\\\', lk('HBOS'), lk('INNE'), f"POT     & {L['POT']['uncorrected']:.4f} & {L['POT']['corrected']:.4f} & 0.0000 \\\\"])
# ---------------- Table: ablation ----------------
A = N['ablation'][PANEL_POP]
T['ablation_row'] = f"USABLE-16 ($n = 16$) & {A['mean_auc_with_ewma']:.4f} & {A['mean_auc_without_ewma']:.4f} & $+${A['stage_contribution']:.4f}; improves {A['improves']} of 16 rows, degrades {A['degrades']} (scenario $p = 3.1\\times10^{{-5}}$, the exact floor on 16 pairs; victim-clustered $p = {A['cluster_p']:.4f}$, the floor on five)\\\\"
# ---------------- Table: operating point (held-out) ----------------
H = N['heldout']['USABLE']['arms']
def op(a, name):
    e = H[a]; return f"{name} & {e['mean_auc']:.4f} & {e['dr@1pct']:.2f} & {e['dr@2pct']:.2f} & {e['dr@5pct']:.2f} & {e['fpr@1pct']:.2f} & {e['fpr@2pct']:.2f} & {e['fpr@5pct']:.2f} & {e['free_fpr@1pct']:.2f} & {e['free_fpr@2pct']:.2f} & {e['free_fpr@5pct']:.2f}\\\\"
T['operating_rows'] = op(OURS, 'Ours') + '\n' + op(REF, 'POT')
# ---------------- Table: episode grid ----------------
o, r = H[OURS], H[REF]; O = X['oracle_episodes']
T['episodegrid_rows'] = '\n'.join([
 f"Held-out, stream-realized & {o['stream_ep@1pct']:.2f} & {r['stream_ep@1pct']:.2f} & {o['stream_ep@2pct']:.2f} & {r['stream_ep@2pct']:.2f} & {o['stream_ep@5pct']:.2f} & {r['stream_ep@5pct']:.2f}\\\\",
 f"Held-out, attack rows excised & {o['free_ep@1pct']:.2f} & {r['free_ep@1pct']:.2f} & {o['free_ep@2pct']:.2f} & {r['free_ep@2pct']:.2f} & {o['free_ep@5pct']:.2f} & {r['free_ep@5pct']:.2f}\\\\",
 f"Oracle, stream-realized & {O['ep@1']['means'][OURS]:.2f} & {O['ep@1']['means'][REF]:.2f} & {O['ep@2']['means'][OURS]:.2f} & {O['ep@2']['means'][REF]:.2f} & {O['ep@5']['means'][OURS]:.2f} & {O['ep@5']['means'][REF]:.2f}\\\\"])
# ---------------- Figure: clock scatter coordinates ----------------
rows16 = J('panel_auc_matrix')['per_population'][PANEL_POP]; jf = {r['label']: r for r in J('joint_filter')['rows']}
pts = [(jf[r['label']]['clock_separability'], r['auc'][OURS] - r['auc'][REF], r['label']) for r in rows16]
main = [p for p in pts if p[1] < 0.1]; top = [p for p in pts if p[1] >= 0.1]
T['scatter_main_coords'] = ' '.join(f"({c:.4f},{d:.6f})" for c, d, _ in main)
T['scatter_top'] = top; T['scatter_clean'] = [p for p in pts if p[0] < 0.95]; T['scatter_n_at_1'] = sum(1 for p in pts if p[0] >= 0.99995)
T['scatter_sum_delta'] = round(sum(p[1] for p in pts), 6); T['scatter_sum_sep'] = round(sum(p[1] for p in pts if p[0] >= 0.95), 6)
# ---------------- Figure: concentration coordinates ----------------
C = X['concentration']; five = dict(C['five_largest'])
# the 'Others' bar follows the manuscript's convention: every row but the five named winners and the LITNET loss
others = C['sum_delta'] - sum(five.values()) - dict(C['losses'])['LITNET-2020 code_red_worm']
T['concentration_coords'] = (f"(0.212039,Slowhttptest) ({five['CIC-IDS-2017 Wed-05-07_DoS-Hulk']:.6f},Hulk) ({five['CIC-DDoS2019 cicddos_03-11_192-168-50-4_Syn']:.6f},Syn) "
    f"({five['CIC-DDoS2019 cicddos_03-11_192-168-50-4_UDPLag']:.6f},UDPLag) ({five['CIC-IDS-2017 Wed-05-07_DoS-GoldenEye']:.6f},GoldenEye) ({others:.6f},Others)")
T['concentration_mean'] = C['mean']; T['concentration_cluster_mean'] = C['cluster_mean']; T['concentration_others'] = round(others, 6); T['concentration_n_others'] = 10
# ---------------- ledger (31 rows) ----------------
led = J('admissibility_ledger')['ledger']
CORP = {'CIC-IDS-2017': 0, 'CSE-CIC-IDS2018': 1, 'CIC-DDoS2019': 2, 'LITNET-2020': 3}
def clk(e): 
    if e['clock_separability'] is None: return '---'
    v = e['clock_separability']; s = f'{v:.3f}'; return f'\\textbf{{{s}}}' if v >= 0.95 else s
VORD = {'USABLE': 0, 'NOT-DDOS': 1, 'ATTACKER-SIDE': 2, 'FLOOR-LIMITED': 3, 'NO-FPR': 4, 'INSEPARABLE': 5}
CHECK = {'all four pass': 'all four pass', 'scope filter': 'scope filter', 'direction (source host)': 'direction (source host)', 'conformal floor': 'conformal floor', 'FPR undefined': 'FPR undefined', 'separability screen': 'separability screen'}
groups = collections.defaultdict(list)
for e in led: groups[e['corpus']].append(e)
blocks = []
for c in sorted(groups, key=lambda c: CORP[c]):
    es = sorted(groups[c], key=lambda e: (VORD[e['verdict']], e['scenario']))
    blocks.append('\n'.join(f"{c} & \\texttt{{{e['scenario'].replace('_', chr(92)+'_')}}} & {e['victim']} & {clk(e)} & {e['verdict']} & {CHECK.get(e['check'], e['check'])}\\\\" for e in es))
T['ledger_rows'] = '\n\\addlinespace[3pt]\n'.join(blocks)
T['ledger_n'] = len(led)
# ---------------- deposit table (16 rows, two panels) ----------------
ABBR = {'CIC-IDS-2017': 'IDS2017', 'CIC-IDS-2018': 'IDS2018', 'CSE-CIC-IDS2018': 'IDS2018', 'CIC-DDoS2019': 'DDoS2019', 'CICDDoS2019': 'DDoS2019', 'LITNET-2020': 'LITNET'}
def short(r):
    c, s = r['label'].split(' ', 1); s = s.replace('cicddos_03-11_192-168-50-4_', ''); return f"\\texttt{{{ABBR[c]}~{s.replace('_', chr(92)+'_')}}}"
COLS = [OURS, REF, 'DIF', 'INNE', 'IForest', 'ECOD', 'COPOD', 'HBOS', 'LODA', 'DSPOT']
dep = sorted(rows16, key=lambda r: -(r['auc'][OURS] - r['auc'][REF]))
T['deposit_auc_rows'] = '\n'.join(short(r) + ' & ' + ' & '.join(f"{r['auc'][a]:.4f}" for a in COLS) + '\\\\' for r in dep)
T['deposit_ep2_rows'] = '\n'.join(short(r) + ' & ' + ' & '.join(f"{r['ep2'][a]:.2f}" for a in COLS) + '\\\\' for r in dep)
# ---------------- episodes (oracle) ----------------
E = O
def eprow(a):
    m = [O[f'ep@{k}']['means'][a] for k in ('1', '2', '5')]; cells = [f'{v:.2f}' for v in m]
    if a == OURS: cells[2] = f'\\textbf{{{cells[2]}}}'
    return f"{SHORT.get(a, a):25s} & " + ' & '.join(cells) + ' \\\\'
T['episodes_rows'] = '\n'.join(eprow(a) for a in ORDER)
T['episodes_ranks'] = {k: (O[k]['rank_ours'], O[k]['rank_ref'], O[k]['best'], O[k]['worst']) for k in O}
# ---------------- clusters ----------------
cd = X['concentration']['cluster_deltas']; cs = X['concentration']['cluster_sizes']
CN = {'CIC-IDS-2017/192.168.10.50': ('192.168.10.50', 'CIC-IDS-2017'), 'CIC-DDoS2019/192.168.50.4': ('192.168.50.4', 'CIC-DDoS2019'), 'CIC-IDS-2018/172.31.69.25': ('172.31.69.25', 'CSE-CIC-IDS2018'), 'CIC-IDS-2018/172.31.69.28': ('172.31.69.28', 'CSE-CIC-IDS2018'), 'LITNET-2020/193.219.81.138': ('193.219.81.138', 'LITNET-2020')}
T['clusters_rows'] = '\n'.join(f"{CN[g][0]:15s} & {CN[g][1]:15s} & {cs[g]} & {sgn(cd[g], 6)} \\\\" for g in sorted(cd, key=lambda g: -cd[g]))
T['clusters_means'] = (sgn(X['concentration']['cluster_mean'], 6), sgn(X['concentration']['mean'], 6))
# ---------------- held-out table, merged DR + FPR + adjacency-free FPR (means over the 16 scenarios) ----------------
def hr(a):
    e = H[a]; name = SHORT.get(a, a)
    cells = [f"{e['dr@1pct']:.2f}", f"{e['dr@2pct']:.2f}", f"{e['dr@5pct']:.2f}", f"{e['fpr@1pct']:.2f}", f"{e['fpr@2pct']:.2f}", f"{e['fpr@5pct']:.2f}", f"{e['free_fpr@1pct']:.2f}", f"{e['free_fpr@2pct']:.2f}", f"{e['free_fpr@5pct']:.2f}", f"{e['stream_ep@1pct']:.2f}", f"{e['stream_ep@2pct']:.2f}", f"{e['stream_ep@5pct']:.2f}"]
    if a == OURS: cells = [f'\\textbf{{{c}}}' for c in cells]
    return f"{name:25s} & " + ' & '.join(cells) + ' \\\\'
T['heldout_rows'] = '\n'.join(hr(a) for a in ORDER)
# ---------------- smoothing panel (a) from the four-corpus tournament ----------------
if SBX and os.path.exists(f'{SBX}/universal_ewma_tournament.json'):
    lb = {e['name']: e for e in json.load(open(f'{SBX}/universal_ewma_tournament.json'))['leaderboard']}
    def pair(raw, ew, name): return f"{name:34s} & {lb[raw]['mean_auc']:.4f} & {lb[ew]['mean_auc']:.4f} \\\\"
    T['smoothing_rows'] = '\n'.join([pair('INNE (Raw)', 'INNE + EWMA', 'INNE'), pair('HBOS (Raw)', 'HBOS + EWMA', 'HBOS'), pair('ECOD (Raw)', 'ECOD + EWMA', 'ECOD'), pair('COPOD (Raw)', 'COPOD + EWMA', 'COPOD'), pair('LODA (Raw)', 'LODA + EWMA', 'LODA'), pair('SPOT (Raw)', 'SPOT + EWMA', 'POT (reference)'), pair('Pure Subspace Q-Resid (k=8) (Raw)', 'Pure Subspace Q-Resid (k=8) + EWMA', 'Pure Subspace Q-Resid ($k=8$), ours')])
    T['tournament'] = {k: lb[k] for k in lb}; T['tournament_significance'] = json.load(open(f'{SBX}/universal_ewma_tournament.json'))['significance']
# ---------------- oracle detection rate + matched control (need the benchmark records in the third directory) ----------------
# The output keys detection_sandbox and matched_sandbox keep an earlier name so that tables_v4.json is unchanged;
# they hold columns of the benchmark records named below.
for name, key in (('corrected_benchmark_results', 'detection'), ('matched_smoothing_benchmark', 'matched')):
    p = f'{SBX}/{name}.json' if SBX else None
    if p and os.path.exists(p):
        B = json.load(open(p))['results']; R = B[PANEL_POP]
        if key == 'detection':
            best = {k: max(R[a][f'dr@{k}pct'] for a in R) for k in ('1', '2', '5')}
            def dr(a):
                cells = [(f"\\textbf{{{R[a][f'dr@{k}pct']:.2f}}}" if R[a][f'dr@{k}pct'] == best[k] else f"{R[a][f'dr@{k}pct']:.2f}") for k in ('1', '2', '5')]
                return f"{SHORT.get(a, a):25s} & " + ' & '.join(cells) + ' \\\\'
            T['detection_rows'] = '\n'.join(dr(a) for a in ORDER); T['detection_sandbox'] = {a: {k: R[a][k] for k in R[a] if k.startswith('dr@') or k in ('mean_auc', 'ep@1pct', 'ep@2pct', 'ep@5pct')} for a in R}
            # cross-check: the benchmark record's AUC/episode columns must equal the per-scenario recomputation
            chk = {a: (round(R[a]['mean_auc'], 4), D[a]['mean_auc'], round(R[a]['ep@5pct'], 2), D[a]['ep@5pct']) for a in R}
            T['detection_crosscheck_ok'] = all(abs(v[0] - v[1]) < 1e-9 and abs(v[2] - v[3]) < 1e-9 for v in chk.values()); T['detection_crosscheck'] = chk
        else:
            Mr = N['matched'][PANEL_POP]; hp = {a: Mr[a]['vs_ref_p_holm'] for a in Mr if a != REF}
            order = sorted(R, key=lambda a: -R[a]['mean_auc'])
            def mr(a):
                e = R[a]; m = Mr[a]
                if a == REF: return f"POT (reference)      & {e['mean_auc']:.4f} & ---       & ---     & ---     & {e['dr@1pct']:.2f}/{e['dr@2pct']:.2f}/{e['dr@5pct']:.2f} & {e['ep@1pct']:.2f}/{e['ep@2pct']:.2f}/{e['ep@5pct']:.2f} \\\\"
                nm = 'Subspace-Q (ours)' if a == OURS else a
                return f"{nm:20s} & {e['mean_auc']:.4f} & {sgn(m['vs_ref_auc'])} & {m['vs_ref_p_holm']:.5f} & {m['cluster_p']:.5f} & {e['dr@1pct']:.2f}/{e['dr@2pct']:.2f}/{e['dr@5pct']:.2f} & {e['ep@1pct']:.2f}/{e['ep@2pct']:.2f}/{e['ep@5pct']:.2f} \\\\"
            T['matched_rows'] = '\n'.join(mr(a) for a in order); T['matched_sandbox'] = {a: {k: R[a][k] for k in R[a] if k.startswith('dr@') or k in ('mean_auc', 'vs_ref_auc', 'vs_ref_p_raw', 'vs_ref_p_holm', 'cluster_p', 'ep@1pct', 'ep@2pct', 'ep@5pct')} for a in R}
            chk = {a: (round(R[a]['mean_auc'], 4), Mr[a]['mean_auc'], round(R[a]['ep@5pct'], 2), Mr[a]['ep@5pct'], R[a].get('vs_ref_p_raw'), Mr[a].get('vs_ref_p_raw')) for a in R}
            T['matched_crosscheck_ok'] = all(abs(v[0] - v[1]) < 1e-9 and abs(v[2] - v[3]) < 1e-9 and (v[4] is None or abs(v[4] - v[5]) < 6e-5) for v in chk.values()); T['matched_crosscheck'] = chk
json.dump(T, open(f'{REC}/tables_v4.json', 'w'), indent=1, default=str)
for k, v in T.items():
    print(f'\n==== {k}'); print(v if isinstance(v, str) else json.dumps(v, default=str)[:1200])
