#!/usr/bin/env python3
"""The pre-registered headline statistics on the 37 feature names against the 39 engine names.

recompute/PREREGISTRATION_39_FEATURES.md asks that the 37-name values of the headline statistics
be printed beside the 39-name values, whatever their direction. This script writes them side by
side, one row per statistic, into recompute/results/feature_set_comparison_37_vs_39.tsv.

  37 names: the records at commit 895e581, read with `git show <commit>:ComparisonResults/<path>`
            (the last commit whose records were scored on 37 names);
  39 names: the records in this checkout, ComparisonResults/<path>.

Every value is read from a record or from recompute/{numbers,extra}.json. Ranks a record does not
store, the repair-effect rows of section B and the cross-check of section X are computed here from
the per-scenario matrices and say so in their source column. Section X recomputes the paired
Wilcoxon p (scipy.stats.wilcoxon), the Holm adjustment over the nine comparisons and the exact
victim-clustered signed-rank p from the per-scenario AUCs, separately from four_corpus_tables.py.

Columns: statistic, value_37, value_39, source_37, source_39, flips. flips names a change of
significance at 0.05 (a p-value, or a 95% interval that starts or stops excluding 0), of rank, of
win count or of sign, the four kinds the pre-registration names; other columns say "none" or
describe a change that is not one of those kinds. Archived-registry LODA cells are unseeded, so a
flip that involves them is not attributable to the features.

Usage (from anywhere, in a git checkout that contains the base commit):
    python3 recompute/compare_feature_sets.py [--base COMMIT] [--old-root DIR] [--out FILE] [--check FILE]
--old-root reads the 37-name records from a directory holding ComparisonResults/ (for example a
`git archive` of the base commit) instead of from git; the source column still names the commit.
--check FILE compares the comparison with FILE, writes nothing, and exits 1 on any difference.
Needs numpy and scipy (ComparisonResults/requirements.txt).
"""
import csv, io, itertools, json, os, statistics, subprocess, sys
import numpy as np
from scipy.stats import wilcoxon

HERE = os.path.dirname(os.path.abspath(__file__))
CR = os.path.dirname(HERE)
ROOT = os.path.dirname(CR)
OUT_DEFAULT = os.path.join(HERE, 'results', 'feature_set_comparison_37_vs_39.tsv')

OURS = 'Subspace-Q + EWMA (ours)'
ARMS = [OURS, 'POT', 'DSPOT', 'ECOD', 'COPOD', 'HBOS', 'LODA', 'INNE', 'IForest', 'DIF']
COMP = [a for a in ARMS if a != 'POT']
NUM = 'recompute/numbers.json'
EXT = 'recompute/extra.json'


def parse_args(argv):
    opt = {'--base': '895e581', '--old-root': None, '--out': OUT_DEFAULT, '--check': None}
    i = 0
    while i < len(argv):
        if argv[i] in opt and i + 1 < len(argv):
            opt[argv[i]] = argv[i + 1]
            i += 2
        else:
            sys.exit(__doc__)
    return opt


OPT = parse_args(sys.argv[1:])
BASE = OPT['--base']
TAG = {'37': BASE + ':ComparisonResults/', '39': 'ComparisonResults/'}

_cache = {}


def J(t, rel):
    """One record: '37' from the base commit, '39' from this checkout."""
    k = (t, rel)
    if k not in _cache:
        if t == '39':
            _cache[k] = json.load(open(os.path.join(CR, rel)))
        elif OPT['--old-root']:
            _cache[k] = json.load(open(os.path.join(OPT['--old-root'], 'ComparisonResults', rel)))
        else:
            r = subprocess.run(['git', '-C', ROOT, 'show', f'{BASE}:ComparisonResults/{rel}'],
                               capture_output=True)
            if r.returncode != 0:
                sys.exit(f'git show {BASE}:ComparisonResults/{rel} failed: '
                         + r.stderr.decode(errors='replace').strip())
            _cache[k] = json.loads(r.stdout)
    return _cache[k]


def G(t, rel, path):
    o = J(t, rel)
    for p in path:
        o = o[int(p)] if isinstance(o, list) else o[p]
    return o


def S(t, rel, path, how=''):
    s = f"{TAG[t]}{rel}#{'/'.join(str(p) for p in path)}"
    return s + (f' ({how})' if how else '')


def sgn(x):
    return (x > 0) - (x < 0)


def wins_n(w):
    return int(str(w).split('/')[0])


def rank_n(r):
    return int(str(r).split('/')[0])


def ci_excl(ci):
    return ci[0] > 0 or ci[1] < 0


def fmt(v):
    if isinstance(v, float):
        return repr(round(v, 6)) if abs(v) >= 1e-4 or v == 0 else '%.3g' % v
    if isinstance(v, (list, tuple)):
        return '[' + ', '.join(fmt(x) for x in v) + ']'
    return str(v)


def flip(kind, a, b):
    out = []
    if a is None or b is None:
        return 'no 39-name counterpart' if b is None else ''
    if kind == 'p':
        if (a < 0.05) != (b < 0.05):
            out.append('significance@0.05')
    elif kind == 'delta':
        if sgn(a) != sgn(b):
            out.append('sign')
    elif kind == 'rank':
        if rank_n(a) != rank_n(b):
            out.append('rank')
    elif kind == 'wins':
        if wins_n(a) != wins_n(b):
            out.append('win count')
    elif kind == 'ci':
        if ci_excl(a) != ci_excl(b):
            out.append('significance@0.05 (95% interval excludes 0)')
    elif kind == 'count':
        if a != b:
            out.append('changed (count; not a pre-registered flip type)')
    elif kind == 'set':
        if a != b:
            out.append('changed (membership/order; not a pre-registered flip type)')
    return '; '.join(out) if out else 'none'


rows = []


def add(section, stat, kind, rel, path, how='', transform=None):
    v = {}
    for t in ('37', '39'):
        x = G(t, rel, path)
        v[t] = transform(x) if transform else x
    rows.append([section, stat, fmt(v['37']), fmt(v['39']),
                 S('37', rel, path, how), S('39', rel, path, how), flip(kind, v['37'], v['39'])])
    return v


def add_val(section, stat, kind, v37, v39, s37, s39, flips=None):
    rows.append([section, stat, fmt(v37), fmt(v39), s37, s39,
                 flip(kind, v37, v39) if flips is None else flips])


# ---------------------------------------------------------------- cross-check helpers (section X)
def holm(ps):
    order = sorted(range(len(ps)), key=lambda i: ps[i])
    m = len(ps)
    adj = [0.0] * m
    run = 0.0
    for r, i in enumerate(order):
        run = max(run, min(1.0, (m - r) * ps[i]))
        adj[i] = run
    return adj


def exact_signed_rank_p(d):
    d = [x for x in d if x != 0]
    n = len(d)
    if n == 0:
        return 1.0
    absd = sorted(range(n), key=lambda i: abs(d[i]))
    rk = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j + 1 < n and abs(d[absd[j + 1]]) == abs(d[absd[i]]):
            j += 1
        for k in range(i, j + 1):
            rk[absd[k]] = (i + j) / 2 + 1
        i = j + 1
    wplus = sum(rk[i] for i in range(n) if d[i] > 0)
    mu = sum(rk) / 2
    cnt = ext = 0
    for signs in itertools.product((0, 1), repeat=n):
        w = sum(rk[i] for i in range(n) if signs[i])
        cnt += 1
        if abs(w - mu) >= abs(wplus - mu) - 1e-12:
            ext += 1
    return ext / cnt


def matrix_check(t, rel):
    """Our row's comparison with POT, recomputed from one per-scenario matrix (PANEL-16)."""
    L = G(t, rel, ['per_population', 'PANEL-16'])
    auc = {a: np.array([r['auc'][a] for r in L]) for a in ARMS}
    raw = {}
    for a in COMP:
        d = auc[a] - auc['POT']
        raw[a] = float(wilcoxon(auc[a], auc['POT']).pvalue) if np.any(d != 0) else 1.0
    adj = dict(zip(COMP, holm([raw[a] for a in COMP])))
    victims = sorted({r['victim'] for r in L})
    dl = auc[OURS] - auc['POT']
    cm = [float(np.mean([dl[i] for i, r in enumerate(L) if r['victim'] == v])) for v in victims]
    means = {a: float(np.mean(auc[a])) for a in ARMS}
    order = sorted(ARMS, key=lambda a: -means[a])
    rec = {'ours_mean_auc': round(means[OURS], 6), 'margin': round(means[OURS] - means['POT'], 6),
           'ours_raw_p': round(raw[OURS], 5), 'ours_holm_p': round(adj[OURS], 5),
           'ours_cluster_mean_delta': round(float(np.mean(cm)), 6),
           'ours_cluster_p': round(exact_signed_rank_p(cm), 5),
           'ours_wins': int(np.sum(dl > 0)), 'ours_auc_rank': order.index(OURS) + 1}
    if 'ep1' in L[0]:
        for k in ('1', '2', '5'):
            em = {a: float(np.mean([r[f'ep{k}'][a] for r in L])) for a in ARMS}
            rec[f'oracle_ep{k}_rank_ours'] = sorted(ARMS, key=lambda a: em[a]).index(OURS) + 1
    return rec


MATRIX = {'deposited (benchmark)': 'results/panel_auc_matrix.json',
          'deposited (split control)': 'results/split_control_deposited_matrix.json',
          'R40': 'results/split_control_threeway40_matrix.json',
          'R60': 'results/split_control_threeway60_matrix.json',
          'matched smoothing': 'results/matched_smoothing_matrix.json'}
CC = {(sp, t): matrix_check(t, rel) for sp, rel in MATRIX.items() for t in ('37', '39')}
XHOW = 'computed here: scipy.stats.wilcoxon against POT, Holm over the nine comparisons, exact victim-clustered signed-rank test'

# ---------------------------------------------------------------- A. margin, deposited split
for pop in ('PANEL-16',):
    base = ['four', 'discrimination', pop]
    sec = f'A. discrimination, deposited split ({pop})'
    add(sec, 'ours mean AUC', '', NUM, base + [OURS, 'mean_auc'])
    add(sec, 'reference (POT) mean AUC', '', NUM, base + ['POT', 'mean_auc'])
    add(sec, 'margin over reference (mean AUC difference)', 'delta', NUM, base + [OURS, 'vs_ref_auc'])
    add(sec, 'raw paired Wilcoxon p', 'p', NUM, base + [OURS, 'vs_ref_p_raw'])
    add(sec, 'Holm-adjusted p (family 9)', 'p', NUM, base + [OURS, 'vs_ref_p_holm'])
    add(sec, 'Bonferroni p', 'p', NUM, base + [OURS, 'vs_ref_p_bonf'])
    add(sec, 'victim-clustered Wilcoxon p (5 clusters, floor 0.0625)', 'p', NUM, base + [OURS, 'cluster_p'])
    add(sec, 'victim-clustered mean difference', 'delta', NUM, base + [OURS, 'cluster_mean_delta'])
    add(sec, 'scenario wins against reference', 'wins', NUM, base + [OURS, 'wins'])
    add(sec, 'i.i.d. bootstrap 95% interval of the difference', 'ci', NUM, base + [OURS, 'boot_ci'])
    add(sec, 'victim-cluster bootstrap 95% interval', 'ci', NUM, base + [OURS, 'cluster_boot_ci'])
    add(sec, 'ours minimum per-scenario AUC', '', NUM, base + [OURS, 'min_auc'])
    add(sec, 'ours median per-scenario AUC', '', NUM, base + [OURS, 'median_auc'])
    for stat, kind, key in (('mean AUC', '', 'mean_auc'), ('margin over reference', 'delta', 'vs_ref_auc'),
                            ('raw paired Wilcoxon p', 'p', 'vs_ref_p_raw'), ('Holm-adjusted p', 'p', 'vs_ref_p_holm'),
                            ('i.i.d. bootstrap 95% interval of the difference', 'ci', 'boot_ci'),
                            ('victim-cluster bootstrap 95% interval', 'ci', 'cluster_boot_ci')):
        add(sec, f'DIF: {stat}', kind, NUM, base + ['DIF', key])
_d = {}
for t in ('37', '39'):
    a = G(t, NUM, ['four', 'discrimination', 'PANEL-16', OURS])
    b = G(t, NUM, ['four', 'discrimination', 'USABLE-strict', OURS])
    _d[t] = ','.join(sorted(k for k in a if a[k] != b.get(k))) or 'none'
add_val('A. discrimination, deposited split (PANEL-16)', 'fields of our row that differ between PANEL-16 and USABLE-strict', 'set',
        _d['37'], _d['39'], S('37', NUM, ['four', 'discrimination', 'USABLE-strict', OURS]),
        S('39', NUM, ['four', 'discrimination', 'USABLE-strict', OURS]))

# ---------------------------------------------------------------- B. split control R40/R60 + sixth victim
for sp, lab, cck in (('deposited', 'deposited split', 'deposited (split control)'), ('threeway40', 'R40 (40/40/20)', 'R40'),
                     ('threeway60', 'R60 (60/20/20)', 'R60')):
    base = ['four', 'split_control', sp, 'PANEL-16']
    sec = f'B. split control, {lab}, PANEL-16'
    add(sec, 'ours mean AUC', '', NUM, base + [OURS, 'mean_auc'])
    add(sec, 'reference (POT) mean AUC', '', NUM, base + ['POT', 'mean_auc'])
    add(sec, 'margin over reference', 'delta', NUM, base + [OURS, 'vs_ref_auc'])
    add(sec, 'raw Wilcoxon p', 'p', NUM, base + [OURS, 'vs_ref_p_raw'])
    add(sec, 'Holm-adjusted p', 'p', NUM, base + [OURS, 'vs_ref_p_holm'])
    add(sec, 'Bonferroni p', 'p', NUM, base + [OURS, 'vs_ref_p_bonf'])
    add(sec, 'victim-clustered p', 'p', NUM, base + [OURS, 'cluster_p'])
    add(sec, 'victim-clustered mean difference', 'delta', NUM, base + [OURS, 'cluster_mean_delta'])
    add(sec, 'scenario wins', 'wins', NUM, base + [OURS, 'wins'])
    add(sec, 'i.i.d. bootstrap 95% interval', 'ci', NUM, base + [OURS, 'boot_ci'])
    add(sec, 'victim-cluster bootstrap 95% interval', 'ci', NUM, base + [OURS, 'cluster_boot_ci'])
    for tgt in ('1', '2', '5'):
        ep = base + ['_episodes_ours_vs_POT', f'ep@{tgt}pct']
        add(sec, f'oracle episodes/1000 @{tgt}%: ours minus POT', 'delta', NUM, ep,
            how='ours - POT', transform=lambda o: round(o['ours'] - o['POT'], 4))
        add(sec, f'oracle episodes/1000 @{tgt}%: scenario-level p', 'p', NUM, ep + ['scenario_p'])
        add(sec, f'oracle episodes/1000 @{tgt}%: victim-clustered p', 'p', NUM, ep + ['cluster_p'])
    for tgt in ('1', '2', '5'):
        k = f'oracle_ep{tgt}_rank_ours'
        rel = MATRIX[cck]
        add_val(sec, f'oracle episodes/1000 @{tgt}%: ours rank of 10 (fewest = 1)', 'rank',
                f"{CC[(cck, '37')][k]}/10", f"{CC[(cck, '39')][k]}/10",
                S('37', rel, ['per_population', 'PANEL-16', '*', f'ep{tgt}'], 'mean over 16 rows, ranked'),
                S('39', rel, ['per_population', 'PANEL-16', '*', f'ep{tgt}'], 'mean over 16 rows, ranked'))
for _k, _lab in (('ours_mean_auc', 'ours mean AUC'), ('margin', 'margin over POT')):
    _v = {t: round(max(abs(CC[(sp_, t)][_k] - CC[('deposited (benchmark)', t)][_k]) for sp_ in ('R40', 'R60')), 6)
          for t in ('37', '39')}
    _src = 'results/split_control_threeway{40,60}_matrix.json and results/panel_auc_matrix.json (computed here: unrounded means of the PANEL-16 rows)'
    add_val('B. split control, repair effect on our row', f'largest |{_lab} under R40 or R60 minus deposited| (unrounded)', '',
            _v['37'], _v['39'], TAG['37'] + _src, TAG['39'] + _src)
for sp in ('threeway40', 'threeway60'):
    rel = f'recompute/results/split_control_benchmark_{sp}_sixvictim.json'
    sec = f'B. sixth-victim check (post hoc), {sp}, PANEL-17'
    base = ['results', 'PANEL-17', OURS]
    add(sec, 'ours mean AUC', '', rel, base + ['mean_auc'])
    add(sec, 'margin over reference', 'delta', rel, base + ['vs_ref_auc'])
    add(sec, 'raw Wilcoxon p', 'p', rel, base + ['vs_ref_p_raw'])
    add(sec, 'Holm-adjusted p', 'p', rel, base + ['vs_ref_p_holm'])
    add(sec, 'victim-clustered p (6 clusters)', 'p', rel, base + ['cluster_p'])
    add(sec, 'scenario wins', 'wins', rel, base + ['wins'])
    add(sec, 'i.i.d. bootstrap 95% interval', 'ci', rel, base + ['boot_ci'])


# ---------------------------------------------------------------- C. per-arm mean AUC ranking
def arm_means(t, rel, pop='PANEL-16'):
    rowsp = G(t, rel, ['per_population', pop])
    return {a: statistics.fmean(r['auc'][a] for r in rowsp) for a in ARMS}


def ranks(means, higher=True):
    order = sorted(means, key=lambda a: -means[a] if higher else means[a])
    return {a: order.index(a) + 1 for a in means}, order


for rel, lab in (('results/panel_auc_matrix.json', 'deposited split'),
                 ('results/split_control_threeway40_matrix.json', 'R40'),
                 ('results/split_control_threeway60_matrix.json', 'R60'),
                 ('results/matched_smoothing_matrix.json', 'matched smoothing (every competitor + EWMA)')):
    sec = f'C. per-arm mean AUC ranking, {lab}, PANEL-16'
    m = {t: arm_means(t, rel) for t in ('37', '39')}
    rk = {t: ranks(m[t]) for t in ('37', '39')}
    for a in ARMS:
        add_val(sec, f'{a}: mean AUC (unrounded) and rank of 10', 'rank',
                f"{rk['37'][0][a]}/10 ({m['37'][a]:.6f})", f"{rk['39'][0][a]}/10 ({m['39'][a]:.6f})",
                S('37', rel, ['per_population', 'PANEL-16', '*', 'auc', a], 'mean over 16 rows, ranked'),
                S('39', rel, ['per_population', 'PANEL-16', '*', 'auc', a], 'mean over 16 rows, ranked'))
    best_other = {t: max((a for a in ARMS if a != OURS), key=lambda a: m[t][a]) for t in ('37', '39')}
    gap = {t: m[t][OURS] - m[t][best_other[t]] for t in ('37', '39')}
    add_val(sec, 'ours minus best other arm (gap to nearest competitor)', '',
            f"{gap['37']:+.6f} (vs {best_other['37']})", f"{gap['39']:+.6f} (vs {best_other['39']})",
            S('37', rel, ['per_population', 'PANEL-16', '*', 'auc'], 'computed'),
            S('39', rel, ['per_population', 'PANEL-16', '*', 'auc'], 'computed'),
            flips=flip('delta', gap['37'], gap['39']))
    add_val(sec, 'full order (best first)', 'set', ' > '.join(rk['37'][1]), ' > '.join(rk['39'][1]),
            S('37', rel, ['per_population', 'PANEL-16'], 'computed'), S('39', rel, ['per_population', 'PANEL-16'], 'computed'),
            flips='rank' if rk['37'][1] != rk['39'][1] else 'none')

# ---------------------------------------------------------------- D. benign alarm episodes
sec = 'D1. benign alarm episodes/1000, oracle targets (corrected benchmark, PANEL-16)'
for tgt in ('1', '2', '5'):
    b = ['oracle_episodes', f'ep@{tgt}']
    add(sec, f'@{tgt}%: ours mean', '', EXT, b + ['means', OURS])
    add(sec, f'@{tgt}%: reference (POT) mean', '', EXT, b + ['means', 'POT'])
    add(sec, f'@{tgt}%: ours minus reference', 'delta', EXT, b + ['means'], how='ours - POT',
        transform=lambda o: round(o[OURS] - o['POT'], 4))
    add(sec, f'@{tgt}%: ours rank of 10 (fewest = 1)', 'rank', EXT, b + ['rank_ours'], transform=lambda r: f'{r}/10')
    add(sec, f'@{tgt}%: reference rank of 10', 'rank', EXT, b + ['rank_ref'], transform=lambda r: f'{r}/10')
    add(sec, f'@{tgt}%: scenarios ours fewer / more / tied', 'count', EXT, b,
        transform=lambda o: f"{o['ours_fewer']}/{o['ours_more']}/{o['ties']}")
    add(sec, f'@{tgt}%: scenario-level p', 'p', EXT, b + ['scenario_p'])
    add(sec, f'@{tgt}%: victim-clustered p', 'p', EXT, b + ['cluster_p'])
    add(sec, f'@{tgt}%: best arm', 'set', EXT, b + ['best'])
    add(sec, f'@{tgt}%: worst arm', 'set', EXT, b + ['worst'])

for blk, lab in (('heldout', 'deposited split'), ('heldout_threeway40', 'R40 (post hoc)')):
    for pop in ('USABLE',):
        sec = f'D2. benign alarm episodes/1000, held-out targets, {lab}, {pop}-16'
        base = ['four', blk, pop]
        for tgt in ('1', '2', '5'):
            for kind_ep, lab_ep in (('stream_ep', 'stream-realized'), ('free_ep', 'attack rows excised')):
                add(sec, f'@{tgt}% {lab_ep}: ours', '', NUM, base + ['arms', OURS, f'{kind_ep}@{tgt}pct'])
                add(sec, f'@{tgt}% {lab_ep}: reference (POT)', '', NUM, base + ['arms', 'POT', f'{kind_ep}@{tgt}pct'])
                add(sec, f'@{tgt}% {lab_ep}: ours minus reference (scenario mean)', 'delta', NUM,
                    base + ['tests_ours_vs_POT', f'{kind_ep}@{tgt}', 'scenario_mean_delta'])
                add(sec, f'@{tgt}% {lab_ep}: ours minus reference (victim-cluster mean)', 'delta', NUM,
                    base + ['tests_ours_vs_POT', f'{kind_ep}@{tgt}', 'mean_delta'])
                add(sec, f'@{tgt}% {lab_ep}: ours rank of 10', 'rank', NUM, base + [f'rank_ours_{kind_ep}@{tgt}pct'])
                add(sec, f'@{tgt}% {lab_ep}: scenario-level p', 'p', NUM,
                    base + ['tests_ours_vs_POT', f'{kind_ep}@{tgt}', 'scenario_p'])
                add(sec, f'@{tgt}% {lab_ep}: victim-clustered p', 'p', NUM,
                    base + ['tests_ours_vs_POT', f'{kind_ep}@{tgt}', 'cluster_p'])
                add(sec, f'@{tgt}% {lab_ep}: clusters ours higher / lower', 'count', NUM,
                    base + ['tests_ours_vs_POT', f'{kind_ep}@{tgt}'],
                    transform=lambda o: f"{o['ours_higher']}/{o['ours_lower']}")

# ---------------------------------------------------------------- E. detection rates and realized FPR
sec = 'E1. detection rate %, oracle thresholds (corrected benchmark, PANEL-16)'
CB = 'results/corrected_benchmark_results.json'
for tgt in ('1', '2', '5'):
    add(sec, f'@{tgt}%: ours', '', CB, ['results', 'PANEL-16', OURS, f'dr@{tgt}pct'])
    add(sec, f'@{tgt}%: reference (POT)', '', CB, ['results', 'PANEL-16', 'POT', f'dr@{tgt}pct'])
    r = {}
    for t in ('37', '39'):
        res = G(t, CB, ['results', 'PANEL-16'])
        vals = {a: res[a][f'dr@{tgt}pct'] for a in ARMS}
        order = sorted(ARMS, key=lambda a: -vals[a])
        r[t] = (f'{order.index(OURS) + 1}/10', order[0], vals[order[0]])
    add_val(sec, f'@{tgt}%: ours rank of 10 (highest = 1)', 'rank', f"{r['37'][0]} (best {r['37'][1]} {r['37'][2]})",
            f"{r['39'][0]} (best {r['39'][1]} {r['39'][2]})",
            S('37', CB, ['results', 'PANEL-16', '*', f'dr@{tgt}pct'], 'ranked'), S('39', CB, ['results', 'PANEL-16', '*', f'dr@{tgt}pct'], 'ranked'),
            flips=flip('rank', r['37'][0], r['39'][0]))
MS = 'results/matched_smoothing_benchmark.json'
sec = 'E2. detection rate %, oracle thresholds, matched smoothing (PANEL-16)'
for tgt in ('1', '2', '5'):
    add(sec, f'@{tgt}%: ours', '', MS, ['results', 'PANEL-16', OURS, f'dr@{tgt}pct'])
    add(sec, f'@{tgt}%: DIF + EWMA', '', MS, ['results', 'PANEL-16', 'DIF', f'dr@{tgt}pct'])
    r = {}
    for t in ('37', '39'):
        res = G(t, MS, ['results', 'PANEL-16'])
        vals = {a: res[a][f'dr@{tgt}pct'] for a in ARMS}
        order = sorted(ARMS, key=lambda a: -vals[a])
        r[t] = (f'{order.index(OURS) + 1}/10', order[0], vals[order[0]])
    add_val(sec, f'@{tgt}%: ours rank of 10', 'rank', f"{r['37'][0]} (best {r['37'][1]} {r['37'][2]})",
            f"{r['39'][0]} (best {r['39'][1]} {r['39'][2]})",
            S('37', MS, ['results', 'PANEL-16', '*', f'dr@{tgt}pct'], 'ranked'), S('39', MS, ['results', 'PANEL-16', '*', f'dr@{tgt}pct'], 'ranked'),
            flips=flip('rank', r['37'][0], r['39'][0]))
SC29 = 'results/scenarios29_corrected_results.json'


def _crw(L):
    return next(r for r in L if r['label'].endswith('code_red_worm'))


for blk, lab in (('heldout', 'deposited split'), ('heldout_threeway40', 'R40 (post hoc)')):
    sec = (f'E3. detection rate % and realized FPR %, held-out targets, {lab}, USABLE-16' if blk == 'heldout'
           else f'E4. detection rate % and realized FPR %, held-out targets, {lab}, USABLE-16')
    base = ['four', blk, 'USABLE']
    for tgt in ('1', '2', '5'):
        add(sec, f'@{tgt}%: ours DR', '', NUM, base + ['arms', OURS, f'dr@{tgt}pct'])
        add(sec, f'@{tgt}%: reference DR', '', NUM, base + ['arms', 'POT', f'dr@{tgt}pct'])
        add(sec, f'@{tgt}%: ours DR rank of 10', 'rank', NUM, base + [f'rank_ours_dr@{tgt}pct'])
        add(sec, f'@{tgt}%: DR ours minus reference (scenario mean)', 'delta', NUM, base + ['tests_ours_vs_POT', f'dr@{tgt}', 'scenario_mean_delta'])
        add(sec, f'@{tgt}%: DR scenario-level p', 'p', NUM, base + ['tests_ours_vs_POT', f'dr@{tgt}', 'scenario_p'])
        add(sec, f'@{tgt}%: DR victim-clustered p', 'p', NUM, base + ['tests_ours_vs_POT', f'dr@{tgt}', 'cluster_p'])
        add(sec, f'@{tgt}%: ours realized FPR', '', NUM, base + ['arms', OURS, f'fpr@{tgt}pct'])
        add(sec, f'@{tgt}%: reference realized FPR', '', NUM, base + ['arms', 'POT', f'fpr@{tgt}pct'])
        add(sec, f'@{tgt}%: realized FPR ours minus reference (scenario mean)', 'delta', NUM, base + ['tests_ours_vs_POT', f'fpr@{tgt}', 'scenario_mean_delta'])
        add(sec, f'@{tgt}%: realized FPR scenario-level p', 'p', NUM, base + ['tests_ours_vs_POT', f'fpr@{tgt}', 'scenario_p'])
        add(sec, f'@{tgt}%: realized FPR victim-clustered p', 'p', NUM, base + ['tests_ours_vs_POT', f'fpr@{tgt}', 'cluster_p'])
        add(sec, f'@{tgt}%: DR ours minus reference (victim-cluster mean, points)', 'delta', NUM, base + ['tests_ours_vs_POT', f'dr@{tgt}', 'mean_delta'])
        add(sec, f'@{tgt}%: realized FPR ours minus reference (victim-cluster mean, points)', 'delta', NUM, base + ['tests_ours_vs_POT', f'fpr@{tgt}', 'mean_delta'])
        if blk == 'heldout':
            add(sec, f'@{tgt}%: episode starts within 30 windows after attack, ours / reference (%)', '', EXT, [f'ep_starts_near_attack@{tgt}'],
                transform=lambda o: f"{o['ours_pct']}/{o['ref_pct']}")
    if blk != 'heldout':
        continue
    for tgt in ('1', '2', '5'):
        add(sec, f'@{tgt}%: benign alarms per monitored host-day, ours / reference (864 x realized FPR %)', '', NUM, ['four', 'heldout', 'USABLE', 'arms'],
            how='computed', transform=lambda o, t=tgt: f"{round(864 * o[OURS][f'fpr@{t}pct'])}/{round(864 * o['POT'][f'fpr@{t}pct'])}")
        add(sec, f'@{tgt}%: Spearman rho, our stream excess over adjacency-free vs benign-after-attack adjacency', 'delta', EXT, ['adjacency', f'spearman_inflation_vs_adjacency@{tgt}', 0])
        add(sec, f'@{tgt}%: Spearman p of that correlation', 'p', EXT, ['adjacency', f'spearman_inflation_vs_adjacency@{tgt}', 1])
        add(sec, f'@{tgt}%: Spearman rho vs attack fraction, [rho, p]', '', EXT, ['adjacency', f'spearman_inflation_vs_attackfrac@{tgt}'])
    for tgt in ('1', '2', '5'):
        add(sec, f'LITNET-2020 code_red_worm: ours realized FPR @{tgt}%', '', SC29, ['per_scenario'],
            how=f'row LITNET-2020 code_red_worm, arms/{OURS}/fpr@{tgt}', transform=lambda L, t=tgt: _crw(L)['arms'][OURS][f'fpr@{t}'])
        add(sec, f'LITNET-2020 code_red_worm: ours stream episodes/1000 @{tgt}%', '', SC29, ['per_scenario'],
            how=f'row LITNET-2020 code_red_worm, arms/{OURS}/ep@{tgt}', transform=lambda L, t=tgt: _crw(L)['arms'][OURS][f'ep@{t}'])
        add(sec, f'LITNET-2020 code_red_worm: reference realized FPR @{tgt}%', '', SC29, ['per_scenario'],
            how=f'row LITNET-2020 code_red_worm, arms/POT/fpr@{tgt}', transform=lambda L, t=tgt: _crw(L)['arms']['POT'][f'fpr@{t}'])
        add(sec, f'LITNET-2020 code_red_worm: realized FPR ours minus reference @{tgt}%', 'delta', SC29, ['per_scenario'],
            how='row LITNET-2020 code_red_worm', transform=lambda L, t=tgt: round(_crw(L)['arms'][OURS][f'fpr@{t}'] - _crw(L)['arms']['POT'][f'fpr@{t}'], 2))

# ---------------------------------------------------------------- F. clock-null comparison
sec = 'F. clock-null comparison (clock score -window index against ours, PANEL-16, deposited split)'
CV = ['clock_vs_ours']
add(sec, 'clock wins of 16', 'wins', EXT, CV + ['clock_wins'], transform=lambda w: f'{w}/16')
add(sec, 'ties', 'count', EXT, CV + ['ties'])
add(sec, 'scenario-level Wilcoxon p', 'p', EXT, CV + ['scenario_p'])
add(sec, 'victim clusters the clock wins (of 5)', 'wins', EXT, CV + ['cluster_wins'], transform=lambda w: f'{w}/5')
add(sec, 'victim-clustered p', 'p', EXT, CV + ['cluster_p'])
add(sec, 'rows with clock separability >= 0.95', 'count', EXT, CV + ['n_ge_095'])
add(sec, 'rows the clock separates perfectly', 'count', EXT, CV + ['n_perfect'])
add(sec, 'summed AUC difference on clock-separated rows', '', EXT, CV + ['sum_delta_on_separated'])
add(sec, 'clock-clean rows (deposited split)', 'set', EXT, CV + ['clean_rows'], transform=lambda L: ';'.join(r[0] for r in L))
add(sec, 'clock-clean row (deposited split): ours minus POT', 'delta', EXT, CV + ['clean_rows'], transform=lambda L: L[0][2])
sec = 'F2. clock-separated counts and clock-clean stratum (label-only counts; stratum statistics read our AUCs)'
for cut in ('0.95', '0.94'):
    for sp in ('deposited', 'threeway'):
        add(sec, f'cut {cut}, {sp} split: rows clock-separated of 16', 'count', NUM, ['four', 'clock', f'cut_{cut}', sp, 'separability_ge_cut'])
    add(sec, f'cut {cut}, three-way split: clock-clean rows', 'count', NUM, ['four', 'clock', f'cut_{cut}', 'threeway', 'clock_clean', 'n'])
    add(sec, f'cut {cut}, three-way split: clock-clean mean difference (R60 scores)', 'delta', NUM, ['four', 'clock', f'cut_{cut}', 'threeway', 'clock_clean', 'mean_delta_auc'])
    add(sec, f'cut {cut}, three-way split: clock-clean wins', 'wins', NUM, ['four', 'clock', f'cut_{cut}', 'threeway', 'clock_clean'],
        transform=lambda o: f"{o['wins']}/{o['n']}")
    add(sec, f'cut {cut}, three-way split: clock-clean victim-clustered p', 'p', NUM, ['four', 'clock', f'cut_{cut}', 'threeway', 'clock_clean', 'cluster_wilcoxon_p'])
JF = 'results/joint_filter.json'
add(sec, 'joint_filter repaired_split_counts (deposited: separates / clean)', 'count', JF, ['repaired_split_counts', 'deposited_split'],
    transform=lambda o: f"{o['clock_separates']}/{o['clock_clean']}")
add(sec, 'joint_filter repaired_split_counts (three-way: separates / clean)', 'count', JF, ['repaired_split_counts', 'threeway_split'],
    transform=lambda o: f"{o['clock_separates']}/{o['clock_clean']}")
add(sec, 'joint_filter clock_clean_stratum three-way: mean difference', 'delta', JF, ['clock_clean_stratum', 'threeway_split', 'mean_delta_auc'])
add(sec, 'joint_filter clock_clean_stratum three-way: wins of 13', 'wins', JF, ['clock_clean_stratum', 'threeway_split'],
    transform=lambda o: f"{o['wins']}/{o['n']}")
add(sec, 'joint_filter clock_clean_stratum three-way: victim-clustered p', 'p', JF, ['clock_clean_stratum', 'threeway_split', 'cluster_wilcoxon_p'])

# ---------------------------------------------------------------- G. matched smoothing
sec = 'G. matched smoothing (every competitor given the EWMA stage, PANEL-16)'
base = ['four', 'matched', 'PANEL-16']
add(sec, 'ours mean AUC', '', NUM, base + [OURS, 'mean_auc'])
add(sec, 'POT + EWMA mean AUC', '', NUM, base + ['POT', 'mean_auc'])
add(sec, 'margin over POT + EWMA', 'delta', NUM, base + [OURS, 'vs_ref_auc'])
add(sec, 'raw p', 'p', NUM, base + [OURS, 'vs_ref_p_raw'])
add(sec, 'Holm p', 'p', NUM, base + [OURS, 'vs_ref_p_holm'])
add(sec, 'victim-clustered p', 'p', NUM, base + [OURS, 'cluster_p'])
add(sec, 'scenario wins', 'wins', NUM, base + [OURS, 'wins'])
add(sec, 'i.i.d. 95% interval', 'ci', NUM, base + [OURS, 'boot_ci'])
add(sec, 'victim-cluster 95% interval', 'ci', NUM, base + [OURS, 'cluster_boot_ci'])
add(sec, 'victim-clustered mean difference', 'delta', NUM, base + [OURS, 'cluster_mean_delta'])
add(sec, 'ours minus DIF + EWMA (unrounded)', 'delta', EXT, ['matched', 'ours_minus_dif'])
for tgt in ('1', '2', '5'):
    b = ['matched_episodes', f'ep@{tgt}']
    add(sec, f'episodes @{tgt}%: ours rank of 10', 'rank', EXT, b + ['rank_ours'], transform=lambda r: f'{r}/10')
    add(sec, f'episodes @{tgt}%: ours minus POT + EWMA', 'delta', EXT, b + ['means'], how='ours - POT',
        transform=lambda o: round(o[OURS] - o['POT'], 4))
    add(sec, f'episodes @{tgt}%: scenarios ours more / fewer / tied', 'count', EXT, b,
        transform=lambda o: f"{o['ours_more']}/{o['ours_fewer']}/{o['ties']}")
    add(sec, f'episodes @{tgt}%: scenario-level p', 'p', EXT, b + ['scenario_p'])
    add(sec, f'episodes @{tgt}%: victim-clustered p', 'p', EXT, b + ['cluster_p'])
sec = 'G2. matched-smoothing concentration (PANEL-16)'
base = ['four', 'matched_concentration', 'PANEL-16']
add(sec, 'top scenario', 'set', NUM, base + ['top_scenario'])
add(sec, 'top-scenario share of the summed matched margin (%)', '', NUM, base + ['top_scenario_share_pct'])
add(sec, 'CIC-DDoS2019 Syn delta (ours minus POT + EWMA)', 'delta', 'results/matched_smoothing_matrix.json',
    ['per_population', 'PANEL-16'], how='row CIC-DDoS2019 cicddos_03-11_192-168-50-4_Syn',
    transform=lambda L: round(next(r for r in L if r['scenario'].endswith('_Syn'))['auc'][OURS] - next(r for r in L if r['scenario'].endswith('_Syn'))['auc']['POT'], 6))
add(sec, 'summed matched margin', '', NUM, base + ['sum_delta_auc'])
add(sec, 'mean matched margin without the top scenario', 'delta', NUM, base + ['mean_after_deleting_top_scenario'])
for _v in sorted(G('37', NUM, base + ['leave_one_victim_out_mean_delta'])):
    add(sec, f'mean matched margin leaving out victim {_v}', 'delta', NUM, base + ['leave_one_victim_out_mean_delta', _v])

# ---------------------------------------------------------------- H. inductive correction
sec = 'H. inductive-correction magnitudes (archived uncorrected against corrected, PANEL-16 mean AUC)'
for a in ('ECOD', 'COPOD', 'DIF', 'DSPOT', 'LODA', OURS):
    tag = ''
    if a == 'LODA':
        tag = ' [uncorrected side is the unseeded archived LODA: not attributable to the features]'
    if a == OURS:
        tag = ' [uncorrected side is the archived Subspace-ECOD (ours) arm]'
    add(sec, f'{a}: uncorrected mean AUC{tag}', '', EXT, ['leakage', a, 'uncorrected'])
    add(sec, f'{a}: corrected mean AUC', '', EXT, ['leakage', a, 'corrected'])
    add(sec, f'{a}: lift (corrected minus uncorrected){tag}', 'delta', NUM, ['four', 'leakage', a, 'change'])
add(sec, 'margin over ECOD, corrected', 'delta', EXT, ['margin_over_ecod', 'corrected'])
add(sec, 'margin over ECOD, counterfactual (ECOD transductive)', 'delta', EXT, ['margin_over_ecod', 'counterfactual'])
add(sec, 'band of six corrected arms (low-high)', '', EXT, ['band_six_arms'], transform=lambda o: f"{o['low']}-{o['high']}")
add(sec, 'smallest lift of ECOD/COPOD/DIF over our margin (ratio)', '', NUM, ['four'], how='min(ECOD,COPOD,DIF change)/discrimination margin',
    transform=lambda f: round(min(f['leakage'][a]['change'] for a in ('ECOD', 'COPOD', 'DIF')) / f['discrimination']['PANEL-16'][OURS]['vs_ref_auc'], 1))
add(sec, 'DIF correction at seed 42 / seed 7', '', EXT, [], transform=lambda o: f"{o['dif_correction_seed42']}/{o['dif_correction_seed7']}")

# ---------------------------------------------------------------- I. batch invariance gate
BG = 'results/batch_invariance_gate.json'
sec = 'I. batch-invariance gate (CIC-IDS-2018 Tue-20-02_DDoS-LOIC-HTTP)'
add(sec, 'archived registry: failed arms', 'set', BG, ['archived', 'failed'])
add(sec, 'archived registry: failed deterministic arms', 'set', BG, ['archived', 'failed_deterministic'])
add(sec, 'archived registry: stochastic arms', 'set', BG, ['archived', 'stochastic'])
add(sec, 'corrected registry: failed arms', 'set', BG, ['corrected', 'failed'])
add(sec, 'corrected registry: max append drift over 10 arms', '', BG, ['corrected', 'arms'],
    transform=lambda o: max(v['append_drift'] for v in o.values()))
add(sec, 'corrected registry: arms moved by prepending (sequential)', 'set', BG, ['corrected', 'sequential'])
add(sec, 'corrected registry: ours prepend drift', '', BG, ['corrected', 'arms', OURS, 'prepend_drift'])
add(sec, 'corrected registry: verdicts', 'set', BG, ['corrected', 'arms'], transform=lambda o: ','.join(f"{k}:{v['verdict']}" for k, v in o.items()))
add(sec, 'archived registry: verdicts', 'set', BG, ['archived', 'arms'], transform=lambda o: ','.join(f"{k}:{v['verdict']}" for k, v in o.items()))

# ---------------------------------------------------------------- J. admissibility census
sec = 'J. admissibility census and USABLE set'
for v in ('USABLE', 'ATTACKER-SIDE', 'FLOOR-LIMITED', 'NOT-DDOS', 'NO-FPR', 'INSEPARABLE'):
    add(sec, f'{v} count', 'count', NUM, ['four', 'admissibility', 'census', v, 'n'])
add(sec, 'candidates', 'count', NUM, ['four', 'admissibility', 'n_candidates'])
add(sec, 'USABLE victims', 'count', NUM, ['four', 'admissibility', 'n_usable_victims'])
add(sec, 'funnel', 'set', NUM, ['four', 'admissibility', 'funnel'])
add(sec, 'USABLE set (ledger)', 'set', 'results/admissibility_ledger.json', ['ledger'],
    transform=lambda L: ';'.join(sorted(f"{r.get('corpus')}/{r['scenario']}" for r in L if r.get('verdict') == 'USABLE')))
add(sec, 'smallest admitted calibration set', 'count', NUM, ['four', 'admissibility', 'smallest_admitted_calib'])
add(sec, 'alpha_conf sensitivity: USABLE at 0.0075 / 0.01 / 0.0125', 'set', 'results/admissibility_ledger.json', ['alpha_conf_sensitivity', 'counts'],
    transform=lambda o: '/'.join(str(o[k]['USABLE']) for k in ('0.0075', '0.01', '0.0125')))

# ---------------------------------------------------------------- K. per-scenario D
CVR = 'results/c_engine_verification_report.json'
for i, s in enumerate(G('37', CVR, ['scenarios'])):
    j = next(k for k, s2 in enumerate(G('39', CVR, ['scenarios'])) if s2['label'] == s['label'])
    add_val('K. active features D per panel row (nonzero range on the fit rows)', f"D, {s['label']}", 'count',
            int(s['d_features']), int(G('39', CVR, ['scenarios', j, 'd_features'])),
            S('37', CVR, ['scenarios', i, 'd_features']),
            S('39', CVR, ['scenarios', j, 'd_features'], 'written with the C port, which is not deposited'))

# ---------------------------------------------------------------- L. C engine, Appendix B
CE = 'results/c_engine_ours.json'
sec = 'L. shipped C engine rule set (Appendix B, PANEL-16)'
add(sec, 'frozen baseline: OR-rule detection rate %', '', CE, ['PANEL-16', 'frozen', 'or_dr'], transform=lambda x: round(100 * x, 2))
add(sec, 'frozen baseline: OR-rule benign false alarms %', '', CE, ['PANEL-16', 'frozen', 'or_fpr'], transform=lambda x: round(100 * x, 2))
add(sec, 'frozen baseline: CUSUM term alone, benign false alarms %', '', CE, ['PANEL-16', 'frozen', 'cusum_fpr'], transform=lambda x: round(100 * x, 2))
add(sec, 'closed loop: OR-rule detection rate %', '', CE, ['PANEL-16', 'closed_loop', 'or_dr'], transform=lambda x: round(100 * x, 2))
add(sec, 'closed loop: OR-rule benign false alarms %', '', CE, ['PANEL-16', 'closed_loop', 'or_fpr'], transform=lambda x: round(100 * x, 2))
add(sec, 'frozen: auc_max_z', '', CE, ['PANEL-16', 'frozen', 'auc_max_z'])
add(sec, 'frozen: z-path false alarms', '', CE, ['PANEL-16', 'frozen', 'z_fpr'])
add(sec, 'closed loop: benign episodes per 1000', '', CE, ['PANEL-16', 'closed_loop', 'benign_episodes_per_1000'])
sec = 'L2. C port parity of the evaluated arm (c_engine_verification_report.json; writer needs the non-deposited subspace_q.c)'
add(sec, 'scenarios passing', 'count', CVR, ['scenarios'], transform=lambda L: f"{sum(bool(s['pass']) for s in L)}/{len(L)}")
add(sec, 'mean AUC, Python', '', CVR, ['scenarios'], how='mean of auc_python', transform=lambda L: round(statistics.fmean(s['auc_python'] for s in L), 6))
add(sec, 'mean AUC, C', '', CVR, ['scenarios'], how='mean of auc_c', transform=lambda L: round(statistics.fmean(s['auc_c'] for s in L), 6))
add(sec, 'maximum relative error', '', CVR, ['scenarios'], transform=lambda L: max(s['max_relative_error'] for s in L))
add(sec, 'maximum absolute error', '', CVR, ['scenarios'], transform=lambda L: max(s['max_absolute_error'] for s in L))

# ---------------------------------------------------------------- M. concentration
sec = 'M. concentration of the margin (PANEL-16, deposited split)'
base = ['four', 'concentration', 'PANEL-16']
add(sec, 'top scenario', 'set', NUM, base + ['top_scenario'])
add(sec, 'top-scenario share of the summed difference (%)', '', NUM, base + ['top_scenario_share_pct'])
add(sec, 'top-scenario difference', 'delta', NUM, base + ['top_scenario_delta'])
add(sec, 'summed difference', 'delta', NUM, base + ['sum_delta_auc'])
add(sec, 'top victim', 'set', NUM, base + ['top_victim'])
add(sec, 'top-victim share (%)', '', NUM, base + ['top_victim_share_pct'])
add(sec, 'mean difference without the top scenario', 'delta', NUM, base + ['mean_after_deleting_top_scenario'])
add(sec, 'largest other single-deletion shift', '', NUM, base + ['max_other_single_deletion_shift'])
add(sec, 'mean difference leaving out victim CIC-IDS-2017/192.168.10.50', 'delta', NUM, base + ['leave_one_victim_out_mean_delta', 'CIC-IDS-2017/192.168.10.50'])
add(sec, 'wins / losses / ties', 'wins', NUM, base, transform=lambda o: f"{o['wins']}/{o['losses']}/{o['ties']}")
add(sec, 'five largest rows, share of summed difference (%)', '', EXT, ['concentration', 'five_largest_share_pct'])
add(sec, 'five largest rows', 'set', EXT, ['concentration', 'five_largest'], transform=lambda L: ';'.join(f'{a} {b:+.6f}' for a, b in L))
add(sec, 'losses (rows where ours < POT)', 'set', EXT, ['concentration', 'losses'], transform=lambda L: ';'.join(f'{a} {b:+.6f}' for a, b in L))
PM = 'results/panel_auc_matrix.json'


def _row(L, key):
    return next(r for r in L if key in r['scenario'])


add(sec, 'LITNET-2020 code_red_worm: ours minus POT', 'delta', PM, ['per_population', 'PANEL-16'],
    how='row LITNET-2020 code_red_worm', transform=lambda L: round(_row(L, 'code_red_worm')['auc'][OURS] - _row(L, 'code_red_worm')['auc']['POT'], 6))
add(sec, 'CSE-CIC-IDS2018 Thu-15-02_DoS-Slowloris: ours minus POT (the row whose sign moves the win count)', 'delta', PM, ['per_population', 'PANEL-16'],
    how='row CIC-IDS-2018 Thu-15-02_DoS-Slowloris', transform=lambda L: round(_row(L, 'Thu-15-02_DoS-Slowloris')['auc'][OURS] - _row(L, 'Thu-15-02_DoS-Slowloris')['auc']['POT'], 6))
add(sec, 'LITNET-2020 code_red_worm: ours AUC', '', PM, ['per_population', 'PANEL-16'],
    how='row LITNET-2020 code_red_worm', transform=lambda L: round(_row(L, 'code_red_worm')['auc'][OURS], 6))
add(sec, 'LITNET-2020 code_red_worm: POT AUC', '', PM, ['per_population', 'PANEL-16'],
    how='row LITNET-2020 code_red_worm', transform=lambda L: round(_row(L, 'code_red_worm')['auc']['POT'], 6))
for sp in ('deposited', 'threeway40', 'threeway60'):
    add(sec, f'Slowhttptest share of summed difference, {sp} split (%)', '', EXT, ['surviving_rows_share', sp, 'slowhttptest_pct'])

# ---------------------------------------------------------------- N. EWMA ablation, order sensitivity, DIF seed
sec = 'N. secondary: EWMA ablation, order sensitivity, DIF seed (PANEL-16 / USABLE-16)'
base = ['four', 'ablation', 'PANEL-16']
add(sec, 'ablation: ours with EWMA', '', NUM, base + ['mean_auc_with_ewma'])
add(sec, 'ablation: ours without EWMA', '', NUM, base + ['mean_auc_without_ewma'])
add(sec, 'ablation: EWMA stage contribution', 'delta', NUM, base + ['stage_contribution'])
add(sec, 'ablation: rows improved / degraded', 'wins', NUM, base, transform=lambda o: f"{o['improves']}/{o['degrades']}")
add(sec, 'ablation: scenario p', 'p', NUM, base + ['scenario_p'])
add(sec, 'ablation: largest gain row and gain', 'set', 'results/ewma_ablation.json', ['PANEL-16', 'largest_gain'], transform=lambda o: f"{o['scenario']} {o['delta']:+.4f}")
add(sec, 'ablation: smallest gain row and gain', 'set', 'results/ewma_ablation.json', ['PANEL-16', 'largest_loss'], transform=lambda o: f"{o['scenario']} {o['delta']:+.4f}")
add(sec, 'ablation: victim-clustered p', 'p', NUM, base + ['cluster_p'])
base = ['four', 'order_sensitivity', 'USABLE-16', OURS]
add(sec, 'order sensitivity: ours interleaved minus appended mean AUC', 'delta', NUM, base, transform=lambda o: round(o['appended_mean_auc'] - o['interleaved_mean_auc'], 6))
add(sec, 'order sensitivity: ours rows moved', 'count', NUM, base + ['rows_moved'])
add(sec, 'DIF corrected mean AUC, seed 42 / seed 7', '', NUM, ['four', 'dif_seed'], transform=lambda o: f"{o['corrected_42']}/{o['corrected_7']}")
add(sec, 'DIF archived mean AUC, seed 42 / seed 7', '', NUM, ['four', 'dif_seed'], transform=lambda o: f"{o['archived_42']}/{o['archived_7']}")
add(sec, 'validation: stored aggregates reproduced / mismatches', 'count', 'recompute/validation.json', [], transform=lambda o: f"{o['ok']}/{len(o['mismatches'])}")

# ---------------------------------------------------------------- S. secondary records the manuscript quotes
FE = 'results/final_evaluation.json'
for pop in ('panel', 'full_tree_USABLE', 'full_tree_non-USABLE', 'full_tree_ALL'):
    sec = f'S1. archived-registry final evaluation (ours against SPOT), {pop}'
    add(sec, 'ours mean AUC', '', FE, ['results', pop, OURS, 'mean_auc'])
    add(sec, 'SPOT mean AUC', '', FE, ['results', pop, 'SPOT', 'mean_auc'])
    add(sec, 'ours minus SPOT', 'delta', FE, ['results', pop, OURS, 'vs_spot_auc'])
    add(sec, 'Wilcoxon p', 'p', FE, ['results', pop, OURS, 'vs_spot_p'])
    add(sec, 'wins', 'wins', FE, ['results', pop, OURS, 'wins'])
UT = 'results/universal_ewma_tournament.json'
sec = 'S2. archived-registry EWMA tournament (20 arms; LODA rows unseeded)'


def _lb_rank(L, name):
    o = sorted(L, key=lambda r: -r['mean_auc'])
    return f"{[r['name'] for r in o].index(name) + 1}/{len(o)}"


def _lb(L, name):
    return next(r for r in L if r['name'] == name)


QR = 'Pure Subspace Q-Resid (k=8) + EWMA'
add(sec, f'{QR}: rank by mean AUC', 'rank', UT, ['leaderboard'], transform=lambda L: _lb_rank(L, QR))
add(sec, f'{QR}: mean AUC', '', UT, ['leaderboard'], transform=lambda L: _lb(L, QR)['mean_auc'])
add(sec, f'{QR}: DR@2%', '', UT, ['leaderboard'], transform=lambda L: _lb(L, QR)['dr_2pct'])
add(sec, 'Subspace-ECOD (k=8) + EWMA: mean AUC', '', UT, ['leaderboard'], transform=lambda L: _lb(L, 'Subspace-ECOD (k=8) + EWMA')['mean_auc'])
add(sec, 'top arm by mean AUC', 'set', UT, ['leaderboard'], transform=lambda L: max(L, key=lambda r: r['mean_auc'])['name'])


def _ewma_up(L):
    d = {r['name']: r['mean_auc'] for r in L}
    base_ = sorted({n.replace(' (Raw)', '') for n in d if n.endswith('(Raw)')})
    up = [b for b in base_ if d.get(b + ' + EWMA', -1) > d[b + ' (Raw)']]
    return f"{len(up)}/{len(base_)}" + ('' if len(up) == len(base_) else ' (not raised: ' + ','.join(b for b in base_ if b not in up) + ')')


add(sec, 'detectors whose EWMA version has the higher mean AUC', 'wins', UT, ['leaderboard'], transform=_ewma_up)
add(sec, 'SPOT raw -> SPOT + EWMA mean AUC', '', UT, ['leaderboard'],
    transform=lambda L: f"{_lb(L, 'SPOT (Raw)')['mean_auc']}->{_lb(L, 'SPOT + EWMA')['mean_auc']}")
for _cmp in [r['comparison'] for r in G('37', UT, ['significance'])]:
    add(sec, f'significance: {_cmp}: mean AUC difference', 'delta', UT, ['significance'], how=f'comparison={_cmp}',
        transform=lambda L, c=_cmp: next(r for r in L if r['comparison'] == c)['delta_mean_auc'])
    add(sec, f'significance: {_cmp}: p (AUC)', 'p', UT, ['significance'], how=f'comparison={_cmp}',
        transform=lambda L, c=_cmp: next(r for r in L if r['comparison'] == c)['p_auc'])
FO = 'results/fpr_dr_optimization_results.json'
sec = 'S3. archived-module optimization sweep (8 entries)'
_A = 'Subspace-ECOD (k=8, EWMA alpha=0.5)'


def _v(L, name):
    return next(v for v in L if v['name'] == name)


add(sec, 'EWMA alpha=0.5 variant: mean AUC rank of 8', 'rank', FO, ['variants'],
    transform=lambda L: f"{sorted([v['name'] for v in L], key=lambda n: -_v(L, n)['mean_auc']).index(_A) + 1}/8")
add(sec, 'EWMA alpha=0.5 variant: mean AUC', '', FO, ['variants'], transform=lambda L: _v(L, _A)['mean_auc'])
add(sec, 'EWMA alpha=0.5 variant: benign episodes @1% rank of 8 (fewest = 1)', 'rank', FO, ['variants'],
    transform=lambda L: f"{sorted([v['name'] for v in L], key=lambda n: _v(L, n)['benign_episodes_1pct']).index(_A) + 1}/8")
add(sec, 'EWMA alpha=0.5 variant: benign episodes @1%', '', FO, ['variants'], transform=lambda L: _v(L, _A)['benign_episodes_1pct'])
SV = 'results/subspace_ecod_validation_report.json'
sec = 'S4. archived-module validation report (unsmoothed Subspace-ECOD)'
for tgt in ('1', '2', '5'):
    add(sec, f'threshold transfer @{tgt}%: supported', 'set', SV, ['task1_threshold_transfer', f'target_{tgt}pct', 'supported'])
    add(sec, f'threshold transfer @{tgt}%: ours realized FPR', '', SV, ['task1_threshold_transfer', f'target_{tgt}pct', 'ours_realized_fpr_mean'])
    add(sec, f'matched per-window episodes @{tgt}%: ours minus SPOT', 'delta', SV, ['task2_episode_metrics', 'matched_per_window', f'target_{tgt}pct'],
        transform=lambda o: round(o['ours_episodes_per_1k'] - o['spot_episodes_per_1k'], 2))
    add(sec, f'matched per-window episodes @{tgt}%: Wilcoxon p', 'p', SV, ['task2_episode_metrics', 'matched_per_window', f'target_{tgt}pct', 'wilcoxon_p_episodes'])
add(sec, 'nested leave-one-scenario-out: selected k counts', 'set', SV, ['task3_justify_k', 'selected_k_counts'], transform=lambda o: json.dumps(o, sort_keys=True).replace('"', ''))
add(sec, 'nested leave-one-scenario-out: held-out mean AUC', '', SV, ['task3_justify_k', 'nested_heldout_mean_auc'])
add(sec, 'nested leave-one-scenario-out: gain over SPOT', 'delta', SV, ['task3_justify_k', 'heldout_gain_vs_spot'])
add(sec, 'nested leave-one-scenario-out: Wilcoxon p', 'p', SV, ['task3_justify_k', 'wilcoxon_p'])
add(sec, 'k grid: k=8, q=0.98 mean AUC (resubstituted)', '', SV, ['task3_justify_k', 'sensitivity_grid', 'k=8_q=0.98'])

# ---------------------------------------------------------------- X. cross-check from the matrices
for sp in ('deposited (benchmark)', 'R40', 'R60', 'matched smoothing'):
    for k, kind in (('margin', 'delta'), ('ours_raw_p', 'p'), ('ours_holm_p', 'p'), ('ours_cluster_mean_delta', 'delta'),
                    ('ours_cluster_p', 'p'), ('ours_wins', 'wins'), ('ours_auc_rank', 'rank')):
        add_val('X. independent re-computation from the per-scenario matrices (scipy wilcoxon, own Holm and exact clustered test)',
                f'{sp}: {k}', kind, CC[(sp, '37')][k], CC[(sp, '39')][k],
                S('37', MATRIX[sp], ['per_population', 'PANEL-16'], XHOW), S('39', MATRIX[sp], ['per_population', 'PANEL-16'], XHOW))

buf = io.StringIO()
w = csv.writer(buf, delimiter='\t', lineterminator='\n')
w.writerow(['statistic', 'value_37', 'value_39', 'source_37', 'source_39', 'flips'])
for r in rows:
    w.writerow([f'{r[0]} :: {r[1]}'] + r[2:])
text = buf.getvalue()
PRE = ('significance@0.05', 'rank', 'win count', 'sign')
n_flip = sum(1 for r in rows if not r[0].startswith('X.') and any(r[6].startswith(p) or ('; ' + p) in r[6] for p in PRE))
if OPT['--check']:
    old = open(OPT['--check']).read()
    if old == text:
        print(f"{len(rows)} rows, {n_flip} with a pre-registered flip outside section X: identical to {OPT['--check']}")
        sys.exit(0)
    a, b = old.splitlines(), text.splitlines()
    for i in range(max(len(a), len(b))):
        if i >= len(a) or i >= len(b) or a[i] != b[i]:
            print(f"first difference at line {i + 1}:\n  file:     {a[i] if i < len(a) else '(none)'}\n  computed: {b[i] if i < len(b) else '(none)'}")
            break
    print(f"{OPT['--check']} differs from the comparison ({len(a)} against {len(b)} lines)")
    sys.exit(1)
os.makedirs(os.path.dirname(os.path.abspath(OPT['--out'])), exist_ok=True)
with open(OPT['--out'], 'w') as fh:
    fh.write(text)
print(f"wrote {OPT['--out']}: {len(rows)} rows, {n_flip} with a pre-registered flip outside section X")
