"""Final evaluation of Subspace-Q + EWMA across every scenario in the tree.

Three populations, because they answer different questions:
  PANEL       the 23 curated scenarios, using their own declared splits
  FULL TREE   every scenario in datasets/extracted under one strict causal
              split, reported separately for USABLE and non-USABLE verdicts
              (the audit quarantined ATTACKER-SIDE and ROLE-UNVERIFIED cases;
              they must never carry a headline)
  CESNET      174 real ISP backbone hosts, benign only -- false alarms only

Every arm gets the same causal EWMA(alpha=0.5) where smoothing applies, so no
arm is handed a filter the others do not get. Chronological order throughout,
fit on train rows only, per-scenario matched FPR.

Writes only to this tree's results/.
"""
import gc
import json
import os
import statistics
import sys
import time

import numpy as np
from sklearn.metrics import roc_auc_score
from scipy import stats as st

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..')))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..', '..', 'experiment')))
sys.path.insert(0, os.path.join(HERE, 'negatives'))

from config import RESULTS_DIR, TAR_PATH, TIMES_TAR, MIN_IP_ROWS_PER_IP
import run_crosscorpus_auc as R
import post2023_competitors as C
from run_post2023_benchmark import load_case, tkey, dr_at

EXTRACTED = '/home/detector/Projects/antiddos/datasets/extracted'
OUT = os.path.join(RESULTS_DIR, 'final_evaluation.json')
ALPHA, K = 0.5, 8
TARGETS = (0.01, 0.02, 0.05)


def ewma(s, alpha=ALPHA):
    out = np.zeros(len(s)); cur = 0.0
    for i, v in enumerate(s):
        cur = alpha * v + (1.0 - alpha) * cur
        out[i] = cur
    return out


def subspace_q_ewma(A, B, k=K):
    """Ours: EWMA-smoothed ECOD surprise of the subspace residual. No SPOT term."""
    N, D = A.shape
    if N < 2 * D:
        return C.spot_baseline_scores(A, B)
    mu = A.mean(axis=0); sd = A.std(axis=0); sd[sd < 1e-9] = 1.0
    Ztr, Zte = (A - mu) / sd, (B - mu) / sd
    _, _, Vt = np.linalg.svd(Ztr, full_matrices=False)
    Vk = Vt[:min(k, Vt.shape[0])]
    Qtr = np.sum(Ztr ** 2, axis=1) - np.sum((Ztr @ Vk.T) ** 2, axis=1)
    Qte = np.sum(Zte ** 2, axis=1) - np.sum((Zte @ Vk.T) ** 2, axis=1)
    Qte_adj = Qte - 1e-12 * np.maximum(1.0, Qte)
    ge = N - np.searchsorted(np.sort(Qtr), Qte_adj, side='left')
    return ewma(-np.log(np.maximum(ge + 1.0, 1.0) / (N + 1.0)))


ARMS = {
    'Subspace-Q + EWMA (ours)': subspace_q_ewma,
    'SPOT':        lambda A, B: C.spot_baseline_scores(A, B),
    'INNE + EWMA': lambda A, B: ewma(C.inne_scores(A, B)),
    'HBOS + EWMA': lambda A, B: ewma(C.hbos_scores(A, B)),
    'ECOD + EWMA': lambda A, B: ewma(C.ecod_scores(A, B)),
    'COPOD + EWMA': lambda A, B: ewma(C.copod_scores(A, B)),
    'LODA + EWMA': lambda A, B: ewma(C.loda_scores(A, B)),
}
REF = 'SPOT'


def episodes(flags, cooldown=30):
    idx = np.flatnonzero(flags)
    return 0 if len(idx) == 0 else 1 + int(np.sum(np.diff(idx) > cooldown))


def score_case(A, B, y, acc):
    for n, fn in ARMS.items():
        try:
            s = np.asarray(fn(A, B), dtype=float)
            if s.shape[0] != len(y) or not np.all(np.isfinite(s)):
                raise ValueError('bad scores')
            nb = int((y == 0).sum())
            rec = {'auc': float(roc_auc_score(y, s))}
            for t in TARGETS:
                rec[f'dr{int(t*100)}'] = dr_at(s, y, t)
                th = np.percentile(s[y == 0], (1 - t) * 100)
                rec[f'ep{int(t*100)}'] = 1000.0 * episodes((s > th) & (y == 0)) / max(nb, 1)
            acc[n].append(rec)
        except Exception:
            acc[n].append(None)


def summarise(acc, label):
    rows = {}
    base = [r['auc'] for r in acc[REF] if r]
    for n in ARMS:
        vals = [r for r in acc[n] if r]
        if not vals:
            continue
        e = {'n': len(vals), 'mean_auc': round(statistics.mean(v['auc'] for v in vals), 4),
             'median_auc': round(statistics.median(v['auc'] for v in vals), 4)}
        for t in TARGETS:
            e[f'dr@{int(t*100)}pct'] = round(statistics.mean(v[f'dr{int(t*100)}'] for v in vals), 2)
            e[f'ep@{int(t*100)}pct'] = round(statistics.mean(v[f'ep{int(t*100)}'] for v in vals), 2)
        if n != REF and len(vals) == len(base):
            a = [v['auc'] for v in vals]
            e['vs_spot_auc'] = round(statistics.mean(a) - statistics.mean(base), 4)
            e['vs_spot_p'] = (1.0 if np.allclose(a, base)
                              else round(float(st.wilcoxon(a, base, zero_method='wilcox')[1]), 5))
            e['wins'] = f"{sum(1 for x, b in zip(a, base) if x > b)}/{len(a)}"
        rows[n] = e
    print(f"\n{label}  (n = {len(base)})")
    print(f"  {'arm':26s} {'meanAUC':>8s} {'vsSPOT':>8s} {'p':>8s} {'wins':>7s} "
          f"{'DR@1%':>7s} {'DR@2%':>7s} {'DR@5%':>7s} {'ep@2%':>7s}")
    for n in sorted(rows, key=lambda n: -rows[n]['mean_auc']):
        e = rows[n]
        print(f"  {n:26s} {e['mean_auc']:>8.4f} {e.get('vs_spot_auc', 0.0):>+8.4f} "
              f"{str(e.get('vs_spot_p', '-')):>8s} {e.get('wins', '-'):>7s} "
              f"{e['dr@1pct']:>7.2f} {e['dr@2pct']:>7.2f} {e['dr@5pct']:>7.2f} {e['ep@2pct']:>7.2f}")
    return rows


def main():
    t0 = time.time()
    out = {}

    # ---------- PANEL ----------
    panel = json.load(open(os.path.join(RESULTS_DIR, 'panel_inventory', 'PANEL.json')))['panel']
    acc = {n: [] for n in ARMS}
    for e in panel:
        fit, cal, tb, atk = load_case(e)
        if fit is None or len(fit) < 10 or len(atk) < 10:
            continue
        feats = R.active_features(fit)
        tg = sorted([(tkey(r), 0, r) for r in tb] + [(tkey(r), 1, r) for r in atk], key=lambda x: x[0])
        y = np.array([t[1] for t in tg])
        score_case(C.mat(fit, feats), C.mat([t[2] for t in tg], feats), y, acc)
    out['panel'] = summarise(acc, 'PANEL — 23 curated scenarios, own splits')

    # ---------- FULL TREE ----------
    accs = {'ALL': {n: [] for n in ARMS}, 'USABLE': {n: [] for n in ARMS},
            'non-USABLE': {n: [] for n in ARMS}}
    n_eval = n_skip = 0
    for corp in sorted(os.listdir(EXTRACTED)):
        ix = os.path.join(EXTRACTED, corp, 'index.json')
        if not os.path.isfile(ix) or corp == 'CESNET-TimeSeries24':
            continue
        d = json.load(open(ix))
        items = d if isinstance(d, list) else (list(d.values())[0] if len(d) == 1 else list(d.values()))
        if isinstance(items, dict):
            items = list(items.values())
        for e in items:
            if not isinstance(e, dict):
                continue
            fn = e.get('file') or (str(e.get('attack_type')) + '.json')
            p = os.path.join(EXTRACTED, corp, fn)
            if not os.path.exists(p) or os.path.getsize(p) > 120e6:
                n_skip += 1; continue
            try:
                dd = json.load(open(p)); pi = dd.get('per_ip_windows', {})
                vic = e.get('victim') if e.get('victim') in pi else next(iter(pi), None)
                rr = sorted(pi.get(vic, []), key=tkey)
                ai = [i for i, r in enumerate(rr) if r.get('_is_attack')]
                if not ai:
                    raise ValueError
                pre = [r for r in rr[:ai[0]] if not r.get('_is_attack')]
                if len(pre) < 30:
                    raise ValueError
                fit = pre[:int(len(pre) * 0.6)]; post = rr[ai[0]:]
                y = np.array([1 if r.get('_is_attack') else 0 for r in post])
                if y.sum() < 10 or (y == 0).sum() < 5:
                    raise ValueError
                feats = R.active_features(fit)
                A, B = C.mat(fit, feats), C.mat(post, feats)
                bucket = 'USABLE' if e.get('verdict') == 'USABLE' else 'non-USABLE'
                for key in ('ALL', bucket):
                    score_case(A, B, y, accs[key])
                n_eval += 1
            except Exception:
                n_skip += 1
            finally:
                try: del dd, pi
                except Exception: pass
                gc.collect()
    print(f"\nfull tree: {n_eval} scenarios evaluated, {n_skip} skipped (thin/absent/oversize)")
    for key in ('ALL', 'USABLE', 'non-USABLE'):
        out[f'full_tree_{key}'] = summarise(accs[key], f'FULL TREE — {key}')

    # ---------- CESNET ----------
    from data_loader import load_per_ip, AVAILABLE_FEATURES
    from pipeline import split_ip_rows
    ip = load_per_ip(TAR_PATH, TIMES_TAR, min_rows=MIN_IP_ROWS_PER_IP)
    fpr = {n: {t: [] for t in TARGETS} for n in ARMS}
    nh = 0
    for _, rows in ip.items():
        tr, cal, te = split_ip_rows(rows)
        if len(te) < 20 or len(cal) < 20 or len(tr) < 40:
            continue
        A = C.mat(tr, AVAILABLE_FEATURES); B = C.mat(cal + te, AVAILABLE_FEATURES); nc = len(cal)
        nh += 1
        for n, f in ARMS.items():
            try:
                s = np.asarray(f(A, B), dtype=float)
                for t in TARGETS:
                    fpr[n][t].append(float((s[nc:] > np.percentile(s[:nc], (1 - t) * 100)).mean()))
            except Exception:
                pass
    ces = {}
    print(f"\nCESNET — {nh} real ISP hosts, benign only (realized FPR at each nominal target)")
    print(f"  {'arm':26s} " + ''.join(f"{('@'+str(int(t*100))+'%'):>10s}" for t in TARGETS))
    for n in ARMS:
        if not fpr[n][TARGETS[0]]:
            continue
        ces[n] = {f'target_{int(t*100)}pct': round(100 * statistics.mean(fpr[n][t]), 2) for t in TARGETS}
        for t in TARGETS:
            a = [abs(x - t) for x in fpr[REF][t]]; b = [abs(x - t) for x in fpr[n][t]]
            ces[n][f'p_vs_spot_{int(t*100)}pct'] = (1.0 if np.allclose(a, b) else
                round(float(st.wilcoxon(b, a, zero_method='wilcox')[1]), 5))
        print(f"  {n:26s} " + ''.join(f"{ces[n][f'target_{int(t*100)}pct']:>9.2f}%" for t in TARGETS))
    out['cesnet'] = {'n_hosts': nh, 'arms': ces}

    json.dump({'alpha': ALPHA, 'k': K, 'results': out,
               'elapsed_sec': round(time.time() - t0, 1)}, open(OUT, 'w'), indent=1)
    print(f"\n-> {OUT}  ({time.time()-t0:.0f}s)")


if __name__ == '__main__':
    main()
