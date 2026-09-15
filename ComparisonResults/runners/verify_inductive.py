"""Acceptance test: every arm must score a row independently of its batch.

The 2026-08-27 audit found four arms whose score for a FIXED row changed with the
composition of the test batch. That invalidated the comparison, because the panel
is 67% attack. This scores the SAME benign rows in batches padded with attack rows
and requires the benign scores to be bit-identical.

An arm that fails this is not a scoring function and cannot appear in a table.

Two registries are run. The ARCHIVED registry (post2023_competitors) is the
pre-correction code, and serves as the positive control: a gate that nothing can
fail measures nothing, so the gate must be shown to fire. The CORRECTED registry
(competitors_fixed) is the one whose scores are reported in the paper, and is the
one whose verdict is the acceptance criterion; the process exit status is set from
it alone.

Padding is applied on BOTH sides of the scored benign rows, and the two sides are
reported as two separate axes, because they test different things.

  APPEND (0/k): rows added AFTER the scored benign rows. A score that moves when
  FUTURE rows are added has read them: that is the transductive leakage this gate
  exists to catch, and append-invariance is the acceptance criterion.

  PREPEND (k/0): rows added BEFORE the scored benign rows. This changes the causal
  history a sequential scorer has seen by the time it reaches each benign row. A
  streaming detector is entitled to depend on its own past, so movement here is
  order-dependence, NOT leakage, and is reported as a disclosed property rather
  than scored as a failure.

The distinction matters because an append-only test has no power against a
forward-only scorer -- it passes by construction -- so the prepend axis is what
identifies which arms that exemption applies to. Two arms here are sequential by
design (our EWMA smoothing, DSPOT's drift window); the gate cannot certify them on
the order axis and says so rather than reporting a silent pass.

Writes results/batch_invariance_gate.json.
"""
import json, os, sys
import numpy as np
from scipy import stats as st

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..')))

from config import RESULTS_DIR
import run_crosscorpus_auc as R
import competitors_fixed
import post2023_competitors
from run_post2023_benchmark import load_case, tkey

LABEL = 'CIC-IDS-2018 Tue-20-02_DDoS-LOIC-HTTP'   # 92.6% attack: worst case
TOL = 1e-9


def run_registry(C, tag, A, B_ben, B_atk, feats):
    """Score B_ben in batches padded (pre, post) with attack rows."""
    nb = len(B_ben)
    na = len(B_atk)
    pads = [(0, 0), (0, 16), (0, na), (16, 0), (na, 0)]
    append_idx = [1, 2]          # (0,16) and (0,na): future rows only
    prepend_idx = [3, 4]         # (16,0) and (na,0): causal history only
    print(f"\n  == {tag} registry ==")
    hdr = ''.join(f"{f'{a}/{b}':>11s}" for a, b in pads)
    print(f"  {'arm':26s}{hdr}   {'append':>10s}{'prepend':>11s}{'repeat':>11s}  verdict")

    rows = {}
    for name, (fn, _) in C.DETECTORS.items():
        # Determinism control: the SAME batch scored twice. An arm that moves here is
        # stochastic, so its drift on any other axis is confounded with reseeding and
        # cannot be read as leakage.
        r1 = np.asarray(fn(A, B_ben), dtype=float)[:nb]
        r2 = np.asarray(fn(A, B_ben), dtype=float)[:nb]
        repeat = float(np.max(np.abs(r1 - r2)))
        runs = []
        for pre, post in pads:
            parts = ([B_atk[:pre]] if pre else []) + [B_ben] + ([B_atk[:post]] if post else [])
            batch = np.vstack(parts)
            s = np.asarray(fn(A, batch), dtype=float)[pre:pre + nb]
            runs.append(s)
        ref = runs[0]
        app = max(float(np.max(np.abs(ref - runs[i]))) for i in append_idx)
        pre = max(float(np.max(np.abs(ref - runs[i]))) for i in prepend_idx)
        rho = min(float(st.spearmanr(ref, runs[i]).statistic) for i in append_idx)
        det = repeat < TOL
        ok = app < TOL
        seq = pre >= TOL
        rows[name] = {'append_drift': app, 'prepend_drift': pre, 'repeat_drift': repeat,
                      'deterministic': det, 'min_spearman_append': rho,
                      'verdict': 'PASS' if ok else ('FAIL' if det else 'FAIL (confounded: stochastic)'),
                      'sequential': seq,
                      'mean_by_pad': {f'{a}/{b}': float(r.mean()) for (a, b), r in zip(pads, runs)}}
        means = ''.join(f"{r.mean():>11.4f}" for r in runs)
        note = 'PASS' if ok else f'FAIL rho={rho:.4f}'
        print(f"  {name:26s}{means}   {app:>10.2e}{pre:>11.2e}{repeat:>11.2e}  {note}"
              f"{'  [sequential]' if seq else ''}{'' if det else '  [STOCHASTIC]'}")

    fails = [n for n, v in rows.items() if v['verdict'].startswith('FAIL')]
    clean = [n for n in fails if rows[n]['deterministic']]
    stoch = [n for n, v in rows.items() if not v['deterministic']]
    seqs = [n for n, v in rows.items() if v['sequential']]
    if stoch:
        print(f"  -> STOCHASTIC (same batch twice moves): {stoch} -- drift not attributable")
    print(f"  -> append (leakage), deterministic arms only: {len(clean)} of "
          f"{len(rows) - len(stoch)} fail" + (f": {clean}" if clean else ""))
    print(f"  -> append (leakage), all arms: {len(fails)} of {len(rows)} fail"
          + (f": {fails}" if fails else ""))
    print(f"  -> prepend (order-dependence, not a failure): {len(seqs)} of {len(rows)} sequential"
          + (f": {seqs}" if seqs else ""))
    return {'registry': tag, 'n_arms': len(rows), 'n_failed': len(fails), 'failed': fails,
            'n_failed_deterministic': len(clean), 'failed_deterministic': clean,
            'n_stochastic': len(stoch), 'stochastic': stoch,
            'n_sequential': len(seqs), 'sequential': seqs,
            'pads': [f'{a}/{b}' for a, b in pads], 'arms': rows}


def main():
    panel = json.load(open(os.path.join(RESULTS_DIR, 'panel_inventory', 'PANEL.json')))['panel']
    e = next(x for x in panel if x['label'] == LABEL)
    fit, cal, tb, atk = load_case(e)
    feats = R.active_features(fit)
    A = competitors_fixed.mat(fit, feats)
    B_ben = competitors_fixed.mat(tb, feats)
    B_atk = competitors_fixed.mat(atk, feats)
    print(f"{LABEL}\n  train={A.shape}  benign={len(B_ben)}  attack={len(B_atk)}"
          f"\n  pads are (pre/post) attack rows; benign scores must be bit-identical (tol {TOL:g})")

    archived = run_registry(post2023_competitors, 'ARCHIVED (pre-correction)', A, B_ben, B_atk, feats)
    corrected = run_registry(competitors_fixed, 'CORRECTED (reported)', A, B_ben, B_atk, feats)

    out = {'scenario': LABEL, 'tolerance': TOL,
           'n_train': int(A.shape[0]), 'n_benign': int(len(B_ben)), 'n_attack': int(len(B_atk)),
           'archived': archived, 'corrected': corrected}
    dst = os.path.join(RESULTS_DIR, 'batch_invariance_gate.json')
    with open(dst, 'w') as f:
        json.dump(out, f, indent=2)
    print(f"\n  wrote {dst}")

    print(f"\n  gate discriminates on the append axis: archived {archived['n_failed']}/"
          f"{archived['n_arms']} fail, corrected {corrected['n_failed']}/{corrected['n_arms']} fail")
    print(f"  order-dependent (append-clean, prepend-moving), corrected registry: "
          f"{corrected['sequential']} -- sequential by design, not certifiable on this axis")
    if corrected['n_failed']:
        print(f"  ACCEPTANCE FAILED: {corrected['failed']}")
        return 1
    print(f"  ACCEPTANCE PASSED: all {corrected['n_arms']} reported arms are inductive")
    return 0


if __name__ == '__main__':
    sys.exit(main())
