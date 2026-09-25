#!/usr/bin/env python3
"""Clock-only null under the deposited split and under the three-way split, both signs.

Two questions in one pass, both label-only: neither reads a detector score.

  1. Is the clock degeneracy a property of the corpora or of the causal split? The
     deposited split sends every pre-attack benign window into fit and calibration, so
     each test stream opens on attack and a decreasing index separates the classes. The
     three-way split returns the last fifth of that benign slice to the test stream.
  2. Does the two-sided reading max(AUC, 1-AUC) flatter the null relative to the fixed
     sign s = -i that a causal detector could commit to in advance? Both are reported
     per row, so the counts can be compared at any cut.

The test stream here is identical for the 40/40/20 and 60/20/20 three-way variants --
only the fit/calibration boundary differs, and the clock reads neither -- so this record
covers both.

A missing input cache is an error, not a skip: a silently shortened panel would change
every count in the summary without changing anything a reader can see. Set
CS_ALLOW_PARTIAL=1 to run on whatever caches are present; the output then carries
n_skipped and the reason for each, and the counts are not comparable with the deposit.

Writes results/clock_split_sensitivity.json (override with CS_OUTDIR / CS_OUT).
"""
import json, os, sys, time
import numpy as np
from sklearn.metrics import roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
for p in (HERE, os.path.abspath(os.path.join(HERE, '..'))):
    if p not in sys.path:
        sys.path.insert(0, p)

from config import RESULTS_DIR
import safe_out
from corpus_names import canon, victim_key, is_separate_capture, spelling_census
from run_post2023_benchmark import tkey

OUT = safe_out.resolve(RESULTS_DIR, 'clock_split_sensitivity.json', 'CS')
CUTS = (0.95, 0.94)


def corpus_of(entry):
    """From the cache PATH, i.e. the extracted directory name, never from the label."""
    return os.path.basename(os.path.dirname(str(entry['cache'])))


def clock(rows):
    y = np.array([1 if r.get('_is_attack') else 0 for r in rows])
    if y.min() == y.max():
        return None, None
    a = float(roc_auc_score(y, -np.arange(len(y), dtype=float)))
    return a, max(a, 1 - a)


def streams(rows, mode):
    """(deposited test stream, three-way test stream)."""
    if mode == 'crossday':
        # Fit comes from the training day, so the attack day is tested whole and already
        # runs benign -> attack -> benign. Nothing was truncated, so the three-way split
        # leaves this row alone and both columns are the same stream.
        return rows, rows
    if mode == 'within':
        ai = [i for i, r in enumerate(rows) if r.get('_is_attack')]
        if not ai:
            return None, None
        pre, post = rows[:ai[0]], rows[ai[0]:]
        return post, sorted(pre[int(len(pre) * 0.8):] + post, key=tkey)
    ben = [r for r in rows if not r.get('_is_attack')]
    atk = [r for r in rows if r.get('_is_attack')]
    s = sorted(ben[int(len(ben) * 0.8):] + atk, key=tkey)
    return s, s          # an index-collision order is the same either way


def main():
    t0 = time.time()
    base = os.environ.get('ANTIDDOS_BASE', os.path.dirname(os.path.dirname(HERE)))
    panel = json.load(open(os.path.join(RESULTS_DIR, 'panel_inventory', 'PANEL.json')))['panel']
    allow_partial = os.environ.get('CS_ALLOW_PARTIAL') == '1'
    rows, skipped, raw = [], [], []
    for e in panel:
        cache = os.path.join(base, str(e['cache']).lstrip('./'))
        if not os.path.exists(cache):
            if not allow_partial:
                raise SystemExit(
                    f"missing input cache for {e['label']}: {cache}\n"
                    "The panel counts in this record are only meaningful over all 23 rows. "
                    "Set CS_ALLOW_PARTIAL=1 to run on the caches present; the output then "
                    "records n_skipped and its counts are not comparable with the deposit.")
            skipped.append({'label': e['label'], 'reason': 'input not in this tree'})
            continue
        corp = corpus_of(e)
        d = json.load(open(cache))
        per = d.get('per_ip_windows', d)
        v = e.get('victim')
        if v not in per:
            raise SystemExit(
                f"victim {v!r} absent from {cache} (scenario {e['label']}). "
                "Scoring a different host would silently answer a different question; "
                "fix PANEL.json or the cache rather than substituting one.")
        rr = sorted(per[v], key=tkey)
        b, t = streams(rr, e.get('mode', 'within'))
        if b is None:
            skipped.append({'label': e['label'], 'reason': 'no attack window'})
            continue
        ab, sb = clock(b)
        at, st = clock(t)
        if ab is None or at is None:
            skipped.append({'label': e['label'], 'reason': 'single-class stream'})
            continue
        raw.append(corp)
        rows.append({'label': e['label'], 'corpus': canon(corp),
                     'victim': victim_key(corp, e.get('victim')), 'mode': e.get('mode', 'within'),
                     'separate_benign_capture': is_separate_capture(corp),
                     'deposited_split': {'clock_auc': round(ab, 4), 'clock_separability': round(sb, 4)},
                     'threeway_split': {'clock_auc': round(at, 4), 'clock_separability': round(st, 4)}})
        print(f"  {e['label'][:54]:54s} {sb:.4f} -> {st:.4f}", flush=True)

    def counts(key, field, cut):
        return sum(1 for r in rows if r[key][field] >= cut)

    summary = {}
    for key, name in (('deposited_split', 'deposited'), ('threeway_split', 'three-way')):
        summary[key] = {f'cut_{c}': {
            'fixed_sign_ge_cut': counts(key, 'clock_auc', c),
            'oracle_signed_ge_cut': counts(key, 'clock_separability', c),
            'joint_survivors': sum(1 for r in rows
                                   if r[key]['clock_separability'] < c
                                   and not r['separate_benign_capture'])} for c in CUTS}
        summary[key]['n'] = len(rows)
    sign_disagreements = [
        {'label': r['label'], 'split': k, 'cut': c,
         'clock_auc': r[k]['clock_auc'], 'clock_separability': r[k]['clock_separability']}
        for r in rows for k in ('deposited_split', 'threeway_split') for c in CUTS
        if (r[k]['clock_separability'] >= c) != (r[k]['clock_auc'] >= c)]

    out = {'note': __doc__.strip(),
           'cuts': list(CUTS),
           'corpus_spelling_census': spelling_census(raw),
           'summary': summary,
           'sign_oracle_disagreements': sign_disagreements,
           'n_panel': len(panel),
           'n_scored': len(rows),
           'n_skipped': len(skipped),
           'allow_partial': allow_partial,
           'skipped': skipped,
           'versions': {'numpy': np.__version__, 'sklearn': __import__('sklearn').__version__},
           'per_scenario': rows,
           'elapsed_sec': round(time.time() - t0, 1)}
    json.dump(out, open(OUT, 'w'), indent=1)
    print('\n' + json.dumps(summary, indent=1))
    print(f"sign-oracle disagreements: {len(sign_disagreements)}")
    print(f"-> {OUT}")


if __name__ == '__main__':
    main()
