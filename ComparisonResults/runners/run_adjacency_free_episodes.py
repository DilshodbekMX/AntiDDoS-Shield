#!/usr/bin/env python3
"""Benign alarm episodes at held-out thresholds, stream-realized and adjacency-free.

The stream-realized figure is what an operator sees: the detector scores the merged
benign+attack test stream, so benign windows inherit EWMA state from the attack block.
The adjacency-free figure re-scores a stream with the attack rows excised, exactly as
runners/run_adjacency_free_fpr.py does for the false-alarm rate, so the same
decomposition applies to the declared primary metric. It is a decomposition, never a
replacement: the stream-realized number stays primary.

Writes results/adjacency_free_episodes.json (override with AFE_OUTDIR / AFE_OUT).
"""
import json, os, statistics, sys, time
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
for p in (HERE, os.path.abspath(os.path.join(HERE, '..'))):
    if p not in sys.path:
        sys.path.insert(0, p)

from config import RESULTS_DIR
import safe_out
from corpus_names import canon, victim_key, is_chronological, spelling_census
import competitors_fixed as C
import run_crosscorpus_auc as R
import run_29_scenarios_corrected as R29
from run_post2023_benchmark import tkey

TARGETS = (0.01, 0.02, 0.05)
OUT = safe_out.resolve(RESULTS_DIR, 'adjacency_free_episodes.json', 'AFE')


def episodes(flags, cooldown=30):
    # verbatim from runners/run_corrected_benchmark_full.py:42-44
    idx = np.flatnonzero(flags)
    return 0 if len(idx) == 0 else 1 + int(np.sum(np.diff(idx) > cooldown))


def episodes_at(positions, cooldown=30):
    """Episodes over ORIGINAL stream positions.

    Excising the attack rows compacts the index, and the cooldown counts stream
    positions, so counting over the compacted index would shrink every arm's episode
    count including the memoryless ones. Mapping each flagged benign window back to the
    position it occupied in the merged stream removes that confound: a memoryless arm,
    whose benign scores do not change, then returns an identical count by construction,
    exactly as it does for the realized false-alarm rate.
    """
    idx = np.asarray(sorted(positions), dtype=int)
    return 0 if len(idx) == 0 else 1 + int(np.sum(np.diff(idx) > cooldown))


def episode_starts(positions, cooldown=30):
    idx = np.asarray(sorted(positions), dtype=int)
    if len(idx) == 0:
        return []
    out = [int(idx[0])]
    out += [int(idx[i]) for i in range(1, len(idx)) if idx[i] - idx[i - 1] > cooldown]
    return out


def main():
    t0 = time.time()
    cases = R29.collect()
    print(f"{len(cases)} scenarios with verdict in (USABLE, ROLE-UNVERIFIED)\n")
    per_scen = []
    for corp, fn, path, e in cases:
        fit, cal, tb, atk = R29.load_case_tree(path, e.get('victim'), e.get('split_mode'))
        if fit is None or len(fit) < 10 or len(cal) < 5 or len(tb) < 5 or len(atk) < 10:
            print(f"  SKIP {corp} {fn[:40]}"); continue
        feats = R.active_features(fit)
        A = C.mat(fit, feats)
        tagged = sorted([(tkey(r), 0, r) for r in tb] + [(tkey(r), 1, r) for r in atk],
                        key=lambda x: x[0])
        y = np.array([t[1] for t in tagged])
        nc = len(cal)
        stream = C.mat(cal + [t[2] for t in tagged], feats)
        benign_only = C.mat(cal + [t[2] for t in tagged if t[1] == 0], feats)
        nb = int((y == 0).sum())
        rec = {'corpus': canon(corp), 'file': fn, 'label': f"{canon(corp)} {fn.replace('.json','')}",
               'victim': victim_key(corp, e.get('victim')), 'verdict': e.get('verdict'),
               'split_mode': e.get('split_mode'),
               'causal': e.get('split_mode') not in ('treefile', 'crossfile'),
               # A stream whose order is an index collision has no interpretable episode
               # RUN, so free_ep/stream_ep on these rows are not episode rates. Flagged
               # from corpus_names, not from a literal at this call site.
               'chronological': is_chronological(corp),
               'n_benign_test': nb, 'arms': {}}
        for name, (fnc, _) in C.DETECTORS.items():
            try:
                s_all = np.asarray(fnc(A, stream), dtype=float)
                s_ben = np.asarray(fnc(A, benign_only), dtype=float)
                cs_a, ts_a = s_all[:nc], s_all[nc:]
                cs_b, ts_b = s_ben[:nc], s_ben[nc:]
                a = {}
                for t in TARGETS:
                    k = int(t * 100)
                    th_a = np.percentile(cs_a, (1 - t) * 100)
                    th_b = np.percentile(cs_b, (1 - t) * 100)
                    ben_pos = np.flatnonzero(y == 0)
                    stream_pos = ben_pos[ts_a[y == 0] > th_a]
                    free_pos = ben_pos[ts_b > th_b]
                    a[f'stream_ep@{k}'] = round(1000.0 * episodes_at(stream_pos) / max(nb, 1), 2)
                    a[f'free_ep@{k}'] = round(1000.0 * episodes_at(free_pos) / max(nb, 1), 2)
                    atk_pos = np.flatnonzero(y == 1)
                    starts = episode_starts(stream_pos)
                    near = 0
                    for p0 in starts:
                        prev = atk_pos[atk_pos < p0]
                        if len(prev) and (p0 - int(prev[-1])) <= 30:
                            near += 1
                    a[f'ep_starts@{k}'] = len(starts)
                    a[f'ep_starts_near_attack@{k}'] = near
                    a[f'stream_fpr@{k}'] = round(float((ts_a[y == 0] > th_a).mean() * 100), 2)
                    a[f'free_fpr@{k}'] = round(float((ts_b > th_b).mean() * 100), 2)
                rec['arms'][name] = a
            except Exception as ex:
                rec['arms'][name] = {'error': str(ex)[:120]}
        rec['_corpus_raw'] = corp
        per_scen.append(rec)
        print(f"  {corp} {fn[:44]:44s} ({time.time()-t0:.0f}s)", flush=True)

    def agg(rows, label):
        tab = {}
        for n in C.DETECTORS:
            v = [r['arms'][n] for r in rows if 'stream_ep@2' in r['arms'].get(n, {})]
            if len(v) != len(rows):
                continue
            ent = {'n': len(v)}
            for t in TARGETS:
                k = int(t * 100)
                for f in ('stream_ep', 'free_ep', 'stream_fpr', 'free_fpr'):
                    ent[f'{f}@{k}pct'] = round(statistics.mean(x[f'{f}@{k}'] for x in v), 2)
                ts_ = sum(x[f'ep_starts@{k}'] for x in v)
                tn_ = sum(x[f'ep_starts_near_attack@{k}'] for x in v)
                ent[f'ep_starts@{k}pct'] = ts_
                ent[f'ep_starts_near_attack@{k}pct'] = tn_
                ent[f'ep_starts_near_attack_frac@{k}pct'] = round(tn_ / ts_, 4) if ts_ else None
            tab[n] = ent
        return tab

    U = [r for r in per_scen if r['verdict'] == 'USABLE']
    out = {'note': ('Benign alarm episodes at held-out thresholds, stream-realized against '
                    'adjacency-free. Adjacency-free re-scores a stream with attack rows excised, '
                    'the same excision runners/run_adjacency_free_fpr.py applies to the '
                    'false-alarm rate, so the EWMA never inherits attack state. It is a '
                    'decomposition of the stream-realized loss, not a replacement: the '
                    'stream-realized figure is what an operator sees and stays primary. '
                    'Cooldown definition verbatim from run_corrected_benchmark_full.py.'),
           'targets': list(TARGETS), 'cooldown_windows': 30,
           'episode_index_convention': ('MERGED-STREAM POSITIONS. Flagged benign windows are mapped '
                                        'back to the index they held in the merged benign+attack test '
                                        'stream before the cooldown is applied, so a batch-invariant arm '
                                        'returns an identical count with and without excision. An earlier '
                                        'version of this runner counted over the compacted benign-only '
                                        'index, which shrank every arm; records without this key are that '
                                        'earlier version and must not be compared with this one.'),
           'corpus_spelling_census': spelling_census([r['_corpus_raw'] for r in per_scen]),
           'non_chronological_strata': ('USABLE-6-crossfile is CIC-IoT-2023 only; its stream order is an '
                                        'index collision, so its episode figures are reported for '
                                        'completeness and are not interpretable as episode rates.'),
           'versions': {'numpy': np.__version__,
                        'scipy': __import__('scipy').__version__,
                        'sklearn': __import__('sklearn').__version__,
                        'pyod': __import__('pyod').__version__},
           'summary': {'USABLE-22': agg(U, 'USABLE-22'),
                       'USABLE-16-causal': agg([r for r in U if r['causal']], 'USABLE-16-causal'),
                       'USABLE-6-crossfile': agg([r for r in U if not r['causal']], 'USABLE-6-crossfile'),
                       'ALL-29': agg(per_scen, 'ALL-29')},
           'n': len(per_scen),
           'per_scenario': [{k: v for k, v in r.items() if k != '_corpus_raw'} for r in per_scen],
           'elapsed_sec': round(time.time() - t0, 1)}
    json.dump(out, open(OUT, 'w'), indent=1)
    print(f"\n-> {OUT}  ({time.time()-t0:.0f}s)")


if __name__ == '__main__':
    main()
