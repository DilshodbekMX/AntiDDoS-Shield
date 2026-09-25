#!/usr/bin/env python3
"""Emit the per-cell provenance of the two operating-point tables in the main text.

Sections 3.6 and 3.7 report their held-out operating point and their benign-episode
grid as tables rather than as numeric prose. Every cell of both is either a summary
cell stored in a deposited record, or an unweighted scenario mean over a deposited
per_scenario block. This runner writes the mapping from table cell to record key so a
reader can trace any printed cell without re-deriving it.

Two things it is deliberately NOT:

  * It is not an analysis. It reads deposited records only, runs no detector and
    fits nothing. Re-running it after a detector re-run will change the file only if
    the records changed.
  * It is not a second source of truth. Where a record stores a summary cell, this
    file cites that cell rather than recomputing it. Only 18 of 102 cells are
    aggregated here, and for those it applies the aggregation the source runners
    themselves apply: the unweighted mean of the ALREADY-ROUNDED per-scenario values,
    rounded to two decimals (run_adjacency_free_fpr.py:93-94,
    run_29_scenarios_corrected.py:171). Averaging unrounded values instead would move
    cells in the last printed digit.

The fourth episode regime -- oracle thresholds with the attack rows excised -- is
absent rather than empty. run_adjacency_free_episodes.py takes both thresholds from
the calibration prefix, so every excised figure in this deposit is a held-out figure.

Writes results/table_cell_provenance.json (override with TP_OUTDIR / TP_OUT).
"""
import json
import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for p in (HERE, os.path.abspath(os.path.join(HERE, '..'))):
    if p not in sys.path:
        sys.path.insert(0, p)

from config import RESULTS_DIR
import safe_out

OUT = safe_out.resolve(RESULTS_DIR, 'table_cell_provenance.json', 'TP')
OURS = 'Subspace-Q + EWMA (ours)'
REF = 'POT'
TARGETS = (1, 2, 5)
ARMS = ((OURS, 'ours'), (REF, 'reference'))

# The held-out record names two strata differently from the manuscript, and its
# 'non-causal-split-only' block is NOT the admissible six: it holds all 13 crossfile
# rows, seven of them ROLE-UNVERIFIED, and reads 6.56 at nominal 1% against the
# admissible six-row 10.55. No cell below is taken from it.
HELDOUT_KEY = {'USABLE-22': 'USABLE-22', 'USABLE-16-causal': 'causal-split-only'}


def load(name):
    with open(os.path.join(RESULTS_DIR, name)) as fh:
        return json.load(fh)


def agg(rows, arm, key):
    """The aggregation the source runners apply: mean of already-rounded cells."""
    return round(statistics.mean(r['arms'][arm][key] for r in rows), 2)


def main():
    heldout = load('scenarios29_corrected_results.json')
    episodes = load('adjacency_free_episodes.json')['summary']
    matrix = load('panel_auc_matrix.json')['per_population']

    usable = [r for r in heldout['per_scenario'] if r['verdict'] == 'USABLE']
    strata = {'USABLE-22': usable,
              'USABLE-16-causal': [r for r in usable if r['causal']],
              'USABLE-6-crossfile': [r for r in usable if not r['causal']]}
    assert [len(v) for v in strata.values()] == [22, 16, 6], 'stratum sizes moved'

    cells = []

    def add(table, row, column, value, record, how):
        cells.append({'table': table, 'row': row, 'column': column,
                      'value': value, 'record': record, 'derivation': how})

    # ---- Table: the held-out operating point (Section 3.6) ----
    for pop, rows in strata.items():
        sk = HELDOUT_KEY.get(pop)
        for arm, label in ARMS:
            for t in TARGETS:
                for key, name in ((f'dr@{t}', 'detection rate %'),
                                  (f'fpr@{t}', 'stream-realized FPR %')):
                    stored = (heldout['summary'].get(sk, {}).get(arm, {}).get(key + 'pct')
                              if sk else None)
                    if stored is not None:
                        add('heldout_operating_point', pop, f'{name} @{t}%, {label}', stored,
                            f'scenarios29_corrected_results.json :: '
                            f'summary["{sk}"]["{arm}"]["{key}pct"]', 'stored summary cell')
                    elif key.startswith('fpr'):
                        add('heldout_operating_point', pop, f'{name} @{t}%, {label}',
                            episodes[pop][arm][f'stream_fpr@{t}pct'],
                            f'adjacency_free_episodes.json :: '
                            f'summary["{pop}"]["{arm}"]["stream_fpr@{t}pct"]', 'stored summary cell')
                    else:
                        add('heldout_operating_point', pop, f'{name} @{t}%, {label}',
                            agg(rows, arm, key),
                            f'scenarios29_corrected_results.json :: mean over per_scenario'
                            f'[verdict=="USABLE" and causal is {pop.endswith("causal")}]'
                            f'["arms"]["{arm}"]["{key}"]', 'unweighted scenario mean')
                add('heldout_operating_point', pop, f'adjacency-free FPR % @{t}%, {label}',
                    episodes[pop][arm][f'free_fpr@{t}pct'],
                    f'adjacency_free_episodes.json :: '
                    f'summary["{pop}"]["{arm}"]["free_fpr@{t}pct"]', 'stored summary cell')

    # ---- Table: the benign-episode grid (Section 3.7) ----
    for pop in strata:
        for regime, prefix in (('stream-realized', 'stream_ep@'),
                               ('attack rows excised', 'free_ep@')):
            for arm, label in ARMS:
                for t in TARGETS:
                    add('episodes', f'held-out, {regime}, {pop}',
                        f'episodes/1000 @{t}%, {label}',
                        episodes[pop][arm][f'{prefix}{t}pct'],
                        f'adjacency_free_episodes.json :: '
                        f'summary["{pop}"]["{arm}"]["{prefix}{t}pct"]', 'stored summary cell')
    for pop in ('PANEL-23', 'USABLE-strict'):
        for arm, label in ARMS:
            for t, key in zip(TARGETS, ('ep1', 'ep2', 'ep5')):
                add('episodes', f'oracle, stream-realized, {pop}',
                    f'episodes/1000 @{t}%, {label}',
                    round(statistics.mean(r[key][arm] for r in matrix[pop]), 2),
                    f'panel_auc_matrix.json :: '
                    f'mean over per_population["{pop}"][*]["{key}"]["{arm}"]',
                    'unweighted scenario mean')

    out = {
        'note': __doc__.strip(),
        'aggregation_rule': ('unweighted mean of the already-rounded per-scenario cells, '
                             'rounded to two decimals, as the source runners do'),
        'not_measured': {
            'regime': 'oracle thresholds x attack rows excised',
            'reason': ('runners/run_adjacency_free_episodes.py takes both thresholds from the '
                       'calibration prefix (cs_a, ts_a = s_all[:nc], s_all[nc:]), so every '
                       'excised figure in this deposit is a held-out figure. The regime was '
                       'not run; its cells are absent rather than estimated.')},
        'stratum_name_trap': (
            'scenarios29_corrected_results.json summary["non-causal-split-only"] is 13 rows, '
            'seven of them ROLE-UNVERIFIED, not the admissible six. Its ours fpr@1pct reads '
            '6.56 against the admissible six-row 10.55. No cell here is taken from it.'),
        'n_cells': len(cells),
        'n_stored': sum(1 for c in cells if c['derivation'] == 'stored summary cell'),
        'cells': cells,
    }
    with open(OUT, 'w') as fh:
        json.dump(out, fh, indent=1)
    print(f"{out['n_cells']} cells ({out['n_stored']} stored, "
          f"{out['n_cells'] - out['n_stored']} aggregated)")
    print(f'-> {OUT}')


if __name__ == '__main__':
    main()
