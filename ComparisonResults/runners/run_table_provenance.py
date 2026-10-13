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
    file cites that cell rather than recomputing it. A minority of cells (n_cells -
    n_stored in the record) are aggregated here, and for those it applies the
    aggregation the source runners themselves apply: the unweighted mean of the
    ALREADY-ROUNDED per-scenario values, rounded to two decimals
    (run_adjacency_free_fpr.py:93-94, run_29_scenarios_corrected.py:158). Averaging
    unrounded values instead would move cells in the last printed digit.

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
EXPECTED_USABLE = 16  # USABLE-16, the population the manuscript tables print


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
    panel = load(os.path.join('panel_inventory', 'PANEL.json'))['panel']

    usable = [r for r in heldout['per_scenario'] if r['verdict'] == 'USABLE']
    strata = {f'USABLE-{len(usable)}': usable}
    assert len(usable) == EXPECTED_USABLE and all(r['causal'] for r in usable), 'USABLE-16 moved'

    cells = []

    def add(table, row, column, value, record, how):
        cells.append({'table': table, 'row': row, 'column': column,
                      'value': value, 'record': record, 'derivation': how})

    # ---- Table: the held-out operating point (Section 3.6) ----
    for pop, rows in strata.items():
        # The held-out summary key equals the stratum key: run_29_scenarios_corrected
        # derives it the same way, f'USABLE-{len(usable)}'.
        sk = pop
        for arm, label in ARMS:
            for t in TARGETS:
                for key, name in ((f'dr@{t}', 'detection rate %'),
                                  (f'fpr@{t}', 'stream-realized FPR %')):
                    stored = heldout['summary'].get(sk, {}).get(arm, {}).get(key + 'pct')
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
                            '[verdict=="USABLE"]'
                            f'["arms"]["{arm}"]["{key}"]', 'unweighted scenario mean')
                add('heldout_operating_point', pop, f'adjacency-free FPR % @{t}%, {label}',
                    episodes[pop][arm][f'free_fpr@{t}pct'],
                    f'adjacency_free_episodes.json :: '
                    f'summary["{pop}"]["{arm}"]["free_fpr@{t}pct"]', 'stored summary cell')

    # Mean AUC advantage by stratum. A different quantity from the detection and
    # false-alarm blocks, and two Limitations sentences depend on it, so it is a cell
    # of the table rather than prose that a later cut can remove.
    for pop, rows in strata.items():
        sk = pop
        for arm, label in ARMS:
            stored = heldout['summary'].get(sk, {}).get(arm, {}).get('mean_auc')
            if stored is not None:
                add('heldout_operating_point', pop, f'mean AUC, {label}', stored,
                    f'scenarios29_corrected_results.json :: summary["{sk}"]["{arm}"]["mean_auc"]',
                    'stored summary cell')
            else:
                add('heldout_operating_point', pop, f'mean AUC, {label}',
                    round(statistics.mean(r['arms'][arm]['auc'] for r in rows), 4),
                    f'scenarios29_corrected_results.json :: mean over per_scenario'
                    f'[verdict=="USABLE"]["arms"]["{arm}"]["auc"]',
                    'unweighted scenario mean')
        add('heldout_operating_point', pop, 'mean AUC advantage over the reference',
            round(statistics.mean(r['arms'][OURS]['auc'] - r['arms'][REF]['auc'] for r in rows), 4),
            f'scenarios29_corrected_results.json :: mean over per_scenario'
            '[verdict=="USABLE"] of '
            f'arms["{OURS}"]["auc"] - arms["{REF}"]["auc"]',
            'unweighted scenario mean of per-row differences')

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
    for pop in (f"PANEL-{len(panel)}", "USABLE-strict"):
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
