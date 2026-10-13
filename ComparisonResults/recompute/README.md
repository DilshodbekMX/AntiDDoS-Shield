# recompute/

Derived numbers for the manuscript, recomputed from the per-scenario records in `results/`. Paths below
are relative to `ComparisonResults/`. The three Python scripts only read `results/`; `regenerate.sh`
rewrites 29 of its 49 records.

## Scripts

Run from `ComparisonResults/`, in this order, since `tables_v4.py` reads the outputs of the other two. The
scripts need numpy and scipy; `four_corpus_tables.py` also imports `corpus_names.py`.

    python3 recompute/four_corpus_tables.py results recompute
    python3 recompute/extra_numbers.py      results recompute
    python3 recompute/tables_v4.py          results recompute results

- `four_corpus_tables.py <results_dir> <out_dir>` recomputes every aggregate the manuscript prints:
  admissibility census, discrimination tests with bootstrap and victim-clustered intervals, Holm and
  Bonferroni corrections from the unrounded p-values, held-out operating points, clock strata, EWMA
  ablation, matched-smoothing and split controls, order sensitivity, DIF seed spread and engine
  verification. It writes `numbers.json`, then checks the recomputation against the aggregates the
  records themselves store and writes `validation.json`.
- `extra_numbers.py <results_dir> <out_dir>` writes `extra.json`, the second-tier quantities the prose quotes
  (AUC-gain concentration, leakage correction, oracle episode means, adjacency, ties, ledger detail).
- `tables_v4.py <results_dir> <recompute_dir> [<records_dir>]` renders the LaTeX table bodies and figure
  coordinates into `tables_v4.json`. The optional third directory supplies `universal_ewma_tournament.json`,
  `corrected_benchmark_results.json` and `matched_smoothing_benchmark.json`; pass `results`, as
  `regenerate.sh` does, or the smoothing, oracle detection-rate and matched-control tables are left out.

## Outputs

- `numbers.json`: every recomputed aggregate, under the key `four`. `extra.json`: the second-tier quantities.
- `tables_v4.json`: the table bodies and figure coordinates by name, plus `detection_crosscheck_ok` and
  `matched_crosscheck_ok`, which check those two tables' records against the recomputation; both are `true`.
  The keys `detection_sandbox` and `matched_sandbox` keep an earlier name; they hold the columns of
  `corrected_benchmark_results.json` and `matched_smoothing_benchmark.json`.
- `validation.json`: `{"ok": 1508, "mismatches": []}`, i.e. 1,508 stored aggregates reproduced and
  0 mismatches. The tolerance for each field is set in `four_corpus_tables.py`.

## recompute/regeneration/

- `regenerate.sh [python]` rewrites 29 of the 49 records in `results/`, then runs the three scripts above.
  Runners run in two waves (the second reads first-wave records); each writes a log to
  `recompute/regeneration/logs/`. They read the derived feature tree at `$ANTIDDOS_BASE/datasets/extracted/`
  (by default the repository root), which is not deposited. `extraction/` rebuilds it and
  `extraction/tree_manifest/` pins its checksums, except for three per-day caches that no deposited script
  writes (CIC-IDS-2017 Wednesday, CSE-CIC-IDS2018 Tuesday, attack-typed CIC-DDoS2019); 9 of the 16 panel
  scenarios depend on them (`extraction/README.md`, "What the chain cannot rebuild"). Needs numpy, scipy,
  scikit-learn, PyTorch (for DIF) and PyOD, plus gcc for `runners/run_c_engine_ours.py`, which compiles the
  engine from `project/layer2/` at the repository root. The records' `versions` blocks name pyod 3.6.5,
  torch 2.13.0+cpu, numpy 2.4.2, scikit-learn 1.8.0 and scipy 1.17.0.
- `sixth_victim.sh [python]` runs the post hoc check below. It copies `ComparisonResults/` to a temporary
  directory (rsync), installs `recompute/results/PANEL_sixvictim.json` there as the panel inventory, runs
  `runners/run_split_control.py` under the `threeway40` and `threeway60` splits and copies the four
  `*_sixvictim*` records into `recompute/results/`. The deposited `results/` is never touched.
- `pass_comparison.tsv` compares two complete regeneration passes over the 49 records in `results/`,
  record by record (columns: record, numeric leaves, values changed from pass 1 to pass 2, cause). Pass 1
  was an earlier full pass at the default BLAS thread count. Pass 2 is the single-threaded `regenerate.sh`
  run that wrote the deposited records; `batch_invariance_gate.json` was rewritten in a follow-up run of
  `runners/verify_inductive.py`, which `regenerate.sh` now includes; pass 1 did not run that writer, so its
  row compares the follow-up run with the previously deposited record. Values are compared on the leaves both
  passes write. The comparison ignores `elapsed_sec` (the wall-clock run time) and free-text notes, and it
  matches renamed population keys.

  `regenerate.sh` does not rewrite the other 20 records; the TSV gives the reason for each. Six are inputs
  with no deposited writer (`panel_inventory/*.json`, `admissibility_inputs.json`). Nine have no deposited
  writer of their own: `full_tree_all_scenarios_metrics.json` and
  `all_extracted_datasets_evaluation_results.json`, whose rows were restricted by hand to the four corpora,
  six rescued LITNET-2020 records, two of which (`rescued/*_CANONICAL.json`) are byte copies of
  `litnet_l1subnet_{16,24}_results.json`, and the rescued dual-scale audit
  (`rescued/dual_scale_union_results.json`, CIC-IDS-2017 and LITNET-2020 blocks). The last five have deposited writers that it does not run.
  `c_engine_verification_report.json` comes from `runners/verify_c_engine_subspace_q.py`, which compiles
  the engine's `subspace_q.c`; that file is not deposited, and the record was restricted to the 16 panel
  rows by hand. `litnet_l1subnet_{16,24}_results.json` (`runners/run_litnet_l1subnet.py`) and
  `rescued/ABLATION_no_unique_dst_l1subnet_{16,24}_results.json` (`runners/ablate_no_unique_dst_runner.py`)
  come from runners that read the LITNET-2020 export or caches built from it (neither is deposited), not the
  derived tree. All four were scored on an incomplete LITNET-2020 export that lacks the `udp_f` attack, and
  none was re-run.

  Of the 29 records it rewrites, 19 keep identical values and 10 change, for three causes:
  1. DIF is seeded, but its fifth decimal depends on the BLAS thread count (`dif_seed_sensitivity.json`,
     `split_control_threeway40_benchmark.json`, `split_control_threeway40_matrix.json` and
     `batch_invariance_gate.json`). Example: one `threeway40` row's DIF AUC moved from 0.993196 to 0.993166.
  2. The archived competitor module `post2023_competitors.py` passes no `random_state` to LODA, so its LODA
     cells change on every run (`post2023_benchmark_results.json`, `universal_ewma_tournament.json`,
     `final_evaluation.json` and `batch_invariance_gate.json`, whose verdicts are all unchanged). The
     tournament's LODA (Raw) moved from 0.6651 to 0.6337 and LODA + EWMA from 0.6536 to 0.6639, so
     whether the EWMA stage helps LODA depends on the draw.
  3. Runner changes between the passes. Eight summary means of `adjacency_free_fpr.json` now use
     `statistics.mean`, as the `scenarios29_corrected_results.json` writer does, so the exact ties 6.865 and
     3.025 round alike in both. Pass 1 stopped on stale assertions in the writers of `joint_filter.json` and
     `table_cell_provenance.json` and kept the earlier records; pass 2 rewrote them.

  Ten rewritten records also store `elapsed_sec`: `adjacency_free_episodes.json`,
  `clock_split_sensitivity.json`, `corrected_benchmark_results.json`, `final_evaluation.json`,
  `matched_smoothing_benchmark.json`, `post2023_benchmark_results.json`,
  `scenarios29_corrected_results.json` and `split_control_{deposited,threeway40,threeway60}_benchmark.json`.
  After a re-run, their entries in `SHA256SUMS.results` and those of the records with LODA cells (cause 2)
  will generally fail. Compare values, not hashes.

## recompute/results/

A post hoc sensitivity check: the 16-row panel plus LITNET-2020 smurf on 193.219.88.36 (17 rows, six victims),
run under the two repaired three-way splits only; the deposited split leaves that row no benign test window.

- `PANEL_sixvictim.json`: the 17-row panel inventory (the input; no deposited writer).
- `split_control_benchmark_threeway{40,60}_sixvictim.json`, `split_control_threeway{40,60}_sixvictim_matrix.json`:
  the records, with populations `PANEL-17` and `USABLE-strict`.
- `SHA256SUMS`: checksums of these five files, which `SHA256SUMS.results` does not list. Run
  `sha256sum -c SHA256SUMS` inside `recompute/results/`. The two benchmark records store `elapsed_sec`, the
  wall-clock run time, so every re-run changes their hashes; compare their values instead.

## Single-thread setting

`regenerate.sh` and `sixth_victim.sh` export `OMP_NUM_THREADS=1`, `OPENBLAS_NUM_THREADS=1` and
`MKL_NUM_THREADS=1` (cause 1 above). Set the same three variables when running a runner by hand. With them,
a re-run of the three scripts reproduces `numbers.json`, `extra.json`, `tables_v4.json` and
`validation.json` byte for byte. Archived-module LODA cells do not reproduce between runs at any thread count.
