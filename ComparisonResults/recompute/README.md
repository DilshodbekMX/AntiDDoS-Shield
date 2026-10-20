# recompute/

Derived numbers for the manuscript, recomputed from the per-scenario records in `results/`. Paths below
are relative to `ComparisonResults/`. The three Python scripts below only read `results/`;
`regenerate.sh` rewrites 29 of its 49 records. `compare_feature_sets.py` sets the records of this
revision, scored on the 39 engine feature names, beside those of commit `895e581`, scored on 37, as
`PREREGISTRATION_39_FEATURES.md` asks.

## Scripts

Run from `ComparisonResults/`, in this order, since `tables_v4.py` reads the outputs of the other two. The
scripts need numpy and scipy; `four_corpus_tables.py` also imports `corpus_names.py`.

    python3 recompute/four_corpus_tables.py results recompute
    python3 recompute/extra_numbers.py      results recompute
    python3 recompute/tables_v4.py          results recompute results

- `four_corpus_tables.py <results_dir> <out_dir>` recomputes the manuscript's aggregates that rest on
  per-scenario records (the Data Availability Statement lists the figures that do not):
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

`compare_feature_sets.py [--base COMMIT] [--old-root DIR] [--out FILE] [--check FILE]` writes
`results/feature_set_comparison_37_vs_39.tsv`. It reads the 37-name records with
`git show 895e581:ComparisonResults/<path>`, so it needs a git checkout that contains that commit;
`--old-root DIR` reads them instead from a directory holding an export of it, such as
`git archive 895e581 | tar -x -C DIR`. It reads the 39-name records from this checkout, needs numpy and
scipy, and with `--check FILE` compares instead of writing and exits 1 on any difference:

    python3 recompute/compare_feature_sets.py --check recompute/results/feature_set_comparison_37_vs_39.tsv

## Outputs

- `numbers.json`: every recomputed aggregate, under the key `four`. `extra.json`: the second-tier quantities.
- `tables_v4.json`: the table bodies and figure coordinates by name, plus `detection_crosscheck_ok` and
  `matched_crosscheck_ok`, which check those two tables' records against the recomputation; both are `true`.
  The keys `detection_sandbox` and `matched_sandbox` keep an earlier name; they hold the columns of
  `corrected_benchmark_results.json` and `matched_smoothing_benchmark.json`.
- `validation.json`: `{"ok": 1968, "mismatches": []}`, i.e. 1,968 stored aggregates reproduced and
  0 mismatches, 460 of them in the three repaired-split held-out records. The tolerance for each field is set in `four_corpus_tables.py`.
- `results/feature_set_comparison_37_vs_39.tsv`: 661 rows, one per statistic, with columns `statistic`,
  `value_37`, `value_39`, `source_37`, `source_39` and `flips`. A source names the record and the JSON path
  of the value, prefixed `895e581:` on the 37-name side, and says when the value is computed here from a
  record (a rank, a difference, or the cross-check of section X, which recomputes our row's Wilcoxon p,
  Holm adjustment and victim-clustered test from the per-scenario matrices). `flips` names a change of
  significance at 0.05 (a p-value, or a 95% interval that starts or stops excluding 0), of rank, of win
  count or of sign, the kinds the pre-registration asks to be printed on both feature sets; 87 rows
  outside section X carry one. Sections A to N follow the pre-registered list (margin and its tests,
  split controls, rankings, benign alarm episodes, detection and false-alarm rates, the clock null,
  matched smoothing, the inductive correction, the batch-invariance gate, the admissibility census,
  active features D per row, the C engine and the C port, concentration, and the secondary analyses);
  section S covers the archived-registry records the manuscript quotes.

## recompute/regeneration/

- `regenerate.sh [python]` rewrites 29 of the 49 records in `results/`, then runs the three scripts above.
  Runners run in two waves (the second reads first-wave records); each writes a log to
  `recompute/regeneration/logs/`. They read the derived feature tree at `$ANTIDDOS_BASE/datasets/extracted/`
  (by default the repository root), which is not deposited. `extraction/` rebuilds it from the corpus
  releases and `extraction/tree_manifest/` pins the checksums of the 39-name tree the authors rebuilt for
  this revision (`extraction/README.md`, "Comparing a rebuilt tree"). Run `heldout_threeway40.sh` before
  it: `four_corpus_tables.py` reads the three `*_threeway40.json` records in `recompute/results/`, so the
  scripts at the end of `regenerate.sh` summarize whatever copies of them are present.
  `ComparisonResults/requirements.txt` pins the environment (Python 3.12, numpy 2.4.2, scipy 1.17.0,
  scikit-learn 1.8.0, PyOD 3.6.5, PyTorch 2.13.0+cpu, dpkt 1.9.8); gcc is also needed for
  `runners/run_c_engine_ours.py`, which compiles the engine from `project/layer2/` at the repository root.
- `sixth_victim.sh [python]` runs the post hoc check below. It copies `ComparisonResults/` to a temporary
  directory (rsync), installs `recompute/results/PANEL_sixvictim.json` there as the panel inventory, runs
  `runners/run_split_control.py` under the `threeway40` and `threeway60` splits and copies the four
  `*_sixvictim*` records into `recompute/results/`. The deposited `results/` is never touched.
- `heldout_threeway40.sh [python]` re-scores the held-out operating point under the repaired 40/40/20 split
  (`ANTIDDOS_SPLIT=threeway40` in `runners/run_29_scenarios_corrected.py`) and writes the three
  `*_threeway40.json` records described below into `recompute/results/`. It does not run the three
  scripts above; run them after it, or run it before `regenerate.sh`.
- `pass_comparison.tsv` compares two passes of the 37-name revision, record by record, with earlier copies
  that are not deposited: pass 1's records and, for `batch_invariance_gate.json`, the previously deposited
  record (columns: record, numeric leaves, values changed from pass 1 to pass 2, cause). Its counts describe
  those passes and not the 39-name records; for the 20 records `regenerate.sh` does not rewrite, the cause
  column gives the reason as it stands in this revision. Pass 1
  was an earlier full pass at the default BLAS thread count. Pass 2 is the single-threaded `regenerate.sh`
  run that wrote the deposited records before the Wednesday regeneration (below); `batch_invariance_gate.json` was rewritten in a follow-up run of
  `runners/verify_inductive.py`, which `regenerate.sh` now includes; pass 1 did not run that writer, so its
  row compares the follow-up run with the previously deposited record. Values are compared on the leaves both
  passes write. The comparison ignores `elapsed_sec` (the wall-clock run time) and free-text notes, and it
  matches renamed population keys. The TSV summarizes a leaf-by-leaf comparison whose scripts are not
  deposited.

  `regenerate.sh` does not rewrite the other 20 records; the TSV gives the reason for each. Five are inputs
  with no deposited writer (`panel_inventory/*.json`). Nine have no deposited writer of their own:
  `full_tree_all_scenarios_metrics.json` and `all_extracted_datasets_evaluation_results.json`, whose rows
  were restricted by hand to the four corpora, six rescued LITNET-2020 records, two of which
  (`rescued/*_CANONICAL.json`) are byte copies of `litnet_l1subnet_{16,24}_results.json`, and the rescued
  dual-scale audit (`rescued/dual_scale_union_results.json`, CIC-IDS-2017 and LITNET-2020 blocks). The
  other six have deposited writers that it does not run. `admissibility_inputs.json`, the ledger's input,
  is written by `extraction/write_admissibility_inputs.py` from the tree's `index.json` files, a step of the
  extraction recipe. `c_engine_verification_report.json` comes from `runners/verify_c_engine_subspace_q.py`,
  which compiles the engine's `subspace_q.c`; that file is not deposited.
  `litnet_l1subnet_{16,24}_results.json` (`runners/run_litnet_l1subnet.py`) and
  `rescued/ABLATION_no_unique_dst_l1subnet_{16,24}_results.json` (`runners/ablate_no_unique_dst_runner.py`)
  come from runners that read the LITNET-2020 export or caches built from it (neither is deposited), not the
  derived tree. All four were scored on an incomplete LITNET-2020 export that lacks the `udp_f` attack, and
  their 39-name re-run read the same export; none was run on the complete file.

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

  Both passes ran on the derived tree as it stood before the six CIC-IDS-2017 Wednesday files were
  regenerated (`extraction/README.md`). For the revision that regenerated them (commit `9d51bdc`, still on
  37 feature names) `regenerate.sh`, `sixth_victim.sh` and `heldout_threeway40.sh` were run again in full
  on the regenerated tree. Three records changed in value and replaced the deposited ones: `results/c_engine_ours.json` (18 values of the shipped engine's rule
  set), and `results/split_control_threeway40_matrix.json` and
  `recompute/results/split_control_threeway40_sixvictim_matrix.json` (one INNE cell each, 0.974410 to
  0.974356), with two leaves of `numbers.json` that derive from that cell. The other records these
  scripts write were unchanged apart from unseeded LODA cells and stored run times, and were kept. `extra.json`,
  `tables_v4.json` and `validation.json` were unchanged. `ComparisonResults/README.md` lists the changes;
  `pass_comparison.tsv` still compares passes 1 and 2.

  For the 39-name revision every record whose deposited writer could be run was re-run on the rebuilt tree:
  the whole `regenerate.sh` set with `heldout_threeway40.sh` and `sixth_victim.sh`, the C-port check with
  the recovered `subspace_q.c`, `extraction/write_admissibility_inputs.py`, and the four LITNET-2020 subnet
  and ablation records with the patched subnet loader. 44 of the 57 records were re-run; six inputs are
  unchanged by construction and seven records with no deposited writer keep their earlier values.
  `ComparisonResults/README.md` ("Records after the 39-name re-run") lists them, and
  `results/feature_set_comparison_37_vs_39.tsv` sets the headline statistics of the two feature sets side by
  side.

## recompute/results/

Two post hoc checks and the 37-against-39 comparison, none listed in `SHA256SUMS.results`.

The held-out operating point re-scored under the repaired 40/40/20 split (`regeneration/heldout_threeway40.sh`):
`scenarios29_corrected_results_threeway40.json`, `adjacency_free_fpr_threeway40.json` and
`adjacency_free_episodes_threeway40.json`, each with a `split` block naming the rule. `numbers.json` summarizes
them as `heldout_threeway40`, and `validation.json` checks 460 of their stored aggregates.

The sixth-victim check: the 16-row panel plus LITNET-2020 smurf on 193.219.88.36 (17 rows, six victims),
run under the two repaired three-way splits only; the deposited split leaves that row no benign test window.

- `PANEL_sixvictim.json`: the 17-row panel inventory (the input; no deposited writer).
- `split_control_benchmark_threeway{40,60}_sixvictim.json`, `split_control_threeway{40,60}_sixvictim_matrix.json`:
  the records, with populations `PANEL-17` and `USABLE-strict`.
- `feature_set_comparison_37_vs_39.tsv`: the pre-registered headline statistics on the 37 and the 39 names
  (see Outputs above), written by `compare_feature_sets.py`.
- `SHA256SUMS`: checksums of all nine files here. Run `sha256sum -c SHA256SUMS` inside
  `recompute/results/`. The two benchmark records and two of the three held-out records (all but `adjacency_free_fpr_threeway40.json`)
  store `elapsed_sec`, the wall-clock run time, so every re-run changes their hashes; compare their values instead.

## Single-thread setting

`regenerate.sh`, `sixth_victim.sh` and `heldout_threeway40.sh` export `OMP_NUM_THREADS=1`, `OPENBLAS_NUM_THREADS=1` and
`MKL_NUM_THREADS=1` (cause 1 above). Set the same three variables when running a runner by hand. With them,
a re-run of the three Python scripts on the same records reproduces `numbers.json`, `extra.json`, `tables_v4.json` and
`validation.json` byte for byte. Archived-module LODA cells do not reproduce between runs at any thread count.
