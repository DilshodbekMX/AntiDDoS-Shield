# ComparisonResults

The evaluation deposit for the Subspace-Q + EWMA detector: the competitor implementations, the
runners that score them, the 49 result records (34 written by those runners; the index marks the 15
that have no deposited writer), the scripts that derive every aggregate the manuscript prints
(`recompute/`), and the extraction chain that builds the per-window feature tree the runners read
(`extraction/`).

The scope is four corpora: CIC-IDS-2017, CSE-CIC-IDS2018, CIC-DDoS2019 and LITNET-2020. The derived
tree names their directories `CIC-IDS-2017`, `CIC-IDS2018`, `CICDDoS2019` and `LITNET-2020`.

No corpus data is deposited. The runners read the derived tree `datasets/extracted/`, which is not
in the repository. `extraction/` holds the scripts that build it from the official corpus releases,
and `extraction/tree_manifest/` holds the authors' tree's `index.json` files and per-file checksums.
The chain is incomplete (see "What the chain cannot rebuild" in `extraction/README.md`). Three
per-day caches that the scenario builders read have no deposited writer: CIC-IDS-2017 Wednesday,
CSE-CIC-IDS2018 Tuesday and the attack-typed CIC-DDoS2019 cache. These scripts alone therefore
cannot rebuild 9 of the 16 panel scenarios, among them CIC-IDS-2017 `Wed-05-07_DoS-Slowhttptest`,
the row that carries 53.8% of the AUC difference reported below. A rebuilt scenario file does not
reproduce its checksum either; compare it with its `index.json` entry instead.

---

## What the records support

**The competitor side is sound.** The corrected registry (`competitors_fixed.py`) scores every arm
inductively: a row's score never reads the rows that follow it in the scored batch.
`runners/verify_inductive.py` is the gate and writes `results/batch_invariance_gate.json`.
On CIC-IDS-2018 `Tue-20-02_DDoS-LOIC-HTTP`, appending 0, 16 or 3,779 attack rows after a fixed
block of benign rows leaves the benign rows' scores unchanged for all ten corrected arms (maximum
append drift 0.0). The archived registry (`post2023_competitors.py`) fails that test on ECOD, COPOD
and DIF, three of its eight deterministic arms; its LODA is unseeded and is marked confounded.
Prepending rows is a separate axis: among the corrected arms it moves only the two sequential ones,
ours and DSPOT.

**Our own claim is not supported by these records.** Items 1 to 5 are from
`results/corrected_benchmark_results.json`, `results/panel_auc_matrix.json` and the
matched-smoothing pair, on PANEL-16; item 6 is from the clock and split-control records.
USABLE-strict holds the same 16 rows in these four records, with the same values except the
cluster bootstrap intervals, which differ by up to 0.0092 (ours, unmatched: [−0.005, 0.0499] on
PANEL-16, [−0.005, 0.05] on USABLE-strict).

1. **Resubstitution.** k = 8, α = 0.5 and the decision to drop the fusion term were chosen on the
   panel that then tested them, and the analysis cuts and the four-corpus scope were fixed after
   seeing results. No p-value here is confirmatory.
2. **Correction and clustering.** Mean AUC is 0.9913 for ours against 0.9667 for the reference
   POT, a difference of +0.0246, raw Wilcoxon p = 0.00919, Holm-adjusted over nine comparisons
   p = 0.0643, Bonferroni 0.08267. The 16 scenarios sit on five victim hosts. The victim-clustered
   Wilcoxon gives p = 0.625, and with five clusters the exact test cannot go below 2/2^5 = 0.0625,
   so 5% is unreachable at the victim level. The cluster bootstrap 95% interval for the mean
   difference, [−0.005, 0.0499], spans zero; the i.i.d. interval, [0.004, 0.0541], does not.
3. **Concentration.** 53.8% of the summed AUC difference comes from one scenario
   (CIC-IDS-2017 `Wed-05-07_DoS-Slowhttptest`) and 80.7% from one victim host (192.168.10.50).
   Deleting that scenario lowers the mean difference from 0.0246 to 0.0121.
4. **Benign alarm episodes**, the project's declared primary metric (episodes per 1,000 benign test
   windows, 30-window cooldown). Ours 5.96 / 8.81 / 12.45 against POT 5.44 / 8.47 / 11.33 at the
   1 / 2 / 5% targets: more at every target, fourth, fourth and eighth of the ten arms. Neither the
   paired nor the clustered episode test separates the two (smallest p = 0.4375).
5. **Matched smoothing.** Ours is the only EWMA-smoothed arm in the corrected benchmark. When every
   competitor gets the same EWMA stage (`matched_smoothing_*.json`) our scores cannot move, but
   every comparison does: the margin over POT + EWMA is +0.0227, raw p = 0.37546, Holm and
   Bonferroni 1.0, clustered p = 1.0, scenario wins 9 of 16 (12 of 16 unmatched), and both 95%
   intervals span zero. DIF + EWMA comes within 0.0004 (0.9909) and takes the detection-rate cell at
   the 5% target (97.60 against our 97.33). On benign episodes the matched field ranks ours fifth,
   fifth and eighth of ten. The only episode test below 5% in either comparison runs against ours:
   at the 1% target ours has 5.96 episodes against 4.94 for POT + EWMA, more in 9 of 16 scenarios
   and fewer in 2, paired Wilcoxon p = 0.04086, clustered p = 0.25
   (`matched_smoothing_matrix.json`, `diagnostics.PANEL-16.episodes.ep1`; the same on USABLE-strict).
6. **Split.** Under the deposited causal split every test stream opens on attack, and a label-only
   clock score (`clock_separability` of at least 0.95) separates 15 of the 16 rows
   (`joint_filter.json`, `repaired_split_counts`). The three-way splits return the last fifth of the
   pre-attack benign windows to the test stream. They leave 3 of 16 rows separable at that cut and 6
   at 0.94 (`clock_split_sensitivity.json`). Over all 16 rows the margin over POT is +0.0238 (threeway40) and
   +0.0253 (threeway60), Holm 0.04401 on both, clustered p 0.625 and 0.4375
   (`split_control_threeway{40,60}_benchmark.json`). On the 13 rows the three-way split leaves
   clock-clean, the threeway60 mean difference is +0.0141 and the clustered p 0.4375; with five
   victims the exact floor is 0.0625, so 5% is out of reach (`joint_filter.json`,
   `clock_clean_stratum`). Benign episodes go the other way under both three-way splits, fewer
   than POT at every target, but no clustered episode test there goes below 0.125.

The competitor numbers are citable. A superiority claim is not.

---

## Populations

Admissibility: `results/admissibility_inputs.json` lists 31 candidate scenarios across the four
corpora; `results/admissibility_ledger.json` gives each one verdict: USABLE 16, ATTACKER-SIDE 6,
FLOOR-LIMITED 4, NOT-DDOS 2, NO-FPR 2, INSEPARABLE 1. The 16 USABLE scenarios sit on five victim
hosts and are exactly the rows of `results/panel_inventory/PANEL.json`. The USABLE count depends on
the conformal-floor cut `alpha_conf`, 0.01 here: it is 15 at 0.0075 and 19 at 0.0125
(`alpha_conf_sensitivity` in the ledger).

| label | rows | where it appears |
|---|---:|---|
| PANEL-16 | 16 (5 victims) | `panel_inventory/PANEL.json`; the corrected-registry benchmark, matrix and split-control records, `ewma_ablation.json`, `dif_seed_sensitivity.json`, `c_engine_ours.json` |
| USABLE-strict | 16 | the PANEL-16 records except `PANEL.json` and `dif_seed_sensitivity.json`, plus the sixth-victim records; the same 16 scenarios as PANEL-16, keyed by scenario file name; the rows carry the tree's corpus spellings in the two matrices, `c_engine_ours.json` and `ewma_ablation.json`, and the canonical names in the split-control and sixth-victim records |
| USABLE-16, ALL-16 | 16 | held-out thresholds: `scenarios29_corrected_results.json` and `adjacency_free_*.json` (both labels; `adjacency_free_episodes.json` also has `USABLE-16-causal`), `order_sensitivity.json` and `table_cell_provenance.json` (USABLE-16 only); both labels hold the same 16 scenarios |
| `panel`, `full_tree_USABLE`, `full_tree_non-USABLE`, `full_tree_ALL` | 16, 16, 12, 28 | `final_evaluation.json` (archived registry) |
| `USABLE`, `ALL_29_SCENARIOS` and per-verdict strata | 16, 29 | `subspace_ecod_validation_report.json`, `task5_full_tree_stratified`; the 29 are the candidates other than the two NO-FPR ones |
| PANEL-17 | 17 (6 victims) | `recompute/results/*_sixvictim*` (post hoc sixth-victim check) |

### Corpus spellings

Corpus names reached the records by several routes, so the 2018 corpus appears as `CIC-IDS-2018`,
`CIC-IDS2018` and its canonical name `CSE-CIC-IDS2018`, and the 2019 corpus as `CIC-DDoS2019` and
`CICDDoS2019`. `panel_auc_matrix.json` and `matched_smoothing_matrix.json` hold two spellings at
once, PANEL-16 rows under `CIC-IDS-2018` / `CIC-DDoS2019` and USABLE-strict rows under the tree's
`CIC-IDS2018` / `CICDDoS2019`. Twelve records use `CSE-CIC-IDS2018`, among them the ledger,
`joint_filter.json`, `scenarios29_corrected_results.json` and the six split-control records. Victim
keys vary the same way: a bare address (`PANEL.json`, the ledger, the PANEL-16 rows of the two
matrices), the tree spelling plus address (their USABLE-strict rows), or the canonical name plus
address (`scenarios29_corrected_results.json`, the split-control matrices). `corpus_names.py` maps
every spelling to one canonical name (`canon()`, which raises on an unmapped one) and every victim
key to one form (`normalise_victim()`); filter and group records through it, never by a literal.

---

## The two competitor registries

| corrected arm (`competitors_fixed.py`) | archived arm (`post2023_competitors.py`) | implementation | citation (`competitors.bib`) |
|---|---|---|---|
| Subspace-Q + EWMA (ours) | Subspace-ECOD (ours) | from paper | Lakhina et al., SIGCOMM 2004; ECOD rank transform (Li et al., 2023) |
| POT | SPOT | from paper | Hosking & Wallis, *Technometrics* 1987 (method-of-moments GPD); cf. Siffer et al., KDD 2017 |
| DSPOT | DSPOT | from paper | Siffer et al., KDD 2017, Sec. 4.2.2, Algorithm 3 |
| ECOD | ECOD | inductive reimplementation (corrected); PyOD (archived) | Li et al., IEEE TKDE 35(12), 2023 |
| COPOD | COPOD | inductive reimplementation (corrected); PyOD (archived) | Li et al., IEEE ICDM 2020 |
| HBOS | HBOS | PyOD | Goldstein & Dengel, KI-2012 |
| LODA | LODA | PyOD; seeded (corrected), unseeded (archived) | Pevný, *Machine Learning* 102(2), 2016 |
| INNE | INNE | PyOD | Bandaragoda et al., *Comput. Intell.* 34(4), 2018 |
| IForest | — | PyOD | Liu, Ting & Zhou, IEEE ICDM 2008 |
| DIF | DIF | PyOD; scaler fitted once on the training pass (corrected) | Xu et al., IEEE TKDE 35(12), 2023 |

Scores are oriented so that higher means more anomalous. The archived arm "Subspace-ECOD (ours)" is
an earlier, unsmoothed variant that fuses the subspace residual with an EVT term; the evaluated arm
is Subspace-Q + EWMA (k = 8, α = 0.5).

The archived module's docstring still says every detector is fitted on train rows only. That is
false for ECOD, COPOD and DIF, which score transductively there, and its LODA is unseeded. The
defects lower those arms (PANEL-16 mean AUC, archived against corrected: ECOD 0.6692 against
0.9621, COPOD 0.6667 against 0.9540, DIF 0.5314 against 0.9829), so every comparison with them in
the archived records that score them (`post2023_benchmark_results.json`, `final_evaluation.json`,
`universal_ewma_tournament.json`, `usable_29_scenarios_benchmark.json`) is tilted in our favour.

**What the corrected registry changes** (its docstring gives the detail):

- **ECOD, COPOD.** PyOD's `decision_function` concatenates the training set onto the scored batch
  and recomputes the ECDF over the union, so a test stream that is half attack becomes its own
  reference. Reimplemented so the ECDF is built on the training rows and only evaluated at test
  points.
- **DIF.** PyOD refits a `StandardScaler` on whichever batch it scores. Subclassed so the scaler is
  fitted once per ensemble member on the training pass and reused.
- **LODA.** Seeded. The archived module passes no `random_state`, so its LODA cells are one draw
  each and can move between runs.
- **DSPOT.** Rebuilt to Siffer et al.'s Algorithm 3: the drift window is frozen on an alarm instead
  of absorbing flagged windows.
- **SPOT renamed POT.** What is implemented is a static per-feature peaks-over-threshold scorer with
  a method-of-moments GPD scale; Siffer et al.'s SPOT is online, univariate and fitted by maximum
  likelihood.
- **IForest added**, the shallow counterpart of DIF.

**Hand-rolled detectors that were removed.** The archived module's docstring records four that were
dropped because they were not the methods they were named after. KitNET was linear PCA
reconstruction error, rank-identical (Spearman 1.000000) to the Q-statistic inside our own detector
on every current panel row; the measurement predates the module's retirement and is not re-run. The
hand-rolled DIF scored closeness to the split, the inverse of isolation. PatchAD used untrained
random matrices. CCAD calibrated and tested on differently standardized data.

**Citations.** `competitors.bib` has 10 entries. Every DOI in it was resolved against Crossref; the
HBOS poster-track paper has none. ECOD and DIF are both IEEE TKDE 35(12), 2023. COPOD's DOI ends in
`.00135`; `.00139` resolves to an unrelated paper. Two archived files keep the old attributions:
`post2023_competitors.py::ms_scale` still cites Siffer et al. for the method-of-moments scale, and
the arm labels in `usable_29_scenarios_benchmark.json` date ECOD 2022 and DIF 2024. The
corrected registry and `competitors.bib` are authoritative.

---

## Results index

`results/` holds 49 JSON records (35 at the top level, 5 in `panel_inventory/`, 9 in `rescued/`)
and one tracked note, `rescued/ABLATION_README.md`. "regen" marks the 29 records that
`recompute/regeneration/regenerate.sh` rewrites; `recompute/regeneration/pass_comparison.tsv` gives
the reason each of the other 20 is not rewritten.

### Corrected registry (ten arms)

| record | writer | regen | content |
|---|---|:-:|---|
| `corrected_benchmark_results.json`, `panel_auc_matrix.json` | `run_corrected_benchmark_full.py` | ✓ | the comparison of record: AUC, detection rate and benign episodes at oracle thresholds, Holm/Bonferroni and victim-clustered tests; the matrix holds per-scenario values and the concentration and episode diagnostics |
| `matched_smoothing_benchmark.json`, `matched_smoothing_matrix.json` | `run_matched_smoothing.py` | ✓ | the same comparison with every competitor given the EWMA stage |
| `split_control_{deposited,threeway40,threeway60}_{benchmark,matrix}.json` (6) | `run_split_control.py` | ✓ | the comparison under the deposited causal split and the two three-way splits that return the last fifth of pre-attack benign windows to the test stream |
| `scenarios29_corrected_results.json` | `run_29_scenarios_corrected.py` | ✓ | thresholds from a held-out benign calibration slice; realized FPR, detection rate and episodes |
| `adjacency_free_fpr.json`, `adjacency_free_episodes.json` | `run_adjacency_free_fpr.py`, `run_adjacency_free_episodes.py` | ✓ | false alarms and episodes with attack rows excised from the scored stream, beside the stream-realized figures |
| `order_sensitivity.json` | `run_order_sensitivity.py` | ✓ | interleaved against appended class order; the memoryless arms are the control |
| `ewma_ablation.json` | `run_ewma_ablation.py` | ✓ | our arm with the EWMA stage on and off |
| `dif_seed_sensitivity.json` | `run_dif_seed_sensitivity.py` | ✓ | DIF at random_state 42 and 7 in both registries |
| `batch_invariance_gate.json` | `verify_inductive.py` | ✓ | append/prepend invariance of both registries on one scenario |

### Archived registry (nine arms)

| record | writer | regen | content |
|---|---|:-:|---|
| `post2023_benchmark_results.json` | `run_post2023_benchmark.py` | ✓ | all nine archived arms on PANEL-16, per-scenario and pooled aggregation |
| `final_evaluation.json` | `run_final_evaluation.py` | ✓ | seven arms on the panel and on the full tree (USABLE, non-USABLE, ALL) |
| `universal_ewma_tournament.json` | `run_universal_ewma_tournament.py` | ✓ | ten detectors raw and EWMA-smoothed (20 arms) |
| `usable_29_scenarios_benchmark.json` | `run_29_usable_benchmark.py` | ✓ | 15 arms on the 16 USABLE scenarios; see the warning below |
| `fpr_dr_optimization_results.json` | `research_fpr_dr_optimization.py` | ✓ | eight entries: the SPOT baseline and seven Subspace-ECOD variants (k, residual metric, EWMA, persistence) |
| `subspace_ecod_validation_report.json` | `run_subspace_ecod_validation.py` | ✓ | threshold transfer, benign-episode metrics, the k grid with nested leave-one-scenario-out selection, and a verdict-stratified comparison |

### Label-only and record-only analyses

| record | writer | regen | content |
|---|---|:-:|---|
| `clock_null.json` | `run_clock_null.py` | ✓ | the clock-only null (score = −window index) on the 31 candidates, 29 of them scorable; reads labels only |
| `clock_split_sensitivity.json` | `run_clock_split_sensitivity.py` | ✓ | the clock null under the deposited and three-way splits, both signs |
| `admissibility_inputs.json` | none | | per-candidate statistics read from the tree's `index.json` files; the ledger's input |
| `admissibility_ledger.json` | `run_admissibility_ledger.py` | ✓ | one verdict per candidate, by fixed precedence; reads records only |
| `joint_filter.json` | `run_joint_filter.py` | ✓ | the clock filter applied to the PANEL-16 comparison; reads records only |
| `table_cell_provenance.json` | `run_table_provenance.py` | ✓ | the record key behind every cell of two operating-point tables; reads records only |

### C engine

| record | writer | regen | content |
|---|---|:-:|---|
| `c_engine_verification_report.json` | `verify_c_engine_subspace_q.py` | | Python against C parity of the Subspace-Q scorer; not rewritten, because the runner needs the engine source `subspace_q.c`, which is not deposited; filtered by hand (below) |
| `c_engine_ours.json` | `run_c_engine_ours.py` | ✓ | the shipped Layer 2 rule set, compiled from `project/layer2/` through `c_engine_shim.c` |

### LITNET-2020 subnet aggregation

None of these is rewritten: the writers read LITNET-2020 caches that are not deposited, and the
subnet and ablation records were scored on an incomplete export (see
[LITNET-2020 records and their input](#litnet-2020-records-and-their-input)).

| record | writer | regen | content |
|---|---|:-:|---|
| `litnet_l1subnet_{16,24}_results.json` | `run_litnet_l1subnet.py` | | /16 and /24 protected-subnet aggregation |
| `rescued/litnet_l1subnet_{16,24}_results_CANONICAL.json` | none | | byte-identical copies of the two records above |
| `rescued/ABLATION_no_unique_dst_l1subnet_{16,24}_results.json` | `ablate_no_unique_dst_runner.py` | | the subnet arm without `unique_dst_ips`; see `rescued/ABLATION_README.md` |
| `rescued/litnet_results_{COMPLETE_EXPORT,TRUNCATED_EXPORT_per_destination}.json` | none | | per-destination evaluation on the complete export and on the truncated `parts/` export; only the complete-export record has a `udp_f` row |
| `rescued/litnet_zone_results_{COMPLETE_EXPORT,POSTHOC_SUM}.json` | none | | /24 and /16 zone-level aggregation, two runs |
| `rescued/dual_scale_union_results.json` | none | | per-host, subnet and union arms with episode metrics on CIC-IDS-2017 and LITNET-2020 |

### Inventories and earlier sweeps

| record | writer | regen | content |
|---|---|:-:|---|
| `panel_inventory/PANEL.json` | none | | the 16-row panel (and 15 excluded candidates), an input; 18 of the 26 runners read it |
| `panel_inventory/{cicids2017,cicids2018,cicddos,litnet}.json` | none | | earlier per-corpus, cache-level panel inventories; no deposited runner reads them |
| `full_tree_all_scenarios_metrics.json` | none | | an earlier full-tree sweep, 31 rows; predates the current extractor and feature schedule and cannot be re-scored |
| `all_extracted_datasets_evaluation_results.json` | none | | an earlier per-scenario sweep, 17 rows; superseded by `final_evaluation.json` |

### Notes on individual records

**`post2023_benchmark_results.json`.** The two aggregations disagree about INNE: at the 2% target
it trails our archived arm per scenario (79.04 against 82.72) and leads it pooled (79.53 against
76.10). Per-scenario aggregation is a per-host threshold; pooled is one threshold across all hosts.
Name the aggregation when quoting either.

**`final_evaluation.json`.** Archived registry: our arm against SPOT, INNE, HBOS, ECOD, COPOD and
LODA, each competitor except SPOT EWMA-smoothed.

| population | n | ours | SPOT | Δ | p | wins |
|---|---:|---:|---:|---:|---:|---:|
| panel | 16 | 0.9913 | 0.9667 | +0.0246 | 0.00919 | 12/16 |
| full tree, USABLE | 16 | 0.9913 | 0.9667 | +0.0246 | 0.00919 | 12/16 |
| full tree, non-USABLE | 12 | 0.8925 | 0.7732 | +0.1193 | 0.00049 | 12/12 |
| full tree, ALL | 28 | 0.9490 | 0.8838 | +0.0652 | < 0.00001 | 24/28 |

Only the USABLE rows carry a headline; the non-USABLE rows are scenarios the admissibility ledger
rejects, and the ALL row includes them. Benign episodes on the USABLE population,
ours against SPOT: 5.96 / 8.81 / 12.45 against 5.44 / 8.47 / 11.33 at 1 / 2 / 5%, worse at every
target. The panel and full-tree USABLE populations score the same 16 scenarios by two code paths
and agree on every stored value of every arm except LODA + EWMA (mean AUC 0.6123 against 0.6517):
two unseeded draws in one run.

**`universal_ewma_tournament.json`.** Each detector raw and smoothed, so the smoothing is not given
to our arm alone. Pure Subspace Q-Resid (k = 8) + EWMA, the archived-module form of the evaluated
arm, has the highest mean AUC (0.9913, DR@2% 93.89), ahead of Subspace-ECOD (k = 8) + EWMA (0.9896,
87.81); dropping the fusion term measured better than keeping it, on the same panel. In this
record EWMA raises the mean AUC of all ten detectors, SPOT included (0.9667 to 0.9686). The LODA
rows are unseeded: in the deposited draw LODA rises under EWMA (0.6337 to 0.6639), and another run
can order them differently.

**`fpr_dr_optimization_results.json`.** Cited for α = 0.5. It scores Subspace-ECOD variants through
the archived module, not the evaluated arm. The EWMA α = 0.5 variant has the highest mean AUC of the
eight entries (0.99) and, at the 1% target, the most benign episodes of the seven Subspace-ECOD
variants (8.75; only the SPOT baseline, 8.97, has more).

**`subspace_ecod_validation_report.json`.** Scored through the archived module on the unsmoothed
Subspace-ECOD variant. The threshold-transfer check (`task1_threshold_transfer`) is marked
`supported: false` at all three targets, and the realized false-alarm rate overshoots each one
(2.56, 5.51 and 9.59% at the 1, 2 and 5% targets). Nested leave-one-scenario-out selection returns
k = 8 on 15 of 16 folds and k = 6 on one (held-out mean AUC 0.9854).

**`c_engine_verification_report.json`.** 16 of 16 scenarios pass; mean AUC 0.991303 on both sides,
maximum relative error 2.64e-16. The record was restricted by hand to the 16 panel scenarios and
its summary recomputed from those rows, because the C source it compiles, `layer2/subspace_q.c`
(with `subspace_q.h`), is not part of this deposit; `verify_c_engine_subspace_q.py` looks for it
through `SUBSPACE_Q_C` or `ANTIDDOS_BASE`.

**`c_engine_ours.json`.** Scores the shipped engine's own Layer 2 rule set (three-tier z-score,
CUSUM and JSD paths), not the Subspace-Q arm, under a frozen and a closed-loop protocol. Its
false-alarm rates are high: on PANEL-16 the frozen OR rule's `or_fpr` is 0.9998 and the closed-loop
`or_fpr` 0.9902, as fractions of benign windows. The nine competitor arms have no C
implementation and are not scored here.

**`dif_seed_sensitivity.json`.** Corrected DIF mean AUC 0.982906 at seed 42 and 0.983338 at seed 7;
archived DIF 0.53141 and 0.526631. The corrected-minus-archived difference is +0.451496 at seed 42
and +0.456707 at seed 7.

### Records edited by hand

These records were edited after they were written, or have no deposited writer.

- `panel_inventory/PANEL.json`: restricted to the four corpora (16 panel rows, 15 excluded, 31
  candidates). The cross-day row was also removed, because its training cache is not deposited.
  The file records this in `four_corpus_note`.
- `full_tree_all_scenarios_metrics.json` (31 rows) and
  `all_extracted_datasets_evaluation_results.json` (17 rows, `_four_corpus_note`): rows restricted
  by hand to the four corpora. Both come from an earlier harness that is not deposited, run on an
  earlier version of the derived tree, and neither has a deposited writer.
  `full_tree_all_scenarios_metrics.json` also predates the current extractor and its feature
  schedule, so its values cannot be re-scored from this deposit.
- `c_engine_verification_report.json`: restricted to the 16 panel rows, summary recomputed (see
  above).
- Ten LITNET records, `litnet_l1subnet_{16,24}_results.json` and eight under `rescued/` (the two
  CANONICAL copies, the two ABLATION records, the two `litnet_results_*` and the two
  `litnet_zone_results_*`): two never-scored names were removed by hand from the inert-feature list
  `metadata.features_inert_auto_excluded`. No other field changed; each record carries an
  `_inert_list_note`.
- `admissibility_inputs.json`: no deposited writer. It holds the 31 four-corpus candidates, and
  every `payload_sha256` in it matches the scenario file's entry in `extraction/tree_manifest/`.

### LITNET-2020 records and their input

`run_litnet_l1subnet.py` and `ablate_no_unique_dst_runner.py` default `LITNET_DIR` to
`datasets/LITNET-2020/parts`, chunks of the 88.5%-truncated export, which loses two attack types
(see `extraction/README.md`). It is the export that
`rescued/litnet_results_TRUNCATED_EXPORT_per_destination.json` also read (its
`metadata.source_dir`), and `rescued/ABLATION_README.md` records that the subnet and ablation
records were produced from it. Both subnet records, `litnet_l1subnet_{16,24}_results.json`, and the
two ablation records were therefore scored on an incomplete export that lacks the `udp_f` attack
type, and none was re-run on the complete file. Do not compare them with complete-export figures.

Both runners first look for `cache/litnet_l1subnet_{16,24}_cache.json`. The three tracked entries
under `cache/` are symbolic links into a developer directory and dangle in any clone; a runner then
streams the export from `LITNET_DIR` and fails when it writes its cache through the dangling link.
Remove the links before running either one.

---

## ⚠ `usable_29_scenarios_benchmark.json`: read before citing

1. **The filename is historical.** The runner selects `verdict == 'USABLE'` on the four corpora and
   writes 16 scenarios, under the key `usable_16_scenarios`. They are the PANEL-16 scenarios, all on
   the causal within-day split; the record is not a second, larger population.
2. **It is an archived-registry record.** ECOD, COPOD and DIF are the transductive PyOD versions
   and LODA is unseeded. Its arm labels carry the old citation years (ECOD 2022, DIF 2024).
3. **It ranks by mean AUC and runs no test.** Ours is first (0.9913) and INNE + EWMA second
   (0.9888), a gap of 0.0026 with no significance test, no correction and no clustering behind it.

Cite `corrected_benchmark_results.json` for the comparison, not this file.

---

## Regenerating the records

### Environment

The records' `versions` blocks name pyod 3.6.5, torch 2.13.0+cpu, numpy 2.4.2, scikit-learn 1.8.0
and scipy 1.17.0 (torch is needed for DIF). `run_c_engine_ours.py` and
`verify_c_engine_subspace_q.py` also need `gcc`.

`ANTIDDOS_BASE` names the directory that holds `datasets/extracted/`. It defaults to the repository
root, so a rebuilt tree at `datasets/extracted/` needs no variable. `run_c_engine_ours.py` compiles
the engine from the repository's own `project/layer2/`. Three runners (`run_joint_filter.py`,
`run_admissibility_ledger.py` and `run_table_provenance.py`) and the three scripts in `recompute/`
read deposited records only. The two LITNET runners read the LITNET-2020 export instead of the
derived tree; every other runner needs the derived tree.

### `recompute/regeneration/regenerate.sh`

Rewrites the 29 records marked "regen" above with 22 runners (24 invocations; `run_split_control.py`
runs once per split), then rebuilds the derived numbers in `recompute/`:

    bash recompute/regeneration/regenerate.sh [python]

It runs from anywhere, sets `ANTIDDOS_OVERWRITE=1` so the runners replace the deposited records, and
pins `OMP_NUM_THREADS`, `OPENBLAS_NUM_THREADS` and `MKL_NUM_THREADS` to 1: DIF's fifth decimal
depends on the BLAS thread count. Wave 1 runs the 19 tree-reading runners in parallel, among them
`verify_inductive.py`; wave 2 runs the three record-only runners; logs go to
`recompute/regeneration/logs/`. It does not run `verify_c_engine_subspace_q.py` (the engine source
`subspace_q.c` is not deposited), `run_litnet_l1subnet.py` or `ablate_no_unique_dst_runner.py` (they
read LITNET-2020 caches that are not deposited), or `run_corrected_benchmark.py` (an earlier form of
`run_corrected_benchmark_full.py` that writes the benchmark record without the matrix).

`recompute/regeneration/pass_comparison.tsv` compares the deposited pass with an earlier full pass
at the default BLAS thread count, record by record (49 rows: numeric leaf count, values changed and
the cause):

- 2 records byte-identical (`clock_null.json`, `fpr_dr_optimization_results.json`) and 17 with
  identical values (population keys and notes renamed);
- `adjacency_free_fpr.json`: 8 summary means, where exact ties are now averaged with
  `statistics.mean` as in `scenarios29_corrected_results.json`;
- `dif_seed_sensitivity.json` and the two `split_control_threeway40_*` records: seeded DIF cells
  whose fifth decimal moved with the BLAS thread count;
- `post2023_benchmark_results.json`, `final_evaluation.json`, `universal_ewma_tournament.json`:
  archived-module LODA cells, which are unseeded;
- `batch_invariance_gate.json`, rewritten by `verify_inductive.py` in a follow-up run: 21 values
  moved (archived-module LODA, and DIF digits that depend on the thread count); every verdict is
  unchanged;
- `joint_filter.json`, `table_cell_provenance.json`: the earlier pass failed on a stale assertion
  (victim count, stratum size) and kept an older record;
- 20 records not rewritten by `regenerate.sh`: the five panel inventories and
  `admissibility_inputs.json` (inputs with no deposited writer), the two hand-filtered sweeps (no
  deposited writer), `c_engine_verification_report.json` (needs `subspace_q.c`), the two LITNET-2020 subnet
  records and the nine rescued records (their writers read caches that are not deposited, or no
  writer is deposited).

No other value changed between the two passes. The archived LODA cells are not guaranteed to
reproduce in any run.

### `recompute/regeneration/sixth_victim.sh`

The post hoc sixth-victim check: both three-way splits on PANEL-17, the 16 panel rows plus
LITNET-2020 `smurf` on 193.219.88.36. It copies the package into a temporary directory, swaps in
`recompute/results/PANEL_sixvictim.json` as the panel inventory (so the deposited inventory is never
touched), runs `run_split_control.py` single-threaded, and copies the four `*_sixvictim*` records to
`recompute/results/`. It links the derived tree from the repository's own `datasets/extracted/`
rather than from `ANTIDDOS_BASE`, and it needs `rsync`.

### Running a single runner

Eight runners route their output through `safe_out.py`: `run_29_scenarios_corrected.py`,
`run_adjacency_free_episodes.py`, `run_admissibility_ledger.py`, `run_clock_split_sensitivity.py`,
`run_joint_filter.py`, `run_order_sensitivity.py`, `run_split_control.py` and
`run_table_provenance.py`. If their record exists they write to `reproduction/` (not deposited)
instead, unless `ANTIDDOS_OVERWRITE=1`; `promote.py` diffs a re-run against the deposit and, with
`--apply` and an explicit record list, copies it into `results/` and rewrites
`SHA256SUMS.results`. The other 18 runners write into `results/` directly and overwrite the
deposited record; run them on a copy, or check `SHA256SUMS.results` afterwards.

`run_matched_smoothing.py` has a gate: `MS_MATCHED=0` runs the same code with the competitors
unsmoothed. Its output reproduces `corrected_benchmark_results.json` on every leaf except
`elapsed_sec`, and `panel_auc_matrix.json` on every leaf. Point `MS_OUT` and `MS_MATRIX` at absolute
paths outside `results/`, or the gate overwrites the two matched-smoothing records:

    MS_MATCHED=0 MS_OUT=/tmp/gate_benchmark.json MS_MATRIX=/tmp/gate_matrix.json \
      python3 runners/run_matched_smoothing.py

`extraction/classify_scenarios.py`, run on the default tree, writes
`results/scenario_classification.json`, which is not a deposited record.

---

## `recompute/`: the numbers the manuscript prints

`recompute/README.md` describes each script and output in detail.

| file | written by | content |
|---|---|---|
| `numbers.json` | `four_corpus_tables.py` | every aggregate in the manuscript's tables, recomputed from the per-scenario records |
| `validation.json` | `four_corpus_tables.py` | the recomputation checked against the aggregates the records store: 1,508 reproduced, 0 mismatches |
| `extra.json` | `extra_numbers.py` | second-tier quantities quoted in the prose |
| `tables_v4.json` | `tables_v4.py` | the rendered table bodies and figure coordinates |
| `results/` | `regeneration/sixth_victim.sh` | the four sixth-victim records, their input `PANEL_sixvictim.json` (no deposited writer) and a `SHA256SUMS` for the five files |
| `regeneration/` | | `regenerate.sh`, `sixth_victim.sh`, `pass_comparison.tsv` |

The three scripts read `results/` only:

    python3 recompute/four_corpus_tables.py results recompute
    python3 recompute/extra_numbers.py results recompute
    python3 recompute/tables_v4.py results recompute results

Holm and Bonferroni adjustments are computed from the unrounded p-values, as the runners compute
them.

---

## Verifying

From `ComparisonResults/results/`:

    sha256sum -c ../SHA256SUMS.results

checks all 49 records (`rescued/ABLATION_README.md` is tracked but not listed). From
`ComparisonResults/recompute/results/`:

    sha256sum -c SHA256SUMS

checks the five sixth-victim files. From `ComparisonResults/extraction/`:

    sha256sum -c SHA256SUMS

checks every tracked file under `extraction/` except the list itself; the per-corpus lists under
`extraction/tree_manifest/` check a rebuilt tree (see `extraction/README.md`).
`ComparisonResults/SHA256SUMS` is an older list of 20 code and record checksums; check it from
`ComparisonResults/` with `sha256sum -c SHA256SUMS`. It is not the record manifest.

---

## Layout

    ComparisonResults/
      README.md                  this index
      competitors_fixed.py       the corrected registry (ten arms)
      post2023_competitors.py    the archived registry (nine arms)
      competitors.bib            competitor citations, resolved against Crossref
      corpus_names.py            canonical corpus names, victim keys, the four-corpus scope filter
      run_crosscorpus_auc.py     active_features(): the non-constant feature set on the fit rows
      feature_filter.py          per-dataset inert-feature filter used by the LITNET runners
      config.py                  harness constants and paths (ANTIDDOS_BASE, results/, cache/)
      baselines.py, detectors.py, pipeline.py, attack_synthesizer.py, data_loader.py,
      litnet_loader.py           the three-tier z / CUSUM / JSD harness the LITNET runners use;
                                 both registries take their log transform from baselines.py
      innovation_path.py         the innovation (forecast-error) path; imported by
                                 project/tests/unit_python/test_innovation_gate.py, by no runner
      c_engine_shim.c            flat ctypes shim over the shipped Layer 2 engine (run_c_engine_ours.py)
      safe_out.py, promote.py    overwrite guard for re-runs, and promotion of re-runs into results/
      runners/                   26 scripts: 22 run_*.py, research_fpr_dr_optimization.py,
                                 ablate_no_unique_dst_runner.py, verify_inductive.py,
                                 verify_c_engine_subspace_q.py
      results/                   49 records (see the index), panel_inventory/, rescued/
      recompute/                 derived numbers, regeneration scripts, sixth-victim records (own README)
      extraction/                scripts that build most of datasets/extracted/ from the corpus
                                 releases (see its README), with tree_manifest/ (index.json,
                                 SHA256SUMS and README per corpus) and a SHA256SUMS of its own files
      cache/                     three symbolic links into a developer directory; dangling in a clone
      SHA256SUMS.results         record manifest (49 entries)
      SHA256SUMS                 older code-and-record checksum list (20 entries)
