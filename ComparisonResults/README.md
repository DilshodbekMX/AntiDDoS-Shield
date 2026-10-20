# ComparisonResults

The evaluation deposit for the Subspace-Q + EWMA detector: the competitor implementations, the
runners that score them, the 49 result records (34 written by those runners and one by
`extraction/write_admissibility_inputs.py`; the index marks the 14 that have no deposited writer),
the scripts that derive the manuscript's aggregates from the per-scenario records (`recompute/`),
and the extraction chain that builds the per-window feature tree the runners read (`extraction/`).

The scope is four corpora: CIC-IDS-2017, CSE-CIC-IDS2018, CIC-DDoS2019 and LITNET-2020. The derived
tree names their directories `CIC-IDS-2017`, `CIC-IDS2018`, `CICDDoS2019` and `LITNET-2020`.

No corpus data is deposited. The runners read the derived tree `datasets/extracted/`, which is not
in the repository. `extraction/` holds the scripts that build all of it from the official corpus
releases, and `extraction/tree_manifest/` holds the tree's `index.json` files and per-file
checksums. In this revision the evaluation uses all 39 feature names the shipped engine scores
(`project/layer2/baselines.c`, `l2_feature_names`), as `recompute/PREREGISTRATION_39_FEATURES.md`
set out before any record was computed on them: the extraction chain now computes `burst_factor`
and `unique_flows` the engine's way, the whole tree was rebuilt with it from the raw captures and
flow files, and `extraction/tree_manifest/` pins the rebuilt tree. On every column the earlier tree
carried, the rebuilt tree equals it by value. Every record whose deposited writer could be run was
then re-run on the rebuilt tree; `recompute/results/feature_set_comparison_37_vs_39.tsv` prints the
pre-registered headline statistics on both feature sets (see
[Records after the 39-name re-run](#records-after-the-39-name-re-run)). The earlier revision
regenerated the six CIC-IDS-2017 Wednesday files with the chain and ran the whole `regenerate.sh`
set again on them; [Records after the Wednesday regeneration](#records-after-the-wednesday-regeneration)
keeps that account.

---

## What the records support

**The corrected competitors pass the batch-invariance gate, which scores one scenario.** The
corrected registry (`competitors_fixed.py`) scores every arm inductively: a row's score never reads the rows that follow it in the scored batch.
`runners/verify_inductive.py` is the gate and writes `results/batch_invariance_gate.json`.
On CIC-IDS-2018 `Tue-20-02_DDoS-LOIC-HTTP`, appending 0, 16 or 3,779 attack rows after a fixed
block of benign rows leaves the benign rows' scores unchanged for all ten corrected arms (maximum
append drift 0.0). The archived registry (`post2023_competitors.py`) fails that test on ECOD, COPOD
and DIF, three of its eight deterministic arms; its LODA is unseeded and is marked confounded.
Prepending rows is a separate axis: among the corrected arms it moves only the two sequential ones,
ours and DSPOT.

**Our own claim is not supported by these records.** Items 1 to 5 are from
`results/corrected_benchmark_results.json`, `results/panel_auc_matrix.json` and the
matched-smoothing pair, on PANEL-16; item 6 is from the clock and split-control records. Every
figure is from the 39-name records of this revision; the value in parentheses, "(37: ...)", is
the same statistic on the 37 names of commit `895e581`, printed wherever the pre-registration
asks for both (`recompute/results/feature_set_comparison_37_vs_39.tsv` holds all of them).
USABLE-strict holds the same 16 rows in these four records, with the same values except the
cluster bootstrap intervals, which differ by up to 0.0118 (37: 0.0092) (ours, unmatched:
[−0.0496, 0.0463] on PANEL-16, [−0.0513, 0.0463] on USABLE-strict).

1. **Resubstitution.** k = 8, α = 0.5 and the decision to drop the fusion term were chosen on the
   panel that then tested them, and the analysis cuts and the four-corpus scope were fixed after
   seeing results. The 39-name feature set was chosen after results on two earlier feature sets
   had been seen. No p-value here is confirmatory.
2. **Correction and clustering.** Mean AUC is 0.9806 for ours against 0.9663 for the reference
   POT, a difference of +0.0143, raw Wilcoxon p = 0.0155, Holm-adjusted over nine comparisons
   p = 0.09302, Bonferroni 0.13953 (37: 0.9913 against 0.9667, +0.0246, p = 0.00919, Holm 0.0643,
   Bonferroni 0.08267). Ours ranks second of the ten arms by mean AUC, behind DIF at 0.9831
   (37: first, DIF second at 0.9829). The 16 scenarios sit on five victim hosts. The
   victim-clustered Wilcoxon gives p = 0.8125 (37: 0.625), and with five clusters the exact test
   cannot go below 2/2^5 = 0.0625, so 5% is unreachable at the victim level; the victim-clustered
   mean difference is −0.021193 (37: +0.012318). Both 95% intervals for the mean difference span
   zero: the cluster bootstrap [−0.0496, 0.0463] and the i.i.d. [−0.0233, 0.0511] (37: the cluster
   interval [−0.005, 0.0499] spanned zero and the i.i.d. interval [0.004, 0.0541] did not).
   Ours wins 13 of 16 rows (37: 12); the extra win is CSE-CIC-IDS2018 `Thu-15-02_DoS-Slowloris`,
   which moves from −0.00002 to +0.000067. Most of the change between the two feature sets comes
   from one row, LITNET-2020 `code_red_worm`, where our AUC falls from 0.9598 to 0.7917; every other
   row moves by at most 0.0016 (`panel_auc_matrix.json`).
3. **Concentration.** 93.1% of the summed AUC difference comes from one scenario
   (CIC-IDS-2017 `Wed-05-07_DoS-Slowhttptest`) and 139.7% from one victim host (192.168.10.50),
   more than all of it because the rows of the other victims sum to a loss, which `code_red_worm`
   alone more than accounts for (37: 53.8% and 80.7%). Deleting that scenario lowers the mean
   difference from 0.0143 to 0.0011 (37: from 0.0246 to 0.0121).
4. **Benign alarm episodes**, the project's declared primary metric (episodes per 1,000 benign test
   windows, 30-window cooldown). Ours 6.08 / 8.09 / 12.21 against POT 5.49 / 8.56 / 11.35 at the
   1 / 2 / 5% targets: more at 1 and 5%, fewer at 2%; fourth, second and tenth of the ten arms
   (37: 5.96 / 8.81 / 12.45 against 5.44 / 8.47 / 11.33, more at every target, fourth, fourth and
   eighth). Neither the paired nor the clustered episode test separates the two (smallest
   p = 0.125; 37: 0.4375).
5. **Matched smoothing.** Ours is the only EWMA-smoothed arm in the corrected benchmark. When every
   competitor gets the same EWMA stage (`matched_smoothing_*.json`) our scores cannot move, but
   every comparison does: the margin over POT + EWMA is +0.0122, raw p = 0.34839, Holm and
   Bonferroni 1.0, clustered p = 1.0, scenario wins 9 of 16 (13 of 16 unmatched), and both 95%
   intervals span zero (37: +0.0227, p = 0.37546, 1.0, 1.0, 9 of 16, 12 of 16 unmatched, both
   spanning zero). Three matched arms now have a higher mean AUC than ours: DIF + EWMA 0.9907,
   INNE + EWMA 0.9888 and IForest + EWMA 0.9834, so ours ranks fourth of ten (37: first, DIF + EWMA
   within 0.0004 at 0.9909). Ours keeps the matched detection-rate cell only at the 1% target;
   INNE + EWMA takes it at 2% (91.88 against our 91.49) and DIF + EWMA at 5% (97.57 against our
   95.57) (37: ours at 1 and 2%, DIF + EWMA at 5%, 97.60 against our 97.33). On benign episodes the
   matched field ranks ours fifth, fourth and eighth of ten (37: fifth, fifth and eighth). At the
   1% target ours has 6.08 episodes against 4.94 for POT + EWMA, more in 10 of 16 scenarios and
   fewer in 2, paired Wilcoxon p = 0.07119, clustered p = 0.625
   (`matched_smoothing_matrix.json`, `diagnostics.PANEL-16.episodes.ep1`; the same on
   USABLE-strict), so no episode test in either comparison goes below 5%. On the 37 names this was
   the one that did, and it ran against ours: 5.96 against 4.94, more in 9 and fewer in 2,
   p = 0.04086, clustered p = 0.25.
6. **Split.** Under the deposited causal split every test stream opens on attack, and a label-only
   clock score (`clock_separability` of at least 0.95) separates 15 of the 16 rows
   (`joint_filter.json`, `repaired_split_counts`). The three-way splits return the last fifth of the
   pre-attack benign windows to the test stream. They leave 3 of 16 rows separable at that cut and 6
   at 0.94 (`clock_split_sensitivity.json`). These counts read labels only and are the same on both
   feature sets. Over all 16 rows the margin over POT is +0.0184 (threeway40) and +0.0199
   (threeway60), Holm 0.09302 and 0.07855, clustered p 0.8125 on both
   (`split_control_threeway{40,60}_benchmark.json`) (37: +0.0238 and +0.0253, Holm 0.04401 on
   both, below 5%, clustered p 0.625 and 0.4375). On the 13 rows the three-way split leaves
   clock-clean, the threeway60 mean difference is +0.0075 and the clustered p 0.8125 (37: +0.0141,
   0.4375); with five victims the exact floor is 0.0625, so 5% is out of reach (`joint_filter.json`,
   `clock_clean_stratum`). Benign episodes go the other way under both three-way splits, fewer
   than POT at every target, but no clustered episode test there goes below 0.25 (37: 0.125); the
   scenario-level episode test goes below 5% at threeway40 2% (p = 0.0356), where on the 37 names
   it did at threeway40 1% (0.00713) and threeway60 2% (0.04431).

The competitor numbers measure these implementations on these 16 scenarios (the DSPOT rebuild's
figures are not a verdict on DSPOT). A superiority claim is not supported.

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
| USABLE-16, ALL-16 under the repaired split | 16 | `recompute/results/*_threeway40.json` (post hoc held-out re-score; each carries a `split` block) |

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
| IForest | none | PyOD | Liu, Ting & Zhou, IEEE ICDM 2008 |
| DIF | DIF | PyOD; scaler fitted once on the training pass (corrected) | Xu et al., IEEE TKDE 35(12), 2023 |

Scores are oriented so that higher means more anomalous. The archived arm "Subspace-ECOD (ours)" is
an earlier, unsmoothed variant that fuses the subspace residual with an EVT term; the evaluated arm
is Subspace-Q + EWMA (k = 8, α = 0.5).

The archived module's docstring still says every detector is fitted on train rows only. That is
false for ECOD, COPOD and DIF, which score transductively there, and its LODA is unseeded. The
defects lower those arms (PANEL-16 mean AUC, archived against corrected: ECOD 0.6660 against
0.9640, COPOD 0.6607 against 0.9530, DIF 0.5321 against 0.9831; 37: 0.6692 against 0.9621, 0.6667
against 0.9540, 0.5314 against 0.9829), so every comparison with them in the archived records
that score them (`post2023_benchmark_results.json`, `final_evaluation.json`,
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
- **DSPOT.** Rebuilt as a modified form of Siffer et al.'s Algorithm 3: the drift window appends only
  at or below the static threshold, so it freezes during a sustained flood (Siffer et al.'s Algorithm 3
  also appends on its peak branch).
- **SPOT renamed POT.** What is implemented is a static per-feature peaks-over-threshold scorer with
  a method-of-moments GPD scale; Siffer et al.'s SPOT is online, univariate and fitted by maximum
  likelihood.
- **IForest added**, the shallow counterpart of DIF.

**Hand-rolled detectors that were removed.** The archived module's docstring records four that were
dropped because they were not the methods they were named after. The manuscript counts five
removed entries; the fifth, QG-DualPOT, has no surviving code or artifact. KitNET was linear PCA
reconstruction error, rank-identical (Spearman 1.000000) to the Q-statistic inside our own detector
on every panel row it was measured on; the measurement predates the module's retirement and the
39-name tree, and is not re-run. The
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
the reason each of the other 20 is not rewritten. "39 names" says what the 39-name re-run did with
each record: **re-run** on the rebuilt tree; **unchanged**, an input whose fields the two new columns
cannot move; or **kept**, a record with no deposited writer that keeps the values of the feature
set it was scored on, named in the column (see
[Records after the 39-name re-run](#records-after-the-39-name-re-run)).

### Corrected registry (ten arms)

| record | writer | regen | 39 names | content |
|---|---|:-:|---|---|
| `corrected_benchmark_results.json`, `panel_auc_matrix.json` | `run_corrected_benchmark_full.py` | ✓ | re-run | the comparison of record: AUC, detection rate and benign episodes at oracle thresholds, Holm/Bonferroni and victim-clustered tests; the matrix holds per-scenario values and the concentration and episode diagnostics |
| `matched_smoothing_benchmark.json`, `matched_smoothing_matrix.json` | `run_matched_smoothing.py` | ✓ | re-run | the same comparison with every competitor given the EWMA stage |
| `split_control_{deposited,threeway40,threeway60}_{benchmark,matrix}.json` (6) | `run_split_control.py` | ✓ | re-run | the comparison under the deposited causal split and the two three-way splits that return the last fifth of pre-attack benign windows to the test stream |
| `scenarios29_corrected_results.json` | `run_29_scenarios_corrected.py` | ✓ | re-run | thresholds from a held-out benign calibration slice; realized FPR, detection rate and episodes |
| `adjacency_free_fpr.json`, `adjacency_free_episodes.json` | `run_adjacency_free_fpr.py`, `run_adjacency_free_episodes.py` | ✓ | re-run | false alarms and episodes with attack rows excised from the scored stream, beside the stream-realized figures |
| `order_sensitivity.json` | `run_order_sensitivity.py` | ✓ | re-run | interleaved against appended class order; the memoryless arms are the control |
| `ewma_ablation.json` | `run_ewma_ablation.py` | ✓ | re-run | our arm with the EWMA stage on and off |
| `dif_seed_sensitivity.json` | `run_dif_seed_sensitivity.py` | ✓ | re-run | DIF at random_state 42 and 7 in both registries |
| `batch_invariance_gate.json` | `verify_inductive.py` | ✓ | re-run | append/prepend invariance of both registries on one scenario |

### Archived registry (nine arms)

| record | writer | regen | 39 names | content |
|---|---|:-:|---|---|
| `post2023_benchmark_results.json` | `run_post2023_benchmark.py` | ✓ | re-run | all nine archived arms on PANEL-16, per-scenario and pooled aggregation |
| `final_evaluation.json` | `run_final_evaluation.py` | ✓ | re-run | seven arms on the panel and on the full tree (USABLE, non-USABLE, ALL) |
| `universal_ewma_tournament.json` | `run_universal_ewma_tournament.py` | ✓ | re-run | ten detectors raw and EWMA-smoothed (20 arms) |
| `usable_29_scenarios_benchmark.json` | `run_29_usable_benchmark.py` | ✓ | re-run | 15 arms on the 16 USABLE scenarios; see the warning below |
| `fpr_dr_optimization_results.json` | `research_fpr_dr_optimization.py` | ✓ | re-run | eight entries: the SPOT baseline and seven Subspace-ECOD variants (k, residual metric, EWMA, persistence) |
| `subspace_ecod_validation_report.json` | `run_subspace_ecod_validation.py` | ✓ | re-run | threshold transfer, benign-episode metrics, the k grid with nested leave-one-scenario-out selection, and a verdict-stratified comparison |

### Label-only and record-only analyses

| record | writer | regen | 39 names | content |
|---|---|:-:|---|---|
| `clock_null.json` | `run_clock_null.py` | ✓ | re-run (byte-identical) | the clock-only null (score = −window index) on the 31 candidates, 29 of them scorable; reads labels only |
| `clock_split_sensitivity.json` | `run_clock_split_sensitivity.py` | ✓ | re-run (byte-identical) | the clock null under the deposited and three-way splits, both signs |
| `admissibility_inputs.json` | `extraction/write_admissibility_inputs.py` | | re-run (new writer) | per-candidate statistics read from the tree's `index.json` files; the ledger's input |
| `admissibility_ledger.json` | `run_admissibility_ledger.py` | ✓ | re-run (byte-identical) | one verdict per candidate, by fixed precedence; reads records only |
| `joint_filter.json` | `run_joint_filter.py` | ✓ | re-run | the clock filter applied to the PANEL-16 comparison; reads records only |
| `table_cell_provenance.json` | `run_table_provenance.py` | ✓ | re-run | the record key behind every cell of two operating-point tables; reads records only |

### C engine

| record | writer | regen | 39 names | content |
|---|---|:-:|---|---|
| `c_engine_verification_report.json` | `verify_c_engine_subspace_q.py` | | re-run (with the C source, which is not deposited) | Python against C parity of the Subspace-Q scorer; not rewritten by `regenerate.sh`, because the runner needs the engine source `subspace_q.c`, which is not deposited (below) |
| `c_engine_ours.json` | `run_c_engine_ours.py` | ✓ | re-run | the shipped Layer 2 rule set, compiled from `project/layer2/` through `c_engine_shim.c` |

### LITNET-2020 subnet aggregation

None of these is rewritten by `regenerate.sh`: the two deposited writers read the LITNET-2020
export or caches built from it, which are not deposited, the other records have no deposited
writer, and the subnet and ablation records were scored on an incomplete export (see
[LITNET-2020 records and their input](#litnet-2020-records-and-their-input)). The subnet and
ablation records were re-run for the 39 names on that same export.

| record | writer | regen | 39 names | content |
|---|---|:-:|---|---|
| `litnet_l1subnet_{16,24}_results.json` | `run_litnet_l1subnet.py` | | re-run (truncated export) | /16 and /24 protected-subnet aggregation |
| `rescued/litnet_l1subnet_{16,24}_results_CANONICAL.json` | none | | byte copies of the re-run records | byte-identical copies of the two records above |
| `rescued/ABLATION_no_unique_dst_l1subnet_{16,24}_results.json` | `ablate_no_unique_dst_runner.py` | | re-run (truncated export) | the subnet arm without `unique_dst_ips`; see `rescued/ABLATION_README.md` |
| `rescued/litnet_results_{COMPLETE_EXPORT,TRUNCATED_EXPORT_per_destination}.json` | none | | kept: 10 LITNET-2020 NetFlow names | per-destination evaluation on the complete export and on the truncated `parts/` export; only the complete-export record has a `udp_f` row |
| `rescued/litnet_zone_results_{COMPLETE_EXPORT,POSTHOC_SUM}.json` | none | | kept: 10 LITNET-2020 NetFlow names | /24 and /16 zone-level aggregation, two runs |
| `rescued/dual_scale_union_results.json` | none | | kept: feature set not stored | per-host, subnet and union arms with episode metrics on CIC-IDS-2017 and LITNET-2020 |

### Inventories and earlier sweeps

| record | writer | regen | 39 names | content |
|---|---|:-:|---|---|
| `panel_inventory/PANEL.json` | none | | unchanged (input) | the 16-row panel (and 15 excluded candidates), an input; 18 of the 26 runners read it |
| `panel_inventory/{cicids2017,cicids2018,cicddos,litnet}.json` | none | | unchanged (input) | earlier per-corpus, cache-level panel inventories; no deposited runner reads them |
| `full_tree_all_scenarios_metrics.json` | none | | kept: feature set not stored | an earlier full-tree sweep, 31 rows; predates the current extractor and feature schedule and cannot be re-scored |
| `all_extracted_datasets_evaluation_results.json` | none | | kept: feature set not stored | an earlier per-scenario sweep, 17 rows; superseded by `final_evaluation.json` |

### Notes on individual records

Figures are from the 39-name records; "(37: ...)" gives the value at commit `895e581`.

**`post2023_benchmark_results.json`.** The two aggregations disagree about INNE: at the 2% target
it trails our archived arm per scenario (79.79 against 82.73) and leads it pooled (80.23 against
76.10) (37: 79.04 against 82.72, and 79.53 against 76.10). Per-scenario aggregation is a per-host
threshold; pooled is one threshold across all hosts. Name the aggregation when quoting either.

**`final_evaluation.json`.** Archived registry: our arm against SPOT, INNE, HBOS, ECOD, COPOD and
LODA, each competitor except SPOT EWMA-smoothed.

| population | n | ours | SPOT | Δ | p | wins | 37 names: ours, SPOT, Δ, p, wins |
|---|---:|---:|---:|---:|---:|---:|---|
| panel | 16 | 0.9806 | 0.9663 | +0.0143 | 0.0155 | 13/16 | 0.9913, 0.9667, +0.0246, 0.00919, 12/16 |
| full tree, USABLE | 16 | 0.9806 | 0.9663 | +0.0143 | 0.0155 | 13/16 | 0.9913, 0.9667, +0.0246, 0.00919, 12/16 |
| full tree, non-USABLE | 12 | 0.8860 | 0.7704 | +0.1156 | 0.00488 | 10/12 | 0.8925, 0.7732, +0.1193, 0.00049, 12/12 |
| full tree, ALL | 28 | 0.9400 | 0.8823 | +0.0577 | 0.00053 | 23/28 | 0.9490, 0.8838, +0.0652, < 0.00001, 24/28 |

Only the USABLE rows carry a headline; the non-USABLE rows are scenarios the admissibility ledger
rejects, and the ALL row includes them. Benign episodes on the USABLE population,
ours against SPOT: 6.08 / 8.09 / 12.21 against 5.49 / 8.56 / 11.35 at 1 / 2 / 5%, worse at 1 and
5% and better at 2% (37: 5.96 / 8.81 / 12.45 against 5.44 / 8.47 / 11.33, worse at every target).
The panel and full-tree USABLE populations score the same 16 scenarios by two code paths and agree
on every stored value of every arm except LODA + EWMA (mean AUC 0.6773 against 0.6829; 37: 0.6123
against 0.6517): two unseeded draws in one run.

**`universal_ewma_tournament.json`.** Each detector raw and smoothed, so the smoothing is not given
to our arm alone. Pure Subspace Q-Resid (k = 8) + EWMA, the archived-module form of the evaluated
arm, ranks eighth of the 20 arms (0.9806, DR@2% 91.49); Subspace-ECOD (k = 8) + EWMA has the highest
mean AUC (0.9895, 87.61), so on the 39 names keeping the fusion term measures better than dropping
it, on the same panel. On the 37 names the Q-Resid arm ranked first (0.9913, 93.89), ahead of
Subspace-ECOD (k = 8) + EWMA (0.9896, 87.81), and dropping the fusion term measured better; that is
the measurement the choice was made on. Its comparison with INNE + EWMA is −0.0082 (p = 0.0076)
against +0.0026 (p = 0.011) on the 37 names. EWMA raises the mean AUC of nine of the ten detectors,
SPOT included (0.9663 to 0.9684); the exception is LODA, whose rows are unseeded: in this draw
LODA falls under EWMA (0.6610 to 0.6272), where in the 37-name draw it rose (0.6337 to 0.6639),
and another run can order them differently.

**`fpr_dr_optimization_results.json`.** Cited for α = 0.5. It scores Subspace-ECOD variants through
the archived module, not the evaluated arm. The EWMA α = 0.5 variant has the highest mean AUC of the
eight entries (0.9899; 37: 0.99) and, at the 1% target, the most benign episodes of the seven
Subspace-ECOD variants (8.74; only the SPOT baseline, 9.06, has more; 37: 8.75 and 8.97).

**`subspace_ecod_validation_report.json`.** Scored through the archived module on the unsmoothed
Subspace-ECOD variant. The threshold-transfer check (`task1_threshold_transfer`) is marked
`supported: false` at all three targets, and the realized false-alarm rate overshoots each one
(2.56, 5.49 and 9.34% at the 1, 2 and 5% targets; 37: 2.56, 5.51 and 9.59). Nested
leave-one-scenario-out selection returns k = 8 on 15 of 16 folds and k = 6 on one (held-out mean
AUC 0.9851; 37: the same folds, 0.9854).

**`c_engine_verification_report.json`.** Python against C parity of the Subspace-Q scorer on the
16 panel scenarios. Its runner, `verify_c_engine_subspace_q.py`, compiles the C source
`layer2/subspace_q.c` (with `subspace_q.h`), which is not part of this deposit; it looks for it
through `SUBSPACE_Q_C` or `ANTIDDOS_BASE`. The authors recovered that source from an earlier commit
of this repository that is not in its published history, and the record here is the runner's
output on the 39-name tree: 16 of 16 scenarios pass, the largest relative error over the 54,462
test windows is 3.13e-16 and the largest absolute error 4.44e-16, and the mean AUC is 0.980587 on
both sides (37: 16 of 16, 2.64e-16, 2.22e-16, 0.991303). The runner reads
`panel_inventory/PANEL.json` and writes the 16 rows and the summary itself, so this record is not
restricted by hand; the 37-name record it replaces was (its `summary.note` said so). The C source
is still not deposited, so a reader cannot repeat the run. The summary's
`c_engine_reproduces_harness` is a constant the runner writes; the per-scenario `pass` fields are
computed. The record also stores D, the number of features scored on each row (`d_features`).

**`c_engine_ours.json`.** Scores the shipped engine's own Layer 2 rule set (three-tier z-score,
CUSUM and JSD paths), not the Subspace-Q arm, under a frozen and a closed-loop protocol. Its
false-alarm rates are high: on PANEL-16 the frozen OR rule's `or_fpr` is 1.0 and the closed-loop
`or_fpr` 0.9983, as fractions of benign windows (37: 0.9998 and 0.9902); the closed-loop `or_dr`
is 0.9388 and the frozen `auc_max_z` 0.9281 (37: 0.9202 and 0.9288). The nine competitor arms have
no C implementation and are not scored here. `run_c_engine_ours.py` passes 0.0 for any of the
engine's 39 features a row lacks. Packet-capture rows now carry all 39 (their 40 columns are the
39 engine names and `dir_ratio`, which the engine does not read), so nothing is filled with 0.0 on
the 15 packet-capture scenarios. The LITNET-2020 `code_red_worm` rows carry 13 of the 39 and lack
the other 26, `new_srcip_rate` among them. `new_srcip_rate` is one of the engine's five CUSUM inputs
(`packets_per_sec`, `bytes_per_sec`, `flows_per_sec`, `new_srcip_rate` and `burst_factor`;
`project/layer2/advanced_detection.c`), so in this record one CUSUM input is constant on
`code_red_worm` and none on the packet-capture scenarios. On the 37 names the packet-capture rows
lacked `burst_factor` and `unique_flows` and the `code_red_worm` rows 28 of the 39, so one CUSUM
input was constant on the 15 packet-capture scenarios and two on `code_red_worm`. The record was
replaced after the Wednesday files were regenerated and again after the 39-name re-run (below).

**`dif_seed_sensitivity.json`.** Corrected DIF mean AUC 0.983106 at seed 42 and 0.984531 at seed 7;
archived DIF 0.532142 and 0.534763. The corrected-minus-archived difference is +0.450965 at seed 42
and +0.449768 at seed 7 (37: 0.982906 and 0.983338; 0.53141 and 0.526631; +0.451496 and
+0.456707).

### Records edited by hand

Seven records were edited after they were written. All seven have no deposited writer and keep
their values on the 39 names; the index says how the 39-name re-run treated each.

- `panel_inventory/PANEL.json`: restricted to the four corpora (16 panel rows, 15 excluded, 31
  candidates). The cross-day row was also removed, because its training cache is not deposited.
  The file records this in `four_corpus_note`.
- `full_tree_all_scenarios_metrics.json` (31 rows) and
  `all_extracted_datasets_evaluation_results.json` (17 rows, `_four_corpus_note`): rows restricted
  by hand to the four corpora. Both come from an earlier harness that is not deposited, run on an
  earlier version of the derived tree, and neither has a deposited writer. Neither stores the
  feature set it scored. `full_tree_all_scenarios_metrics.json` also predates the current extractor
  and its feature schedule, so its values cannot be re-scored from this deposit. Both records hold
  CIC-IDS-2017 Wednesday rows scored before those files were regenerated, and both are kept as
  written (see [Records after the Wednesday regeneration](#records-after-the-wednesday-regeneration)).
- Four LITNET records under `rescued/`, the two `litnet_results_*` and the two
  `litnet_zone_results_*`: two never-scored names were removed by hand from the inert-feature list
  `metadata.features_inert_auto_excluded`. No other field changed; each record carries an
  `_inert_list_note`.

Eight records that were edited by hand before this revision are now written by a script, or
copied from a record that is, and no longer carry the edit:

- `c_engine_verification_report.json` is now the runner's output (above).
- `litnet_l1subnet_{16,24}_results.json` and the two ABLATION records were re-run, and their two
  CANONICAL copies replaced by byte copies of the re-run records. The runners write no
  `_inert_list_note`; their inert-feature lists are the runners' own.
- `admissibility_inputs.json` is now written by `extraction/write_admissibility_inputs.py`, which
  projects it from the tree's `index.json` files. Before this revision it had no writer. Its content
  equals a projection of those files: run on the 37-name tree, the writer reproduces the earlier
  file byte for byte. Its `payload_sha256` values had been updated by
  `extraction/drop_duplicate_columns.py` when the two placeholder columns were dropped from the
  tree, and the five CIC-IDS-2017 `Wed-05-07` values again, by a scripted hand edit, when those
  files were regenerated. Run on the 39-name tree, the writer changes only the 31 `payload_sha256`
  values, each of which now matches the scenario file's entry in `extraction/tree_manifest/`.

Fourteen of the 49 records have no deposited writer: the five `panel_inventory/` files, the two
earlier sweeps, and the seven `rescued/` records other than the two ABLATION records (the two
CANONICAL files among them are byte copies of records that have one). In `recompute/results/`,
`PANEL_sixvictim.json` has none either.

### LITNET-2020 records and their input

`run_litnet_l1subnet.py` and `ablate_no_unique_dst_runner.py` default `LITNET_DIR` to
`datasets/LITNET-2020/parts`, chunks of an export 11.5% short of the complete file, which loses
two attack types, `udp_f` and `smtp_b` (see `extraction/README.md`). It is the export that
`rescued/litnet_results_TRUNCATED_EXPORT_per_destination.json` also read (its
`metadata.source_dir`), and `rescued/ABLATION_README.md` records that the subnet and ablation
records were produced from it. Both subnet records, `litnet_l1subnet_{16,24}_results.json`, and the
two ablation records were therefore scored on an incomplete export that lacks the `udp_f` attack
type. Their 39-name re-run read the same truncated export, to stay comparable with the records it
replaced, and none was run on the complete file. Do not compare them with complete-export figures.

Both runners first look for `cache/litnet_l1subnet_{16,24}_cache.json` and otherwise stream the
export from `LITNET_DIR` and write that cache. The deposit no longer tracks the three symbolic links
that stood under `cache/`; on the authors' machine they pointed at caches built from the incomplete
export, the export the records above were scored on. Those caches lack the two new columns, so the
39-name records were scored from caches the patched loader streamed afresh from that export.

---

## Records after the Wednesday regeneration

This section describes the revision before this one (commit `9d51bdc`), whose records were scored
on 37 feature names. The records it names were re-run again for the 39 names, all but the two
sweeps without a deposited writer
([Records after the 39-name re-run](#records-after-the-39-name-re-run)).

Until that revision the six CIC-IDS-2017 Wednesday files of the derived tree (the five `Wed-05-07`
slices and `benign_pool_wednesday.json`) stored `dst_port_density` 1000 times smaller than every
other packet-capture file, because the cache they came from predates that feature's factor of 1000.
The authors regenerated them with `extraction/` (see its README). The whole set of runners that
`recompute/regeneration/regenerate.sh`, `sixth_victim.sh` and `heldout_threeway40.sh` run was then
run again, single-threaded, followed by the three `recompute/` scripts: once on the regenerated tree
and, as a control, once on an unmodified copy of the earlier tree. The control reproduced every
deposited record except the archived-registry LODA cells, which are unseeded, and the stored run
times (`elapsed_sec`).

Against the control, the regenerated files changed the values of three records, which replace the
deposited ones. One derived file and one input were updated with them:

| file | what changed |
|---|---|
| `results/c_engine_ours.json` (replaced) | 18 values of the shipped engine's rule set. On PANEL-16 and USABLE-strict, closed-loop `or_dr` 0.9194 to 0.9202 and frozen `auc_max_z` 0.9317 to 0.9288. Per scenario, frozen `auc_max_z` on the four Wednesday rows (Slowhttptest 0.6098 to 0.5595), closed-loop `or_dr` on Hulk (0.1793 to 0.1901) and Slowloris (0.8903 to 0.8911), and closed-loop `or_fpr` on Hulk (0.8531 to 0.8535). Frozen `or_dr` and `or_fpr` and closed-loop `or_fpr` are unchanged at their stored precision |
| `results/split_control_threeway40_matrix.json` (replaced) | INNE's AUC on `Wed-05-07_DoS-Hulk` under the 40/40/20 split, 0.974410 to 0.974356 (the scenario row and its two population copies) |
| `recompute/results/split_control_threeway40_sixvictim_matrix.json` (replaced) | the same INNE cell |
| `recompute/numbers.json` (recomputed) | INNE's `cluster_mean_delta` under `split_control/threeway40`, PANEL-16 and USABLE-strict, −0.003439 to −0.003441, recomputed from the matrix above |
| `results/admissibility_inputs.json` (edited by hand) | `payload_sha256` of the five Wednesday candidates (no writer; see below) |

The two threeway40 benchmark records (`split_control_threeway40_benchmark.json` and the sixth-victim
`split_control_benchmark_threeway40_sixvictim.json`) store four decimals, at which nothing moved,
so they were kept. `recompute/extra.json`, `recompute/tables_v4.json` and `recompute/validation.json`
(1,968 aggregates, 0 mismatches), recomputed from the replaced records, are byte-identical to the
deposited ones. Every other record these scripts write was unchanged apart from unseeded LODA cells
and stored run times, and was kept. The deterministic ones reproduced on the regenerated tree to every stored
value: the ten corrected arms standardise each feature or work on its ranks, and the
column's scale reached only the engine's rule set and, at the fifth decimal, one INNE cell. The
records with archived-registry LODA cells (`post2023_benchmark_results.json`,
`final_evaluation.json`, `universal_ewma_tournament.json`, `usable_29_scenarios_benchmark.json` and
`batch_invariance_gate.json`) differ only in those cells, which are unseeded and differed between
the runs, the control's included; a re-run would only replace one unseeded draw with another. In
`usable_29_scenarios_benchmark.json`, for example, only the two LODA rows differ, and the
Subspace-ECOD (k = 8) mean AUC is bit-identical.

### Records with Wednesday rows that these scripts do not rewrite

- `c_engine_verification_report.json`. Its runner, `verify_c_engine_subspace_q.py`, needs the
  engine source `subspace_q.c`, which is not deposited. The authors recovered that source from an
  earlier commit of this repository that is not in its published history and re-ran the runner on
  the regenerated files: all 166 values it writes equal the record, and every per-window Python and
  C score is bit-identical to a run on the earlier files on 16 of 16 rows. The record is kept. The C
  source is still not deposited, so a reader cannot repeat this check.
- `admissibility_inputs.json`. No deposited writer. Re-measured on the regenerated files with
  `extraction/classify_scenarios.py`, all ten statistics of all 31 candidates are unchanged; only
  the five Wednesday `payload_sha256` values were updated, by hand, to match the regenerated files.
- `full_tree_all_scenarios_metrics.json`. No deposited writer. Its five Wednesday rows were scored
  on the earlier `dst_port_density` scale and are kept as written. The authors re-scored them
  outside the deposit, through a reconstruction of the undeposited scoring code that reproduces four
  of the record's seven arms exactly on 30 of its 31 rows of the earlier files. On the regenerated
  files six of the seven arms move on the Wednesday rows, by up to 0.065 AUC on one row and by at
  most 0.0031 in an arm's 31-row mean; for `ens` and `pewma`, which the reconstruction does not
  reproduce exactly, the movement is an estimate. The ordering the manuscript cites still holds:
  each of `anewma`, `mcpts`, `pewma` and `cv` has a lower mean AUC than each of `ens`, `z` and
  `spot` (smallest gap +0.0439 before, +0.0430 after).
- `all_extracted_datasets_evaluation_results.json`. No deposited writer. Its four Wednesday rows
  were scored on the earlier scale and were not re-measured.

At the time `SHA256SUMS.results` and `recompute/results/SHA256SUMS` listed the replaced files;
they now list the 39-name records.

---

## Records after the 39-name re-run

`recompute/PREREGISTRATION_39_FEATURES.md` (sha256
`813f3c20917d3b8e5054e70bee4431c38a8e56c524cfcbe76e1caf90e189aaef`) was written on 2026-10-19,
before any record was computed on the new columns, and committed as `895e581`; its base is
`9d51bdc`. It fixed the plan: the evaluation uses every feature name the shipped engine scores
(`l2_feature_names` in `project/layer2/baselines.c`, 39 names), with `burst_factor` and
`unique_flows` computed the engine's way, and nothing else changes (k = 8, α = 0.5, the splits,
thresholds, targets and seeds, the per-scenario zero-range filter and the four-check admissibility
rule). It is the third feature set used on these corpora, chosen after results on the first two had
been seen: 39 names with the two as placeholder copies of `packets_per_sec` and `flows_per_sec`
written by an older offline extractor; 37 names with the copies dropped (the records the harness wrote up
to `895e581`); and the 39 names of this revision. All p-values stay descriptive.

**What changed in the code.**

- Extraction. `pcap_feature_extractor.py` (and through it `pcap_feature_extractor_cicids2018.py`
  and `run_cicids2017_pcap.py`) and the per-destination builder of `litnet_loader.py` write the two
  columns; their definitions are in `extraction/tree_manifest/README.md`. `verify_extracted_tree.py`
  checks them, `drop_duplicate_columns.py` now drops the pair only where both columns copy their
  twins in every row (so it leaves the rebuilt tree alone), and `build_scenario_inventory.py`
  states the new column counts. `extraction/README.md` gives the detail.
- Harness, as pre-registered. `unique_flows` joins the `ln(x+1)` set
  (`baselines.LOG_TRANSFORM_FEATURES`), `burst_factor` joins the harness CUSUM features
  (`config.CUSUM_FEATURES`; `new_srcip_rate` stays out because LITNET-2020 lacks it), and
  `feature_filter.PRODUCTION_39_FEATURES` lists all 39 names. The log transform reaches every
  re-run record of both registries, through `baselines._log_xform`. Among the re-run records the
  other two reach only the four LITNET-2020 subnet and ablation records: `config.CUSUM_FEATURES` is
  read only by `detectors.CUSUMDetector`, and `PRODUCTION_39_FEATURES` only by the two subnet
  runners and by `extraction/run_cicids2017_pcap.py`, which writes no record. The ten corrected arms and the
  archived arms score the columns that vary on a row's fit windows
  (`run_crosscorpus_auc.active_features`), not a fixed list: both new columns enter on all 16 panel
  rows, and D, the number of scored columns, rises by 2 on each (34 on the five CIC-IDS-2017 rows;
  34, 34, 33, 33, 31 and 31 on the six CSE-CIC-IDS2018 rows; 29 on the four CIC-DDoS2019 rows; 12
  on LITNET-2020 `code_red_worm`; `c_engine_verification_report.json`, `d_features`). `dir_ratio`,
  which the tree carries and the engine does not score, is constant on the fit windows of every
  panel row and never enters. `c_engine_ours.json` sees `burst_factor` through the engine's own
  CUSUM.
- Subnet aggregation, a deviation (below). `litnet_loader.load_litnet_per_subnet` writes the two
  columns for a protected-subnet slot, and `ablate_no_unique_dst_runner.py` checks for 12 scored
  features instead of 10.
- The engine changes of this revision, under `project/layer1/`, `project/core/`,
  `project/common/` and `project/tests/` (listed in `project/LAYER1_FIXES.md`), enter no scored
  record. The pre-registration says so of the syn_proxy and flow_table fixes; the other fixes that
  file lists were not pre-registered and enter none either: `run_c_engine_ours.py` builds only the
  Layer 2 sources it lists, the shared library it builds is byte-identical with and without them, and with the first
  of them applied it wrote the `895e581` record byte for byte on the 37-name tree.

**The tree.** Rebuilt from the raw releases with the patched chain (`extraction/README.md`,
[The 39-name tree](extraction/README.md#the-39-name-tree)): 65 files and 2,056,369,268 bytes as
built, where the 37-name tree had 1,912,630,664, both counted with the tree README files of commit
`895e581`; with this revision's README files copied in, as `extraction/README.md` says to do
before `verify_readme_claims.py`, 2,056,372,694 bytes.
Packet-capture rows carry 40 columns, the 39 engine names and `dir_ratio`; LITNET-2020
rows carry 15. On every column the 37-name tree carried, all 2,165,971 rows of its 39 payloads are
equal by value. The four-check classifier admits the same 16 scenarios with the same census
(USABLE 16, ATTACKER-SIDE 6, FLOOR-LIMITED 4, NOT-DDOS 2, NO-FPR 2, INSEPARABLE 1) and the same
`verdict`, `best_feature` and `best_auc` on all 31 candidates, so the pre-registered rule for
reporting a second panel did not apply.

**How the records were re-run.** With one BLAS thread, as pre-registered: the 24 runner commands of
`regenerate.sh` and `heldout_threeway40.sh` and `sixth_victim.sh` as shipped, followed by the
three `recompute/` scripts; `verify_c_engine_subspace_q.py` with the recovered C source (not deposited);
`extraction/write_admissibility_inputs.py`; and, with the patched subnet loader,
`run_litnet_l1subnet.py` and `ablate_no_unique_dst_runner.py` on the truncated LITNET-2020 export
that the records they replace used. A control run of the same code on the 37-name tree reproduced
every deterministic record of `895e581` by value; it differed only in the unseeded archived-registry
LODA cells (with the list positions and derived values that follow from them), the stored run times
and the hand-written `summary.note` of the C-port record. So every other change below comes from the
two new columns. `recompute/validation.json` again reproduces
1,968 stored aggregates with 0 mismatches.

| status | records (of the 57: 49 in `results/`, 8 in `recompute/results/`) |
|---|---|
| re-run on the 39-name tree (44) | the 29 that `regenerate.sh` writes; the three `*_threeway40.json` and four `*_sixvictim*` records in `recompute/results/`; `c_engine_verification_report.json` (with the C source, which is not deposited); `admissibility_inputs.json` (its new writer); `litnet_l1subnet_{16,24}_results.json`, the two ABLATION records, and the two CANONICAL files copied byte for byte from the re-run subnet records |
| unchanged (6) | `panel_inventory/PANEL.json`, the four per-corpus panel inventories and `recompute/results/PANEL_sixvictim.json`: inputs that hold scenario names, victims, window counts, split sizes, verdicts and the classifier's best AUC, none of which the two new columns move (the `best_auc`, counts, victim, mode and verdict of all 31 `PANEL.json` rows equal the `index.json` entries of both trees; `PANEL_sixvictim.json` differs from them only in admitting LITNET-2020 `smurf`, which the index records as NO-FPR, as the check intends) |
| kept from an earlier feature set (7) | records with no deposited writer: the two `rescued/litnet_results_*` and two `rescued/litnet_zone_results_*` records (10 LITNET-2020 NetFlow names, `metadata.features_used`); `full_tree_all_scenarios_metrics.json`, `all_extracted_datasets_evaluation_results.json` and `rescued/dual_scale_union_results.json`, which store no feature list, so their feature set is unknown; all seven predate the 39-name tree |

Of the 44 re-run records, `clock_null.json`, `clock_split_sensitivity.json` and
`admissibility_ledger.json` are byte-identical to `895e581`: they read labels, or records that
the new columns do not move. `admissibility_inputs.json` changed only in its 31 `payload_sha256`
values.

**The 37-name values.** The pre-registration asks that the 37-name values of the headline
statistics be printed beside the 39-name values, whatever their direction, and that a statistic
that changes significance at 0.05, rank, win count or sign be printed with both values and neither
preferred. `recompute/results/feature_set_comparison_37_vs_39.tsv` does this: 661 rows, one per
statistic, with the value on each feature set, the record and JSON path of each, and a `flips`
column that names every such change. `recompute/compare_feature_sets.py` writes it from the
records at `895e581`, read with `git show`, and the records here (`recompute/README.md`). The
largest changes:

- Discrimination, deposited split: our mean AUC 0.9913 to 0.9806, margin over POT +0.0246 to
  +0.0143, raw p 0.00919 to 0.0155, Holm 0.0643 to 0.09302, victim-clustered p 0.625 to 0.8125; the
  victim-clustered mean difference changes sign (+0.012318 to −0.021193), the i.i.d. interval now
  spans zero ([0.004, 0.0541] to [−0.0233, 0.0511]), and our rank by mean AUC goes from first to
  second of ten (DIF 0.9831, whose own i.i.d. interval against POT now excludes zero,
  [−0.0005, 0.0386] to [0.0005, 0.0385]). Wins go from 12 to 13 of 16 on a tie-level row.
- Repaired splits: Holm 0.04401 to 0.09302 (threeway40) and 0.04401 to 0.07855 (threeway60), from
  below 0.05 to above it; the clustered mean difference changes sign on both. The sixth-victim
  check under threeway40 crosses too, Holm 0.04657 to 0.10427; on the 39 names one of its rows,
  LITNET-2020 `smurf`, ties POT exactly, so `scipy.stats.wilcoxon` computes that p-value by its
  normal approximation.
- Matched smoothing: margin +0.0227 to +0.0122; our rank by mean AUC first to fourth.
- Benign alarm episodes at the oracle targets: our rank 4, 4 and 8 to 4, 2 and 10 at 1, 2 and 5%;
  at 2% ours now has fewer episodes than POT.
- Held-out targets, deposited split: our episode rank at 5% goes from eighth to second (10.80 to
  9.02 against POT's 9.60 to 9.29), at 1% from fewer episodes than POT to more (6.62 against 6.71
  to 7.06 against 6.69; second to third), and our realized false-alarm rate, lower than POT's at every
  target on the 37 names, is higher at every target (1%: 2.06 to 7.81% against 5.25 to 5.19%).
  Almost all of that difference is `code_red_worm`, 0.64 to 90.42% at 1%.
- Clock null: the clock still wins 8 of 16 rows and 3 of 5 victims; scenario p 0.5966 to 0.7436,
  clustered p 0.8125 to 0.625.
- Inductive correction: ours +0.0093 to −0.0013 (sign); ECOD +0.2929 to +0.2980, COPOD +0.2874 to
  +0.2923, DIF +0.4515 to +0.4510.
- Census: unchanged.

Most of the change comes from one row, LITNET-2020 `code_red_worm`: our AUC there falls from 0.9598
to 0.7917, while every other row moves by at most 0.0016 (`panel_auc_matrix.json`). Changes in
archived-registry LODA cells cannot be told apart from the run-to-run variation of an unseeded arm,
so the flips that involve them (LODA's inductive lift, −0.0323 to +0.0191; the tournament's ten of
ten detectors raised by EWMA becoming nine) are not attributed to the features.

**Deviations from the pre-registration.**

1. *A writer for a record that had none.* The pre-registration says records without a writer keep
   their values. `admissibility_inputs.json` had none; `extraction/write_admissibility_inputs.py`
   was added, reproduces the `895e581` file byte for byte from the 37-name tree, and was run on the
   39-name tree, where only the 31 `payload_sha256` values changed.
2. *A loader change for the subnet records.* The pre-registration recomputes every record with a
   deposited writer, but the extraction patch gave the two columns to the per-destination builder
   only, and the subnet and ablation runners read `load_litnet_per_subnet`. It now computes them for
   a protected-subnet slot as the engine does: `ip_protected_subnet_add` registers one per-IP slot
   keyed by the network, so `unique_flows` counts the engine flow key {lower address, higher
   address, protocol} over the slot's records, which inside a subnet is the unordered address pair
   plus protocol rather than the (source, destination, protocol) triple, and `burst_factor` runs one
   EWMA per slot over its `packets_per_sec`, stepping every silent second with x = 0. A control run
   of the `895e581` code on the same export reproduced every value of the four records (it differed
   only in metadata: the hand-written `_inert_list_note` is absent, and in the two ablation records
   the runner's inert-feature list also names `unique_dst_ips`); the patched loader leaves every
   earlier column of the subnet caches unchanged; and the authors traced every
   value change in the re-run records to `burst_factor`, outside the deposit (scored without it,
   they give their 37-name values back). The scored feature count rises from 11 to 13, and from 10
   to 12 in the ablation; `rescued/ABLATION_README.md` gives the changed figures.
3. *DIF's fifth decimal.* The pre-registration does not attribute changes there to the features,
   because they can come from the BLAS thread count. Every run here used one thread and the control
   reproduced every DIF value, so the comparison prints DIF's changes as they are, including those
   below 1e-4. The closest DIF gap in the four mean-AUC rankings is 0.00068 (our margin over DIF
   under threeway40).
4. *Both values printed here, not in the manuscript.* The pre-registration says the 37-name values
   of the headline statistics are reported beside the 39-name values and that both values of every
   flip are printed. After seeing both sets, the authors decided that the manuscript prints the
   39-name values without the 37-name values beside them. Its Methods names the earlier feature set and points to
   `recompute/results/feature_set_comparison_37_vs_39.tsv`, which prints both values of every
   pre-registered statistic with the flips marked.

---

## ⚠ `usable_29_scenarios_benchmark.json`: read before citing

1. **The filename is historical.** The runner selects `verdict == 'USABLE'` on the four corpora and
   writes 16 scenarios, under the key `usable_16_scenarios`. They are the PANEL-16 scenarios, all on
   the causal within-day split; the record is not a second, larger population.
2. **It is an archived-registry record.** ECOD, COPOD and DIF are the transductive PyOD versions
   and LODA is unseeded. Its arm labels carry the old citation years (ECOD 2022, DIF 2024).
3. **It ranks by mean AUC and runs no test.** INNE + EWMA is first (0.9888), the two unsmoothed
   Subspace-ECOD arms second and third (0.9857 and 0.9818), and ours fourth (0.9806); on the 37
   names ours was first (0.9913) and INNE + EWMA second (0.9888). Neither order has a significance
   test, a correction or clustering behind it.

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
`run_admissibility_ledger.py` and `run_table_provenance.py`) and the three derivation scripts in
`recompute/` read deposited records only; `recompute/compare_feature_sets.py` also reads the git
history. The two LITNET runners read the LITNET-2020 export instead of the
derived tree; every other runner needs the derived tree. `extraction/write_admissibility_inputs.py`
reads the tree's `index.json` files only.

### `recompute/regeneration/regenerate.sh`

Rewrites the 29 records marked "regen" above with 22 runners (24 invocations; `run_split_control.py`
runs once per split), then rebuilds the derived numbers in `recompute/`:

    bash recompute/regeneration/heldout_threeway40.sh [python]   # first (see below)
    bash recompute/regeneration/regenerate.sh [python]

Run `heldout_threeway40.sh` first, or run the three `recompute/` scripts again after it:
`regenerate.sh` ends with them, and `four_corpus_tables.py` reads the three `*_threeway40.json`
records in `recompute/results/` when they are present, so a `regenerate.sh` run on its own
recomputes `numbers.json#four/heldout_threeway40` from whatever copies of those records are there.
None of the three derivation scripts in `recompute/` reads the sixth-victim records, so
`sixth_victim.sh` can run before or after `regenerate.sh`; `recompute/compare_feature_sets.py`
reads them, so run it after both.

`regenerate.sh` runs from anywhere, sets `ANTIDDOS_OVERWRITE=1` so the runners replace the deposited records, and
pins `OMP_NUM_THREADS`, `OPENBLAS_NUM_THREADS` and `MKL_NUM_THREADS` to 1: DIF's fifth decimal
depends on the BLAS thread count. Wave 1 runs the 19 tree-reading runners in parallel, among them
`verify_inductive.py`; wave 2 runs the three record-only runners; logs go to
`recompute/regeneration/logs/`. It does not run `verify_c_engine_subspace_q.py` (the engine source
`subspace_q.c` is not deposited), `run_litnet_l1subnet.py` or `ablate_no_unique_dst_runner.py` (they
read the LITNET-2020 export, which is not deposited, or caches built from it),
`extraction/write_admissibility_inputs.py` (it belongs to the extraction recipe, after the tree's
`index.json` files are written), or `run_corrected_benchmark.py` (an earlier form of
`run_corrected_benchmark_full.py` that writes the benchmark record without the matrix).

`recompute/regeneration/pass_comparison.tsv` compares two passes of the 37-name revision, record by
record: pass 2, the single-threaded pass that wrote the records deposited before the Wednesday files
were regenerated, and pass 1, an earlier full pass at the default BLAS thread count (49 rows:
numeric leaf count, values changed and the cause). Its counts describe those passes, not the
39-name records; its cause column says why each record `regenerate.sh` does not rewrite is left
out, as it stands now:

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
- 20 records not rewritten by `regenerate.sh`: the five panel inventories (inputs with no
  deposited writer), `admissibility_inputs.json` (an input, written by
  `extraction/write_admissibility_inputs.py` from the tree's `index.json` files), the two
  hand-filtered sweeps (no deposited writer), `c_engine_verification_report.json` (needs
  `subspace_q.c`), the two LITNET-2020 subnet records and the nine rescued records (their writers
  read the LITNET-2020 export or caches built from it, neither of which is deposited, or no writer
  is deposited; the two CANONICAL files are byte copies of the subnet records).

No other value changed between the two passes. The archived LODA cells are not guaranteed to
reproduce in any run. Both passes ran on the tree as it stood before the Wednesday files were
regenerated; the three records replaced afterwards are listed in
[Records after the Wednesday regeneration](#records-after-the-wednesday-regeneration), and the
39-name re-run in [Records after the 39-name re-run](#records-after-the-39-name-re-run).

### `recompute/regeneration/sixth_victim.sh`

The post hoc sixth-victim check: both three-way splits on PANEL-17, the 16 panel rows plus
LITNET-2020 `smurf` on 193.219.88.36. It copies the package into a temporary directory, swaps in
`recompute/results/PANEL_sixvictim.json` as the panel inventory (so the deposited inventory is never
touched), runs `run_split_control.py` single-threaded, and copies the four `*_sixvictim*` records to
`recompute/results/`. It links the derived tree from the repository's own `datasets/extracted/`
rather than from `ANTIDDOS_BASE`, and it needs `rsync`.

### `recompute/regeneration/heldout_threeway40.sh`

The post hoc held-out re-score under the repaired split. With `ANTIDDOS_SPLIT=threeway40`,
`run_29_scenarios_corrected.load_case_tree` (which both adjacency-free runners use) fits on the first
40% of each victim's pre-attack benign windows, calibrates on the next 40% and returns the last fifth
to the test stream; unset, it keeps the deposited split and its records are unchanged. The script
writes `scenarios29_corrected_results_threeway40.json`, `adjacency_free_fpr_threeway40.json` and
`adjacency_free_episodes_threeway40.json` to `recompute/results/`; `recompute/four_corpus_tables.py`
summarizes them as `heldout_threeway40` in `numbers.json`.

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
`results/scenario_classification.json`, which is not a deposited record. Given a tree path, it
writes that file into the tree's root instead (`extraction/README.md`, Provenance, item 4).

---

## `recompute/`: the numbers the manuscript prints

`recompute/README.md` describes each script and output in detail.

| file | written by | content |
|---|---|---|
| `numbers.json` | `four_corpus_tables.py` | the manuscript's aggregates, recomputed from the per-scenario records; the oracle detection-rate columns and the appendix figures (k grid, verdict strata, uncooled episodes, tournament) that the Data Availability Statement lists come from records without per-scenario rows |
| `validation.json` | `four_corpus_tables.py` | the recomputation checked against the aggregates the records store: 1,968 reproduced (460 in the repaired-split held-out records), 0 mismatches |
| `extra.json` | `extra_numbers.py` | second-tier quantities quoted in the prose |
| `tables_v4.json` | `tables_v4.py` | the rendered table bodies and figure coordinates |
| `results/` | `regeneration/sixth_victim.sh`, `regeneration/heldout_threeway40.sh`, `compare_feature_sets.py` | the four sixth-victim records and their input `PANEL_sixvictim.json` (no deposited writer); the three held-out records re-scored under the repaired 40/40/20 split (`*_threeway40.json`); `feature_set_comparison_37_vs_39.tsv`, the pre-registered headline statistics on the 37 and the 39 names; a `SHA256SUMS` for the nine files |
| `regeneration/` | | `regenerate.sh`, `sixth_victim.sh`, `heldout_threeway40.sh`, `pass_comparison.tsv` |
| `PREREGISTRATION_39_FEATURES.md` | | the pre-registration of the 39-name re-run (see above) |

The three scripts read `results/`; `four_corpus_tables.py` also reads the three `*_threeway40.json` records in `recompute/results/` when they are present:

    python3 recompute/four_corpus_tables.py results recompute
    python3 recompute/extra_numbers.py results recompute
    python3 recompute/tables_v4.py results recompute results

Holm and Bonferroni adjustments are computed from the unrounded p-values, as the runners compute
them. `compare_feature_sets.py` reads the 37-name records with `git show 895e581:...`, so it needs
a git checkout that contains that commit (or `--old-root` pointing at an export of it):

    python3 recompute/compare_feature_sets.py --check recompute/results/feature_set_comparison_37_vs_39.tsv

---

## Verifying

From `ComparisonResults/results/`:

    sha256sum -c ../SHA256SUMS.results

checks all 49 records (`rescued/ABLATION_README.md` is tracked but not listed). From
`ComparisonResults/recompute/results/`:

    sha256sum -c SHA256SUMS

checks the nine files there: the five sixth-victim files, the three repaired-split held-out
records (`*_threeway40.json`) and `feature_set_comparison_37_vs_39.tsv`. From
`ComparisonResults/extraction/`:

    sha256sum -c SHA256SUMS

checks every tracked file under `extraction/` except the list itself. The per-corpus lists under
`extraction/tree_manifest/` pin the 39-name tree the authors rebuilt for this revision, 47 lines in
all; `extraction/README.md` says what a rebuild reproduces and how to compare one.
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
      recompute/                 derived numbers, regeneration scripts, sixth-victim and held-out re-score records,
                                 the 39-name pre-registration and the 37-against-39 comparison (own README)
      extraction/                scripts that build datasets/extracted/ from the corpus
                                 releases and write admissibility_inputs.json from it (see its README),
                                 with tree_manifest/ (index.json, SHA256SUMS and README per corpus)
                                 and a SHA256SUMS of its own files
      cache/                     not tracked; config.py creates it, and the LITNET-2020 scripts write their caches there
      requirements.txt           the harness environment (Python 3.12, NumPy, SciPy, scikit-learn, PyOD, PyTorch, dpkt)
      SHA256SUMS.results         record manifest (49 entries)
      SHA256SUMS                 older code-and-record checksum list (20 entries)
