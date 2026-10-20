<div align="center">

<img src="assets/banner.svg" alt="AntiDDoS Shield: an evaluation protocol for training-free DDoS detection" width="100%">

<br> 

[![License](https://img.shields.io/badge/license-PolyForm%20Noncommercial%201.0.0-2ea44f?style=flat-square)](LICENSE)
[![Records](https://img.shields.io/badge/deposit-49%20records%20%C2%B7%20SHA256%20verified-0b7285?style=flat-square)](ComparisonResults/)
[![Corpora](https://img.shields.io/badge/corpora-4%20public-495057?style=flat-square)](datasets/README.md)
[![Engine](https://img.shields.io/badge/engine-C%20%2B%20DPDK-a6324a?style=flat-square)](project/)
[![Stack](https://img.shields.io/badge/stack-FastAPI%20%C2%B7%20React-6741d9?style=flat-square)](project/dashboard)

**Protocol, not algorithm, determined most of the manuscript's DDoS-detection results.<br>This repository holds the protocol, the records it produced, and the prototype system.**

</div>

<br>

## What applying the protocol changed

The manuscript *A Clock Can Score Like a DDoS Detector: How Split Construction and Scoring
Protocol Can Manufacture Training-Free Benchmark Results* sets out a six-rule evaluation protocol and
applies it to four public corpora (CIC-IDS-2017, CSE-CIC-IDS2018, CIC-DDoS2019 and LITNET-2020).
Four of its rules ask which victim-scenario slices are
admissible, whether a library baseline scores a row independently of the batch it arrives in,
what the unit of statistical analysis is, and whether a scorer that reads only the window index
already separates the test stream. The contribution is the protocol and the measurement of what
it changes, not a new detector. Hyperparameters, the feature set, cuts and the four-corpus scope were
chosen after seeing results, and no p-value in the manuscript is confirmatory.

<img src="assets/protocol.svg" alt="31 candidate slices reduced to 16 admissible; the mean AUC of three library baselines rises by 0.29 to 0.45 under batch-invariant scoring; on the 39 engine feature names the detector's advantage has a raw paired p of 0.016 by scenario (Holm-adjusted 0.093) and 0.81 once scenarios are clustered on their victim host" width="100%">

| Check | What it changed on the four corpora |
| :-- | :-- |
| Admissibility | 31 candidate scenarios, one recorded verdict each; 16 admitted, on five victim hosts. |
| Batch-invariant scoring | Inductive re-scoring raises the mean AUC of three library baselines (ECOD, COPOD, DIF) by 0.29 to 0.45. |
| Unit of analysis | On the 39 feature names the shipped engine scores, the detector's mean AUC advantage over the peaks-over-threshold (POT) reference is +0.0143: paired by scenario, Wilcoxon p = 0.0155 (Holm-adjusted 0.093); clustered by victim host, p = 0.8125. Both bootstrap intervals span zero (i.i.d. [−0.0233, 0.0511], by victim host [−0.0496, 0.0463]). |
| Clock-only null | The causal split puts every pre-attack benign window into fit and calibration, so each test stream opens on attack, and a scorer that reads only the window index reaches AUC 0.95 or more on 15 of the 16 admitted scenarios. Returning the last fifth of that benign slice to the test stream (the repaired split, post hoc) leaves 3. |

## How the system is built

A DPDK packet datapath in C, a statistical detector in C that decides once per second, and a
web control plane. No machine-learning model at any layer.

<img src="assets/pipeline.svg" alt="Packets flow from the NIC through the DPDK datapath, over POSIX shared memory into the Layer 2 detector, then over a Unix socket and TCP to the FastAPI backend and the React dashboard" width="100%">

## What the evaluation found

Every number below comes from the deposited records in
[`ComparisonResults/results/`](ComparisonResults/results/) and
[`ComparisonResults/recompute/results/`](ComparisonResults/recompute/results/), directly or
through the scripts in
[`ComparisonResults/recompute/`](ComparisonResults/recompute/). They are the records of this
revision, scored on all 39 feature names the shipped engine scores, as pre-registered in
[`ComparisonResults/recompute/PREREGISTRATION_39_FEATURES.md`](ComparisonResults/recompute/PREREGISTRATION_39_FEATURES.md),
with the four deviations that [`ComparisonResults/README.md`](ComparisonResults/README.md) lists (the
fourth: the manuscript, like this page, does not print the 37-name values beside the 39-name ones);
`ComparisonResults/recompute/results/feature_set_comparison_37_vs_39.tsv` compares every
pre-registered statistic with the earlier feature set. On the 16 admitted scenarios:

- The detector's mean AUC is 0.9806 against 0.9663 for the POT reference, a difference of +0.0143
  (scenario-level Holm-adjusted p = 0.093), second of the ten arms behind DIF (0.9831). One
  LITNET-2020 scenario, `code_red_worm`, pulls the mean down: the detector's AUC there is 0.7917.
  One scenario, CIC-IDS-2017 `Wed-05-07_DoS-Slowhttptest`, carries 93.1% of the summed
  per-scenario difference, and on it the clock-only null (AUC 0.9927) scores higher than the
  detector (0.9859).
- When every arm gets the same EWMA smoothing stage, the detector's margin over the reference
  narrows to +0.0122 (Holm-adjusted p = 1.0), and three smoothed arms have a higher mean AUC than
  the detector: DIF (0.9907), INNE (0.9888) and IForest (0.9834). The equally smoothed reference records fewer benign alarm episodes
  than the detector at every oracle target. At 1% the detector records more episodes than that
  reference on 10 of the 16 scenarios and fewer on 2 (scenario-level p = 0.071; victim-clustered
  p = 0.625).
- The 16 scenarios sit on five victim hosts, which floors the exact victim-clustered test at
  0.0625: no clustered comparison on them can reach 5%, whatever the effect.
- At held-out thresholds the detector detects more than the reference at the 1%, 2% and 5% targets.
  Its mean false-alarm rate is higher than the reference's at every target, on the deposited split
  (7.81, 8.46 and 10.61% against 5.19, 6.81 and 10.33%) and on the repaired split (9.35% against
  8.11% at 5%). On the deposited split that difference is LITNET-2020 `code_red_worm`'s: the row accounts for nearly all
  of it at 1% and for more than all of it at 2 and 5%, with the detector at 90.42% at every target
  against the reference's 51.12, 62.62 and 74.12%. These are point estimates from an unmatched comparison: the
  detector is the only smoothed arm, EWMA state carried across the attack block inflates its
  detection, and no victim-level test supports either difference.
- On benign alarm episodes, the declared primary metric, the detector records more episodes than
  the reference on the deposited split at the 1% and 5% oracle targets and fewer at 2% (fourth,
  second and tenth of ten arms). At held-out thresholds it records more at 1% (7.06 against 6.69
  per 1000 benign windows; third of ten, fifth without `code_red_worm`, whose continuous alarm
  counts as one episode) and fewer at 2% and 5% (7.60 against 8.31 and 9.02 against 9.29), at 5%
  only through that alarm (90.42% false alarms). Re-scored post hoc under the repaired split, it
  records fewer episodes than the reference at every oracle and held-out target (scenario
  means).

> [!NOTE]
> Inductive re-scoring ran *against* the evaluated detector, cutting its margin over ECOD to 0.0166
> from a counterfactual 0.3146. The DSPOT rebuild lowered DSPOT, *in the detector's favour*; seeding moved
> LODA by +0.0191 or −0.0459, depending on which of two unseeded draws of the archived LODA it is
> compared with. The manuscript records each movement.

## Verify the deposit

The detector results and test statistics in the manuscript are read from 49 JSON records that
verify against their manifest from inside `results/`:

```bash
cd ComparisonResults/results
sha256sum -c ../SHA256SUMS.results     # 49 lines, each ending in OK
```

Four further records from a post hoc check that admits a sixth victim host, the panel
inventory they read (`PANEL_sixvictim.json`, no deposited writer), the three post hoc records that
re-score the held-out operating point under the repaired 40/40/20 split (`*_threeway40.json`) and
the 37-against-39 comparison (`feature_set_comparison_37_vs_39.tsv`) are in
`ComparisonResults/recompute/results/` with their own `SHA256SUMS`. Three Python scripts in
`ComparisonResults/recompute/` (`four_corpus_tables.py`, `extra_numbers.py` and `tables_v4.py`)
derive the aggregates the manuscript prints from the per-scenario records, among them the Holm
adjustment of the victim-clustered p-values, which no runner computes and no record stores;
`recompute/validation.json` records 1,968 aggregates stored in the records reproduced with no
mismatch (460 of them in the repaired-split held-out records).

`recompute/regeneration/regenerate.sh` rewrites 29 of the 49 records on the four corpora,
single-threaded; run `heldout_threeway40.sh` before it, because its last step summarizes that
script's records. For this revision both, with `sixth_victim.sh`, were run on the 39-name tree, and
every other record whose deposited writer could be run was re-run too: 44 of the 57 records in
`results/` and `recompute/results/` (`ComparisonResults/README.md`, "Records after the 39-name
re-run"). `recompute/regeneration/pass_comparison.tsv` lists all 49 records of `results/`. For each
of the 20 that `regenerate.sh` does not rewrite it gives the reason: inputs and hand-filtered
records with no deposited writer, `admissibility_inputs.json`, which an extraction script writes,
LITNET-2020 records whose writers read the export or caches built from it, neither of which is
deposited (both subnet records, `litnet_l1subnet_{16,24}_results.json`, and the two rescued
`unique_dst_ips` ablations were scored on an incomplete LITNET-2020 export that lacks `udp_f`, and
re-scored on it for the 39 names), and `c_engine_verification_report.json`, whose writer needs
engine source that is not deposited. It also compares each of the 29 between two passes of the
previous revision (`batch_invariance_gate.json` was rewritten in a follow-up run). Seeded DIF cells
move at the fifth decimal or later with the BLAS thread count; LODA cells from the archived
competitor module, which gives LODA no random seed, change from run to run; eight summary means in
`adjacency_free_fpr.json` changed because the runner now averages with `statistics.mean`, which
rounds two exact ties differently; and the earlier pass did not rewrite `joint_filter.json` or
`table_cell_provenance.json`, so the comparison does not test them.

The guard-band leak, the admissibility census statistics and the CIC-IDS-2017 benign-pool audit
have no record; the extraction scripts compute them from the per-day caches, the feature tree and
the CIC-IDS-2017 flow-label files, and rebuild the caches and the tree from the official releases
(below). Three records were restricted to the four corpora by hand
(`full_tree_all_scenarios_metrics.json`, `all_extracted_datasets_evaluation_results.json` and
`panel_inventory/PANEL.json`); no writer for them or for the rest of `panel_inventory/` is
deposited. Four LITNET records had one metadata list edited by hand, and each says so in an
`_inert_list_note` field. These seven keep their values on the 39 names. Eight records edited by
hand before this revision are now written by a script or copied from one that is:
`c_engine_verification_report.json`, now
its runner's output (the runner needs engine source that is not deposited), the four LITNET-2020
subnet and ablation records and their two copies, re-run, and `admissibility_inputs.json`, now
written by `extraction/write_admissibility_inputs.py`.

> [!NOTE]
> `ComparisonResults/SHA256SUMS` is an older list of 20 code and record checksums, checked from
> `ComparisonResults/` with `sha256sum -c SHA256SUMS`; it is not the record manifest, which is
> `SHA256SUMS.results`. `ComparisonResults/extraction/SHA256SUMS` lists every other file in
> `extraction/` and is checked from that directory the same way.

> [!IMPORTANT]
> The deposit does not run end to end: it contains neither the four corpora nor the derived
> per-window feature tree. Three of the 22 `runners/run_*.py` scripts
> (`run_joint_filter.py`, `run_admissibility_ledger.py` and `run_table_provenance.py`) and the
> three derivation scripts in `recompute/` run from the deposited records alone, and
> `recompute/compare_feature_sets.py` from the records and the git history. Of the other 19
> runners, 18 need the feature tree and `run_litnet_l1subnet.py` reads the raw LITNET-2020 flow
> export. The extraction chain is deposited under
> [`ComparisonResults/extraction/`](ComparisonResults/extraction/) (nineteen scripts,
> `drop_duplicate_columns.py`, a helper module and a README), with the tree's own `index.json`
> files and per-file `SHA256SUMS`. For this revision the chain computes the two engine features the
> earlier tree lacked, `burst_factor` and `unique_flows`, and the whole tree was rebuilt with it from
> the raw captures and flow files; the deposited checksums are those of that rebuild, every one of
> whose files the chain wrote, and on every earlier column it equals the earlier tree by value.
> Packet-capture rows carry 40 columns (the engine's 39 names and `dir_ratio`), LITNET-2020 rows 15.
> Every record whose deposited writer could be run was then re-run on the rebuilt tree, as
> pre-registered, with the four deviations that `ComparisonResults/README.md` lists. The revision before regenerated the six CIC-IDS-2017 Wednesday files with the
> chain (their `dst_port_density` had been stored 1000 times smaller than in every other file);
> [`ComparisonResults/README.md`](ComparisonResults/README.md) keeps the account of both runs and
> says which records each one replaced, and the extraction README describes both rebuilds. Seven
> records without a deposited writer keep the values of the feature set they were scored on, and
> two of them, the earlier sweeps, still hold CIC-IDS-2017 Wednesday rows scored before those files
> were regenerated; that README lists them. The
> harness environment is pinned in
> [`ComparisonResults/requirements.txt`](ComparisonResults/requirements.txt).

The per-record index is in [`ComparisonResults/README.md`](ComparisonResults/README.md);
corpus download pointers are in [`datasets/README.md`](datasets/README.md). No corpus data is committed.

## Run the prototype

<details>
<summary><b>Build the C engine</b>: Meson + Ninja, DPDK for the datapath (<a href="INSTALL.md">INSTALL.md</a>)</summary>

```bash
cd project
meson setup build -Dbuild_tests=true
ninja -C build
```

</details>

<details>
<summary><b>Run the backend</b>: FastAPI</summary>

```bash
cd project/backend
pip install -r api/requirements.txt
uvicorn api.main:app
```

</details>

<details>
<summary><b>Run the dashboard</b>: React + Vite</summary>

```bash
cd project/dashboard
npm install
npm run dev
```

</details>

<details>
<summary><b>Run the fidelity unit tests</b></summary>

```bash
python -m pytest project/tests/unit_python/
```

</details>

## Scope

- **Not a benchmark win.** The manuscript reports a negative result where the evidence is negative.
- **Not a performance claim.** `project/` is a research prototype; throughput and detection latency have not been measured.
- **Not the evaluated detector.** The arm the manuscript evaluates is in no build target of the engine; where a figure scores the shipped engine instead, the manuscript says so.
- **Not a machine-learning system.** There is no trained model at any layer.
- **Not a corpus mirror.** No dataset content is redistributed.

## Authors

| | Affiliation | |
| :-- | :-- | :-- |
| **Pulatjon Oripov** | Cybersecurity Center, Tashkent, Uzbekistan | first author |
| **Sardor Iskandarov** | Cybersecurity Center, Tashkent · School of Computing, New Uzbekistan University, Tashkent, Uzbekistan | |
| **Rustamjon Oripov** | Department of Cybersecurity and Forensics, Tashkent University of Information Technologies named after Muhammad al-Khwarizmi, Tashkent, Uzbekistan | |
| **Dilshodjon Mamadaliev** | Cybersecurity Center, Tashkent, Uzbekistan | corresponding · [ORCID](https://orcid.org/0009-0008-0073-7535) |

Correspondence: mamadalievdilshodjon@gmail.com

## Cite

```bibtex
@software{antiddos_shield_2026,
  title   = {AntiDDoS Shield: an evaluation protocol for training-free {DDoS} detection},
  author  = {Oripov, Pulatjon and Iskandarov, Sardor and Oripov, Rustamjon and Mamadaliev, Dilshodjon},
  year    = {2026},
  url     = {https://github.com/DilshodbekMX/AntiDDoS-Shield},
  version = {see the commit cited in the manuscript's Data Availability Statement},
  note    = {Companion deposit of the manuscript \emph{A Clock Can Score Like a {DDoS} Detector: How Split Construction and Scoring Protocol Can Manufacture Training-Free Benchmark Results}}
}
```

## License

Code is released under the [PolyForm Noncommercial License 1.0.0](LICENSE): research, teaching and other
noncommercial use are permitted; commercial use needs the authors' written permission. Earlier commits,
through `2e59ab9`, were published under the MIT License, which still applies to copies taken from them.
Third-party components keep their own licences: portions of `project/core/dpdk_core.c` derive from DPDK's
`examples/l2fwd` (BSD-3-Clause, Intel), and cJSON is embedded in `project/external/` under the MIT license; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Dataset-derived caches and results remain under their upstream corpus licenses (CIC-IDS-2017,
CSE-CIC-IDS2018, CIC-DDoS2019, LITNET-2020); consult each dataset's terms before redistributing anything
derived from it.
