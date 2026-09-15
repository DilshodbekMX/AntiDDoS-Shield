# ComparisonResults

> ## STATUS after the 2026-08-27 audit and re-run
>
> A 12-agent audit found 58 verified defects (2 blockers). The competitor side has
> been **rebuilt and re-run**; our own claim has **not** been rescued by it.
>
> **FIXED — the competitor comparison is now sound**
> 1. **Transductive scoring.** ECOD, COPOD and DIF scored a row differently
>    depending on batch composition (PyOD concatenates train onto the scored batch
>    and recomputes the ECDF). Reimplemented inductively; DIF's representation
>    scaler is now frozen after the train pass. `runners/verify_inductive.py` is
>    the gate. With 0, 16 or 3,779 attack rows appended after fixed benign rows,
>    all 10 corrected arms score them **bit-identically** (max drift 0.00e+00);
>    the archived registry fails that append axis on ECOD, COPOD and DIF, three
>    of its eight deterministic arms (LODA is stochastic there and excluded from
>    that count). Prepending the same rows is a separate, reported axis: among
>    the corrected arms it moves only the two sequential ones, ours and DSPOT.
>    Verdicts: `results/batch_invariance_gate.json`.
> 2. **DSPOT.** Rebuilt to Siffer Algorithm 3 (drift window frozen on alarm).
> 3. **LODA.** Seeded; its row is reproducible.
> 4. **Citations.** `competitors.bib` — 9 entries, every DOI resolved against
>    Crossref by content negotiation. ECOD is 2023 (not 2022), DIF is 2023 (not
>    2024 — TKDE 2024 is vol. 36), and `ms_scale()` now cites Hosking & Wallis
>    1987 for method-of-moments instead of Siffer, who explicitly rejects MoM.
>    COPOD's DOI is ...00135; ...00139 resolves to a patent-mining paper.
>
> **NOT FIXED — these concern our own claim, and the re-run made them sharper**
> 5. **Resubstitution.** k=8, alpha=0.5 and the "drop the SPOT fusion" decision
>    were selected on the same panel the n=17 population is drawn from. No
>    held-out set exists. p-values here are not tests.
> 6. **Correction and clustering.** On USABLE-strict, Holm(m=9) = **0.079** and the
>    victim-cluster Wilcoxon is **p = 0.625**. The cluster bootstrap CI on the mean
>    delta spans zero on **both** populations.
> 7. **Concentration.** 55% of the panel effect is one scenario (2017 Wed
>    Slowhttptest); 3 of 23 are byte-identical because ours falls back to POT at
>    N < 2D.
> 8. **Episodes.** Ours 8.33 vs POT 8.07 at 2% on the headline population — still
>    worse on this project's own preferred metric.
>
> **Bottom line:** the competitor numbers are now citable; the *superiority claim*
> is not. See `results/corrected_benchmark_results.json`, which supersedes
> `post2023_benchmark_results.json` and `final_evaluation.json` for the table.

Every competitor comparison for the Subspace-Q + EWMA detector: the
implementations, the runners, and the result artifacts they produced.

This folder is an **archive**, not a working tree. The runners under `runners/`
are copies kept next to their output so a reader can see what produced each
number; they import from their home tree. To *regenerate* anything, run it from
this package, which is now self-contained:

    ANTIDDOS_BASE=/home/detector/Projects/antiddos \
      python3 runners/run_post2023_benchmark.py

`ANTIDDOS_BASE` is required. Without it `config.BASE` falls back to
`AntiDDOS_Shield/`, whose `datasets/` holds only a `.gitkeep`.

---

## The competitor set

`post2023_competitors.py` — nine detectors, one registry. Every one is either a
PyOD reference implementation or written from the cited paper. Scores are
oriented so **higher = more anomalous**.

> **CORRECTION (2026-08-27).** An earlier version of this file claimed "every
> detector is fit on training rows only". **That is false for four of the nine.**
> PyOD's ECOD and COPOD `decision_function` concatenate the training set onto the
> scored batch and recompute the ECDF over the union
> (`pyod/models/ecod.py`, `copod.py`); PyOD's DIF refits a `StandardScaler` on
> whichever batch it scores (`dif.py:281`); LODA is additionally unseeded. Our own
> detector ranks against the **train** sort only — the correct inductive form. The
> comparison is therefore asymmetric **in our favour**. See the banner at the top.

| Detector | Source | Citation |
|---|---|---|
| Subspace-ECOD (ours) | from paper | Lakhina SIGCOMM 2004 + Li TKDE + Siffer KDD 2017 |
| SPOT | from paper | Siffer et al., ACM SIGKDD 2017, pp. 1067–1075 |
| DSPOT | from paper | Siffer et al., ACM SIGKDD 2017, Sec. 4.2 |
| ECOD | PyOD | Li et al., IEEE TKDE |
| COPOD | PyOD | Li et al., IEEE ICDM 2020, pp. 1118–1123 |
| HBOS | PyOD | Goldstein & Dengel, KI-2012 |
| LODA | PyOD | Pevný, *Machine Learning* 102(2):275–304, 2016 |
| INNE | PyOD | Bandaragoda et al., *Comput. Intell.* 34(4):968–998, 2018 |
| DIF | PyOD | Xu et al., IEEE TKDE (requires torch) |

SPOT and DSPOT are implemented rather than imported because DSPOT's causal
de-drifting window is the method — approximating it with a static mean makes it
a different detector.

### Detectors removed, and why

Five earlier entries were dropped after testing. They are recorded here because
their absence from the table is a result in itself:

- **KitNET** — was linear PCA reconstruction error, which is *rank-identical*
  to the Q-statistic inside our own detector (Spearman 1.000000 on 23/23
  scenarios). It was our second component under another name, not a competitor.
- **DIF (hand-rolled)** — built no trees and computed no path lengths. It
  scored `exp(-|x - split|)`, highest for points *nearest* the split: the
  inverse of isolation. Proof: `auc(s) + auc(-s) = 1.0000` exactly. Replaced
  with the PyOD implementation, which is now in the table above.
- **PatchAD** — random matrices, never trained. Correlated ρ=0.995 with a plain
  mean-squared-z statistic, and that trivial statistic scored *higher*
  (0.9564 vs 0.9550).
- **CCAD** — calibration scores computed on doubly-standardised data, test
  scores on singly-standardised data. The conformal p-values were not calibrated.
- **QG-DualPOT** — carried an evaluation-ordering artifact: 88.9% of benign
  windows fall *after* the first attack window, and a stateful detector's score
  depends on array order.

---

## Results index

### `post2023_benchmark_results.json` — 23-scenario panel, all 9 detectors
Chronological order, per-scenario and pooled (one global threshold) aggregation.

| detector | mean AUC | vs SPOT | p | per-scen DR@2% | pooled DR@2% |
|---|---:|---:|---:|---:|---:|
| **Subspace-ECOD (ours)** | **0.9862** | +0.0113 | 0.00102 | 86.04 | 65.50 |
| INNE | 0.9806 | +0.0057 | 0.988 | 82.94 | 79.19 |
| SPOT | 0.9748 | — | — | 86.11 | 62.84 |
| HBOS | 0.9431 | −0.0317 | 0.00098 | 46.91 | 29.94 |
| DSPOT | 0.7493 | −0.2255 | <1e-5 | 39.81 | 21.76 |
| ECOD | 0.7295 | −0.2453 | <1e-5 | 24.41 | 5.44 |
| COPOD | 0.7252 | −0.2496 | <1e-5 | 27.61 | 7.18 |
| LODA | 0.5876 | −0.3872 | <1e-5 | 22.70 | 2.43 |
| DIF | 0.5503 | −0.4245 | 0.00242 | 36.88 | 0.00 |

Note the two aggregations disagree about INNE: it trails us per-scenario but
leads on pooled DR. Per-scenario is a per-host-tuned deployment; pooled is one
threshold across all hosts. Report both or name which one you mean.

### `final_evaluation.json` — three populations, 7 arms, one causal split
The headline artifact. Populations answer different questions and must not be
merged.

| population | n | ours | SPOT | Δ | p | wins |
|---|---:|---:|---:|---:|---:|---:|
| PANEL (own splits) | 23 | 0.9937 | 0.9748 | +0.0189 | 0.00055 | 18/23 |
| **FULL TREE — USABLE** | **17** | **0.9904** | **0.9672** | **+0.0232** | **0.011** | **12/17** |
| FULL TREE — non-USABLE | 12 | 0.8922 | 0.7732 | +0.1190 | 0.00049 | 12/12 |
| FULL TREE — ALL | 29 | 0.9498 | 0.8869 | +0.0628 | <1e-4 | 24/29 |

Benign alarm **episodes** on that same population (lower is better), which the
runner computes and this index previously omitted:

| arm | ep@1% | ep@2% | ep@5% |
|---|---:|---:|---:|
| Subspace-Q + EWMA (ours) | 5.76 | 8.33 | 12.20 |
| SPOT | **5.22** | **8.07** | **11.32** |

Ours is worse at all three targets. This project's standing rule is that the
episode metric, not per-window FPR or AUC, is the judge.

**The USABLE row is the one that carries a headline.** The audit quarantined
ATTACKER-SIDE and ROLE-UNVERIFIED scenarios; the non-USABLE and ALL rows include
them and are reported only for completeness. INNE + EWMA is the closest arm and
essentially ties us on the panel (0.9919, p=0.008) while falling behind on the
strict USABLE set (0.9633, p=0.28, i.e. not distinguishable from SPOT there).

### `cesnet_ewma_control.json` — 174 real ISP hosts, benign only
No attacks, no labels: this measures false alarms and nothing else, which is
exactly why a floor measured here cannot be dismissed as a testbed artifact.
242,712 benign test windows. Realized FPR at each nominal target:

| arm | @1% | @2% | @5% | @10% |
|---|---:|---:|---:|---:|
| **Subspace-Q + EWMA (ours)** | 5.22 | **6.83** | **10.58** | **16.38** |
| SPOT | **5.00** | 6.87 | 11.47 | 17.36 |
| INNE + EWMA | 10.87 | 13.38 | 19.34 | 26.48 |

Every arm overshoots its nominal target by 4–5 pp — the calibration floor this
project has documented repeatedly. We are marginally better than SPOT at 2/5/10%
and marginally worse at 1%. INNE + EWMA, the arm that rivals us on AUC, is
roughly twice as badly calibrated here. This is the strongest argument for the
detector that the AUC tables do not make.

> On CESNET the `*_per_sec` feature names carry **hourly counts, not rates**.
> Scale-invariant scores are unaffected; do not compare these magnitudes against
> the pcap corpora.

### `universal_ewma_tournament.json` — EWMA ablation, 20 arms
Each detector raw and EWMA-smoothed, so the smoothing is not handed only to us.
This is the artifact that found the shipped variant: **Pure Subspace-Q + EWMA**
at 0.9936 mean AUC / 95.66 DR@2%, beating Subspace-ECOD + EWMA (0.9862 / 78.18).
Dropping the SPOT fusion measured *better* than keeping it.

It also shows EWMA is not a free win: it **hurts** SPOT (0.9748 → 0.9666) and
LODA (0.5536 → 0.6467 mean but worse median behaviour), so applying it to our
arm is not the asymmetry it might look like.

### `fpr_dr_optimization_results.json` — k and residual-metric sweep
k=4 → k=8 and raw → EWMA, with benign-episode counts alongside DR. Kept because
it is the evidence for k=8 and α=0.5 rather than an assertion.

### `c_engine_verification_report.json` — Python ↔ C parity
23/23 scenarios pass. Mean AUC identical to six decimals (0.993685 both sides);
max relative error **2.21e-16**, i.e. floating-point noise. The C port
reproduces the harness.

### `all_extracted_datasets_evaluation_results.json`
Earlier per-scenario sweep from `experiments_copy_copy`, superseded by
`final_evaluation.json`. Retained for provenance only.

---

## ⚠ `usable_29_scenarios_benchmark.json` — read this before citing it

**This file does not contain a win for us**, and its filename oversells its
population. Both points are verified against the tree:

1. **Selection.** The runner selects `verdict in ('USABLE', 'ROLE-UNVERIFIED')`
   (`run_29_usable_benchmark.py:79`). Census of the extracted tree confirms the
   29 are **22 USABLE + 7 ROLE-UNVERIFIED** — seven are audit-quarantined — and
   **13 of the 29 use `crossfile`**, a benign 60/20/20 split with no pre-attack
   history, i.e. not the strict causal split. It is not the population its
   filename implies.

2. **Result.** The runner ranks by mean AUC, and on that statistic **INNE + EWMA
   comes first, ours second**:

   | | mean AUC | median AUC |
   |---|---:|---:|
   | INNE + EWMA | **0.960004** | 0.99767 |
   | Pure Subspace-Q + EWMA (ours) | 0.959360 | **0.99858** |

   The gap is 0.0006 — noise in either direction — and the two statistics
   disagree about the order. Anyone presenting this table ranked by *median*
   would show us first; that ranking was not declared in advance, so it is not
   a result. **Do not cite this file as a win.**

Use `final_evaluation.json` FULL TREE — USABLE (n=17) instead: strict verdict
filter, one causal split, ours +0.0232 over SPOT at p=0.011.

## Layout

    ComparisonResults/
      README.md                      this index
      post2023_competitors.py        the 9-detector registry
      runners/                       scripts that produced each artifact
      results/                       the artifacts
      SHA256SUMS                     checksums, verify with: sha256sum -c SHA256SUMS
