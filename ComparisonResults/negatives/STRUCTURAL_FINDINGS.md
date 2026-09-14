# Inbound-only L3/L4 structural discriminators — pilot + integration findings

**Status: NEGATIVE for an FPR win at usable detection. No promotion to the ensemble, C engine, or paper.**

> **α-era note.** This is a frozen honest-negative. Its B0/B1 reference figures — CIC-IDS-2017
> cross-day FPR **75.4%** (fixed θ), **40.4%** (conformal), θ→∞ floor **≈26.6%**, and 13-case mean
> ROC-AUC **0.882** — were measured under the *retired* EWMA baseline α = 0.2/0.1/0.05. The current
> committed baseline is α = 0.15/0.05/0.01 (`config.py`), where those anchors now read **71.8% /
> 46.3% / ≈23.5% / 0.878**. Only the absolute reference point moved; the *relative* A/B verdict
> below is unchanged, and the frozen measurements are left exactly as recorded at experiment time.

Hypothesis (sound): organic benign traffic is heterogeneous; tool-generated floods are homogeneous /
non-completing. Discriminate by header structure and regularity, not volume — inbound-only, L3/L4, no
re-extraction. Code: `run_structural_pilot.py`, `run_structural_gate_ab.py`. Results:
`results/structural_pilot_results.json`, `results/structural_gate_ab_results.json`. Run 2026-06-18.
Deterministic; training-free (structural calibration on benign only; labels score metrics only).

## Stage 1 — single-feature separation pilot (13 documented victim cases)

Committed one-sided directions (from mechanism, not chosen per corpus). "Clears" = AUC(attack vs ALL
benign) ≥ 0.70 AND AUC(attack vs TOP-QUARTILE-VOLUME benign) ≥ 0.70.

| Feature | Cleared | Median AUC_all | Median AUC_burst |
|---|---|---|---|
| small_pkt_ratio | 5/13 | 0.63 | 0.61 |
| ack_to_syn | 3/13 | 0.50 | 0.52 |
| bytes_per_packet | 2/13 | 0.50 | 0.50 |
| syn_share | 2/13 | 0.50 | 0.50 |
| nonsyn_to_syn (data_to_syn proxy) | 1/13 | 0.50 | 0.50 |
| tcp_completion_rate | 1/13 | 0.50 | 0.50 |

- **No universal lever.** Five of six features sit at AUC 0.50 (no separation) on the median case —
  the heterogeneity signal collapses on testbed corpora whose benign traffic is also machine-generated
  (the predicted caveat, confirmed). `data_to_syn`/completion are duds (1/13).
- **CIC-IDS-2017 is the exception:** five features (`ack_to_syn`, `nonsyn_to_syn`, `bytes_per_packet`,
  `small_pkt_ratio`, `syn_share`) clear ≥0.70 against benign bursts on the LOIC HTTP DDoS — the corpus
  where FPR = 75.4% is the actual problem. CIC-IoT SYN_Flood and Mirai also clear (ack_to_syn / small_pkt).
- Notably `syn_per_sec` is 0 for both attack and benign on the spoofed SYN floods (CIC-IoT, CIC-DDoS2019)
  in these caches, so `ack_to_syn`/`data_to_syn` cannot fire there — the Group-0 completion proxy is a
  dud exactly on the spoofed floods it targets.

## Stage 2 — integration A/B (CIC-IDS-2017, full 530-IP cross-day pool)

A structural OR-path can only raise FPR, so the FPR lever is a **conjunctive veto**: alarm only if the
volume/conformal path fires AND structure looks tool-generated. Structural p-values are one-sided
split-conformal, calibrated per-victim on benign warm windows.

| Config | Best FPR @ victim DR ≥ 99% | Note |
|---|---|---|
| B1 (3-path conformal, Bonferroni) | **40.4%** (DR 99.8%) | reproduces reference exactly |
| Gall = B1 ∧ (min structural p ≤ α) | **none** | best non-99 point: 73.1% DR / 5.4% FPR (α=0.05) |
| Gsmp = B1 ∧ (small_pkt p ≤ α) | **none** | DR = 0 at every α |

The veto crushes FPR (40.4% → 0.1–5.4%) but vetoes the attack with the benign bursts. No gated config
reaches DR ≥ 99%; `small_pkt_ratio` alone vetoes 100% of victim detection.

## Why the pilot's AUC ≥ 0.70 did not translate (the real finding)

The pilot measured **population-level** AUC — attack vs benign bursts pooled across all hosts. The gate
uses **per-victim conformal calibration** (the victim's own warm benign), which is how the detector
operates. At the per-destination scope, the victim's attack windows are not structurally anomalous
*relative to that victim's own benign baseline* sharply enough to survive a conjunction with the volume
path: many true attack windows are volume-anomalous but structure-normal (or vice versa) and get
vetoed, so DR collapses. **Population-level separation ≠ per-victim conformal-gate usability** — and
that is on top of the testbed-collapse that already flattens 5 of 6 features.

## Verdict (3 sentences)

Inbound-only structural/heterogeneity features separate flood from benign at the population level only
on CIC-IDS-2017 (and partially on CIC-IoT SYN/Mirai), and not at all on the median corpus, because
testbed benign traffic is itself machine-generated and uniform. Even where the single-feature AUC
clears 0.70, the signal is too dull at the per-destination scope to act as a conjunctive veto without
destroying detection (gated DR < 74% at every operating point; small-packet veto kills DR entirely),
so it cannot beat B1's 40.4% FPR at the required DR ≥ 99%. The honest, useful takeaway is that this
class of features is **not** a deployable FPR lever for this per-destination detector on these corpora;
the only thing it buys is an unrequested high-precision regime (73% DR / 5.4% FPR) that does not meet
the in-scope detection bar — so the work stops at the harness with no integration, C-engine, or paper change.
