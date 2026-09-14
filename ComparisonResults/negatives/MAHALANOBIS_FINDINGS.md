# Mahalanobis (covariance-aware) detection path — A/B findings

**Status: NEGATIVE. The method does not win. No promotion to the C engine or the paper.**

> **α-era note.** This is a frozen honest-negative. Its B0/B1 reference figures — CIC-IDS-2017
> cross-day FPR **75.4%** (fixed θ), **40.4%** (conformal), θ→∞ floor **≈26.6%**, and 13-case mean
> ROC-AUC **0.882** — were measured under the *retired* EWMA baseline α = 0.2/0.1/0.05. The current
> committed baseline is α = 0.15/0.05/0.01 (`config.py`), where those anchors now read **71.8% /
> 46.3% / ≈23.5% / 0.878**. Only the absolute reference point moved; the *relative* A/B verdict
> below is unchanged, and the frozen measurements are left exactly as recorded at experiment time.

Spec: `MAHALANOBIS_PROTOTYPE_BRIEF.md`. Code: `mahalanobis.py`, `run_mahalanobis_ab.py`,
`test_mahalanobis.py`. Numbers: `results/mahalanobis_ab_results.json` (deterministic; no RNG).
All fits are benign-only; attack labels touch only the metrics. Run date: 2026-06-18.

## Results

| Detector | CIC2017 FPR | CIC2017 victim DR | LITNET-HTTP AUC | CIC-IoT-SYN AUC | 13-case mean AUC | CESNET FPR |
|---|---|---|---|---|---|---|
| **B0** OR ensemble (θ=4.0) | 76.1% | 99.6% | 0.216 | 0.631 | **0.882** | 3.49%¹ |
| **B1** 3-path conformal (Bonf.) | **42.3%** | 99.8% | — | — | — | — |
| **M1** Mahalanobis, single path | 0.3%² | **62.1%²** | **0.128** | **0.952** | **0.768** | **6.2%** |
| **M2** +Mahalanobis, 4-path (Bonf.) | 42.2% | 99.8% | — | — | — | — |

FPR/DR are per-window at the best operating point with victim DR ≥ 99% (B1, M2); ROC-AUC is
threshold-free on identical splits/features. ¹ z-path reference (paper §6.8). ² M1 has **no**
operating point at DR ≥ 99% — its victim DR caps at 63.8% across the whole α grid; the cell shows a
representative low-FPR point (α=0.005). B1/M2 are combination *rules*, not scores, so a single
threshold-free AUC is not defined for them; their AUC cells are blank by construction.

## Win-condition audit

Win = M1 or M2 strictly improves **both** (a) CIC-2017 FPR vs B1 **and** (b) ≥1 worst-case AUC vs B0,
with **no material regression** on CESNET FPR or the 13-case mean.

- (a) FPR vs B1 (42.3%): **M1 fails** — it cannot reach victim DR ≥ 99% at any α (caps at 63.8%).
  **M2 = 42.2%**, a 0.1 pp move within pool noise, not an improvement.
- (b) worst-case AUC vs B0: **CIC-IoT-SYN 0.631 → 0.952 (met)**; LITNET-HTTP 0.216 → 0.128 (worse).
- Regression: **13-case mean 0.882 → 0.768 (−0.114, material)** and **CESNET FPR 3.49% → 6.2% (~1.8×)**.
  Both regression gates fail.

Neither configuration satisfies the win condition. Per the brief, this is reported as a negative and
the work stops here — no C-engine port, no paper edits, no per-corpus tuning of α/shrinkage/features.

## Why it fails (the science in the negative)

1. **Covariance-awareness is attack-structure-specific, not a general FPR lever.** It wins exactly
   when an attack *distorts* the feature correlation — CIC-IoT SYN flood (SYNs up, completion/flows
   off their benign ratio): 0.631 → 0.952. It collapses when an attack scales features *proportionately*
   — CIC-2018 Hulk 0.990 → 0.241, CIC-DDoS2019 0.945 → 0.769, CIC-IoT ICMP-Frag 0.884 → 0.181, and the
   CIC-2017 LOIC flood (DR capped at 63.8%). The brief's hypothesis ("attacks move off-manifold") holds
   for protocol-distorting attacks and is **false for proportionate volumetric floods**, which ride the
   benign manifold and are read as benign — the same property that gives M1 its excellent 0.3% FPR.
2. **As an ensemble member it does not move the FPR floor.** M2 (4 paths under Bonferroni) = 42.2% vs
   B1's 42.3%: the OR-conformal FPR is dominated by the z/CUSUM/JSD paths, and adding a 4th path at
   α/4 barely shifts it. Collapsing the OR into one multivariate statistic (M1) does cut FPR sharply,
   but only by also discarding detection of on-manifold floods.
3. **The conformal bound degrades on CESNET (6.2% at α=0.03).** The 60/15/25 chronological split is
   not exchangeable across CESNET's hourly drift, so the right-tail p-values under-cover by ~2×.

## Caveats worth recording

- **Higher warm-up requirement.** Fitting a d≈34 covariance needs ≥~134 benign windows per context;
  84 of 530 CIC-2017 IPs were skipped for too little benign history (the z-path needs far less). B0
  therefore reads 76.1% on the reduced 446-IP pool vs the then-committed 75.4% (α = 0.2-era) on the full pool. The A/B is
  internally fair (all configs share the 446-IP pool), but the larger data appetite is a real
  deployability cost.
- **Not novel vs the existing baseline.** `streaming_baselines.pewma_scores` is already a static-
  covariance Mahalanobis distance (the "PEWMA 0.676" on LITNET-HTTP, paper §6.5). M1's only deltas are
  Ledoit-Wolf shrinkage (vs diagonal loading) and use as the *primary* conformal path. M1's LITNET-HTTP
  AUC (0.128) is in fact below PEWMA's (0.676), so even the one prior covariance-aware win does not
  reproduce here under Ledoit-Wolf + this split — the gain is fragile, not a robust property.

## Verdict (3 sentences)

A training-free per-IP Mahalanobis path is an excellent false-positive suppressor but a poor detector
of proportionate volumetric floods, because those attacks scale all features along the benign
correlation manifold and are scored as on-manifold — the exact mechanism that makes its FPR low also
makes it blind to the dominant CIC-2017/CIC-2018/CIC-DDoS attack class (victim DR ≤ 64%). It helps only
for protocol-distorting attacks (CIC-IoT SYN flood 0.631 → 0.952), regresses the 13-case mean AUC
(0.882 → 0.768) and CESNET FPR (3.49% → 6.2%), and adds nothing to the ensemble FPR floor (M2 42.2% ≈
B1 42.3%). The covariance idea is therefore not a general improvement to this detector; the honest,
useful takeaway is that covariance-awareness is **attack-structure-specific** and would only belong as
a narrowly-scoped SYN/protocol-distortion sub-path, not as a replacement for or addition to the
shipped ensemble.
