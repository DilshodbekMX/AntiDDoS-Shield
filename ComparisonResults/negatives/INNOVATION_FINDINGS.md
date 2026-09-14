# Innovation (forecast-error) conformal path — findings

**Status: SCOPED POSITIVE. First lever that delivers high DR AND low FPR — but only for abrupt-onset
attacks. Not a universal replacement. Validate the scope before any C-engine / paper step.**

> **α-era note.** This is a frozen honest-negative. Its B0/B1 reference figures — CIC-IDS-2017
> cross-day FPR **75.4%** (fixed θ), **40.4%** (conformal), θ→∞ floor **≈26.6%**, and 13-case mean
> ROC-AUC **0.882** — were measured under the *retired* EWMA baseline α = 0.2/0.1/0.05. The current
> committed baseline is α = 0.15/0.05/0.01 (`config.py`), where those anchors now read **71.8% /
> 46.3% / ≈23.5% / 0.878**. Only the absolute reference point moved; the *relative* A/B verdict
> below is unchanged, and the frozen measurements are left exactly as recorded at experiment time.

Idea: score the one-step EWMA forecast error `gamma_t = |x_t - Z_{t-1}|` (surprise) instead of the
level `z = (x - mu)/sigma`. A smooth benign burst is predictable (low surprise → no alarm); an abrupt
flood is a jump (high surprise → alarm). Code: `innovation_path.py`, `run_innovation_ab.py`. Results:
`results/innovation_ab_results.json`. CIC-IDS-2017 cross-day pool (530 uninvolved + victim), same
protocol as `run_fpr_conformal.py`. Deterministic, training-free (Γ̄/Σ and forecast fit on benign only).

## CIC-IDS-2017 (the FPR-problem corpus): a real win

| Config | victim DR | uninvolved FPR | |
|---|---|---|---|
| B1 conformal(z,CUSUM,JSD), Bonferroni | 99.8% | **40.4%** | high DR, high FPR |
| **I0 innovation-only conformal**, α=5e-4 | **90.8%** | **0.0%** | |
| **I0**, α=5e-3 | **93.6%** | 5.5% | |
| I1 conformal(INNOV,CUSUM,JSD) | 89–94% | 32.8%+ | mixing reintroduces FPR |
| Iadd 4-path (z,INNOV,CUSUM,JSD) | 99.8% | 40.3% | OR-compounding, no help |

**~91% DR at 0.0% FPR**, vs B1's 99.8% at 40.4%. Per-episode (victim): detection rises 66% (onset
ramp) → 97.9% → **100% sustained** through the rest of the attack; the ~9% per-window miss is the
earliest low-rate ramp windows only — the flood is flagged promptly and continuously.

**Why 0% FPR (the mechanism):** the level path's conformal calibration does NOT transfer across the
Monday→Friday shift (≈40% realized FPR at nominal α). The innovation statistic is level-RELATIVE
(forecast error, not magnitude), so its calibration IS cross-day stable — benign Friday windows stay
low-surprise and almost none exceed the calibrated tail. Distribution-shift robustness, not luck.

## Scope: where it works and where it fails (the honest boundary)

The innovation statistic is the AnEWMA statistic (anewma.py), so its cross-corpus behavior is already
measured (`results/anewma_allsets_results.json`, threshold-free AUC and DR@5%FPR):

| Corpus / attack | innovation AUC | DR@5%FPR | level z-path AUC |
|---|---|---|---|
| CIC-IDS-2017 (LOIC) | **0.944** | 92.6% | 0.881 |
| CIC-IoT SYN_Flood | **0.983** | 84.4% | 0.631 |
| CIC-IoT SlowLoris | 0.992 | 91.2% | 0.967 |
| CIC-IoT HTTP_Flood | 0.998 | 98.0% | 0.996 |
| LITNET Code Red / Smurf | 0.989 / 1.000 | 93 / 100% | 0.995 / 1.000 |
| CIC-DDoS2019 | 0.925 | 46.3% | 0.945 |
| **CIC-IDS-2018 Wed (LOIC-UDP+HOIC)** | **0.674** | **10.6%** | 0.992 |
| **CIC-IDS-2018 Thu (GoldenEye+Slowloris)** | **0.704** | 37.2% | 0.989 |
| **CIC-IoT ICMP-Fragmentation** | **0.303** | 2.1% | 0.884 |
| **LITNET HTTP flood** | 0.540 | 0.0% | 0.216 |

13-case mean AUC: innovation **0.846** < level ensemble **0.882**. It wins on **abrupt-onset
volumetric/protocol floods** and collapses on **gradual / low-rate / multi-vector** attacks
(GoldenEye, Slowloris, slow HTTP, fragmentation) — exactly the forecast-tracking blind spot: a slow
ramp is tracked by `Z`, so its forecast error stays small and it is under-detected.

## Verdict (3 sentences)

An innovation (forecast-error) conformal path achieves ~91% detection at 0.0% cross-day false-positive
rate on CIC-IDS-2017 — high DR AND low FPR — because, unlike the level z-path, its calibration is
distribution-shift robust, and it flags abrupt floods promptly and sustains 100% through the episode.
It is NOT a universal replacement: on gradual / low-rate attacks (GoldenEye, Slowloris, slow HTTP,
ICMP-fragmentation) the slow forecast tracks the ramp and detection collapses (AUC 0.30–0.70), so its
13-case mean AUC (0.846) trails the level ensemble (0.882). The correct integration is therefore an
additional low-FPR DETECTION MODE for the in-scope abrupt-onset L3/L4 flood threat model — not a
swap-out of the ensemble — and that scoped claim is what a C-engine port and paper section may make,
pending the confirmation runs below.

## Before C-engine / paper (required confirmation, not yet run)

1. Re-measure I0 with the FPR/DR conformal protocol (not the AUC proxy) on the other abrupt-onset
   corpora (CIC-DDoS2019, CIC-IoT SYN_Flood) — confirm the 0%-FPR/high-DR point reproduces.
2. CESNET benign-FPR regression for I0 (must stay ≤ the level path's 3.49%, expected lower given the
   cross-day stability).
3. Decide the integration shape: innovation as an operator-selectable low-FPR mode vs. a co-equal
   conformal path gated by a regime detector (abrupt vs gradual). Do NOT ship it as an ensemble
   replacement — that regresses gradual-attack detection.
