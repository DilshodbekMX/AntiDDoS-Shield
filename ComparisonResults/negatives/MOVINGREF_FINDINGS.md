# Moving-reference (NEWMA / two-timescale RFF-MMD) change path — A/B findings

**Verdict: NEGATIVE.** A moving-reference change path (the one training-free idea, out of 33 surveyed,
that *structurally* targets the cross-day stale-reference root cause) provides **no net detection or
false-alarm value over having no middle path at all**, and its detection collapses on sustained floods.
The negative is decisive because of a control arm (`NONE = z ∨ JSD`) that bounds any middle-path swap.

## What it is

Replace the non-resetting CUSUM path with a NEWMA statistic (Keriven, Garreau & Poli, *IEEE TSP* 68,
2020; arXiv:1805.08061): per-window feature vector `x_t` over the active set (30 features, `log1p` on the
four cardinality features), standardized by benign-train mean/scale, mapped through a fixed Gaussian
random-Fourier embedding `φ(x) ∈ R^D`. Keep two EWMAs of `φ` — `z_fast` (α=0.10) and `z_slow` (α=0.02) —
and score `s_t = ‖z_fast − z_slow‖₂`. Slow cross-day benign drift is present in **both** EWMAs and cancels
in the gap, so the reference cannot go stale by construction; only an abrupt break survives. Turned into a
split-conformal path (benign-calibration right-tail p-value, headline `α_mr=0.01`), training-free, O(D)
memory/work. Params: `D=256`, seed `1234`, σ = median heuristic on benign-train, burn-in 200.

## Results — CIC-IDS-2017 cross-day (Monday→Friday), 1 victim + 150 uninvolved IPs, episode level (30 s cooldown)

| Op point | Arm | epi/IP/day (95% IP-cluster CI) | per-window FPR % | victim DR % |
|---|---|---|---|---|
| fixed θ=4.0 | B0 = z ∨ CUSUM ∨ JSD | 123.8 [108.8, 140.1] | 61.55 | 99.30 |
| | **CAND = z ∨ MOVINGREF ∨ JSD** | 118.9 [104.0, 135.1] | 60.18 | 99.30 |
| | **NONE = z ∨ JSD (control)** | 119.1 [104.2, 135.1] | 59.95 | 99.30 |
| calibrated | B0 | 78.3 [66.2, 90.6] | 34.99 | 99.16 |
| | **CAND** | 68.2 [57.8, 79.3] | 31.84 | 99.16 |
| | **NONE = z ∨ JSD (control)** | 66.9 [56.6, 77.8] | 31.00 | 99.16 |
| op-independent | MOVINGREF-alone | 2.94 [1.8, 4.2] | 1.30 | **23.13** |

**Paired IP-clustered bootstrap (same IPs):**
- `CAND − B0`: fixed Δ = −4.87 epi/IP/day [−7.08, −2.59]; calibrated Δ = −10.13 [−15.45, −6.11]. Looks like a win.
- `CAND − NONE` (**the decisive control** — MOVINGREF's value over dropping the middle path): fixed Δ = **−0.13 epi/IP/day [−0.57, +0.22]** (spans 0, p(no-improvement)=0.32); calibrated Δ = **+1.27 [+0.59, +2.24]** and Δ per-window FPR **+0.84 pp** — MOVINGREF makes it *worse*.

Baseline fidelity anchor: B0 fixed-θ per-window FPR 61.55% reproduces the committed 61.6%, victim DR 99.3%
reproduces committed ~99.3%. Diagnostic: the raw `s_t` statistic has victim AUC 0.835 (onset signal
exists), but that does not translate into episode-level ensemble value.

## Win-condition audit

Win = strictly improve episode-level cross-day FPR vs B0 **and** no material DR regression.
- FPR: `CAND < B0` is real but **entirely attributable to removing CUSUM** — `B0 − NONE` = CUSUM's unique
  false-alarm contribution (4.7 fixed / 11.4 calibrated epi/IP/day). Against the correct control (`NONE`),
  MOVINGREF's net contribution is statistically zero (fixed) or harmful (calibrated). **FAIL.**
- DR: the `CAND` guardrail passes (99.3%) but only because DR is carried by the unchanged z-path; the
  path's own DR (`MRALONE`) is **23.1%**. **FAIL on the merits.**

## Why it fails (the science in the negative)

1. **The cross-day FPR floor is z-path-dominated and OR-pass-through.** In a disjunctive OR ensemble, any
   single non-z middle-path swap is capped at the `z ∨ JSD` floor (≈60% / 31% per-window; 119 / 67
   epi/IP/day) — undeployable and *unchanged*. By construction the best `CAND` can do is match `NONE`; it
   cannot beat it. No moving-reference hyperparameter (D, α_fast/α_slow, α_mr) can move a floor set by a
   path it does not replace. Corroborates the project's prior finding that the volume/z-path dominates the
   false-alarm budget.
2. **Drift-cancellation and sustained-attack detection are in fundamental tension.** The moving reference
   cancels *slow* shifts by design; a sustained flood is a slow shift to the slow EWMA, which saturates so
   the gap closes (`s_t` decays back toward the benign max within the flood → DR-alone 23%). It replaces
   CUSUM's *role* (the sustained-shift path) with a detector explicitly blind to sustained shifts. The
   shipped z-path keeps its DR precisely because it **freezes** during attack — which is the very thing
   that makes it cross-day stale. You cannot get both from one per-IP temporal statistic.
3. Net: `CAND ≈ "delete CUSUM."` If the goal were only to shed CUSUM's few pp of FPR, drop the path —
   MOVINGREF adds nothing and (calibrated) slightly regresses.

## Caveats worth recording

- Novelty was independently refuted upstream: NEWMA is off-the-shelf and its 2025 RFF-MMD successor adds
  optimality proofs, so even a positive result could only have been an *application/systems* contribution.
- Scoped to CIC-IDS-2017 cross-day (the acute stale-reference case), 150-uninvolved deterministic cap,
  committed caches. The z-path-dominance and freeze/move-tension arguments are architectural, not
  corpus-specific, so they generalize; the exact deltas do not.
- The only structurally-remaining training-free levers both look weak: a *moving z-path* hits the same
  freeze/move tension; ensemble-level cross-IP spatial coincidence suppresses single-victim benchmark
  attacks (sub-k) and overlaps the existing subnet-aggregation workstream.

## Verdict (3 sentences)

A moving-reference change path is the only training-free idea that structurally attacks the cross-day
stale-reference root cause, but against the correct control (`z ∨ JSD`) it contributes zero net FPR
reduction and slightly regresses under calibration, while its own detection collapses to 23% on sustained
floods. The result localizes the floor to the **z-path × OR-fusion** — a middle-path swap cannot move it —
and exposes a fundamental tension between benign-drift cancellation and sustained-attack detection.
Per the staged protocol: **stop; no C port, no paper claim.** Reproduce with
`cd experiment && PYTHONPATH="$PWD" python3 negatives/run_movingref_ab.py`
(→ `negatives/movingref_ab_results.json`).
