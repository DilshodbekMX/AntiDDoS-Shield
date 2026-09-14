# Implementation Brief: Covariance-Aware (Mahalanobis) Detection Path for Layer-2

**Audience:** an autonomous coding agent with full access to the AntiDDoS Shield repo
(`/home/detector/Projects/antiddos`) but **no prior conversation context**. Read this brief
end-to-end before writing code. Everything you need is here or in the cited harness files.

> **α-era note.** The target/reference figures in this brief — CIC-IDS-2017 cross-day FPR **75.4%**
> (fixed θ), **40.4%** (conformal), θ→∞ floor **≈26.6%**, and 13-case mean ROC-AUC **0.882** — are
> from the *retired* EWMA baseline α = 0.2/0.1/0.05. The current committed baseline is
> α = 0.15/0.05/0.01 (`config.py`), where those anchors read **71.8% / 46.3% / ≈23.5% / 0.878**. The
> Mahalanobis path was measured (see `MAHALANOBIS_FINDINGS.md`) and rejected; this brief is retained
> as the negative's specification, not as a live task.

---

## 1. Mission (one sentence)

Add a **training-free, per-destination, streaming covariance-aware (Mahalanobis) anomaly path** to
the Layer-2 evaluation harness, compose it with the existing conformal combiner, and **A/B-test
whether it lowers false-positive rate AND raises detection on the hardest cases** versus the current
`z ∨ CUSUM ∨ JSD` ensemble — measured on the committed caches, with no attack labels used for fitting.

This is a **harness prototype only**. Do **not** modify the production C engine (`layer2/*.c`). If the
result is positive, wiring it into C is a separate, later task.

## 2. Why (the diagnosis this addresses)

The current detector scores each of ~39 features independently and combines them disjunctively
(`detected = max-z over features ≥ θ  ∨  CUSUM  ∨  JSD`). Two consequences, both measured:

- **High FPR that aggregation does not fix.** On CIC-IDS-2017, per-window uninvolved FPR was 75.4% (α = 0.2-era; 71.8% at the current α = 0.15)
  at θ=4.0; conformal calibration brings it to 40.4%; a flow-level re-accounting still leaves **58.4%**.
  The FPR is real, not a windowing artifact. Root cause: a **benign burst moves correlated features
  together** (pps, bytes, flows rise in their usual ratio), and the per-feature max-z fires on it. The
  detector has **no model of the joint/correlation structure of benign traffic**.
- **Worst-case detection collapse.** On LITNET HTTP flood the ensemble scores ROC-AUC **0.216**
  (below chance). The only baseline that recovered it (0.676) was **PEWMA — the one covariance-aware
  detector** in the comparison grid (it scores by Mahalanobis distance against a benign covariance).

**Hypothesis:** a Mahalanobis distance against the benign feature covariance suppresses on-manifold
benign bursts (→ lower FPR) while still firing on off-manifold attack structure such as single-source
floods or spoofed cardinality spikes (→ preserved/raised DR). Collapsing the OR-of-paths into one
multivariate statistic also removes the path-compounding that inflates FPR (the measured CUSUM∪JSD
floor is ≈26.6%).

## 3. The method

For each monitoring context (one protected destination IP) and the corpus's **active feature set**
`A` (see §5, step 1):

1. **Feature vector.** Build `x_t ∈ R^d` over `A`. Apply `log1p` to the cardinality features
   present in `A` — `unique_src_ips`, `unique_dst_ports`, `unique_flows`, `dst_port_density` —
   matching the z-path's in-baseline log transform. No other scaling (Mahalanobis standardizes via Σ⁻¹).
2. **Fit on benign only (training-free).** On the benign **train** split (60%), estimate the mean
   `μ ∈ R^d` and a **shrunk** covariance `Σ` using Ledoit–Wolf
   (`sklearn.covariance.LedoitWolf`) → well-conditioned, invertible. Store `μ`, the precision `Σ⁻¹`,
   and the shrinkage intensity λ. **No attack labels touch this fit.**
3. **Score.** `d²(x) = (x − μ)ᵀ Σ⁻¹ (x − μ)` (use `LedoitWolf.mahalanobis()`; it returns d²).
   Right tail = anomalous. Under a benign Gaussian, `d² ~ χ²_d`.
4. **Conformal p-value.** Compute `d²` on the held-out benign **calibration** split (15%), sort it,
   and for each test window take the right-tail split-conformal p-value
   `p = (#calib ≥ d²_test + 1)/(n+1)` — **reuse `pval()` from `run_fpr_conformal.py`**.
5. **Decision.** Alarm if `p ≤ α`. A single path needs **no** family-wise correction. Sweep
   `α ∈ ALPHAS` (defined in `run_fpr_conformal.py`).

**Streaming variant (second iteration, only if step 2 wins).** Replace the batch benign-fit with an
EWMA covariance `S_t = (1−β) S_{t−1} + β (x−μ_{t−1})(x−μ_{t−1})ᵀ` plus diagonal loading `S+εI` for
invertibility, `β = TIER1_ALPHA`. This is the production-faithful form; the batch-on-benign-train
form above is the correct **first** A/B because it is stable and matches the harness's train/calib/test
protocol. Do the batch version first.

## 4. Numerical & training-free guardrails

- Ledoit–Wolf shrinkage is **mandatory** — `d` can approach the benign-sample count per IP, so the raw
  covariance is singular. Do not invert a raw `S`.
- Cap `d²` (e.g. at 1e6) and skip contexts with fewer than `~2·d` benign train rows (document the floor;
  rely on shrinkage for borderline cases).
- **Training-free invariant:** `μ`, `Σ` fit on benign rows only. Attack labels are used **exclusively**
  to compute DR / FPR / ROC-AUC after scoring, never to fit or to pick α per result.
- **Determinism:** fixed seed (reuse the harness seed in `config.py`); no wall-clock/`random` nondeterminism.

## 5. A/B experiment

### Configurations (all training-free, identical splits & active features)

| ID | Detector |
|----|----------|
| **B0** | Current OR ensemble `tier-z ∨ CUSUM ∨ JSD` at θ=4.0 (shipped default) |
| **B1** | Current conformal combination (z, CUSUM, JSD paths under Bonferroni / e-value) — reuse `run_fpr_conformal.py` |
| **M1** | Mahalanobis-conformal, **single path** (the main hypothesis) |
| **M2** | Mahalanobis **added** to {z, CUSUM, JSD} under FWER (4 paths) |

### Target measurements

1. **CIC-IDS-2017** — uninvolved external pool (530 IPs): per-window **FPR**; victim
   `192.168.10.50`: **DR**. Hypothesis: `FPR(M1) < FPR(B1)=40.4% < FPR(B0)=75.4%`, victim DR ≥ ~99%.
2. **LITNET HTTP flood** victim — threshold-free **ROC-AUC** of the Mahalanobis score. Current z-path
   0.216, PEWMA 0.676. Hypothesis: M1 AUC ≳ 0.6.
3. **CIC-IoT SYN_Flood** victim — **ROC-AUC**, current 0.631. Hypothesis: ≥ 0.631.
4. **Regression checks** — CESNET benign **FPR** (must stay near 3.49%, not blow up) and the 13-case
   mean ROC-AUC (must not materially regress from 0.882).

### Loaders (reuse, do not re-extract)

- CESNET: `data_loader.load_per_ip(...)`
- LITNET per-IP: `litnet_loader.load_litnet_per_ip(...)`
- CIC-IDS-2017 / CIC-DDoS / CIC-IDS-2018 / CIC-IoT: the per-IP pcap caches the existing
  `run_cicids2017_pcap.py`, `run_litnet.py`, `run_cicios2023_pcap.py` already consume (find the cache
  paths in those runners; do not re-parse raw pcaps).

### Splits, features, constants (from `config.py` / `feature_filter.py`)

- `TRAIN_FRAC=0.60`, `CALIB_FRAC=0.15`, test = remainder; attack windows → test only.
- Active features: `filter_active(PRODUCTION_39_FEATURES, benign_sample_rows)` per corpus.
- `ALPHAS`, `pval`, `akey`, `combine_decisions`, `PathScorer` live in `run_fpr_conformal.py` — import them.

## 6. Deliverables

1. `experiment/mahalanobis.py` — `class MahalanobisPath` with
   `fit(benign_rows, active_features)` → stores μ, precision, λ; `score(row)` → d²; helpers to build
   the log-transformed vector. Pure, unit-testable, no global state.
2. `experiment/run_mahalanobis_ab.py` — runs B0/B1/M1/M2 across the four target corpora, writes JSON.
   Reuse `PathScorer`, `pval`, loaders, split logic. Deterministic.
3. `experiment/results/mahalanobis_ab_results.json` — full per-config numbers + metadata
   (seed, split fractions, active features per corpus, per-IP shrinkage λ summary, α grid).
4. `experiment/MAHALANOBIS_FINDINGS.md` — one results table
   (detector × {CIC2017 FPR, CIC2017 victim DR, LITNET-HTTP AUC, CIC-IoT-SYN AUC, 13-case mean AUC,
   CESNET FPR}) and a 3-sentence **honest** verdict.
5. A unit test (`experiment/test_mahalanobis.py` or under `tests/unit_python/`): synthetic on-manifold
   vs off-manifold points — off-manifold `d²` must be ≫ on-manifold for the same Euclidean distance.

## 7. Success criteria & honest-negative protocol

**Win** = M1 (or M2) **strictly improves both**: (a) CIC-IDS-2017 FPR vs B1, **and** (b) at least one of
{LITNET-HTTP, CIC-IoT-SYN} worst-case ROC-AUC vs B0 — with **no material regression** on CESNET FPR or
the 13-case mean.

If the win condition is **not** met, **report the measured numbers as a negative result** in
`MAHALANOBIS_FINDINGS.md`. Do **not** tune α, shrinkage, or feature subsets per-corpus to manufacture a
win — that would leak evaluation into the method and is the exact failure mode this project's prior
audits exist to catch. A clean negative ("joint-covariance structure does not separate these benign
bursts from attacks at 1 Hz") is a publishable, valuable finding.

## 8. Project conventions you must honor

- **The committed harness is the source of truth for paper numbers.** Match existing constants, splits,
  log-transform, and feature filtering exactly; deviations must be justified in `MAHALANOBIS_FINDINGS.md`.
- **No attack labels in any fit or per-result α choice** (training-free guarantee).
- **Do not modify `layer2/*.c` / production C.** Harness only.
- **Do not commit to git** unless explicitly asked.
- **No fabricated numbers or citations.** Every number traces to a committed JSON / a run you executed.
- Reuse before reinventing: `PathScorer`, `pval`, `filter_active`, the loaders, `config.py`.
