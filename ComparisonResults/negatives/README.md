# `negatives/` — characterized negative & scoped results (audit trail)

Detection ideas prototyped under the training-free A/B protocol that did **not** become a shipped
contribution. Kept (not archived) because they are — or are intended to be — cited in the paper's
limitations / characterization discussion. Each has a runner, its result JSON, and a findings note.

> **α-era note.** The B0/B1 reference figures quoted in the rows and notes below (13-case mean
> ROC-AUC **0.882**, CIC-IDS-2017 cross-day FPR **75.4%** fixed-θ / **40.4%** conformal, θ→∞ floor
> **≈26.6%**) were measured under the *retired* EWMA baseline α = 0.2/0.1/0.05. The current committed
> baseline is α = 0.15/0.05/0.01 (`config.py`), where they read **0.878 / 71.8% / 46.3% / ≈23.5%**.
> These are frozen honest-negatives: only the absolute reference point moved, and every *relative*
> A/B verdict stands. Measurements are left as recorded at experiment time.

## How to run (flat layout, parent on the path)

These reuse the shared harness in the parent directory (`config`, `baselines`, `run_anewma_allsets`,
`run_fpr_conformal`, …). Invoke with the parent `experiment/` on `PYTHONPATH`:

```bash
cd experiment
PYTHONPATH="$PWD" python3 negatives/run_innovation_ab.py
PYTHONPATH="$PWD" python3 negatives/test_mahalanobis.py     # unit test, fast
```

The private modules (`mahalanobis.py`, `innovation_path.py`) live here alongside their runners, so
intra-`negatives/` imports resolve locally while shared modules resolve to the parent.

## Contents

| Topic | Files | Result JSON | Verdict |
|---|---|---|---|
| **Mahalanobis** (Σ-aware path) | `run_mahalanobis_ab.py`, `mahalanobis.py`, `test_mahalanobis.py`, `MAHALANOBIS_FINDINGS.md`, `MAHALANOBIS_PROTOTYPE_BRIEF.md` | `mahalanobis_ab_results.json` | **Negative** — mean AUC 0.768 < ensemble 0.882; helps only protocol-distorting attacks, hurts proportionate floods. |
| **Structural** (inbound L3/L4 discriminators) | `run_structural_pilot.py`, `run_structural_gate_ab.py`, `STRUCTURAL_FINDINGS.md` | `structural_pilot_results.json`, `structural_gate_ab_results.json` | **Negative** — no universal lever; conjunctive veto can't beat B1 (40.4%) at usable DR. |
| **Innovation** (forecast-error path) | `run_innovation_ab.py`, `innovation_path.py`, `INNOVATION_FINDINGS.md` | `innovation_ab_results.json` | **Scoped** — 91% DR @ 0% cross-day FPR on abrupt floods (CIC-2017); collapses on gradual attacks (mean AUC 0.845). |
| **Moving-reference** (NEWMA / two-timescale RFF-MMD change path) | `run_movingref_ab.py`, `movingref_detector.py`, `MOVINGREF_FINDINGS.md` | `movingref_ab_results.json` | **Negative** — vs the `z∨JSD` control, net FPR value ≈0 (calibrated: +1.3 epi/IP/day); DR-alone 23% on sustained floods. Localizes the floor to the z-path × OR-fusion. |
| **Detector comparison** | `run_full_auc_table.py`, `run_full_drfpr_table.py` | `full_auc_table_results.json`, `full_drfpr_table_results.json` | Extended Table 13 (our 3 prototypes vs 7 baselines) + the heavy-tail DR/FPR diagnostic. |

None of these change any paper-cited number; the shipped detector and its evaluation are unchanged.
