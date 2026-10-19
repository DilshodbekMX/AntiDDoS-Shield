# Pre-registration: re-run on all 39 engine feature names

Written 2026-10-19, before any record was computed on the new columns. Base: commit
9d51bdcbcb25beac54f9795d83200ce0f2ffe5e4. The authors decided that the evaluation uses
every feature the shipped engine scores (`project/layer2/baselines.c`, `l2_feature_names`,
39 names), so the 39-name set is the primary set of the paper and the deposit.

## Why this is post hoc

This is the third feature set used on these corpora, chosen after results under the first
two had been seen:

1. 39 names, two of them placeholder copies written by the offline extractor
   (`burst_factor` = `packets_per_sec`, `unique_flows` = `flows_per_sec`);
2. 37 names, the two copies removed (the deposit up to 9d51bdc);
3. 39 names, the two features computed the engine's way (this re-run).

All p-values stay descriptive, as before.

## Feature definitions

- `burst_factor`, as in `project/layer1/telemetry/burst_ewma.h` and
  `per_ip_features.c`:
  - `mean_post = x` if `mean_pre < 1`, else `mean_pre + 0.033 (x - mean_pre)`;
  - value `floor(100 x / mean_post)`, or 100 when `mean_post = 0`;
  - `x` is the window's `packets_per_sec` (packet captures: packets in the one-second bin;
    LITNET-2020: packets of the NetFlow records starting in the bin, both directions);
  - one EWMA per destination over the whole capture pass, in time order, from the
    destination's first window;
  - a second with no window for that destination is stepped with `x = 0`;
  - computed on the per-day caches before scenario files are cut, never on a slice.
- `unique_flows`: the number of distinct engine flow keys {lower address, higher address,
  protocol} among the window's packets (LITNET-2020: records) addressed to the
  destination. With the destination fixed, this is the number of distinct (source address,
  protocol) pairs. The count is exact, like the tree's `unique_src_ips`; the engine samples 1
  packet in 8 into a HyperLogLog. Where every source uses one protocol it equals
  `unique_src_ips`; the paper says so.
- `flows_per_sec` is unchanged: distinct 5-tuples per bin. It differs in kind from the
  engine's count of new flow-table entries, as the paper already states.

## Harness changes

Each change follows the engine, and each removes a divergence that existed only because the
column was missing:

- `unique_flows` joins the `ln(x+1)` set (`baselines.c:260-264`).
- `burst_factor` joins the harness CUSUM features (`advanced_detection.c:244-250`).
  `new_srcip_rate` stays out of the harness CUSUM because LITNET-2020 lacks it, as before.
- `feature_filter.PRODUCTION_39_FEATURES` lists all 39 names.

Nothing else changes: detector hyperparameters (k = 8, alpha = 0.5), splits, thresholds,
targets, seeds, the per-scenario zero-range filter and the four-check admissibility rule.

## Panel

The four-check classifier is re-run on the new tree. If the admitted set differs from the 16
scenarios of the 37-name analysis, the new set is primary and the 16-scenario results are
reported beside it.

## Reporting rule

- Every printed number with a deposited writer is recomputed on the 39-name tree.
- Records without a writer keep their values and are labelled with the feature set they used.
- The 37-name values of these headline statistics are reported beside the 39-name values,
  whatever their direction:
  - our margin over the reference and its Holm and victim-clustered p-values;
  - benign-alarm-episode ranks and differences at the held-out and oracle targets;
  - the clock-null comparison;
  - the matched-smoothing comparison;
  - the inductive-correction magnitudes;
  - the admissibility census.
- If a statistic changes significance at 0.05, rank, win count or sign, both values are
  printed and neither is preferred.

## Execution

Single-threaded BLAS (`OMP_NUM_THREADS=OPENBLAS_NUM_THREADS=MKL_NUM_THREADS=1`). The archived
module's LODA is unseeded and DIF's fifth decimal depends on the BLAS thread count; changes
there are not attributed to the features. Fixes to the Layer 1 `syn_proxy` and `flow_table`
code made at the same time enter no scored record, because the harness and
`run_c_engine_ours.py` use only Layer 2.
