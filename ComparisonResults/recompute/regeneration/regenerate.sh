#!/bin/bash
# Regenerate the 29 result records (of the 49 in ../../results/) that the runners listed below write, then the derived
# numbers in ../. The other 20 are inputs, records restricted by hand, or records whose writers are not run here;
# pass_comparison.tsv gives the reason for each. Run from anywhere.
# The runners read the derived feature tree at $ANTIDDOS_BASE/datasets/extracted/ (default: the repository root), which
# is not deposited. ../../extraction/ rebuilds it and ../../extraction/tree_manifest/ pins its checksums, except for
# four per-day caches that no deposited script writes as used, behind 10 of the 16 panel scenarios (../../extraction/README.md).
# Records are written single-threaded: the DIF arm's fifth decimal depends on the BLAS thread count. LODA in the
# archived module post2023_competitors.py is unseeded and changes on every run, and ten records store elapsed_sec,
# so compare a re-run with the deposited records by value (e.g. as pass_comparison.tsv does), not by hash.
# Usage: regenerate.sh [python]   (default python3; needs numpy, scipy, scikit-learn, torch (for DIF), pyod 3.6.5,
# and gcc for runners/run_c_engine_ours.py, which compiles the engine from project/layer2/ at the repository root)
set -u
CR=$(cd "$(dirname "$0")/../.." && pwd); L=$CR/recompute/regeneration/logs; mkdir -p "$L"
export ANTIDDOS_BASE=${ANTIDDOS_BASE:-$(dirname "$CR")} ANTIDDOS_OVERWRITE=1 SC_INTRACK_ONLY=1 CS_ALLOW_PARTIAL=0
export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1
PY=${1:-python3}
cd "$CR"
run () { local name=$1; shift; ( "$@" > "$L/$name.log" 2>&1; echo "exit $?" >> "$L/$name.log" ); echo "done $name: $(tail -n1 "$L/$name.log")"; }
# wave 1: each runner reads only the panel inventory and the tree
run clock_null            $PY runners/run_clock_null.py &
run scenarios29           $PY runners/run_29_scenarios_corrected.py &
run corrected_full        $PY runners/run_corrected_benchmark_full.py &
run matched_smoothing     $PY runners/run_matched_smoothing.py &
run split_deposited       env ANTIDDOS_SPLIT= SC_OUT=split_control_deposited_benchmark.json SC_MATRIX_OUT=split_control_deposited_matrix.json $PY runners/run_split_control.py &
run split_threeway40      env ANTIDDOS_SPLIT=threeway40 SC_OUT=split_control_threeway40_benchmark.json SC_MATRIX_OUT=split_control_threeway40_matrix.json $PY runners/run_split_control.py &
run split_threeway60      env ANTIDDOS_SPLIT=threeway60 SC_OUT=split_control_threeway60_benchmark.json SC_MATRIX_OUT=split_control_threeway60_matrix.json $PY runners/run_split_control.py &
run clock_split           $PY runners/run_clock_split_sensitivity.py &
run adjacency_fpr         $PY runners/run_adjacency_free_fpr.py &
run adjacency_episodes    $PY runners/run_adjacency_free_episodes.py &
run order_sensitivity     $PY runners/run_order_sensitivity.py &
run dif_seed              $PY runners/run_dif_seed_sensitivity.py &
run ewma_ablation         $PY runners/run_ewma_ablation.py &
run post2023              $PY runners/run_post2023_benchmark.py &
run tournament            $PY runners/run_universal_ewma_tournament.py &
run validation            $PY runners/run_subspace_ecod_validation.py &
run c_engine_ours         $PY runners/run_c_engine_ours.py &
run usable29              $PY runners/run_29_usable_benchmark.py &
run final_evaluation      $PY runners/run_final_evaluation.py &
run fpr_dr_optimization   $PY runners/research_fpr_dr_optimization.py &
run batch_invariance     $PY runners/verify_inductive.py &
wait
# wave 2: reads wave-1 records
run ledger                $PY runners/run_admissibility_ledger.py
run joint_filter          $PY runners/run_joint_filter.py
run table_provenance      $PY runners/run_table_provenance.py
# derived numbers the manuscript prints
$PY recompute/four_corpus_tables.py results recompute && $PY recompute/extra_numbers.py results recompute && $PY recompute/tables_v4.py results recompute results
echo ALL-DONE
