#!/bin/bash
# Post hoc re-score of the held-out operating point (manuscript Tables 4 and A7) under the repaired 40/40/20 split:
# fit on the first 40% of each victim's pre-attack benign windows, calibrate on the next 40%, and return the last
# fifth to the test stream (ANTIDDOS_SPLIT=threeway40 in runners/run_29_scenarios_corrected.py, whose load_case_tree
# the two adjacency-free runners share). Writes the three *_threeway40.json records to ../results/; the deposited-split
# records in ../../results/ are untouched. Needs the derived feature tree, like regenerate.sh. Run it before
# regenerate.sh, whose last step (../four_corpus_tables.py) summarizes these three records.
# Usage: heldout_threeway40.sh [python]
set -eu
CR=$(cd "$(dirname "$0")/../.." && pwd); PY=${1:-python3}
export ANTIDDOS_BASE=${ANTIDDOS_BASE:-$(dirname "$CR")} ANTIDDOS_OVERWRITE=1 ANTIDDOS_SPLIT=threeway40
export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1
cd "$CR"
env S29_OUTDIR=recompute/results S29_OUT=scenarios29_corrected_results_threeway40.json $PY runners/run_29_scenarios_corrected.py
env AFF_OUT=../recompute/results/adjacency_free_fpr_threeway40.json $PY runners/run_adjacency_free_fpr.py
env AFE_OUTDIR=recompute/results AFE_OUT=adjacency_free_episodes_threeway40.json $PY runners/run_adjacency_free_episodes.py
echo "wrote the three *_threeway40.json records to $CR/recompute/results/"
