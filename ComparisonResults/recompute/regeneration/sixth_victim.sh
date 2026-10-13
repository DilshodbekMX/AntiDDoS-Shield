#!/bin/bash
# Post hoc sixth-victim check: re-run both repaired splits on the 16-row panel plus LITNET-2020 smurf
# (../results/PANEL_sixvictim.json, 17 rows, 6 victims) with the deposited run_split_control.py, in a scratch copy
# so the deposited panel inventory is never touched. Writes the four *_sixvictim* records to ../results/.
# Usage: sixth_victim.sh [python]
set -eu
CR=$(cd "$(dirname "$0")/../.." && pwd); ROOT=$(dirname "$CR"); PY=${1:-python3}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/ComparisonResults/results/panel_inventory" "$T/datasets"
rsync -a --exclude 'results/' --exclude 'recompute/' --exclude '__pycache__/' "$CR/" "$T/ComparisonResults/"
cp "$CR/recompute/results/PANEL_sixvictim.json" "$T/ComparisonResults/results/panel_inventory/PANEL.json"
ln -s "$ROOT/datasets/extracted" "$T/datasets/extracted"; ln -s "$ROOT/project" "$T/project"
export ANTIDDOS_BASE=$T ANTIDDOS_OVERWRITE=1 SC_INTRACK_ONLY=1 CS_ALLOW_PARTIAL=0 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1
cd "$T/ComparisonResults"
for s in 40 60; do
  env ANTIDDOS_SPLIT=threeway$s SC_OUT=split_control_benchmark_threeway${s}_sixvictim.json \
      SC_MATRIX_OUT=split_control_threeway${s}_sixvictim_matrix.json $PY runners/run_split_control.py > "$T/r$s.log" 2>&1 &
done
wait
cp results/*_sixvictim*.json "$CR/recompute/results/"
echo "wrote $(ls results/*_sixvictim*.json | wc -l) records to $CR/recompute/results/"
