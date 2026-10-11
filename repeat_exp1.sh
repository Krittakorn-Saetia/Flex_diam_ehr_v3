#!/usr/bin/env bash
# repeat_exp1.sh — Experiment 1 as REPEATS full independent runs (each one
# re-calibrates the chain, re-measures every crypto unit and re-runs the batch
# verifier), then the per-cell mean and stdev.
# Usage:  REPEATS=30 ./repeat_exp1.sh        (PILOT=1 for a quick shape check)
set -eo pipefail
R="${REPEATS:-30}"
cd "$(dirname "$0")"
. ./env.sh

# Earlier results are moved aside, never overwritten.
if compgen -G "exp1_rep*.csv" >/dev/null || [ -f exp1_authz_throughput.csv ]; then
  A="results_archive/$(date +%Y%m%d_%H%M%S)_exp1"
  mkdir -p "$A"
  mv exp1_rep*.csv "$A"/ 2>/dev/null || true
  for f in exp1_authz_throughput.csv exp1_authz_throughput_std.csv exp1_authz_throughput_detail.csv exp1_authz_throughput_detail_std.csv; do
    if [ -f "$f" ]; then mv "$f" "$A"/; fi
  done
  echo "previous Experiment 1 results moved to $A"
fi

reps=()
for i in $(seq 1 "$R"); do
  echo ""
  echo "################ Experiment 1 — run $i / $R ################"
  OUT="exp1_rep${i}.csv" ./run_exp1.sh | tail -3
  reps+=("exp1_rep${i}.csv")
done

"$FLEX_PY" average_csvs.py exp1_authz_throughput.csv "${reps[@]}"
echo "=== Experiment 1 done: mean -> exp1_authz_throughput.csv (+ _std.csv) ==="
