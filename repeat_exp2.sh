#!/usr/bin/env bash
# repeat_exp2.sh — Experiment 2 (scoped user revocation overhead) as REPEATS full
# independent runs, then the per-cell mean and stdev. The paper states "All
# results are averaged over 30 independent runs", hence REPEATS=30; inside each
# run every cell is measured TRIALS times (default 1 here, since the runs
# themselves are the independent samples).
# Usage:  ./repeat_exp2.sh        (REPEATS=5 PILOT=1 for a quick shape check)
set -eo pipefail
R="${REPEATS:-30}"
export TRIALS="${TRIALS:-1}"
cd "$(dirname "$0")"
. ./env.sh

# Earlier results are moved aside, never overwritten.
if compgen -G "exp2_rep*.csv" >/dev/null || [ -f exp2_scoped_revocation.csv ]; then
  A="results_archive/$(date +%Y%m%d_%H%M%S)_exp2"
  mkdir -p "$A"
  mv exp2_rep*.csv "$A"/ 2>/dev/null || true
  for f in exp2_scoped_revocation.csv exp2_scoped_revocation_std.csv exp2_scoped_revocation_detail.csv exp2_scoped_revocation_detail_std.csv; do
    if [ -f "$f" ]; then mv "$f" "$A"/; fi
  done
  echo "previous Experiment 2 results moved to $A"
fi

reps=()
details=()
for i in $(seq 1 "$R"); do
  echo ""
  echo "################ Experiment 2 — run $i / $R ################"
  OUT="exp2_rep${i}.csv" ./run_exp2.sh | tail -14
  reps+=("exp2_rep${i}.csv")
  details+=("exp2_rep${i}_detail.csv")
done

"$FLEX_PY" average_csvs.py exp2_scoped_revocation.csv "${reps[@]}"
"$FLEX_PY" average_csvs.py exp2_scoped_revocation_detail.csv "${details[@]}"
echo "=== Experiment 2 done: mean -> exp2_scoped_revocation.csv (+ _std.csv, _detail.csv) ==="
