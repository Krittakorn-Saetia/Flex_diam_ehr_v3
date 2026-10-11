#!/usr/bin/env bash
# repeat_exp3.sh — Experiment 3 (unaffected-user continuity) as REPEATS full
# independent runs, then the per-cell mean and stdev. The paper states "All
# results are averaged over 30 independent runs", hence REPEATS=30; inside each
# run every cell is measured TRIALS times (default 1 here, since the runs
# themselves are the independent samples).
# Usage:  ./repeat_exp3.sh        (REPEATS=5 PILOT=1 for a quick shape check)
set -eo pipefail
R="${REPEATS:-30}"
export TRIALS="${TRIALS:-1}"
cd "$(dirname "$0")"
. ./env.sh

# Earlier results are moved aside, never overwritten.
if compgen -G "exp3_rep*.csv" >/dev/null || [ -f exp3_unaffected_continuity.csv ]; then
  A="results_archive/$(date +%Y%m%d_%H%M%S)_exp3"
  mkdir -p "$A"
  mv exp3_rep*.csv "$A"/ 2>/dev/null || true
  for f in exp3_unaffected_continuity.csv exp3_unaffected_continuity_std.csv exp3_unaffected_continuity_detail.csv exp3_unaffected_continuity_detail_std.csv; do
    if [ -f "$f" ]; then mv "$f" "$A"/; fi
  done
  echo "previous Experiment 3 results moved to $A"
fi

reps=()
details=()
for i in $(seq 1 "$R"); do
  echo ""
  echo "################ Experiment 3 — run $i / $R ################"
  OUT="exp3_rep${i}.csv" ./run_exp3.sh | tail -14
  reps+=("exp3_rep${i}.csv")
  details+=("exp3_rep${i}_detail.csv")
done

"$FLEX_PY" average_csvs.py exp3_unaffected_continuity.csv "${reps[@]}"
"$FLEX_PY" average_csvs.py exp3_unaffected_continuity_detail.csv "${details[@]}"
echo "=== Experiment 3 done: mean -> exp3_unaffected_continuity.csv (+ _std.csv, _detail.csv) ==="
