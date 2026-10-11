#!/usr/bin/env bash
# run_exp3.sh — one run of Experiment 3 (unaffected-user continuity) on the live Fabric network.
# Environment variables of the driver pass through (TRIALS, PILOT, OUT, ...).
set -e
cd "$(dirname "$0")"
. ./env.sh
"$FLEX_PY" exp3_unaffected_continuity.py
