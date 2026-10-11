#!/usr/bin/env bash
# run_exp1.sh — one run of Experiment 1 (authorization throughput) on the live Fabric network.
# Environment variables of the driver pass through (TRIALS, PILOT, OUT, ...).
set -e
cd "$(dirname "$0")"
. ./env.sh
"$FLEX_PY" exp1_authz_throughput.py
