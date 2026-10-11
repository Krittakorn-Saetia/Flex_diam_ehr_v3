#!/usr/bin/env bash
# run_exp2.sh — one run of Experiment 2 (scoped user revocation overhead) on the live Fabric network.
# Environment variables of the driver pass through (TRIALS, PILOT, OUT, ...).
set -e
cd "$(dirname "$0")"
. ./env.sh
"$FLEX_PY" exp2_scoped_revocation.py
