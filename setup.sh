#!/usr/bin/env bash
# setup.sh — one-time build of everything that does not need the blockchain:
#   1. circomlib (reused from the V2 checkout when present, else npm install)
#   2. ZKP: oracle + authz circuits, credential-issuer key, Groth16 keys
#   3. native batch verifier (Go)
#   4. proof corpus for Experiment 1 (K proofs, default 32)
# Afterwards deploy the chaincode with chaincode/deploy_ccaas.sh.
set -e
cd "$(dirname "$0")"
. ./env.sh

if [ ! -d zkp/node_modules/circomlib ] && [ -d "$FLEX_INFRA/zkp/node_modules/circomlib" ]; then
  echo "=== reusing circomlib from $FLEX_INFRA/zkp/node_modules ==="
  mkdir -p zkp/node_modules
  cp -r "$FLEX_INFRA/zkp/node_modules/circomlib" zkp/node_modules/
fi

./zkp/build_zkp.sh

echo "=== building the native batch verifier ==="
# gnark-crypto needs Go >= 1.25.7; with GOTOOLCHAIN=auto (the default) an older
# `go` switches to that toolchain automatically.
( cd zkp/batchverify_native && go build -o batchverify_native . )

echo "=== generating the Experiment 1 proof corpus ==="
"$FLEX_PY" zkp/gen_corpus.py "${CORPUS:-32}"
FLEX_ZKP_BUILD="$PWD/zkp/build" zkp/batchverify_native/batchverify_native selftest

echo ""
echo "=== baseline implementations ==="
"$FLEX_PY" -m baselines.selftest

echo ""
echo "=== offline protocol check (in-memory ledger, no Docker) ==="
"$FLEX_PY" smoke_protocol.py --offline
