#!/usr/bin/env bash
# build_zkp.sh — one-time ZKP setup for FLEX-DIAM (Phase 1 Step 1):
#   1. compile the witness-only oracle circuit
#   2. generate the credential issuer key pk_CI and bake it into the authz circuit
#   3. compile the authz circuit (eq. 19-22) and run the Groth16 setup -> (PK_zk, VK_zk)
# Produces build/authz.zkey, build/authz_vk.json, build/authz_js/, build/ci_key.json.
set -e
cd "$(dirname "$0")"

POT="${POT:-13}"   # 2^13 = 8192 >= 3,810 constraints of the authz circuit

command -v circom >/dev/null || { echo "circom not on PATH"; exit 1; }
command -v snarkjs >/dev/null || { echo "snarkjs not on PATH (source nvm)"; exit 1; }

# circomlib provides Poseidon, Baby-Jubjub and the EdDSA-Poseidon verifier
if [ ! -d node_modules/circomlib ]; then
  echo "Installing circomlib..."
  npm install circomlib
fi

mkdir -p build
echo "=== [1/5] Compiling oracle.circom (witness calculator only) ==="
circom oracle.circom --wasm -l node_modules -o build

echo "=== [2/5] Credential issuer key ==="
if [ ! -f build/ci_key.json ]; then
  node oracle.js ci-keygen build/ci_key.json
else
  echo "build/ci_key.json exists — reusing (delete it to rotate pk_CI; that changes VK_zk)"
fi
AX=$(node -e 'console.log(JSON.parse(require("fs").readFileSync("build/ci_key.json")).Ax)')
AY=$(node -e 'console.log(JSON.parse(require("fs").readFileSync("build/ci_key.json")).Ay)')
cat > build/authz.circom <<EOF
pragma circom 2.0.0;
include "../authz_template.circom";
// NA = 4 credential attributes, NP = 4 policy slots, pk_CI baked in.
component main {public [did, pid, rho]} = Authz(4, 4, $AX, $AY);
EOF

echo "=== [3/5] Compiling authz circuit ==="
circom build/authz.circom --r1cs --wasm --sym -l node_modules -o build
snarkjs r1cs info build/authz.r1cs

echo "=== [4/5] Powers of tau (2^$POT) ==="
cd build
if [ ! -f "pot${POT}_final.ptau" ]; then
  snarkjs powersoftau new bn128 "$POT" "pot${POT}_0.ptau"
  snarkjs powersoftau contribute "pot${POT}_0.ptau" "pot${POT}_1.ptau" --name="flex-diam" -e="entropy-string-1"
  snarkjs powersoftau prepare phase2 "pot${POT}_1.ptau" "pot${POT}_final.ptau"
  rm -f "pot${POT}_0.ptau" "pot${POT}_1.ptau"
fi

echo "=== [5/5] Groth16 setup ==="
snarkjs groth16 setup authz.r1cs "pot${POT}_final.ptau" authz_0.zkey
snarkjs zkey contribute authz_0.zkey authz.zkey --name="flex-diam" -e="entropy-string-2"
rm -f authz_0.zkey
snarkjs zkey export verificationkey authz.zkey authz_vk.json

echo ""
echo "=== ZKP circuit ready ==="
echo "  build/authz.zkey      (PK_zk)"
echo "  build/authz_vk.json   (VK_zk)"
echo "  build/authz_js/       (wasm witness generator)"
echo "  build/ci_key.json     (credential issuer key)"
