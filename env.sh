#!/usr/bin/env bash
# env.sh — shared environment for every V3 script (source it, do not execute).
#
# V3 reuses the infrastructure installed for V2: the Python venv (Charm-Crypto,
# cryptography, matplotlib) and the Fabric test-network live in the V2 checkout.
# Override FLEX_INFRA if yours is elsewhere.

FLEX_INFRA="${FLEX_INFRA:-$HOME/flex-diam}"
TN="$FLEX_INFRA/fabric-samples/test-network"

export FLEX_TN="$TN"
export FLEX_CC="${FLEX_CC:-flexv3}"          # V3 chaincode name (V2's "flex" is untouched)
export FLEX_CHANNEL="${FLEX_CHANNEL:-mychannel}"
export PATH="$TN/../bin:/usr/local/go/bin:$PATH"
export FABRIC_CFG_PATH="$TN/../config/"
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_TLS_ROOTCERT_FILE="$TN/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
export CORE_PEER_MSPCONFIGPATH="$TN/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
export CORE_PEER_ADDRESS=localhost:7051

# node + snarkjs (nvm)
export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"

FLEX_PY="${FLEX_PY:-$FLEX_INFRA/venv/bin/python}"
export FLEX_PY
