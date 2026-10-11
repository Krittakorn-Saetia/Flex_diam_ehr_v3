#!/usr/bin/env bash
# deploy_ccaas.sh — build, package, install, start, approve and commit the V3
# FLEX-DIAM chaincode as chaincode-as-a-service (ccaas) on the running
# test-network. It is deployed under its own name ("flexv3"), so the V2
# chaincode "flex" and its ledger state are left untouched.
#
# Prereqs: Docker running, test-network up with channel 'mychannel', jq installed.
#
#   ./deploy_ccaas.sh                 first deployment
#   IMAGE_ONLY=1 ./deploy_ccaas.sh    rebuild the image and restart the container
#                                     after editing the Go code (same package id,
#                                     no new lifecycle round)
set -euo pipefail
cd "$(dirname "$0")"

CC_NAME="${FLEX_CC:-flexv3}"
CC_LABEL="${CC_NAME}_1.0"
CHANNEL="${FLEX_CHANNEL:-mychannel}"
CC_PORT="9998"
CONTAINER_NAME="${CC_NAME}-chaincode"
IMAGE="${CC_NAME}-chaincode:latest"
FABRIC_NET="fabric_test"   # docker network created by test-network
SEQ="${SEQ:-1}"

FLEX_INFRA="${FLEX_INFRA:-$HOME/flex-diam}"
TN="$FLEX_INFRA/fabric-samples/test-network"
export PATH="$TN/../bin:$PATH"
export FABRIC_CFG_PATH="$TN/../config/"

ORDERER_CA="$TN/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
ORG1_CA="$TN/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
ORG2_CA="$TN/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"

setOrg1() {
  export CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_LOCALMSPID="Org1MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE="$ORG1_CA"
  export CORE_PEER_MSPCONFIGPATH="$TN/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
  export CORE_PEER_ADDRESS=localhost:7051
}
setOrg2() {
  export CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_LOCALMSPID="Org2MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE="$ORG2_CA"
  export CORE_PEER_MSPCONFIGPATH="$TN/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp"
  export CORE_PEER_ADDRESS=localhost:9051
}

queryPkgId() {
  peer lifecycle chaincode queryinstalled --output json \
    | jq -r ".installed_chaincodes[]? | select(.label==\"${CC_LABEL}\") | .package_id"
}

startContainer() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  docker run -d \
    --name "$CONTAINER_NAME" \
    --network "$FABRIC_NET" \
    -e CHAINCODE_ID="$1" \
    -e CHAINCODE_SERVER_ADDRESS="0.0.0.0:${CC_PORT}" \
    "$IMAGE"
  sleep 3
  docker ps --filter "name=$CONTAINER_NAME" --format "  {{.Names}}  {{.Status}}"
}

echo "=== [0/8] Preconditions: test-network up, channel '$CHANNEL' created ==="
UP="$(docker ps --format '{{.Names}}')"
running() { grep -qx "$1" <<<"$UP"; }
if [[ ! -d "$TN/organizations/peerOrganizations" ]] \
   || ! running peer0.org1.example.com || ! running peer0.org2.example.com \
   || ! running orderer.example.com; then
  echo "FATAL: the Fabric test-network is not running (no peer/orderer containers or no crypto material)."
  echo "Bring it up and create the channel first:"
  echo "    cd $TN && ./network.sh up createChannel -c $CHANNEL"
  exit 1
fi
setOrg1
if ! peer channel getinfo -c "$CHANNEL" >/dev/null 2>&1; then
  echo "FATAL: channel '$CHANNEL' does not exist on peer0.org1. Create it first:"
  echo "    cd $TN && ./network.sh createChannel -c $CHANNEL"
  exit 1
fi

echo "=== [1/8] Build the chaincode image ==="
docker build -t "$IMAGE" flex

if [[ "${IMAGE_ONLY:-0}" == "1" ]]; then
  setOrg1
  PKG_ID="$(queryPkgId)"
  if [[ -z "$PKG_ID" ]]; then echo "FATAL: $CC_LABEL is not installed yet — run without IMAGE_ONLY"; exit 1; fi
  startContainer "$PKG_ID"
  echo "=== image rebuilt, container restarted (package id unchanged) ==="
  exit 0
fi

echo "=== [2/8] Build the ccaas package ==="
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cat > "$WORK/connection.json" <<EOF
{
  "address": "${CONTAINER_NAME}:${CC_PORT}",
  "dial_timeout": "10s",
  "tls_required": false
}
EOF
cat > "$WORK/metadata.json" <<EOF
{
  "type": "ccaas",
  "label": "${CC_LABEL}"
}
EOF
( cd "$WORK" && tar -czf code.tar.gz connection.json )
( cd "$WORK" && tar -czf "${CC_NAME}.tar.gz" metadata.json code.tar.gz )
PKG="$WORK/${CC_NAME}.tar.gz"

echo "=== [3/8] Install on peer0.org1 and peer0.org2 ==="
# Only "already successfully installed" is tolerated; any other failure stops here.
installPkg() {
  local out
  if out="$(peer lifecycle chaincode install "$PKG" 2>&1)"; then
    echo "$out"
  elif grep -q "already successfully installed" <<<"$out"; then
    echo "  (already installed on $CORE_PEER_LOCALMSPID)"
  else
    echo "$out"
    echo "FATAL: chaincode install failed on $CORE_PEER_LOCALMSPID"
    exit 1
  fi
}
setOrg1; installPkg
setOrg2; installPkg

echo "=== [4/8] Query package ID ==="
setOrg1
PKG_ID="$(queryPkgId)"
echo "PKG_ID=$PKG_ID"
if [[ -z "$PKG_ID" ]]; then echo "FATAL: could not resolve package id"; exit 1; fi

echo "=== [5/8] (Re)start the chaincode container ==="
startContainer "$PKG_ID"

echo "=== [6/8] Approve for Org1 and Org2 (sequence $SEQ) ==="
approve() {
  peer lifecycle chaincode approveformyorg \
    -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --channelID "$CHANNEL" --name "$CC_NAME" --version 1.0 \
    --package-id "$PKG_ID" --sequence "$SEQ" --tls --cafile "$ORDERER_CA"
}
setOrg1; approve
setOrg2; approve

echo "=== [7/8] Commit ==="
setOrg1
peer lifecycle chaincode commit \
  -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
  --channelID "$CHANNEL" --name "$CC_NAME" --version 1.0 --sequence "$SEQ" \
  --tls --cafile "$ORDERER_CA" \
  --peerAddresses localhost:7051 --tlsRootCertFiles "$ORG1_CA" \
  --peerAddresses localhost:9051 --tlsRootCertFiles "$ORG2_CA"

sleep 3
echo "=== [8/8] Smoke: an unknown request must resolve to all-zero versions ==="
peer chaincode query --channelID "$CHANNEL" --name "$CC_NAME" \
  -c '{"function":"ResolveState","Args":["did:x","did:hs","did:hd","cid:x","pid:x"]}'
echo ""
echo "=== ccaas deploy complete: chaincode '$CC_NAME' on channel '$CHANNEL' ==="
