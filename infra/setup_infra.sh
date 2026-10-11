#!/usr/bin/env bash
# infra/setup_infra.sh — one-time installation of the infrastructure the
# experiments run on. Run inside Ubuntu 22.04 (WSL2 on Windows, or native Linux):
#
#     ./infra/setup_infra.sh
#
# Installs into $FLEX_INFRA (default ~/flex-diam), which is where env.sh looks:
#     $FLEX_INFRA/venv             Python venv with Charm-Crypto (built on PBC)
#     $FLEX_INFRA/fabric-samples   Hyperledger Fabric 2.5.9 binaries + test-network
# plus system-wide: build tools, Go, PBC 0.5.14, Node 18, circom 2.1.9, snarkjs.
# The test-network's BatchTimeout is set to 1 s, the value used for every
# measurement in REPORT.md.
#
# Docker (Docker Desktop with WSL integration, or Docker Engine) must already be
# installed and running. The script uses sudo and downloads from the network.
# It skips a step whose output already exists, so it is safe to re-run.
#
# NOTE: this is the installer used for the V2 code base, adapted to install into
# $FLEX_INFRA. The V3 results were measured on an environment built with the V2
# installer; this adapted copy has not been run end to end on a fresh machine.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
FLEX_INFRA="${FLEX_INFRA:-$HOME/flex-diam}"
mkdir -p "$FLEX_INFRA"
cd "$FLEX_INFRA"

echo "############################################################"
echo "# [1/6] APT build dependencies"
echo "############################################################"
sudo apt-get update -y
sudo apt-get install -y build-essential libgmp-dev libssl-dev flex bison \
    python3-dev python3-pip python3-venv git wget curl m4 autoconf automake \
    libtool pkg-config jq rsync

echo "############################################################"
echo "# [2/6] Go 1.22 (the batch verifier pulls a newer toolchain automatically)"
echo "############################################################"
if ! command -v go >/dev/null 2>&1 && [ ! -x /usr/local/go/bin/go ]; then
  cd /tmp
  wget -q https://go.dev/dl/go1.22.5.linux-amd64.tar.gz
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz
  grep -q '/usr/local/go/bin' ~/.bashrc || echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
  cd "$FLEX_INFRA"
fi
export PATH=$PATH:/usr/local/go/bin
go version

echo "############################################################"
echo "# [3/6] PBC 0.5.14 (pairing library, built from source)"
echo "############################################################"
if [ ! -f /usr/local/lib/libpbc.so ]; then
  [ -f pbc-0.5.14.tar.gz ] || wget -q https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
  tar xzf pbc-0.5.14.tar.gz
  cd pbc-0.5.14
  ./configure --prefix=/usr/local
  make -j"$(nproc)"
  sudo make install
  sudo ldconfig
  cd "$FLEX_INFRA"
fi
ldconfig -p | grep -q libpbc && echo "PBC OK"

echo "############################################################"
echo "# [4/6] Python venv + Charm-Crypto (from source) + pip deps"
echo "############################################################"
if [ ! -d venv ]; then
  python3 -m venv venv
fi
# shellcheck disable=SC1091
source venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r "$HERE/requirements.txt"
if ! python -c "import charm.toolbox.pairinggroup" 2>/dev/null; then
  [ -d charm ] || git clone https://github.com/JHUISI/charm.git
  cd charm
  ./configure.sh
  make -j"$(nproc)" || true
  # sudo strips env, so pass the OpenSSL include path through explicitly:
  sudo C_INCLUDE_PATH=/usr/include CPLUS_INCLUDE_PATH=/usr/include make install
  sudo ldconfig
  cd "$FLEX_INFRA"
fi
python -c "from charm.toolbox.pairinggroup import PairingGroup; PairingGroup('BN254'); print('Charm OK (BN254)')"
deactivate

echo "############################################################"
echo "# [5/6] Node 18 + circom 2.1.9 + snarkjs (zero-knowledge proofs)"
echo "############################################################"
if [ ! -s "$HOME/.nvm/nvm.sh" ]; then
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
fi
export NVM_DIR="$HOME/.nvm"; [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
nvm install 18 && nvm use 18
mkdir -p "$HOME/bin"
if [ ! -x "$HOME/bin/circom" ]; then
  wget -q -O "$HOME/bin/circom" https://github.com/iden3/circom/releases/download/v2.1.9/circom-linux-amd64
  chmod +x "$HOME/bin/circom"
  grep -q 'HOME/bin' ~/.bashrc || echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bashrc
fi
export PATH="$HOME/bin:$PATH"
command -v snarkjs >/dev/null 2>&1 || npm install -g snarkjs@0.7.6
circom --version && echo "circom OK"

echo "############################################################"
echo "# [6/6] Hyperledger Fabric 2.5.9 (binaries + docker images + samples)"
echo "############################################################"
if [ ! -d fabric-samples ]; then
  curl -sSL https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh -o install-fabric.sh
  chmod +x install-fabric.sh
  ./install-fabric.sh --fabric-version 2.5.9 --ca-version 1.5.12 binary docker samples
fi
CFG="fabric-samples/test-network/configtx/configtx.yaml"
if grep -q 'BatchTimeout: 2s' "$CFG"; then
  sed -i 's/BatchTimeout: 2s/BatchTimeout: 1s/' "$CFG"
  echo "BatchTimeout set to 1s in $CFG (takes effect when the channel is created)"
fi
grep -n 'BatchTimeout' "$CFG"

echo ""
echo "=== INFRASTRUCTURE READY in $FLEX_INFRA ==="
echo "Open a NEW shell (so PATH updates load), then from the repository root:"
echo "    ./setup.sh                      # circuits, keys, verifier, offline checks"
echo "    (bring the Fabric network up and deploy the chaincode — see README.md)"
