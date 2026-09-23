#!/usr/bin/env bash
# Brings up a local Hyperledger Fabric network for the compliance-evidence
# audit layer (problem-statement sections 14-15), using the official Fabric
# "test-network" (a single Docker Compose network with two peer orgs + one
# orderer org, TLS enabled) rather than hand-rolled crypto tooling — this is
# the same approach Hyperledger's own samples use for local/demo networks.
#
# Pinned, not "latest" (RULE: no unpinned prod-like containers).
set -euo pipefail

FABRIC_SAMPLES_VERSION="${FABRIC_SAMPLES_VERSION:-v2.5.9}"
FABRIC_VERSION="${FABRIC_VERSION:-2.5.9}"
FABRIC_CA_VERSION="${FABRIC_CA_VERSION:-1.5.12}"
CHANNEL_NAME="${FABRIC_CHANNEL:-compliance-audit-channel}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FABRIC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORK_DIR="$FABRIC_DIR/network/.fabric-samples"

echo "== compliance-evidence: bringing up Fabric network =="

if [ ! -d "$WORK_DIR" ]; then
  echo "-- fetching hyperledger/fabric-samples @ $FABRIC_SAMPLES_VERSION --"
  git clone --depth 1 \
    https://github.com/hyperledger/fabric-samples.git "$WORK_DIR"
fi

cd "$WORK_DIR"

if [ ! -d "bin" ] || [ ! -f "bin/peer" ]; then
  echo "-- pulling Fabric Docker images + extracting binaries ($FABRIC_VERSION / CA $FABRIC_CA_VERSION) --"
  # GitHub CDN subdomains (raw.githubusercontent.com, release-assets.githubusercontent.com)
  # are TLS-blocked on this host, so install-fabric.sh cannot download the tarballs.
  # Work-around: pull the official Docker images (Docker Hub is reachable) and copy the
  # CLI binaries out of the containers.  This produces the exact same binaries that
  # install-fabric.sh would have unpacked.
  mkdir -p bin config

  # Peer binary
  docker pull "hyperledger/fabric-peer:${FABRIC_VERSION}" >/dev/null
  docker run --rm --entrypoint cat "hyperledger/fabric-peer:${FABRIC_VERSION}" /usr/local/bin/peer > bin/peer
  chmod +x bin/peer

  # Orderer binary
  docker pull "hyperledger/fabric-orderer:${FABRIC_VERSION}" >/dev/null
  docker run --rm --entrypoint cat "hyperledger/fabric-orderer:${FABRIC_VERSION}" /usr/local/bin/orderer > bin/orderer
  chmod +x bin/orderer

  # Admin tools (configtxgen, configtxlator, discover, osnadmin) live in fabric-tools
  docker pull "hyperledger/fabric-tools:${FABRIC_VERSION}" >/dev/null
  for _bin in configtxgen configtxlator discover osnadmin; do
    docker run --rm --entrypoint cat "hyperledger/fabric-tools:${FABRIC_VERSION}" "/usr/local/bin/${_bin}" > "bin/${_bin}"
    chmod +x "bin/${_bin}"
  done
  # Copy default config files from tools image
  docker run --rm --entrypoint tar "hyperledger/fabric-tools:${FABRIC_VERSION}" \
    -cC /etc/hyperledger/fabric . | tar -xC config 2>/dev/null || true

  # Fabric CA client + server
  docker pull "hyperledger/fabric-ca:${FABRIC_CA_VERSION}" >/dev/null
  docker run --rm --entrypoint cat "hyperledger/fabric-ca:${FABRIC_CA_VERSION}" /usr/local/bin/fabric-ca-client > bin/fabric-ca-client
  docker run --rm --entrypoint cat "hyperledger/fabric-ca:${FABRIC_CA_VERSION}" /usr/local/bin/fabric-ca-server > bin/fabric-ca-server
  chmod +x bin/fabric-ca-client bin/fabric-ca-server

  echo "-- Fabric binaries extracted from Docker images --"
fi

export PATH="$WORK_DIR/bin:$PATH"

cd "$WORK_DIR/test-network"

echo "-- starting test-network with CAs --"
./network.sh up createChannel -ca -c "$CHANNEL_NAME" -s couchdb

echo "-- exporting connection profile + identity material for fabric-gateway --"
mkdir -p "$FABRIC_DIR/network/connection-profile"
cp -f organizations/peerOrganizations/org1.example.com/connection-org1.json \
  "$FABRIC_DIR/network/connection-profile/connection-org1.json"

mkdir -p "$FABRIC_DIR/network/crypto"
rm -rf "$FABRIC_DIR/network/crypto/org1"
cp -r organizations/peerOrganizations/org1.example.com "$FABRIC_DIR/network/crypto/org1"

echo "== Fabric network is up. Channel '$CHANNEL_NAME' created. =="
echo "   Next: fabric/scripts/deploy-chaincode.sh"
