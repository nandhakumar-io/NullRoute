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
  git clone --depth 1 --branch "$FABRIC_SAMPLES_VERSION" \
    https://github.com/hyperledger/fabric-samples.git "$WORK_DIR"
fi

cd "$WORK_DIR"

if [ ! -d "bin" ] || [ ! -f "bin/peer" ]; then
  echo "-- installing Fabric binaries + Docker images ($FABRIC_VERSION / CA $FABRIC_CA_VERSION) --"
  ./install-fabric.sh --fabric-version "$FABRIC_VERSION" --ca-version "$FABRIC_CA_VERSION" docker binary
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
