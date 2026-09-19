#!/usr/bin/env bash
# Packages, installs, approves and commits the compliance-evidence Go
# chaincode (section 16) onto the channel brought up by up.sh. Uses
# test-network's own deployCC.sh helper so the standard endorsement-policy /
# multi-org approval flow is followed instead of a shortcut.
set -euo pipefail

CHANNEL_NAME="${FABRIC_CHANNEL:-compliance-audit-channel}"
CC_NAME="${FABRIC_CHAINCODE:-compliance-evidence}"
CC_VERSION="${FABRIC_CHAINCODE_VERSION:-1.0}"
CC_SEQUENCE="${FABRIC_CHAINCODE_SEQUENCE:-1}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FABRIC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORK_DIR="$FABRIC_DIR/network/.fabric-samples"
CC_SRC_PATH="$FABRIC_DIR/chaincode/compliance-evidence"

if [ ! -d "$WORK_DIR/test-network" ]; then
  echo "Fabric network not found — run fabric/scripts/up.sh first." >&2
  exit 1
fi

export PATH="$WORK_DIR/bin:$PATH"
cd "$WORK_DIR/test-network"

echo "-- vendoring chaincode Go modules --"
( cd "$CC_SRC_PATH" && GO111MODULE=on go mod tidy && GO111MODULE=on go mod vendor )

echo "-- ensuring ccenv and baseos images exist --"
docker pull "hyperledger/fabric-ccenv:2.5" || true
docker pull "hyperledger/fabric-baseos:2.5" || true
docker pull "hyperledger/fabric-ccenv:2.5.16" || true
docker pull "hyperledger/fabric-baseos:2.5.16" || true

echo "-- deploying $CC_NAME v$CC_VERSION (sequence $CC_SEQUENCE) on $CHANNEL_NAME --"
./network.sh deployCC \
  -c "$CHANNEL_NAME" \
  -ccn "$CC_NAME" \
  -ccp "$CC_SRC_PATH" \
  -ccl go \
  -ccv "$CC_VERSION" \
  -ccs "$CC_SEQUENCE"

echo "== chaincode '$CC_NAME' committed to channel '$CHANNEL_NAME' =="
