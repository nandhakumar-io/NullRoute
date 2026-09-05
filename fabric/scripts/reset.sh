#!/usr/bin/env bash
# Full wipe: stops the network AND deletes all generated crypto material,
# channel artifacts, and the vendored fabric-samples checkout. Next `up.sh`
# starts completely from scratch (new MSPs, new channel genesis — any
# previously anchored evidence becomes unverifiable against a fresh ledger,
# which is expected for a dev/demo reset, never for a production ledger).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FABRIC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORK_DIR="$FABRIC_DIR/network/.fabric-samples"

if [ -d "$WORK_DIR/test-network" ]; then
  export PATH="$WORK_DIR/bin:$PATH"
  ( cd "$WORK_DIR/test-network" && ./network.sh down ) || true
fi

echo "-- removing generated network artifacts --"
rm -rf "$FABRIC_DIR/network/.fabric-samples"
rm -rf "$FABRIC_DIR/network/connection-profile"
rm -rf "$FABRIC_DIR/network/crypto"
rm -rf "$FABRIC_DIR/chaincode/compliance-evidence/vendor"

echo "== Fabric network fully reset. Run up.sh to bootstrap again. =="
