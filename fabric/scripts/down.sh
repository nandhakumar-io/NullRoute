#!/usr/bin/env bash
# Stops the Fabric network (containers only — ledger volumes/crypto
# material are preserved so `up.sh` can restart without recreating the
# channel). Use reset.sh for a full wipe.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FABRIC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORK_DIR="$FABRIC_DIR/network/.fabric-samples"

if [ ! -d "$WORK_DIR/test-network" ]; then
  echo "No Fabric network found under $WORK_DIR — nothing to stop."
  exit 0
fi

export PATH="$WORK_DIR/bin:$PATH"
cd "$WORK_DIR/test-network"
./network.sh down

echo "== Fabric network stopped =="
