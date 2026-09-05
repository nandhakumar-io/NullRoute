#!/usr/bin/env bash
# Quick health probe for the Fabric network + chaincode, and (if running)
# the fabric-gateway HTTP service. Non-destructive; safe to run anytime.
set -euo pipefail

CHANNEL_NAME="${FABRIC_CHANNEL:-compliance-audit-channel}"
CC_NAME="${FABRIC_CHAINCODE:-compliance-evidence}"
GATEWAY_URL="${FABRIC_GATEWAY_URL:-http://localhost:8080}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FABRIC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORK_DIR="$FABRIC_DIR/network/.fabric-samples"

echo "== docker containers =="
docker ps --filter "name=peer0.org" --filter "name=orderer" --filter "name=ca_" \
  --format "table {{.Names}}\t{{.Status}}" || true

if [ -d "$WORK_DIR/test-network" ]; then
  export PATH="$WORK_DIR/bin:$PATH"
  export FABRIC_CFG_PATH="$WORK_DIR/config"
  export CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_LOCALMSPID="Org1MSP"
  export CORE_PEER_MSPCONFIGPATH="$WORK_DIR/test-network/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
  export CORE_PEER_TLS_ROOTCERT_FILE="$WORK_DIR/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
  export CORE_PEER_ADDRESS=localhost:7051

  echo "== chaincode query (GetEvidenceByHash on a dummy hash, expect empty array) =="
  peer chaincode query -C "$CHANNEL_NAME" -n "$CC_NAME" \
    -c '{"function":"GetEvidenceByHash","Args":["health-check-probe"]}' || \
    echo "chaincode query failed — network/chaincode may not be up yet"
fi

echo "== fabric-gateway HTTP health =="
curl -sf "$GATEWAY_URL/health" && echo || echo "fabric-gateway not reachable at $GATEWAY_URL"
