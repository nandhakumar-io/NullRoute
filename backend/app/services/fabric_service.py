"""
Hyperledger Fabric integration — the immutable evidence/audit layer
(RULE 5, RULE 11, sections 14-19).

This module never talks to Fabric peers/orderers directly. It calls the
internal `fabric-gateway` Node.js service (fabric-gateway/src/server.ts),
which holds the actual Fabric Gateway client, identity, and TLS material
(FABRIC_GATEWAY_URL, default http://fabric-gateway:8080). That separation
keeps Fabric certificates and private keys entirely off the Python/FastAPI
process and out of the browser.

Design rules this module enforces:
  - If FABRIC_ENABLED is false, every function raises FabricNotConfiguredError
    immediately — callers must not report a false "anchored" status.
  - If Fabric is enabled but the gateway is unreachable or errors, functions
    raise FabricUnavailableError. Callers (evidence pipeline, evidence
    router) must map this to FABRIC_UNAVAILABLE and continue operating
    off-chain rather than pretending an anchor succeeded (section 19).
  - Retries use bounded exponential backoff (FABRIC_MAX_RETRIES) and a
    request timeout, so a stalled Fabric network never blocks a scan
    indefinitely (section 20).
"""
from __future__ import annotations

import asyncio
import os
from typing import Any, Dict, List, Optional

import httpx

FABRIC_ENABLED = os.getenv("FABRIC_ENABLED", "false").strip().lower() == "true"
FABRIC_GATEWAY_URL = os.getenv("FABRIC_GATEWAY_URL", "http://fabric-gateway:8080").rstrip("/")
FABRIC_CHANNEL = os.getenv("FABRIC_CHANNEL", "compliance-audit-channel")
FABRIC_CHAINCODE = os.getenv("FABRIC_CHAINCODE", "compliance-evidence")
FABRIC_ASYNC_ANCHOR = os.getenv("FABRIC_ASYNC_ANCHOR", "true").strip().lower() == "true"
FABRIC_REQUIRED_FOR_CRITICAL_CHANGES = os.getenv("FABRIC_REQUIRED_FOR_CRITICAL_CHANGES", "false").strip().lower() == "true"
FABRIC_MAX_RETRIES = int(os.getenv("FABRIC_MAX_RETRIES", "5"))
FABRIC_TIMEOUT = float(os.getenv("FABRIC_TIMEOUT", "10.0"))
FABRIC_RETRY_BASE_SECONDS = float(os.getenv("FABRIC_RETRY_BASE_SECONDS", "0.5"))


class FabricNotConfiguredError(Exception):
    """Raised whenever Fabric integration is called while FABRIC_ENABLED is
    false. Evidence remains fully built, hashed, and stored off-chain."""


class FabricUnavailableError(Exception):
    """Raised when Fabric is enabled but the gateway is unreachable, times
    out, or returns an error after exhausting retries. Callers must map
    this to FABRIC_UNAVAILABLE rather than reporting success."""


def _require_enabled(op: str) -> None:
    if not FABRIC_ENABLED:
        raise FabricNotConfiguredError(
            f"Fabric {op} was requested but FABRIC_ENABLED=false. Evidence remains fully built, "
            "hashed, and stored off-chain; set FABRIC_ENABLED=true and stand up fabric-gateway "
            "(see fabric/scripts/up.sh) to enable on-chain anchoring."
        )


async def _request(method: str, path: str, *, json_body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """POST/GET to the fabric-gateway HTTP bridge with bounded exponential
    backoff. Never retries indefinitely — a stuck Fabric network must not
    hang a scan (section 20)."""
    last_error: Optional[Exception] = None
    for attempt in range(FABRIC_MAX_RETRIES):
        try:
            async with httpx.AsyncClient(timeout=FABRIC_TIMEOUT) as client:
                resp = await client.request(method, f"{FABRIC_GATEWAY_URL}{path}", json=json_body)
            if resp.status_code == 404:
                raise FabricUnavailableError(f"fabric-gateway 404 for {path}: {resp.text}")
            resp.raise_for_status()
            return resp.json()
        except (httpx.HTTPError, FabricUnavailableError) as e:
            last_error = e
            if attempt < FABRIC_MAX_RETRIES - 1:
                await asyncio.sleep(FABRIC_RETRY_BASE_SECONDS * (2 ** attempt))
    raise FabricUnavailableError(
        f"fabric-gateway unreachable after {FABRIC_MAX_RETRIES} attempts ({FABRIC_GATEWAY_URL}{path}): {last_error}"
    )


async def health_check() -> Dict[str, Any]:
    """Used by the UI's Fabric status indicator. Never raises — reports
    disabled/unhealthy states as data instead."""
    if not FABRIC_ENABLED:
        return {"enabled": False, "healthy": False, "status": "DISABLED"}
    try:
        data = await _request("GET", "/health")
        return {"enabled": True, "healthy": True, "status": "OK", **data}
    except FabricUnavailableError as e:
        return {"enabled": True, "healthy": False, "status": "FABRIC_UNAVAILABLE", "error": str(e)}


async def anchor_evidence(evidence_id: str, evidence_hash: str, **fields: Any) -> Dict[str, Any]:
    """Anchor an evidence record on-chain. `fields` may include scan_id,
    device_id, tenant_id, event_type, config_hash, baseline_hash,
    opa_decision, batfish_decision, final_decision, policy_version,
    batfish_snapshot, model_version, timestamp, actor, schema_version —
    all forwarded verbatim (camelCased) to the chaincode; secrets must
    never appear here (RULE 11) and this function does not accept any
    field that could carry one.

    Returns {"status": "ANCHORED", "transaction_id": ..., "block_number": ...}
    on success. Raises FabricNotConfiguredError / FabricUnavailableError
    otherwise — never fabricates a transaction id (section 19)."""
    _require_enabled("anchor_evidence")

    def camel(v: Any) -> Any:
        return v if v is not None else ""

    body = {
        "evidenceId": evidence_id,
        "evidenceHash": evidence_hash,
        "scanId": camel(fields.get("scan_id")),
        "deviceId": camel(fields.get("device_id")),
        "tenantId": camel(fields.get("tenant_id")),
        "eventType": camel(fields.get("event_type")),
        "configHash": camel(fields.get("config_hash")),
        "baselineHash": camel(fields.get("baseline_hash")),
        "opaDecision": camel(fields.get("opa_decision")),
        "batfishDecision": camel(fields.get("batfish_decision")),
        "finalDecision": camel(fields.get("final_decision")),
        "policyVersion": camel(fields.get("policy_version")),
        "batfishSnapshot": camel(fields.get("batfish_snapshot")),
        "modelVersion": camel(fields.get("model_version")),
        "timestamp": camel(fields.get("timestamp")),
        "actor": camel(fields.get("actor")) or "system:pipeline",
        "schemaVersion": camel(fields.get("schema_version")) or "1.0",
    }
    data = await _request("POST", "/evidence", json_body=body)
    return {
        "status": "ANCHORED",
        "transaction_id": data.get("txId"),
        # The Fabric Gateway client confirms commit but this REST bridge does
        # not currently surface a block number (would require an additional
        # ledger query the gateway doesn't yet expose) — left None rather
        # than fabricated. UI should treat a present tx_id as sufficient
        # proof of anchoring.
        "block_number": data.get("blockNumber"),
        "raw": data,
    }


async def get_evidence(evidence_id: str) -> Dict[str, Any]:
    _require_enabled("get_evidence")
    return await _request("GET", f"/evidence/{evidence_id}")


async def verify_evidence(evidence_id: str, expected_hash: str) -> Dict[str, Any]:
    """Compares `expected_hash` (recomputed off-chain from the stored
    evidence JSON) against the on-chain evidenceHash for evidence_id.
    Returns {"match": bool, "status": "INTEGRITY_VERIFIED"|"INTEGRITY_FAILURE"}.
    """
    _require_enabled("verify_evidence")
    return await _request("POST", f"/evidence/{evidence_id}/verify", json_body={"evidenceHash": expected_hash})


async def get_history(evidence_id: str) -> List[Dict[str, Any]]:
    _require_enabled("get_history")
    data = await _request("GET", f"/evidence/{evidence_id}/history")
    return data if isinstance(data, list) else []
