"""
Evidence engine: builds the immutable evidence package for a scan,
canonicalizes it deterministically, and SHA-256 hashes it.

Fabric anchoring is implemented and wired into the pipeline (see
app/services/fabric_service.py, called from services/pipeline.py step 8b).
This module only builds, canonicalizes, hashes, and stores evidence
off-chain (PostgreSQL here; MinIO in the full architecture); the pipeline
then calls fabric_service.anchor_evidence(evidence_id, evidence_hash) and
writes the returned transaction id back onto the EvidenceRecord — nothing
about the evidence shape here changes based on whether Fabric is enabled.

RULE 11 / section 12: NEVER put secrets on evidence. The evidence package
below only ever contains hashes, decisions, and identifiers — never raw
configuration text or credentials.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

APPLICATION_VERSION = "0.1.0"
PARSER_VERSION = "1.0.0"


def _iso(dt: Optional[datetime] = None) -> str:
    return (dt or datetime.now(timezone.utc)).replace(microsecond=0).isoformat()


def canonicalize_evidence(evidence: Dict[str, Any]) -> str:
    """Deterministic JSON serialization: sorted keys, UTF-8, no whitespace
    ambiguity, no random fields. Two calls with the same logical evidence
    must always produce byte-identical output — this is what makes the hash
    meaningful as an integrity check."""
    return json.dumps(evidence, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def hash_evidence(canonical_json: str) -> str:
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def build_evidence(
    *,
    scan_id: str,
    device_id: str,
    tenant_id: str,
    event_type: str,
    actor: str,
    vendor: str,
    config_hash: str,
    baseline_hash: str,
    opa_result: Dict[str, Any],
    batfish_result: Dict[str, Any],
    risk_result: Dict[str, Any],
    final_decision: str,
    framework: str,
    control_ids: List[str],
    finding_ids: List[str],
    model_version: Optional[str] = None,
    evidence_id: Optional[str] = None,
    timestamp: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Assemble the evidence dict per problem-statement section 11. Callers
    must canonicalize + hash the *exact* dict returned here (don't mutate it
    afterwards) or the stored hash will not match on verification."""
    return {
        "evidence_id": evidence_id or str(uuid.uuid4()),
        "scan_id": scan_id,
        "device_id": device_id,
        "tenant_id": tenant_id,
        "event_type": event_type,
        "timestamp": _iso(timestamp),
        "actor": actor,
        "vendor": vendor,
        "config_hash": config_hash,
        "baseline_hash": baseline_hash,
        "opa_result": {
            "decision": opa_result.get("decision"),
            "policy_version": opa_result.get("policy_version"),
            "decision_id": opa_result.get("decision_id"),
            "violation_count": len(opa_result.get("violations", [])),
        },
        "opa_policy_version": opa_result.get("policy_version"),
        "batfish_result": batfish_result,  # e.g. {"status": "NOT_INTEGRATED"} in this deployment phase
        "batfish_snapshot": batfish_result.get("snapshot"),
        "risk_result": risk_result,
        "final_decision": final_decision,
        "framework": framework,
        "control_ids": sorted(control_ids),
        "finding_ids": sorted(finding_ids),
        "model_version": model_version,
        "parser_version": PARSER_VERSION,
        "application_version": APPLICATION_VERSION,
    }


def verify_evidence(stored_hash: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Recompute the hash of `evidence` and compare against `stored_hash`.
    Returns both hashes plus a boolean so the UI can show "Stored Hash" vs
    "Calculated Hash" side by side per section 29."""
    canonical = canonicalize_evidence(evidence)
    calculated_hash = hash_evidence(canonical)
    return {
        "match": calculated_hash == stored_hash,
        "stored_hash": stored_hash,
        "calculated_hash": calculated_hash,
        "status": "INTEGRITY_VERIFIED" if calculated_hash == stored_hash else "INTEGRITY_FAILURE",
    }


def store_evidence(db: Session, evidence: Dict[str, Any], evidence_hash: str) -> "EvidenceRecord":
    """Persist the evidence package off-chain. In the full target
    architecture this also writes the raw JSON to MinIO and the reference to
    PostgreSQL (RULE 6/13); this pass stores the canonical JSON directly in
    PostgreSQL, which is sufficient for hashing/verification/tamper-demo
    purposes and is a strict subset of the eventual MinIO-backed storage."""
    from app.models.db import EvidenceRecord  # local import avoids a cycle at module load time

    record = EvidenceRecord(
        evidence_id=evidence["evidence_id"],
        scan_id=evidence["scan_id"],
        device_id=evidence["device_id"],
        tenant_id=evidence["tenant_id"],
        event_type=evidence["event_type"],
        evidence_json=evidence,
        evidence_hash=evidence_hash,
        opa_decision_id=evidence["opa_result"].get("decision_id"),
        final_decision=evidence["final_decision"],
        fabric_status="NOT_ANCHORED",  # pipeline.py step 8b flips this to "ANCHORED"/"FABRIC_UNAVAILABLE"
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def get_evidence(db: Session, evidence_id: str) -> Optional["EvidenceRecord"]:
    from app.models.db import EvidenceRecord
    return db.query(EvidenceRecord).filter(EvidenceRecord.evidence_id == evidence_id).first()


def get_evidence_history(db: Session, scan_id: str) -> List["EvidenceRecord"]:
    from app.models.db import EvidenceRecord
    return (
        db.query(EvidenceRecord)
        .filter(EvidenceRecord.scan_id == scan_id)
        .order_by(EvidenceRecord.created_at.asc())
        .all()
    )


async def anchor_event(
    db: Session,
    *,
    event_type: str,
    actor: str,
    device_id: str,
    tenant_id: str,
    final_decision: str,
    scan_id: Optional[str] = None,
    vendor: str = "Unknown",
    config_hash: Optional[str] = None,
    baseline_hash: Optional[str] = None,
    opa_result: Optional[Dict[str, Any]] = None,
    batfish_result: Optional[Dict[str, Any]] = None,
    risk_result: Optional[Dict[str, Any]] = None,
    framework: str = "ALL",
    control_ids: Optional[List[str]] = None,
    finding_ids: Optional[List[str]] = None,
) -> "EvidenceRecord":
    """Build, hash, store off-chain, and (if FABRIC_ENABLED) anchor on-chain
    a single evidence event for something other than a scan completing --
    e.g. a deployment or a rollback. Same shape/pattern services/pipeline.py
    step 8/8b already uses for `event_type="scan.completed"`; this is that
    same pattern factored out so deployment_service.py and
    rollback_service.py don't reimplement it (RULE 11 -- no second
    evidence-building implementation), just with a caller-supplied
    `event_type` -- the chaincode's `eventType` field is free-form, so no
    chaincode change is needed to anchor new event kinds.

    `scan_id` may be None (e.g. a deployment that failed before a
    post-deploy scan could run) -- EvidenceRecord.scan_id is nullable
    specifically to allow anchoring failure/abort events that never reached
    a Scan. Never raises for a Fabric-unavailable/disabled condition; the
    returned record's `fabric_status` reports that instead (mirrors
    pipeline.py's own handling exactly).
    """
    from app.services import fabric_service

    evidence = build_evidence(
        scan_id=scan_id or "", device_id=device_id, tenant_id=tenant_id,
        event_type=event_type, actor=actor, vendor=vendor,
        config_hash=config_hash or "", baseline_hash=baseline_hash or "",
        opa_result=opa_result or {}, batfish_result=batfish_result or {},
        risk_result=risk_result or {}, final_decision=final_decision,
        framework=framework, control_ids=control_ids or [], finding_ids=finding_ids or [],
    )
    # build_evidence always stamps a scan_id (even "" above); EvidenceRecord
    # itself must get the real nullable value, not the placeholder. Must
    # happen BEFORE canonicalize/hash below, not after -- otherwise the
    # stored evidence_hash and the stored evidence_json would describe two
    # different dicts and every later integrity check would fail.
    evidence["scan_id"] = scan_id
    canonical = canonicalize_evidence(evidence)
    evidence_hash = hash_evidence(canonical)
    record = store_evidence(db, evidence, evidence_hash)

    if fabric_service.FABRIC_ENABLED:
        try:
            anchor = await fabric_service.anchor_evidence(
                record.evidence_id, evidence_hash,
                scan_id=scan_id or "", device_id=device_id, tenant_id=tenant_id,
                event_type=event_type, config_hash=evidence["config_hash"],
                baseline_hash=evidence["baseline_hash"],
                opa_decision=(opa_result or {}).get("decision"),
                batfish_decision=(batfish_result or {}).get("status"),
                final_decision=final_decision,
                policy_version=(opa_result or {}).get("policy_version"),
                batfish_snapshot=(batfish_result or {}).get("snapshot_name") or "",
                timestamp=evidence["timestamp"], actor=actor,
            )
            record.fabric_status = "ANCHORED"
            record.fabric_tx_id = anchor.get("transaction_id")
            record.fabric_block_number = anchor.get("block_number")
            db.commit()
        except fabric_service.FabricUnavailableError:
            record.fabric_status = "FABRIC_UNAVAILABLE"
            db.commit()
    return record
