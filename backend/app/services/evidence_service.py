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