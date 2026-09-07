"""Evidence Ledger endpoints (sections 11, 17, 29, 30).

Wraps app.services.evidence_service (build/hash/store, already implemented)
with the HTTP surface the Evidence Ledger UI needs: list evidence, fetch one
record, verify integrity (recompute hash vs. stored hash), and the demo-safe
tamper simulation / restore pair used to show INTEGRITY_FAILURE detection.

Fabric anchoring status (fabric_status/fabric_tx_id) is surfaced as stored on
the record. Until app.services.fabric_service is backed by a real Gateway,
those fields stay NOT_ANCHORED — this router never fabricates a transaction
id or block number.
"""
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.db import EvidenceRecord
from app.schemas import EvidenceDetailOut, EvidenceOut, VerifyResultOut
from app.services import evidence_service, fabric_service

from app.auth.dependencies import get_current_user, require_role

router = APIRouter(prefix="/api/evidence", tags=["evidence"], dependencies=[Depends(get_current_user)])


@router.get("", response_model=List[EvidenceOut])
def list_evidence(scan_id: str | None = None, db: Session = Depends(get_db)):
    q = db.query(EvidenceRecord)
    if scan_id:
        q = q.filter(EvidenceRecord.scan_id == scan_id)
    return q.order_by(EvidenceRecord.created_at.desc()).limit(500).all()


@router.get("/{evidence_id}", response_model=EvidenceDetailOut)
def get_evidence(evidence_id: str, db: Session = Depends(get_db)):
    record = evidence_service.get_evidence(db, evidence_id)
    if not record:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return record


@router.get("/{evidence_id}/history", response_model=List[EvidenceOut])
def get_evidence_history(evidence_id: str, db: Session = Depends(get_db)):
    record = evidence_service.get_evidence(db, evidence_id)
    if not record:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return evidence_service.get_evidence_history(db, record.scan_id)


@router.post("/{evidence_id}/verify", response_model=VerifyResultOut)
async def verify_evidence(
    evidence_id: str,
    db: Session = Depends(get_db),
    _user=Depends(require_role("auditor", "admin")),
):
    """Recompute SHA-256 over the stored evidence_json and compare against
    evidence_hash. This is the off-chain half of verification; once Fabric
    is wired, fabric_service.verify_evidence() additionally compares against
    the on-chain evidenceHash and both must agree."""
    record = evidence_service.get_evidence(db, evidence_id)
    if not record:
        raise HTTPException(status_code=404, detail="Evidence not found")
    result = evidence_service.verify_evidence(record.evidence_hash, record.evidence_json)

    # On-chain half of verification (section 17): compare the recomputed
    # hash against what's anchored on Fabric, when enabled. This never
    # overrides the off-chain result above — a mismatch on either side is
    # reported, not silently absorbed.
    if fabric_service.FABRIC_ENABLED and record.fabric_status == "ANCHORED":
        try:
            fabric_result = await fabric_service.verify_evidence(evidence_id, result["calculated_hash"])
            result["fabric_checked"] = True
            result["fabric_match"] = bool(fabric_result.get("match"))
            result["fabric_status"] = fabric_result.get("status")
            if not fabric_result.get("match"):
                result["status"] = "INTEGRITY_FAILURE"
                result["match"] = False
        except fabric_service.FabricUnavailableError as e:
            result["fabric_checked"] = False
            result["fabric_status"] = "FABRIC_UNAVAILABLE"

    return result


@router.post("/{evidence_id}/simulate-tamper", response_model=EvidenceDetailOut)
def simulate_tamper(evidence_id: str, db: Session = Depends(get_db)):
    """Demo-safe tampering (section 30): mutates ONLY the off-chain
    evidence_json (e.g. flips final_decision), never evidence_hash and never
    anything on Fabric. Verify Integrity afterwards must report
    INTEGRITY_FAILURE. Refuses to run twice without a restore in between so
    the original value isn't lost."""
    record = evidence_service.get_evidence(db, evidence_id)
    if not record:
        raise HTTPException(status_code=404, detail="Evidence not found")
    if record.evidence_json.get("_tamper_backup") is not None:
        raise HTTPException(status_code=409, detail="Already tampered — restore before tampering again")

    tampered = dict(record.evidence_json)
    tampered["_tamper_backup"] = {"final_decision": tampered.get("final_decision")}
    tampered["final_decision"] = "PASS" if tampered.get("final_decision") != "PASS" else "BLOCK"
    record.evidence_json = tampered
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


@router.post("/{evidence_id}/restore", response_model=EvidenceDetailOut)
def restore_evidence(evidence_id: str, db: Session = Depends(get_db)):
    """Undo simulate-tamper, restoring the original off-chain record so
    Verify Integrity returns INTEGRITY_VERIFIED again."""
    record = evidence_service.get_evidence(db, evidence_id)
    if not record:
        raise HTTPException(status_code=404, detail="Evidence not found")
    backup = record.evidence_json.get("_tamper_backup")
    if backup is None:
        raise HTTPException(status_code=409, detail="Evidence is not currently tampered")

    restored = dict(record.evidence_json)
    restored["final_decision"] = backup.get("final_decision")
    restored.pop("_tamper_backup", None)
    record.evidence_json = restored
    db.add(record)
    db.commit()
    db.refresh(record)
    return record
