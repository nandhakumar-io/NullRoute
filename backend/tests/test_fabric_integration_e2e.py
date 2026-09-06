from sqlalchemy.orm import Session
from app.db import SessionLocal, Base, engine

import os
import pytest
from app.models.db import EvidenceRecord, Device, Scan, Tenant
from app.services import evidence_service, fabric_service

@pytest.fixture
def db():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

# Skip this test by default unless explicitly running integration tests against a real network
pytestmark = pytest.mark.skipif(
    os.getenv("FABRIC_INTEGRATION_TESTS") != "true",
    reason="Set FABRIC_INTEGRATION_TESTS=true to run real Ledger tests"
)

@pytest.mark.asyncio
async def test_fabric_e2e_anchoring(db: Session):
    """
    END-TO-END FABRIC INTEGRATION TEST
    Requires a REAL running Fabric network and fabric-gateway.
    """
    assert fabric_service.FABRIC_ENABLED is True, "FABRIC_ENABLED must be True for this test"

    # Pre-populate device and scan
    if not db.query(Tenant).filter(Tenant.id == "tenant-fabric").first():
        db.add(Tenant(id="tenant-fabric", name="Fabric Test Tenant"))
        db.commit()
    if not db.query(Device).filter(Device.id == "dev-fabric-test-1").first():
        db.add(Device(id="dev-fabric-test-1", tenant_id="tenant-fabric", hostname="testhost", management_address="1.1.1.1", enabled=True, vendor="cisco_ios"))
        db.commit()
    if not db.query(Scan).filter(Scan.id == "scan-fabric-test-1").first():
        db.add(Scan(id="scan-fabric-test-1", tenant_id="tenant-fabric", device_id="dev-fabric-test-1", status="COMPLETED"))
        db.commit()

    # 1. Generate deterministic test evidence
    evidence = evidence_service.build_evidence(
        scan_id="scan-fabric-test-1",
        device_id="dev-fabric-test-1",
        tenant_id="tenant-fabric",
        event_type="test",
        vendor="cisco_ios",
        actor="test_user",
        config_hash="testconfig",
        baseline_hash="testbaseline",
        opa_result={"decision": "PASS", "violations": []},
        batfish_result={"status": "PASS"},
        risk_result={"risk_score": 10},
        final_decision="PASS",
        framework="ALL",
        control_ids=["ctrl-1"],
        finding_ids=[],
    )
    
    canonical = evidence_service.canonicalize_evidence(evidence)
    
    # 2. Calculate SHA-256
    evidence_hash = evidence_service.hash_evidence(canonical)
    
    # 3. Store evidence through the existing evidence service
    record = evidence_service.store_evidence(db, evidence, evidence_hash)
    assert record.fabric_status == "NOT_ANCHORED"
    assert record.fabric_tx_id is None

    # 4. Anchor hash to Fabric
    anchor_result = await fabric_service.anchor_evidence(
        record.evidence_id,
        evidence_hash,
        scan_id=record.scan_id,
        device_id=record.device_id,
        tenant_id=record.tenant_id,
    )
    
    # 5. Receive real Fabric transaction ID
    assert anchor_result["status"] == "ANCHORED"
    tx_id = anchor_result["transaction_id"]
    assert tx_id is not None
    assert type(tx_id) == str and len(tx_id) > 10

    # 6. Persist transaction ID in PostgreSQL
    record.fabric_status = "ANCHORED"
    record.fabric_tx_id = tx_id
    db.add(record)
    db.commit()

    # 7 & 8. Query Fabric using evidence ID and compare stored hash with ledger hash
    verify_result = await fabric_service.verify_evidence(record.evidence_id, evidence_hash)
    
    # 9. Return INTEGRITY_VERIFIED
    assert verify_result["match"] is True
    assert verify_result["status"] == "INTEGRITY_VERIFIED"

    # 10. Check Idempotency and ID rejection
    with pytest.raises(fabric_service.FabricUnavailableError):
        await fabric_service.anchor_evidence(record.evidence_id, "DIFFERENT_HASH")

    # 11. Test history retrieval
    history = await fabric_service.get_history(record.evidence_id)
    assert isinstance(history, list)
    assert len(history) >= 1
    assert history[0]["evidenceId"] == record.evidence_id
    assert history[0]["evidenceHash"] == evidence_hash
    assert history[0]["txId"] == tx_id
