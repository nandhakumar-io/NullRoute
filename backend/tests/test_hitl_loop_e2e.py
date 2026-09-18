"""
NetSecAuditor - HITL Learning Loop E2E Test
============================================
Validates the AI continuous learning loop:
1. Upload an unknown configuration that the AI misclassifies.
2. Submit a HITL correction.
3. Re-upload the same configuration and verify the AI learned from the
   correction, applies the correct normalization, and fails compliance/OPA.
4. Continue with remediation, change request, deployment, and evidence anchoring.
"""
import time
import pytest
import hashlib
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.db import SessionLocal

client = TestClient(app)

@pytest.fixture(scope="module")
def db():
    session = SessionLocal()
    from app.models.db import CommandMapping, TrainingExample
    mappings = session.query(CommandMapping).filter(
        CommandMapping.raw_command_pattern.in_(['legacy-insecure-mgmt-on', '!'])
    ).all()
    for m in mappings:
        session.query(TrainingExample).filter(TrainingExample.source_mapping_id == m.id).delete()
        session.delete(m)
    session.commit()
    yield session
    session.close()

@pytest.fixture(autouse=True)
def mock_llm_interpreter():
    from unittest.mock import patch
    import app.models.baseline
    
    async def mock_predict(vendor, line, retrieved, *args, **kwargs):
        if "legacy-insecure-mgmt-on" in line:
            from app.ai.normalize import AIInterpretation
            if retrieved:
                param = AIInterpretation(
                    raw_command=line,
                    normalized_parameter="management.telnet.enabled",
                    value=True,
                    confidence=1.0,
                    retrieved_knowledge=[str(retrieved)],
                    model_version="mock-test",
                    needs_human_review=False,
                    reasoning="Mapped by retrieved context"
                )
                return [param]
            else:
                param = AIInterpretation(
                    raw_command=line,
                    normalized_parameter="extra_parameters.unknown_evidence",
                    value=True,
                    confidence=0.2,
                    retrieved_knowledge=[],
                    model_version="mock-test",
                    needs_human_review=True,
                    reasoning="Simulated LLM failing to classify"
                )
                return [param]
        return []

    with patch("app.services.pipeline.interpret_line", new=mock_predict):
        yield

# An unknown command that requires human-in-the-loop retraining
UNKNOWN_DIRTY_CONFIG = b"""\
!
version 15.2
hostname CoreRouter
!
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
!
legacy-insecure-mgmt-on
!
end
"""

def test_hitl_learning_loop_e2e(db):
    print("\n\n=== PASS 1: Upload Unknown Config ===")
    
    r = client.post(
        "/api/scans/upload",
        data={"framework": "CIS"},
        files={"file": ("unknown_router.cfg", UNKNOWN_DIRTY_CONFIG, "text/plain")},
    )
    assert r.status_code == 200, f"Upload failed: {r.text}"
    scan1 = r.json()
    scan_id_1 = scan1["id"]
    
    # Assert that the system did NOT normalize the telnet/ssh properly and OPA missed it
    # We check if OPA issued a BLOCK; ideally it probably gave 100% or PASS for the telnet control 
    # because it had no idea what 'legacy-insecure-mgmt-on' meant.
    r_detail = client.get(f"/api/scans/{scan_id_1}")
    assert r_detail.status_code == 200
    baseline1 = r_detail.json().get("baseline_json", {})
    mgmt1 = baseline1.get("management", {})
    
    print(f"  -> Pass 1 mgmt baseline: {mgmt1}")
    # Assert that prior to the training, it did NOT enable telnet correctly.
    assert mgmt1.get("telnet", {}).get("enabled") is not True, "Pass 1 should not have successfully normalized telnet before correction!"
    
    # Assert OPA missed it
    print(f"  -> Pass 1 OPA compliance: {scan1['compliance_score']}%, decision: {scan1.get('opa_decision')}")
    # We do NOT assert on compliance score here, just care that the mgmt object didn't have telnet
    
    # -----------------------------------------------------------------------
    # STAGE 2: HITL Correction
    # -----------------------------------------------------------------------
    print("\n=== STAGE 2: Retrieving AI Analysis & Providing HITL Correction ===")
    
    # We need the AIAnalysis ID to submit a correction
    r_ai = client.get(f"/api/scans/{scan_id_1}/ai")
    assert r_ai.status_code == 200
    analyses = r_ai.json().get("analyses", [])
    print(f"  -> Found {len(analyses)} AI analyses for scan 1")
    
    target_hash = hashlib.sha256(b"legacy-insecure-mgmt-on").hexdigest()
    analysis_id_to_correct = None
    for a in analyses:
        if a["raw_command_hash"] == target_hash:
            analysis_id_to_correct = a["id"]
            break
        
    assert analysis_id_to_correct is not None, "Could not find an AIAnalysis record to correct"
    
    hitl_payload = {
        "scan_id": scan_id_1,
        "analysis_id": analysis_id_to_correct,
        "action": "correct",
        "corrected_parameter": "management.telnet.enabled",
        "correction_reason": "Mapped 'legacy-insecure-mgmt-on' to telnet",
    }
    
    r_hitl = client.post("/api/ai/training-feedback", json=hitl_payload)
    assert r_hitl.status_code == 200, f"HITL correction failed: {r_hitl.text}"
    print(f"  -> HITL correction applied successfully")
    
    # -----------------------------------------------------------------------
    # STAGE 3: PASS 2 - Re-upload same config and prove it learned
    # -----------------------------------------------------------------------
    print("\n=== STAGE 3: PASS 2 - Upload Same Config ===")
    
    r2 = client.post(
        "/api/scans/upload",
        data={"framework": "CIS"},
        files={"file": ("unknown_router_2.cfg", UNKNOWN_DIRTY_CONFIG, "text/plain")},
    )
    assert r2.status_code == 200, f"Upload 2 failed: {r2.text}"
    scan2 = r2.json()
    scan_id_2 = scan2["id"]
    device_id = scan2["device_id"]
    
    # Wait, the RAG retrieved the new embedded mapping, setting "management.telnet.enabled" = True 
    r_detail2 = client.get(f"/api/scans/{scan_id_2}")
    assert r_detail2.status_code == 200
    baseline2 = r_detail2.json().get("baseline_json", {})
    mgmt2 = baseline2.get("management", {})
    
    print(f"  -> Pass 2 mgmt baseline: {mgmt2}")
    
    telnet_enabled_2 = mgmt2.get("telnet", {}).get("enabled")
    
    print(f"  -> PROVENANCE: {baseline2.get('provenance', [])}")
    print(f"  -> EXTRA PARAMETERS: {baseline2.get('extra_parameters', {})}")
    assert telnet_enabled_2 is True, f"Pass 2 must normalize telnet! Mgmt={mgmt2}"

    # OPA compliance should now be < 100% or Decision = BLOCK because we enabled telnet in the normalization
    compliance_score = scan2["compliance_score"]
    opa_decision = scan2.get("opa_decision")
    print(f"  -> Pass 2 OPA compliance: {compliance_score}%, decision: {opa_decision}")
    
    # We expect OPA to catch the telnet finding
    assert compliance_score < 100.0 or str(opa_decision) == "BLOCK", "OPA should have lowered the score or blocked after hitl taught it telnet is enabled"
    
    # -----------------------------------------------------------------------
    # STAGE 4: Full validation of Batfish, Remediation, and Blockchain
    # -----------------------------------------------------------------------
    print("\n=== STAGE 4: Full Validation (Batfish, Remediation, Blockchain) ===")
    
    batfish_status = scan2.get("batfish_status")
    print(f"  -> Batfish Status: {batfish_status}")
    assert batfish_status != "BATFISH_UNAVAILABLE", "Batfish must be working"
    
    r_rem = client.get(f"/api/scans/{scan_id_2}/remediation/generate-cli")
    assert r_rem.status_code == 200
    remediations = r_rem.json().get("remediations", [])
    assert len(remediations) > 0, "Remediations should be generated"
    cli_steps = remediations[0].get("cli_steps", [])
    
    proposed_config = "\n".join(cli_steps)
    cr_payload = {
        "device_id": device_id,
        "proposed_config": proposed_config,
    }
    
    with patch("app.services.minio_service.get_object", return_value=b"# prior config placeholder"), \
         patch("app.services.minio_service.put_object", return_value=None):
        r_cr = client.post("/api/change-requests", json=cr_payload)
    assert r_cr.status_code == 200
    cr_id = r_cr.json()["id"]
    
    r_approve = client.post(f"/api/change-requests/{cr_id}/approve")
    assert r_approve.status_code == 200
    
    with patch("app.services.minio_service.get_object", return_value=b"# prior config placeholder"), \
         patch("app.services.minio_service.put_object", return_value=None), \
         patch("app.services.deployment_service.get_collector") as mock_get_col, \
         patch("app.services.deployment_service.get_deployer") as mock_get_dep:
        
        expected_hash = hashlib.sha256(proposed_config.strip().encode("utf-8")).hexdigest()
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.config_hash = expected_hash
        mock_result.raw_config = "\n".join(["no legacy-insecure-mgmt-on"])
        mock_result.output = None
        
        mock_col = MagicMock()
        mock_col.collect_config.return_value = mock_result
        mock_get_col.return_value = mock_col
        mock_dep = MagicMock()
        mock_dep.push_config.return_value = mock_result
        mock_get_dep.return_value = mock_dep

        r_deploy = client.post(f"/api/change-requests/{cr_id}/deploy")
        assert r_deploy.status_code == 200
    
    # Blockchain Anchoring Check
    from app.models.db import EvidenceRecord
    evidence = db.query(EvidenceRecord).filter(EvidenceRecord.scan_id == scan_id_2).first()
    assert evidence is not None, "EvidenceRecord should exist"
    assert evidence.fabric_status == "ANCHORED", f"Fabric status should be ANCHORED, not {evidence.fabric_status}"
    assert evidence.fabric_tx_id, "blockchain tx_id cannot be empty"
    
    print("\n=== TEST PASSED SUCCESSFULLY ===")
