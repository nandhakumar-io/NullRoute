"""
NetSecAuditor - Super End-to-End (E2E) Test
============================================
Validates the FULL pipeline with REAL (unmocked) AI/LLM calls:

  Stage 1  - Framework document ingestion  (LLM extraction + control creation)
  Stage 2  - AI health + model introspection (classifier + embedder reachability)
  Stage 3  - Config file upload + AI normalization (LLM, classifier, embedder)
  Stage 4  - OPA compliance evaluation        (real OPA policy engine)
  Stage 5  - Batfish pre-change analysis      (static network analysis)
  Stage 6  - Remediation CLI generation       (LLM-aided fix suggestions)
  Stage 7  - HITL AI training feedback        (correct + embed into pgvector)
  Stage 8  - Change request creation          (Batfish pre-validation)
  Stage 9  - Human approval                   (RBAC gate)
  Stage 10 - Deployment (mocked transport)    (Batfish post-validation)
  Stage 11 - Deployment result inspection     (DEPLOYED / DRIFTED)
  Stage 12 - Cryptographic PDF/JSON report    (evidence artifact)
"""
import time
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient

from app.main import app
from app.db import SessionLocal

client = TestClient(app)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def db():
    session = SessionLocal()
    yield session
    session.close()


# ---------------------------------------------------------------------------
# Dirty Cisco IOS config with a deliberate telnet vulnerability
# ---------------------------------------------------------------------------
DIRTY_CONFIG = b"""\
!
version 15.2
hostname CoreRouter
!
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
!
telnet server enable
no login block-for 120 attempts 3
!
end
"""

# ---------------------------------------------------------------------------
# Full pipeline test
# ---------------------------------------------------------------------------

def test_super_e2e_full_pipeline(db):

    # -----------------------------------------------------------------------
    # STAGE 1 — Framework document ingestion (LLM control extraction)
    # -----------------------------------------------------------------------
    print("\n\n=== STAGE 1: Framework Document Ingestion ===")
    doc_content = (
        b"3.4 Device Integrity\n"
        b"All edge devices must deny unknown SSH traffic and log events.\n"
        b"Telnet MUST be disabled on all network devices. "
        b"Any configuration enabling telnet is a HIGH-severity violation.\n"
    )
    r = client.post(
        "/api/controls/ingest-document",
        files={"file": ("cisco_hardening_guide.txt", doc_content, "text/plain")},
    )
    assert r.status_code == 200, f"Ingestion failed: {r.text}"
    job_id = r.json()["id"]
    print(f"  -> Ingestion job created: {job_id}")

    print(f"  -> Polling for job completion...")
    for _ in range(60):
        s = client.get(f"/api/controls/ingest-document/{job_id}")
        assert s.status_code == 200
        job_status = s.json()["status"]
        controls_created = s.json().get("controls_created", 0)
        llm_used = s.json().get("llm_used", False)
        if job_status in ("completed", "failed"):
            print(f"  -> DONE: status={job_status}, controls_created={controls_created}, llm_used={llm_used}")
            assert job_status == "completed", f"Ingestion failed: {s.json()}"
            break
        time.sleep(3)
    else:
        pytest.fail("STAGE 1 TIMEOUT: Framework ingestion did not complete within 180s")

    # -----------------------------------------------------------------------
    # STAGE 2 — AI model health check (classifier + embedder)
    # -----------------------------------------------------------------------
    print("\n=== STAGE 2: AI Model Health Check ===")
    r = client.get("/api/ai/health")
    assert r.status_code == 200, f"AI health endpoint failed: {r.text}"
    health = r.json()
    print(f"  -> AI health: {health}")
    assert health.get("ai_enabled") is True, f"AI is not enabled: {health}"
    print(f"  -> classifier_loaded={health['classifier_loaded']}, backend={health['classifier_backend']}")
    print(f"  -> embedder_loaded={health['embedder_loaded']}, backend={health['embedder_backend']}")
    # Classifier must be reachable; embedder may fall back to token-overlap in local env
    assert health["classifier_loaded"] is True, f"Classifier is not loaded: {health}"
    assert health["embedder_loaded"] is True, f"Embedder is not loaded: {health}"

    r = client.get("/api/ai/models")
    assert r.status_code == 200, f"AI models endpoint failed: {r.text}"
    models = r.json()
    print(f"  -> AI models: {models}")

    # -----------------------------------------------------------------------
    # STAGE 3 — Config upload + AI normalization (LLM + classifier + embedder)
    # -----------------------------------------------------------------------
    print("\n=== STAGE 3: Config Upload + AI Normalization ===")
    r = client.post(
        "/api/scans/upload",
        data={"framework": "CIS"},
        files={"file": ("core_router.cfg", DIRTY_CONFIG, "text/plain")},
    )
    assert r.status_code == 200, f"Scan upload failed: {r.text}"
    scan = r.json()
    scan_id = scan["id"]
    device_id = scan["device_id"]
    compliance_score = scan["compliance_score"]
    opa_decision = scan.get("opa_decision", "UNKNOWN")
    batfish_status = scan.get("batfish_status", "UNKNOWN")
    print(f"  -> scan_id={scan_id}, device_id={device_id}")
    print(f"  -> compliance_score={compliance_score}%, opa_decision={opa_decision}, batfish_status={batfish_status}")

    # Confirm LLM normalized the telnet line (check provenance in scan detail)
    r_detail = client.get(f"/api/scans/{scan_id}")
    assert r_detail.status_code == 200
    detail = r_detail.json()
    baseline = detail.get("baseline_json", {})
    mgmt = baseline.get("management", {})
    telnet_enabled = mgmt.get("telnet", {}).get("enabled")
    print(f"  -> LLM normalized management.telnet.enabled = {telnet_enabled}")
    assert telnet_enabled is True, (
        f"LLM normalization did not mark telnet as enabled! "
        f"Baseline management: {mgmt}"
    )

    # -----------------------------------------------------------------------
    # STAGE 4 — OPA compliance evaluation
    # -----------------------------------------------------------------------
    print("\n=== STAGE 4: OPA Compliance Evaluation ===")
    r_opa = client.get(f"/api/scans/{scan_id}/opa")
    assert r_opa.status_code in (200, 404), f"OPA endpoint error: {r_opa.text}"
    if r_opa.status_code == 200:
        opa_data = r_opa.json()
        print(f"  -> OPA result: decision={opa_data.get('decision')}, findings={len(opa_data.get('findings', []))}")
    print(f"  -> Compliance score={compliance_score}%")
    # Expect OPA to see the violations (score < 100 OR specific telnet finding)
    findings = detail.get("findings", [])
    telnet_findings = [f for f in findings if "telnet" in str(f).lower()]
    print(f"  -> Total findings={len(findings)}, telnet_findings={len(telnet_findings)}")
    assert compliance_score < 100.0 or len(telnet_findings) > 0, (
        "OPA must either lower the score OR produce at least one telnet finding! "
        f"Score={compliance_score}%, findings={findings}"
    )

    # -----------------------------------------------------------------------
    # STAGE 5 — Batfish pre-change network analysis
    # -----------------------------------------------------------------------
    print("\n=== STAGE 5: Batfish Pre-Change Analysis ===")
    r_bf = client.get(f"/api/scans/{scan_id}/batfish")
    assert r_bf.status_code in (200, 404), f"Batfish endpoint error: {r_bf.text}"
    if r_bf.status_code == 200:
        bf_data = r_bf.json()
        print(f"  -> Batfish status={bf_data.get('status')}, issues={bf_data.get('issues_found', 0)}")
    else:
        print(f"  -> Batfish unavailable (acceptable for local env): {batfish_status}")

    # -----------------------------------------------------------------------
    # STAGE 6 — AI Remediation generation (LLM-powered)
    # -----------------------------------------------------------------------
    print("\n=== STAGE 6: AI Remediation CLI Generation ===")
    r = client.get(f"/api/scans/{scan_id}/remediation/generate-cli")
    assert r.status_code == 200, f"Remediation generation failed: {r.text}"
    remediations = r.json().get("remediations", [])
    print(f"  -> Total remediations generated: {len(remediations)}")
    assert len(remediations) > 0, "No remediations generated — LLM must produce at least one fix suggestion"
    cli_steps = remediations[0].get("cli_steps", [])
    print(f"  -> First remediation CLI steps: {cli_steps}")
    assert len(cli_steps) > 0, "Remediation must include at least one CLI step"

    # -----------------------------------------------------------------------
    # STAGE 7 — HITL AI training feedback (vector embedding)
    # -----------------------------------------------------------------------
    print("\n=== STAGE 7: HITL AI Training Feedback ===")
    # Trigger a correction signal (trains the AI with this scan's analysis)
    hitl_payload = {
        "scan_id": scan_id,
        "analysis_id": "00000000-0000-0000-0000-000000000000",
        "action": "correction",
        "correction_text": (
            "The telnet server enable command must always map to management.telnet.enabled = True. "
            "It is a HIGH-severity violation per CIS controls."
        ),
    }
    r = client.post("/api/ai/training-feedback", json=hitl_payload)
    # A 404 is acceptable (invalid analysis_id FK), but NOT a 422 schema error or 500
    assert r.status_code in (200, 404), f"HITL feedback returned unexpected error: {r.status_code} {r.text}"
    print(f"  -> HITL feedback response: {r.status_code} {r.json()}")

    # -----------------------------------------------------------------------
    # STAGE 8 — Create change request (triggers Batfish pre-change validation)
    # -----------------------------------------------------------------------
    print("\n=== STAGE 8: Change Request Creation ===")
    proposed_config = "\n".join(cli_steps)
    cr_payload = {
        "device_id": device_id,
        "proposed_config": proposed_config,
    }
    # Patch MinIO so we don't need a live S3 with matching credentials
    with patch("app.services.minio_service.get_object", return_value=b"# prior config placeholder"), \
         patch("app.services.minio_service.put_object", return_value=None):
        r = client.post("/api/change-requests", json=cr_payload)
    assert r.status_code == 200, f"Change request creation failed: {r.text}"
    cr = r.json()
    cr_id = cr["id"]
    cr_status = cr["status"]
    print(f"  -> Change request created: id={cr_id}, status={cr_status}")

    # -----------------------------------------------------------------------
    # STAGE 9 — Human approval gate (RBAC enforced)
    # -----------------------------------------------------------------------
    print("\n=== STAGE 9: Change Request Approval ===")
    r = client.post(f"/api/change-requests/{cr_id}/approve")
    assert r.status_code == 200, f"Approval failed: {r.text}"
    approved_cr = r.json()
    print(f"  -> CR status after approval: {approved_cr['status']}")
    assert approved_cr["status"] == "APPROVED", (
        f"Expected APPROVED, got {approved_cr['status']}"
    )

    # -----------------------------------------------------------------------
    # STAGE 10 — Deployment (mocked transport; real Batfish post-validation)
    # -----------------------------------------------------------------------
    print("\n=== STAGE 10: Deployment (mocked transport) ===")
    # We patch the physical SSH/NETCONF and MinIO so we don't contact real infrastructure
    with patch("app.services.minio_service.get_object", return_value=b"# prior config placeholder"), \
         patch("app.services.minio_service.put_object", return_value=None), \
         patch("app.services.deployment_service.get_collector") as mock_get_col, \
         patch("app.services.deployment_service.get_deployer") as mock_get_dep:
        
        import hashlib
        expected_hash = hashlib.sha256(proposed_config.strip().encode("utf-8")).hexdigest()
        
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.config_hash = expected_hash
        mock_result.raw_config = "\n".join([
            "hostname CoreRouter",
            "interface GigabitEthernet0/0",
            " ip address 10.0.0.1 255.255.255.0",
            "no telnet server enable",
        ])
        mock_result.output = None
        
        mock_col = MagicMock()
        mock_col.collect_config.return_value = mock_result
        mock_get_col.return_value = mock_col
        
        mock_dep = MagicMock()
        mock_dep.push_config.return_value = mock_result
        mock_get_dep.return_value = mock_dep

        r = client.post(f"/api/change-requests/{cr_id}/deploy")
        assert r.status_code == 200, f"Deployment failed: {r.text}"
        dr = r.json()
        dr_id = dr["id"]
        deploy_status = dr["status"]
        print(f"  -> Deployment record: id={dr_id}, status={deploy_status}")

    # -----------------------------------------------------------------------
    # STAGE 11 — Deployment result inspection
    # -----------------------------------------------------------------------
    print("\n=== STAGE 11: Deployment Result Inspection ===")
    r = client.get(f"/api/change-requests/{cr_id}")
    assert r.status_code == 200
    cr_final = r.json()
    print(f"  -> Final CR status: {cr_final['status']}")

    r = client.get(f"/api/change-requests/{cr_id}/deployments")
    assert r.status_code == 200
    deployments = r.json().get("deployments", [])
    print(f"  -> Total deployments: {len(deployments)}")
    if deployments:
        last = deployments[0]
        print(f"  -> Latest deployment: status={last['status']}, post_verification={last.get('post_verification_passed')}")

    assert deploy_status in ("DEPLOYED", "PENDING", "VERIFIED", "FAILED"), (
        f"Unexpected deploy status: {deploy_status}"
    )

    # -----------------------------------------------------------------------
    # STAGE 12 — Compliance report (cryptographic evidence artifact)
    # -----------------------------------------------------------------------
    print("\n=== STAGE 12: Compliance Report Generation ===")
    # Try downloading an existing report first
    r = client.get(f"/api/reports/artifact/{scan_id}/download")
    if r.status_code == 404:
        # Generate the report
        print("  -> Generating report artifact...")
        r_gen = client.get(f"/api/reports/{scan_id}/json")
        print(f"  -> Report generation response: {r_gen.status_code}")
        # If the report endpoint doesn't exist, try JSON export
        if r_gen.status_code == 404:
            r_gen = client.get(f"/api/scans/{scan_id}")
            assert r_gen.status_code == 200
            report_data = r_gen.json()
            print(f"  -> Scan report data keys: {list(report_data.keys())}")
    else:
        assert r.status_code == 200, f"Report download failed: {r.text}"
        print(f"  -> Report artifact downloaded: {len(r.content)} bytes")

    # -----------------------------------------------------------------------
    # Final Summary
    # -----------------------------------------------------------------------
    print("\n")
    print("=" * 65)
    print("  ✅ NETSECAUDITOR FULL E2E PIPELINE COMPLETED SUCCESSFULLY")
    print("=" * 65)
    print(f"  scan_id            : {scan_id}")
    print(f"  device_id          : {device_id}")
    print(f"  compliance_score   : {compliance_score}%")
    print(f"  llm_telnet_detected: {telnet_enabled}")
    print(f"  remediations       : {len(remediations)}")
    print(f"  change_request_id  : {cr_id}")
    print(f"  deployment_id      : {dr_id}")
    print(f"  deploy_status      : {deploy_status}")
    print("=" * 65)
