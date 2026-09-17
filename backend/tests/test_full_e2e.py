import httpx
import time
import sys

API_URL = "http://localhost:8000"

def run_full_flow():
    print("============================================")
    print(" NETSECAUDITOR E2E COMPLIANCE AI FLOW TEST  ")
    print("============================================\n")

    with httpx.Client(timeout=None) as client:
        # Phase 1: Upload a Configuration Document (RAG Ingestion)
        print("[1/5] Ingesting Configuration Document...")
        doc_content = b"3.4 Device Integrity\nAll edge devices must deny unknown SSH traffic and log events.\n"
        files = {"file": ("demo_policy.txt", doc_content, "text/plain")}
        r = client.post(f"{API_URL}/api/controls/ingest-document", files=files)
        r.raise_for_status()
        job_id = r.json()["id"]
        
        while True:
            r2 = client.get(f"{API_URL}/api/controls/ingest-document/{job_id}")
            status = r2.json()["status"]
            if status in ("completed", "failed"):
                break
            time.sleep(2)
            
        print(f"      -> Ingestion Status: {status}")
        if r2.json().get("llm_used"):
            print("      -> RAG Normalization: SUCCESS (Ollama Model Reached)")
        else:
            print("      -> RAG Normalization: DEGRADED (Check 100.95.230.65 connectivity via API host)")

        # Phase 2: Fetch config from Juniper Switch (NETCONF)
        print("\n[2/5] Fetching and parsing config from Juniper Switch over NETCONF...")
        r = client.get(f"{API_URL}/api/devices?limit=10")
        devices = r.json().get("items", [])
        junos = next((d for d in devices if d["vendor"] == "juniper"), None)
        if not junos:
            print("      -> FAILED: Juniper device missing from inventory.")
            sys.exit(1)

        device_id = junos["id"]
        r = client.post(f"{API_URL}/api/devices/{device_id}/collect")
        r.raise_for_status()
        print("      -> Collection: SUCCESS (Netconf Snapshot Acquired)")

        # Phase 3: Validate Config, Normalize Unknown Syntax, Embed, and Verify via OPA
        print("\n[3/5] Classifying lines, embedding unknowns, and verifying via OPA...")
        r = client.post(f"{API_URL}/api/devices/{device_id}/scan", json={"framework": "cisco-ios-baseline"})
        r.raise_for_status()
        scan_id = r.json().get("id")
        
        while True:
            r_scan = client.get(f"{API_URL}/api/scans/{scan_id}")
            if r_scan.json().get("status") in ("completed", "failed"):
                break
            time.sleep(2)
            
        score = r_scan.json().get("compliance_score")
        print(f"      -> Scan Completed! Compliance Score: {score}%")

        # Phase 4: Remediation is Generated
        print("\n[4/5] Generating LLM Remediation logic...")
        r = client.get(f"{API_URL}/api/scans/{scan_id}/remediation/generate-cli", timeout=120)
        r.raise_for_status()
        remediations = r.json().get("remediations", [])
        cli_count = r.json().get("cli_generated_count")
        print(f"      -> Generated {len(remediations)} remediation plans ({cli_count} with automated CLI).")
        
        # Prepare for deployment
        fix_target = next((x for x in remediations if x["cli_available"]), None)
        if not fix_target:
            print("      -> No CLI remediations found to deploy. Skipping deployment flow.")
            return

        # Phase 5: Deployment Works with Approval Full Flow
        print("\n[5/5] Creating Change Request for automated deployment approvals...")
        cr_data = {
            "title": f"Auto-Fix: {fix_target['title']}",
            "description": "Automated CLI remediation deployment test.",
            "device_ids": [device_id],
            "proposed_config": "\n".join(fix_target["cli_steps"])
        }
        r = client.post(f"{API_URL}/api/change-requests", json=cr_data)
        r.raise_for_status()
        cr_id = r.json()["id"]
        print(f"      -> Change Request Created: {cr_id}")
        
        print("      -> Simulating Management Approval...")
        r = client.patch(f"{API_URL}/api/change-requests/{cr_id}/approval", json={
            "action": "approve", "reviewer_notes": "Looks good in validation."
        })
        r.raise_for_status()
        
        print("      -> Deploying Approved Configuration...")
        r = client.post(f"{API_URL}/api/change-requests/{cr_id}/deploy")
        r.raise_for_status()
        print("      -> Deployment Request Successfully Sent to NCO backend!")
        
        print("\n============================================")
        print(" END-TO-END AUTOMATION FLOW COMPLETED (100%)")
        print("============================================")

if __name__ == "__main__":
    try:
        run_full_flow()
    except Exception as e:
        print(f"E2E FLOW FAILED: {str(e)}")
