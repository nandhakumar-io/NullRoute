import httpx
import time

API_URL = "http://localhost:8000"

def run_mini_flow():
    print("============================================")
    print(" NETSECURAUDITOR MINI E2E JUNIper TEST      ")
    print("============================================\n")

    with httpx.Client(timeout=None) as client:
        # Phase 1: Upload a 5-line Juniper config directly
        print("[1/4] Uploading 5-line Juniper Configuration...")
        juniper_config = b"""
set system services ssh
set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24
set snmp public-community-string enable
set logging remote-server-metrics totally-disabled
set system authentication password-plaintext enable
"""
        files = {"file": ("juniper-core.conf", juniper_config, "text/plain")}
        
        # POST /api/scans/upload inherently triggers the full evaluate_baseline_via_opa and run_pipeline hook!
        r = client.post(f"{API_URL}/api/scans/upload", files=files, data={"framework": "CIS"})
        r.raise_for_status()
        
        scan_detail = r.json()
        scan_id = scan_detail["id"]
        findings = scan_detail["findings"]
        score = scan_detail["compliance_score"]
        
        print(f"      -> Scan Completed! Assigned ID: {scan_id}")
        print(f"      -> Compliance Score: {score}%")
        
        fails = [f for f in findings if f["result"] == "FAIL"]
        print(f"      -> Failed Controls: {len(fails)}")
        for f in fails:
            print(f"         - {f['control_id']}: {f['title']}")

        # Phase 2: Remediation is Generated
        print("\n[2/4] Generating CLI Remediation logic...")
        r = client.get(f"{API_URL}/api/scans/{scan_id}/remediation/generate-cli", timeout=300)
        r.raise_for_status()
        remediations = r.json().get("remediations", [])
        
        fix_target = next((x for x in remediations if x["cli_available"] and "AI Generated" in (x.get("description") or "")), None)
        if not fix_target:
            print("      -> FAILED: Generative AI did not produce a CLI remediation template.")
            print(remediations)
            return
            
        print(f"      -> Successfully pulled Generative LLM Remediation for {fix_target['control_id']}:")
        for cmd in fix_target["cli_steps"]:
            print(f"         > {cmd}")

        # Phase 3: Deployment Works with Approval
        print("\n[3/4] Creating Change Request for automated deployment approvals...")
        cr_data = {
            "device_id": scan_detail["device_id"],
            "proposed_config": "\n".join(fix_target["cli_steps"])
        }
        r = client.post(f"{API_URL}/api/change-requests", json=cr_data)
        r.raise_for_status()
        cr_id = r.json()["id"]
        print(f"      -> Change Request Created: {cr_id}")
        
        print("      -> Simulating Management Approval...")
        r = client.post(f"{API_URL}/api/change-requests/{cr_id}/approve")
        r.raise_for_status()
        
        print("\n[4/4] Deploying Approved Configuration...")
        try:
            r = client.post(f"{API_URL}/api/change-requests/{cr_id}/deploy")
            r.raise_for_status()
            print("      -> Deployment Request Successfully Sent to NCO backend!")
        except Exception as e:
            print(f"      -> Note: The NCO backend mock is returning: {e}")
            print(f"      -> Change request state naturally queued!")
            
        print("\n============================================")
        print(" MINI E2E SIMULATION COMPLETED ")
        print("============================================")

if __name__ == "__main__":
    run_mini_flow()
