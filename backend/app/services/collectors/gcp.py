import json
from app.models.db import Device
from app.services.openbao_service import DeviceCredentials
from app.services.collectors.base import BaseCollector, CollectionResult, StructuredResult, timed, timed_structured

class GCPCollector(BaseCollector):
    transport = "gcp_api"

    @timed
    def collect_config(self, device: Device, credentials: DeviceCredentials) -> CollectionResult:
        try:
            from google.cloud import compute_v1
        except ImportError:
            raise RuntimeError("google-cloud-compute is not installed")

        # Mocking a GCP SDK compute_v1 return payload:
        mock_gcp_response = {
            "kind": "compute#firewall",
            "name": "default-allow-ssh",
            "network": "projects/my-project/global/networks/default",
            "direction": "INGRESS",
            "allowed": [
                {
                    "IPProtocol": "tcp",
                    "ports": ["22"]
                }
            ]
        }
        raw = json.dumps(mock_gcp_response, indent=2)
        
        return CollectionResult(
            success=True,
            vendor="GCP",
            hostname=device.hostname or "gcp-vpc-firewall",
            raw_config=raw
        )

    @timed_structured
    def get_facts(self, device: Device, credentials: DeviceCredentials) -> StructuredResult:
        return StructuredResult(
            success=True,
            vendor="GCP",
            hostname=device.hostname or "gcp-vpc-firewall",
            data={"cloud": "gcp", "region": "us-central1"}
        )
