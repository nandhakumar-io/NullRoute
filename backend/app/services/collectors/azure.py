import json
from app.models.db import Device
from app.services.openbao_service import DeviceCredentials
from app.services.collectors.base import BaseCollector, CollectionResult, StructuredResult, timed, timed_structured

class AzureCollector(BaseCollector):
    transport = "azure_api"

    @timed
    def collect_config(self, device: Device, credentials: DeviceCredentials) -> CollectionResult:
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.network import NetworkManagementClient
        except ImportError:
            raise RuntimeError("Azure SDKs are not installed; Azure collection requires azure-mgmt-network")

        # Mocking an Azure SDK ARM return payload:
        mock_azure_response = {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "resources": [
                {
                    "type": "Microsoft.Network/networkSecurityGroups",
                    "apiVersion": "2020-05-01",
                    "name": "Azure-NSG",
                    "properties": {
                        "securityRules": [
                            {
                                "name": "AllowSSHInBound",
                                "properties": {
                                    "protocol": "Tcp",
                                    "sourcePortRange": "*",
                                    "destinationPortRange": "22",
                                    "access": "Allow",
                                    "direction": "Inbound"
                                }
                            }
                        ]
                    }
                }
            ]
        }
        raw = json.dumps(mock_azure_response, indent=2)
        
        return CollectionResult(
            success=True,
            vendor="Azure",
            hostname=device.hostname or "azure-nsg",
            raw_config=raw
        )

    @timed_structured
    def get_facts(self, device: Device, credentials: DeviceCredentials) -> StructuredResult:
        return StructuredResult(
            success=True,
            vendor="Azure",
            hostname=device.hostname or "azure-nsg",
            data={"cloud": "azure", "region": "eastus"}
        )
