import json

vault_path = "/home/kenpachi-zaraki/NetSecAuditor/backend/app/services/.mock_vault.json"
try:
    with open(vault_path, "r") as f:
        vault = json.load(f)
except Exception:
    vault = {}

key = "netsec-auditor/devices/SIH-Demo/dev-32b35100-a04a-4b75-b0bd-d9b04f06f5c5"
vault[key] = {
    "credential_type": "ssh_password",
    "username": "admin",
    "password": "salzer@1"
}

with open(vault_path, "w") as f:
    json.dump(vault, f)
print("Injected into mock vault successfully!")
