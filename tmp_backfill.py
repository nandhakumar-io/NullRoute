import json
from sqlalchemy import text
from app.db import SessionLocal
import ast

def _load_vault():
    try:
        with open("app/services/.mock_vault.json", "r") as f:
            return json.load(f)
    except:
        return {}

def run():
    vault = _load_vault()
    db = SessionLocal()
    refs = db.execute(text("SELECT id, tenant_id, device_id FROM device_credential_refs WHERE secret_data IS NULL")).fetchall()
    
    updated = 0
    for ref in refs:
        # Check vault paths for this device
        path1 = f"netsec-auditor/devices/{ref[1]}/dev-{ref[2]}"
        path2 = f"netsec-auditor/devices/SIH-Demo/dev-{ref[2]}"
        
        data = vault.get(path1) or vault.get(path2)
        if data:
            secret = {}
            if "username" in data: secret["username"] = data["username"]
            if "password" in data: secret["password"] = data["password"]
            if "private_key" in data: secret["private_key"] = data["private_key"]
            if "community" in data: secret["community"] = data["community"]
            
            db.execute(
                text("UPDATE device_credential_refs SET secret_data = :s WHERE id = :i"),
                {"s": json.dumps(secret), "i": ref[0]}
            )
            updated += 1
            print(f"Updated {ref[2]} credentials")
            
    db.commit()
    print(f"Backfilled {updated} credential refs.")

if __name__ == "__main__":
    run()
