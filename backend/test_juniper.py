import asyncio
from app.db import SessionLocal
from app.models.db import Device
db = SessionLocal()
device = db.query(Device).filter(Device.vendor == "juniper").first()
if device:
    print(f"FOUND JUNIPER ID: {device.id} TENANT: {device.tenant_id}")
    print("CONFIG LENGTH:", len(device.last_config_raw) if device.last_config_raw else "NONE")
    # write to file
    with open("/tmp/juniper_raw.cfg", "w") as f:
        f.write(device.last_config_raw or "set system services ftp connection-limit 10")
else:
    print("NO JUNIPER DEVICE FOUND!")
