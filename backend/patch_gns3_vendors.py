from app.models.db import Device
from app.db import SessionLocal
def _guess_vendor(name: str) -> str:
    name_lower = name.lower()
    if 'cisco' in name_lower: return 'cisco'
    if 'arista' in name_lower or 'veos' in name_lower: return 'arista'
    if 'forti' in name_lower: return 'fortigate'
    if 'palo' in name_lower or 'panos' in name_lower: return 'palo_alto'
    if 'juniper' in name_lower or 'vsrx' in name_lower: return 'juniper'
    return 'GNS3'

db = SessionLocal()
devices = db.query(Device).filter(Device.vendor == "GNS3").all()
for d in devices:
    d.vendor = _guess_vendor(d.hostname)
db.commit()
print(f"Patched {len(devices)} devices")
