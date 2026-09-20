import asyncio
from app.db import SessionLocal
from app.models.db import Device
from app.services.collectors.netconf import NetconfCollector
from app.services.collectors.ssh import SSHCollector
from app.services.deployment_service import _resolve_credentials
from app.services.config_merge import config_hash, canonical_text
import re

db = SessionLocal()
device = db.query(Device).filter(Device.hostname == "172.17.1.99").first()

if not device:
    print("Device not found")
    exit(1)

cred = _resolve_credentials(db, device, device.tenant_id, transport="netconf")

nc = NetconfCollector()
nc_res = nc.collect_config(device, cred)

ssh_c = SSHCollector()
ssh_res = ssh_c.collect_config(device, cred)

print("NETCONF success:", nc_res.success)
print("SSH success:", ssh_res.success)

if nc_res.success and ssh_res.success:
    nc_hash = config_hash(nc_res.raw_config)
    ssh_hash = config_hash(ssh_res.raw_config)
    print("NETCONF hash:", nc_hash)
    print("SSH hash:", ssh_hash)
    if nc_hash != ssh_hash:
        print("Hash mismatch!")
        nc_lines = canonical_text(nc_res.raw_config).splitlines()
        ssh_lines = canonical_text(ssh_res.raw_config).splitlines()
        import difflib
        diff = list(difflib.unified_diff(ssh_lines, nc_lines, fromfile="ssh", tofile="netconf", n=0))
        if diff:
            print("\n".join(diff[:20]))
        else:
            print("No diff in canonical lines? Something is wrong.")
