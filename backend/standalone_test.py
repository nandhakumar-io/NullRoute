import sys
import difflib
from app.services.collectors.netconf import NetconfCollector
from app.services.collectors.ssh import SSHCollector
from app.services.openbao_service import DeviceCredentials
from app.services.config_merge import config_hash, canonical_text

class DummyDevice:
    def __init__(self, hostname, vendor):
        self.hostname = hostname
        self.vendor = vendor
        self.management_address = hostname

device = DummyDevice("172.17.1.99", "juniper")
cred = DeviceCredentials(credential_type="password", secret={"username": "kenpachi", "password": "password", "port": 830, "timeout": 10})

nc = NetconfCollector()
nc_res = nc.collect_config(device, cred)

cred.secret["port"] = 22
ssh_c = SSHCollector()
ssh_res = ssh_c.collect_config(device, cred)

print("NETCONF success:", nc_res.success)
if not nc_res.success: print(nc_res.error)

print("SSH success:", ssh_res.success)
if not ssh_res.success: print(ssh_res.error)

if nc_res.success and ssh_res.success:
    nc_hash = config_hash(nc_res.raw_config)
    ssh_hash = config_hash(ssh_res.raw_config)
    print("NETCONF hash:", nc_hash)
    print("SSH hash:", ssh_hash)
    
    if nc_hash != ssh_hash:
        print("\n--- HASH MISMATCH ---")
        nc_lines = canonical_text(nc_res.raw_config).splitlines()
        ssh_lines = canonical_text(ssh_res.raw_config).splitlines()
        diff = list(difflib.unified_diff(ssh_lines, nc_lines, fromfile="ssh", tofile="netconf", n=0))
        print("\n".join(diff[:20]))
    else:
        print("Hashes match perfectly!")
