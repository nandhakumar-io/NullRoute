import asyncio
from pysnmp.hlapi.asyncio import UdpTransportTarget

try:
    UdpTransportTarget(("1.2.3.4", 161), timeout=5)
    print("Success with keyword")
except Exception as e:
    print(f"Failed with keyword: {e}")

try:
    UdpTransportTarget(("1.2.3.4", 161), 5)
    print("Success with positional")
except Exception as e:
    print(f"Failed with positional: {e}")
