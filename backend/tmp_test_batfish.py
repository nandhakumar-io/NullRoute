import asyncio
import os
from pybatfish.client.session import Session
import logging

logging.basicConfig(level=logging.INFO)

async def test_batfish():
    host = os.getenv("BATFISH_HOST", "localhost")
    print(f"Connecting to Batfish at {host}")
    
    session = Session(host=host)
    print("Batfish connection successful!")
    
    # Let's create a minimal config mock
    config_text = """
hostname test-router
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!
"""
    os.makedirs("bf_test_net/configs", exist_ok=True)
    with open("bf_test_net/configs/test-router.cfg", "w") as f:
        f.write(config_text)
        
    print("Uploading network snapshot...")
    session.set_network("test_network")
    session.init_snapshot("bf_test_net", name="test_snapshot", overwrite=True)
    
    print("Snapshot initialized. Checking nodes...")
    nodes = session.q.nodeProperties().answer().frame()
    print(nodes)
    print("Test complete.")

if __name__ == "__main__":
    asyncio.run(test_batfish())
