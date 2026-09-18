import urllib.request
import tarfile
import os
import time

urls = [
    "https://github.com/hyperledger/fabric/releases/download/v2.5.9/hyperledger-fabric-linux-amd64-2.5.9.tar.gz",
    "https://github.com/hyperledger/fabric-ca/releases/download/v1.5.12/hyperledger-fabric-ca-linux-amd64-1.5.12.tar.gz"
]

os.makedirs("bin", exist_ok=True)
os.makedirs("config", exist_ok=True)

for url in urls:
    filename = url.split("/")[-1]
    if not os.path.exists(filename) or os.path.getsize(filename) == 0:
        print(f"Downloading {filename}...")
        for attempt in range(5):
            try:
                urllib.request.urlretrieve(url, filename)
                break
            except Exception as e:
                print(f"Attempt {attempt+1} failed: {e}")
                time.sleep(2)
        else:
            raise Exception("Failed to download after 5 attempts")
            
    print(f"Extracting {filename}...")
    with tarfile.open(filename, "r:gz") as tar:
        tar.extractall()
print("Done extracting Fabric binaries.")
