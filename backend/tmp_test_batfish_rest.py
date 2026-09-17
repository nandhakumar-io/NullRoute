import requests
import json
import os

def test_batfish():
    # Batfish coordinator defaults to port 9996
    url = "http://localhost:9996/v2/version"
    try:
        resp = requests.get(url)
        print("Batfish Version response:")
        print(resp.json())
        print("Batfish is UP!")
    except Exception as e:
        print(f"Error connecting to coordinator: {e}")

if __name__ == "__main__":
    test_batfish()
