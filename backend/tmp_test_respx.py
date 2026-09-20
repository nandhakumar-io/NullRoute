import pytest, httpx, respx, asyncio
from httpx import Response
import re

@respx.mock
def test_sync():
    respx.post("http://opa:8181/v1/data/compliance/evaluate").mock(return_value=Response(200, json={}))
    respx.post("http://100.95.230.65:8000/generate").mock(return_value=Response(200, json={}))
    
    r1 = httpx.post("http://opa:8181/v1/data/compliance/evaluate")
    print("OPA:", r1.status_code)
    try:
        r2 = httpx.post("http://100.95.230.65:8000/generate")
        print("GENERATE:", r2.status_code)
    except Exception as e:
        print("GENERATE FAILED:", type(e), str(e))

test_sync()
