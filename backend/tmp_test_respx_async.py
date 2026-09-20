import pytest, httpx, respx, asyncio
from httpx import Response

@respx.mock
async def test_async():
    respx.post("http://100.95.230.65:8000/generate").mock(return_value=Response(200, json={}))
    
    async with httpx.AsyncClient() as client:
        r2 = await client.post("http://100.95.230.65:8000/generate")
        print("GENERATE:", r2.status_code)

asyncio.run(test_async())
