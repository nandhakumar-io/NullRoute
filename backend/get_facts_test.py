import asyncio
from app.db import SessionLocal
from app.gateway.publisher import submit_job

async def main():
    db = SessionLocal()
    tenant_id = "SIH-Demo"
    device_id = "91f1d58c-c451-4b9f-90c9-b18884d9ca25"
    try:
        res = await submit_job(
            db,
            tenant_id=tenant_id,
            requester_id="test_admin",
            device_id=device_id,
            operation="GET_FACTS",
            protocol="ssh"
        )
        print("Result:", res)
    except Exception as e:
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
