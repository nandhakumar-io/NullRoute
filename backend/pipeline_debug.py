import asyncio
from dotenv import load_dotenv
load_dotenv()
from app.db import SessionLocal
from app.models.db import Device, Scan
from app.services.pipeline import run_pipeline

async def main():
    db = SessionLocal()
    device = db.query(Device).filter(Device.vendor == "cisco").first()
    if not device:
        print("No cisco device found")
        return
        
    print(f"Triggering scan for: {device.hostname}")
    scan = Scan(
        tenant_id=device.tenant_id,
        device_id=device.id,
        framework="cisco_ios_xe_hardening",
        status="running"
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    print(f"Pipeline started: {scan.id}")
    with open("/home/kenpachi-zaraki/NetSecAuditor/sample_configs/demo_cisco_ios_xe.cfg", "r") as f:
        raw_text = f.read()
    await run_pipeline(db, scan, raw_text)
    print(f"Pipeline finished! Check Scan ID: {scan.id}")

if __name__ == "__main__":
    asyncio.run(main())
