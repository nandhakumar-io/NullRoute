"""
Seed the database with demo devices/scans by running the real pipeline
against the bundled sample_configs/ so `docker compose up` produces a
populated dashboard immediately, and pre-approves a couple of Training
Center mappings to show the learned-knowledge-base flow.

Usage: python -m app.seed
"""
import asyncio
import glob
import os

from app.db import SessionLocal, init_db
from app.models.db import CommandMapping, Device, Scan, Tenant
from app.routers.devices import DEMO_TENANT_NAME
from app.services.pipeline import run_pipeline

SAMPLE_DIR = os.getenv("SAMPLE_CONFIG_DIR", "/app/sample_configs")


async def seed():
    init_db()
    db = SessionLocal()
    try:
        tenant = db.query(Tenant).filter(Tenant.name == DEMO_TENANT_NAME).first()
        if not tenant:
            tenant = Tenant(name=DEMO_TENANT_NAME)
            db.add(tenant)
            db.commit()
            db.refresh(tenant)

        if db.query(Scan).count() > 0:
            print("Seed data already present — skipping.")
            return

        for path in sorted(glob.glob(os.path.join(SAMPLE_DIR, "*"))):
            hostname = os.path.basename(path).split(".")[0]
            with open(path, "r", errors="replace") as f:
                raw_text = f.read()
            device = Device(tenant_id=tenant.id, hostname=hostname)
            db.add(device)
            db.commit()
            db.refresh(device)
            scan = Scan(tenant_id=tenant.id, device_id=device.id, framework="ALL", status="uploaded")
            db.add(scan)
            db.commit()
            db.refresh(scan)
            try:
                await run_pipeline(db, scan, raw_text, framework="ALL")
                print(f"Seeded {hostname}: score={scan.compliance_score}")
            except Exception as e:
                print(f"Failed to seed {hostname}: {e}")

        # Pre-approve one training example so the Knowledge Base page has content
        pending = db.query(CommandMapping).filter(CommandMapping.status == "pending").limit(2).all()
        for m in pending:
            m.status = "approved"
            m.reviewed_by = "seed-script"
        db.commit()
        print(f"Auto-approved {len(pending)} sample training mappings.")
    finally:
        db.close()


if __name__ == "__main__":
    asyncio.run(seed())
