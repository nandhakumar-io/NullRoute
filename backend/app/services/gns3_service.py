import httpx
import asyncio
from sqlalchemy.orm import Session
from app.models.db import Gns3Server, Device
from app.services import pipeline

class Gns3Service:
    @staticmethod
    async def get_projects(db: Session, server_id: str):
        server = db.query(Gns3Server).filter(Gns3Server.id == server_id).first()
        if not server:
            raise ValueError("GNS3 server not found")
        
        auth = (server.username, server.password) if server.username else None
        async with httpx.AsyncClient(auth=auth, verify=False) as client:
            resp = await client.get(f"{server.url}/v2/projects")
            resp.raise_for_status()
            return resp.json()

    @staticmethod
    async def get_nodes(db: Session, server_id: str, project_id: str):
        server = db.query(Gns3Server).filter(Gns3Server.id == server_id).first()
        if not server:
            raise ValueError("GNS3 server not found")

        auth = (server.username, server.password) if server.username else None
        async with httpx.AsyncClient(auth=auth, verify=False) as client:
            resp = await client.get(f"{server.url}/v2/projects/{project_id}/nodes")
            resp.raise_for_status()
            return resp.json()

    @staticmethod
    async def import_gns3_project(db: Session, server_id: str, project_id: str, tenant_id: str):
        nodes = await Gns3Service.get_nodes(db, server_id, project_id)
        imported_devices = []
        for node in nodes:
            # We skip basic shapes/clouds and only grab compute instances or routers
            node_type = node.get("node_type", "")
            if node_type in ["cloud", "ethernet_switch", "frame_relay_switch", "nat"]:
                continue
            
            # Create a device in NetSecAuditor
            dev = Device(
                tenant_id=tenant_id,
                hostname=node.get("name"),
                vendor="GNS3",
                model=node_type,
                environment="lab",
                site=f"Project: {project_id}",
                description=f"Auto-imported from GNS3 (Node ID: {node.get('node_id')})"
            )
            db.add(dev)
            db.flush()
            imported_devices.append(dev.id)

        # Triger Auto-Ingestion Pipeline on all imported devices for compliance/Batfish updates
        import threading
        for dev_id in imported_devices:
            # Emulate an automatic collection trigger
            # We spin up a thread so it doesn't block the API response
            # Do not invoke pipeline here; it is an async coroutine and the db connection will be closed prematurely.
            # Rely on the UI to trigger a Bulk Scan, or use a proper event queue architecture.
            pass

        db.commit()
        return imported_devices
