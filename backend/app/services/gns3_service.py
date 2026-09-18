import httpx
import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session
from app.models.db import Gns3Server, Device

logger = logging.getLogger(__name__)

_GNS3_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


def _client(server: Gns3Server) -> httpx.AsyncClient:
    auth = (server.username, server.password) if server.username else None
    return httpx.AsyncClient(auth=auth, verify=False, timeout=_GNS3_TIMEOUT)


class Gns3Service:

    @staticmethod
    async def ping(db: Session, server_id: str) -> Dict[str, Any]:
        """Check if the GNS3 server is reachable and return its version info."""
        server = db.query(Gns3Server).filter(Gns3Server.id == server_id).first()
        if not server:
            raise ValueError("GNS3 server not found")
        start = datetime.utcnow()
        try:
            async with _client(server) as client:
                resp = await client.get(f"{server.url}/v2/version")
                resp.raise_for_status()
                data = resp.json()
                elapsed = (datetime.utcnow() - start).total_seconds() * 1000
                return {
                    "reachable": True,
                    "version": data.get("version"),
                    "local": data.get("local", False),
                    "gns3vm": data.get("gns3vm", False),
                    "latency_ms": round(elapsed, 1),
                }
        except Exception as e:
            return {"reachable": False, "error": str(e)}

    @staticmethod
    async def get_projects(db: Session, server_id: str) -> List[Dict]:
        server = db.query(Gns3Server).filter(Gns3Server.id == server_id).first()
        if not server:
            raise ValueError("GNS3 server not found")
        async with _client(server) as client:
            resp = await client.get(f"{server.url}/v2/projects")
            resp.raise_for_status()
            return resp.json()

    @staticmethod
    async def get_nodes(db: Session, server_id: str, project_id: str) -> List[Dict]:
        server = db.query(Gns3Server).filter(Gns3Server.id == server_id).first()
        if not server:
            raise ValueError("GNS3 server not found")
        async with _client(server) as client:
            resp = await client.get(f"{server.url}/v2/projects/{project_id}/nodes")
            resp.raise_for_status()
            return resp.json()

    @staticmethod
    async def get_links(db: Session, server_id: str, project_id: str) -> List[Dict]:
        """Return the link/edge topology for a project."""
        server = db.query(Gns3Server).filter(Gns3Server.id == server_id).first()
        if not server:
            raise ValueError("GNS3 server not found")
        async with _client(server) as client:
            resp = await client.get(f"{server.url}/v2/projects/{project_id}/links")
            resp.raise_for_status()
            return resp.json()

    @staticmethod
    async def get_topology(db: Session, server_id: str, project_id: str) -> Dict:
        """Return nodes + links together as a topology snapshot."""
        nodes_task = Gns3Service.get_nodes(db, server_id, project_id)
        links_task = Gns3Service.get_links(db, server_id, project_id)
        nodes, links = await asyncio.gather(nodes_task, links_task)

        # Annotate whether each node has already been imported into NetSecAuditor
        existing_hostnames = {
            d.hostname for d in db.query(Device.hostname).all()
        }
        for node in nodes:
            node["already_imported"] = node.get("name") in existing_hostnames

        return {"nodes": nodes, "links": links}

    @staticmethod
    async def start_project(db: Session, server_id: str, project_id: str) -> Dict:
        server = db.query(Gns3Server).filter(Gns3Server.id == server_id).first()
        if not server:
            raise ValueError("GNS3 server not found")
        async with _client(server) as client:
            resp = await client.post(f"{server.url}/v2/projects/{project_id}/open")
            resp.raise_for_status()
            # Start all nodes
            resp2 = await client.post(f"{server.url}/v2/projects/{project_id}/nodes/start")
            resp2.raise_for_status()
            return {"status": "started", "project_id": project_id}

    @staticmethod
    async def stop_project(db: Session, server_id: str, project_id: str) -> Dict:
        server = db.query(Gns3Server).filter(Gns3Server.id == server_id).first()
        if not server:
            raise ValueError("GNS3 server not found")
        async with _client(server) as client:
            resp = await client.post(f"{server.url}/v2/projects/{project_id}/nodes/stop")
            resp.raise_for_status()
            return {"status": "stopped", "project_id": project_id}

    @staticmethod
    async def import_gns3_project(
        db: Session, server_id: str, project_id: str, tenant_id: str,
        node_ids: Optional[List[str]] = None,
    ) -> List[str]:
        """Import GNS3 nodes as NetSecAuditor devices.

        Args:
            node_ids: Optional list of specific node_id values to import.
                      If None, all non-infrastructure nodes are imported.
        """
        nodes = await Gns3Service.get_nodes(db, server_id, project_id)

        # Resolve the project name from the project list for a nicer site label.
        try:
            projects = await Gns3Service.get_projects(db, server_id)
            project_name = next(
                (p.get("name", project_id) for p in projects if p.get("project_id") == project_id),
                project_id,
            )
        except Exception:
            project_name = project_id

        SKIP_TYPES = {"cloud", "ethernet_switch", "frame_relay_switch", "nat", "ethernet_hub"}
        imported_ids: List[str] = []

        for node in nodes:
            node_type = node.get("node_type", "")
            if node_type in SKIP_TYPES:
                continue
            if node_ids and node.get("node_id") not in node_ids:
                continue

            hostname = node.get("name", "unknown")
            mgmt_ip = None
            # GNS3 nodes may expose a console host that can double as management IP
            if node.get("console_host") and node.get("console_host") not in ("0.0.0.0", ""):
                mgmt_ip = node["console_host"]

            # Skip if already imported (idempotent by hostname + tenant)
            existing = db.query(Device).filter(
                Device.tenant_id == tenant_id,
                Device.hostname == hostname,
            ).first()
            if existing:
                imported_ids.append(existing.id)
                continue

            dev = Device(
                tenant_id=tenant_id,
                hostname=hostname,
                name=hostname,
                vendor="GNS3",
                model=node_type,
                environment="lab",
                site=f"GNS3 / {project_name}",
                management_address=mgmt_ip,
                description=f"Auto-imported from GNS3 project '{project_name}' (node_id={node.get('node_id')})",
                enabled=True,
            )
            db.add(dev)
            db.flush()
            imported_ids.append(dev.id)

        db.commit()
        return imported_ids
