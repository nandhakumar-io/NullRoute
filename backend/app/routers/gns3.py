from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel

from app.db import get_db
from app.auth.dependencies import require_permission, get_current_tenant
from app.auth.rbac import Permission
from app.models.db import Gns3Server
from app.services.gns3_service import Gns3Service

router = APIRouter(prefix="/api/gns3", tags=["gns3"])


class Gns3ServerCreate(BaseModel):
    name: str
    url: str
    username: Optional[str] = None
    password: Optional[str] = None


class ImportPayload(BaseModel):
    node_ids: Optional[List[str]] = None  # None = import all eligible nodes


@router.get("/servers")
def list_servers(
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    _ = Depends(require_permission(Permission.VIEW)),
):
    return db.query(Gns3Server).filter(Gns3Server.tenant_id == tenant_id).all()


@router.post("/servers")
def add_server(
    server_in: Gns3ServerCreate,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    _ = Depends(require_permission(Permission.SCAN)),
):
    server = Gns3Server(
        tenant_id=tenant_id,
        name=server_in.name,
        url=server_in.url.rstrip("/"),
        username=server_in.username,
        password=server_in.password,
    )
    db.add(server)
    db.commit()
    db.refresh(server)
    return server


@router.delete("/servers/{server_id}", status_code=204)
def delete_server(
    server_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    _ = Depends(require_permission(Permission.SCAN)),
):
    server = db.query(Gns3Server).filter(
        Gns3Server.id == server_id, Gns3Server.tenant_id == tenant_id
    ).first()
    if not server:
        raise HTTPException(404, "GNS3 server not found")
    db.delete(server)
    db.commit()
    return None


@router.get("/servers/{server_id}/ping")
async def ping_server(
    server_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    """Check reachability and get version info from a GNS3 server."""
    try:
        return await Gns3Service.ping(db, server_id)
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/servers/{server_id}/labs")
async def list_labs(
    server_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    try:
        return await Gns3Service.get_projects(db, server_id)
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/servers/{server_id}/labs/{lab_id}/topology")
async def get_topology(
    server_id: str,
    lab_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    """Return nodes + links for rendering a topology map in the UI."""
    try:
        return await Gns3Service.get_topology(db, server_id, lab_id)
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/servers/{server_id}/labs/{lab_id}/start")
async def start_lab(
    server_id: str,
    lab_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    _ = Depends(require_permission(Permission.SCAN)),
):
    """Open the project and start all nodes."""
    try:
        return await Gns3Service.start_project(db, server_id, lab_id)
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/servers/{server_id}/labs/{lab_id}/stop")
async def stop_lab(
    server_id: str,
    lab_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    _ = Depends(require_permission(Permission.SCAN)),
):
    """Stop all nodes in the project."""
    try:
        return await Gns3Service.stop_project(db, server_id, lab_id)
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/servers/{server_id}/labs/{lab_id}/import")
async def import_lab(
    server_id: str,
    lab_id: str,
    payload: ImportPayload = ImportPayload(),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    _ = Depends(require_permission(Permission.SCAN)),
):
    """Import selected (or all) nodes from a GNS3 lab as NetSecAuditor devices."""
    try:
        device_ids = await Gns3Service.import_gns3_project(
            db, server_id, lab_id, tenant_id, node_ids=payload.node_ids
        )
        return {"imported": len(device_ids), "device_ids": device_ids}
    except Exception as e:
        raise HTTPException(500, str(e))
