"""Datacenter / Rack / NetworkGroup topology management + full-potential
Batfish group analysis.

Hierarchy: Datacenter -> Rack -> Device, and independently, NetworkGroup
("block") <- many Devices, which is the unit Batfish analyzes as one
snapshot. A NetworkGroup can be scoped to a whole datacenter, a single
rack, or an arbitrary hand-picked set of devices spanning both.

Admins author "desired network behaviour" as structured BatfishQuestion
rows on a group (see batfish_service.QUESTION_TYPES for the supported
question vocabulary); POST /api/topology/groups/{id}/scan uploads every
member device's latest collected/uploaded config into one Batfish
snapshot and evaluates the built-in segmentation checks plus every
enabled custom question against it.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth.dependencies import CurrentUser, get_current_tenant, get_current_user, require_role
from app.db import get_db
from app.models.db import (BatfishQuestion, Datacenter, Device, NetworkGroup,
                            NetworkGroupMember, Rack, Scan)
from app.services import batfish_service
from app.services import minio_service

router = APIRouter(prefix="/api/topology", tags=["topology-groups"], dependencies=[Depends(get_current_user)])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class DatacenterCreate(BaseModel):
    name: str
    location: Optional[str] = None
    description: Optional[str] = None


class DatacenterOut(DatacenterCreate):
    id: str
    created_at: datetime

    class Config:
        from_attributes = True


class RackCreate(BaseModel):
    datacenter_id: str
    name: str
    row: Optional[str] = None
    unit_count: Optional[int] = None
    description: Optional[str] = None


class RackOut(RackCreate):
    id: str
    created_at: datetime

    class Config:
        from_attributes = True


class GroupCreate(BaseModel):
    name: str
    description: Optional[str] = None
    datacenter_id: Optional[str] = None
    rack_id: Optional[str] = None
    device_ids: List[str] = Field(default_factory=list)


class GroupOut(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    datacenter_id: Optional[str] = None
    rack_id: Optional[str] = None
    device_ids: List[str] = Field(default_factory=list)
    last_batfish_status: Optional[str] = None
    last_batfish_run_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class DevicePlacement(BaseModel):
    datacenter_id: Optional[str] = None
    rack_id: Optional[str] = None


class QuestionCreate(BaseModel):
    name: str
    description: Optional[str] = None
    question_type: str
    params: Dict[str, Any] = Field(default_factory=dict)
    severity: str = "MEDIUM"
    enabled: bool = True


class QuestionOut(QuestionCreate):
    id: str
    group_id: str
    last_status: Optional[str] = None
    last_result: Optional[Dict[str, Any]] = None
    last_run_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _group_out(db: Session, g: NetworkGroup) -> GroupOut:
    device_ids = [m.device_id for m in db.query(NetworkGroupMember).filter(NetworkGroupMember.group_id == g.id).all()]
    return GroupOut(
        id=g.id, name=g.name, description=g.description, datacenter_id=g.datacenter_id,
        rack_id=g.rack_id, device_ids=device_ids, last_batfish_status=g.last_batfish_status,
        last_batfish_run_at=g.last_batfish_run_at, created_at=g.created_at,
    )


def _get_group_or_404(db: Session, group_id: str, tenant_id: str) -> NetworkGroup:
    g = db.query(NetworkGroup).filter(NetworkGroup.id == group_id, NetworkGroup.tenant_id == tenant_id).first()
    if not g:
        raise HTTPException(404, "Network group not found")
    return g


# ---------------------------------------------------------------------------
# Datacenters
# ---------------------------------------------------------------------------

@router.post("/datacenters", response_model=DatacenterOut, dependencies=[Depends(require_role("admin", "operator"))])
def create_datacenter(body: DatacenterCreate, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    dc = Datacenter(tenant_id=tenant_id, **body.dict())
    db.add(dc)
    db.commit()
    db.refresh(dc)
    return dc


@router.get("/datacenters", response_model=List[DatacenterOut])
def list_datacenters(db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    return db.query(Datacenter).filter(Datacenter.tenant_id == tenant_id).order_by(Datacenter.created_at.desc()).all()


@router.delete("/datacenters/{dc_id}", dependencies=[Depends(require_role("admin", "operator"))])
def delete_datacenter(dc_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    dc = db.query(Datacenter).filter(Datacenter.id == dc_id, Datacenter.tenant_id == tenant_id).first()
    if not dc:
        raise HTTPException(404, "Datacenter not found")
    db.delete(dc)
    db.commit()
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Racks
# ---------------------------------------------------------------------------

@router.post("/racks", response_model=RackOut, dependencies=[Depends(require_role("admin", "operator"))])
def create_rack(body: RackCreate, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    dc = db.query(Datacenter).filter(Datacenter.id == body.datacenter_id, Datacenter.tenant_id == tenant_id).first()
    if not dc:
        raise HTTPException(404, "Datacenter not found")
    rack = Rack(tenant_id=tenant_id, **body.dict())
    db.add(rack)
    db.commit()
    db.refresh(rack)
    return rack


@router.get("/racks", response_model=List[RackOut])
def list_racks(datacenter_id: Optional[str] = None, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    q = db.query(Rack).filter(Rack.tenant_id == tenant_id)
    if datacenter_id:
        q = q.filter(Rack.datacenter_id == datacenter_id)
    return q.order_by(Rack.created_at.desc()).all()


@router.delete("/racks/{rack_id}", dependencies=[Depends(require_role("admin", "operator"))])
def delete_rack(rack_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    rack = db.query(Rack).filter(Rack.id == rack_id, Rack.tenant_id == tenant_id).first()
    if not rack:
        raise HTTPException(404, "Rack not found")
    db.delete(rack)
    db.commit()
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Device placement (assign a device into a datacenter/rack)
# ---------------------------------------------------------------------------

@router.put("/devices/{device_id}/placement", dependencies=[Depends(require_role("admin", "operator"))])
def set_device_placement(device_id: str, body: DevicePlacement, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    device = db.query(Device).filter(Device.id == device_id, Device.tenant_id == tenant_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    if body.datacenter_id is not None:
        device.datacenter_id = body.datacenter_id or None
    if body.rack_id is not None:
        device.rack_id = body.rack_id or None
    db.commit()
    return {"device_id": device_id, "datacenter_id": device.datacenter_id, "rack_id": device.rack_id}


# ---------------------------------------------------------------------------
# Network groups ("blocks" / topologies to analyze together in Batfish)
# ---------------------------------------------------------------------------

@router.post("/groups", response_model=GroupOut, dependencies=[Depends(require_role("admin", "operator"))])
def create_group(body: GroupCreate, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    g = NetworkGroup(
        tenant_id=tenant_id, name=body.name, description=body.description,
        datacenter_id=body.datacenter_id, rack_id=body.rack_id,
    )
    db.add(g)
    db.flush()
    for device_id in set(body.device_ids):
        device = db.query(Device).filter(Device.id == device_id, Device.tenant_id == tenant_id).first()
        if not device:
            raise HTTPException(404, f"Device {device_id} not found")
        db.add(NetworkGroupMember(group_id=g.id, device_id=device_id))
    db.commit()
    db.refresh(g)
    return _group_out(db, g)


@router.get("/groups", response_model=List[GroupOut])
def list_groups(db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    groups = db.query(NetworkGroup).filter(NetworkGroup.tenant_id == tenant_id).order_by(NetworkGroup.created_at.desc()).all()
    return [_group_out(db, g) for g in groups]


@router.get("/groups/{group_id}", response_model=GroupOut)
def get_group(group_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    g = _get_group_or_404(db, group_id, tenant_id)
    return _group_out(db, g)


@router.put("/groups/{group_id}/devices", response_model=GroupOut, dependencies=[Depends(require_role("admin", "operator"))])
def set_group_devices(group_id: str, device_ids: List[str], db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    """Replace the full membership list of a group in one call."""
    g = _get_group_or_404(db, group_id, tenant_id)
    db.query(NetworkGroupMember).filter(NetworkGroupMember.group_id == group_id).delete()
    for device_id in set(device_ids):
        device = db.query(Device).filter(Device.id == device_id, Device.tenant_id == tenant_id).first()
        if not device:
            raise HTTPException(404, f"Device {device_id} not found")
        db.add(NetworkGroupMember(group_id=group_id, device_id=device_id))
    db.commit()
    db.refresh(g)
    return _group_out(db, g)


@router.delete("/groups/{group_id}", dependencies=[Depends(require_role("admin", "operator"))])
def delete_group(group_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    g = _get_group_or_404(db, group_id, tenant_id)
    db.delete(g)
    db.commit()
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Admin-defined "desired network behaviour" questions
# ---------------------------------------------------------------------------

@router.get("/question-types")
def list_question_types():
    """The fixed, structured menu of Batfish question kinds an admin can
    author -- never free-text/eval, so results stay deterministic."""
    return batfish_service.QUESTION_TYPES


@router.post("/groups/{group_id}/questions", response_model=QuestionOut, dependencies=[Depends(require_role("admin", "operator"))])
def create_question(group_id: str, body: QuestionCreate, db: Session = Depends(get_db),
                     tenant_id: str = Depends(get_current_tenant), user: CurrentUser = Depends(get_current_user)):
    _get_group_or_404(db, group_id, tenant_id)
    if body.question_type not in batfish_service.QUESTION_TYPES:
        raise HTTPException(400, f"Unknown question_type. Supported: {sorted(batfish_service.QUESTION_TYPES)}")
    q = BatfishQuestion(
        tenant_id=tenant_id, group_id=group_id, name=body.name, description=body.description,
        question_type=body.question_type, params=body.params, severity=body.severity,
        enabled=body.enabled, created_by=getattr(user, "id", None) or getattr(user, "username", None),
    )
    db.add(q)
    db.commit()
    db.refresh(q)
    return q


@router.get("/groups/{group_id}/questions", response_model=List[QuestionOut])
def list_questions(group_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    _get_group_or_404(db, group_id, tenant_id)
    return db.query(BatfishQuestion).filter(
        BatfishQuestion.group_id == group_id, BatfishQuestion.tenant_id == tenant_id
    ).order_by(BatfishQuestion.created_at.desc()).all()


@router.put("/questions/{question_id}", response_model=QuestionOut, dependencies=[Depends(require_role("admin", "operator"))])
def update_question(question_id: str, body: QuestionCreate, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    q = db.query(BatfishQuestion).filter(BatfishQuestion.id == question_id, BatfishQuestion.tenant_id == tenant_id).first()
    if not q:
        raise HTTPException(404, "Question not found")
    if body.question_type not in batfish_service.QUESTION_TYPES:
        raise HTTPException(400, f"Unknown question_type. Supported: {sorted(batfish_service.QUESTION_TYPES)}")
    for field_name in ("name", "description", "question_type", "params", "severity", "enabled"):
        setattr(q, field_name, getattr(body, field_name))
    db.commit()
    db.refresh(q)
    return q


@router.delete("/questions/{question_id}", dependencies=[Depends(require_role("admin", "operator"))])
def delete_question(question_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    q = db.query(BatfishQuestion).filter(BatfishQuestion.id == question_id, BatfishQuestion.tenant_id == tenant_id).first()
    if not q:
        raise HTTPException(404, "Question not found")
    db.delete(q)
    db.commit()
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Trigger a full group scan: upload every member device's latest config to
# Batfish as one snapshot, run built-in segmentation checks + every enabled
# custom question.
# ---------------------------------------------------------------------------

def _latest_raw_config(db: Session, device: Device) -> Optional[str]:
    scan = db.query(Scan).filter(
        Scan.device_id == device.id, Scan.raw_config_path.isnot(None)
    ).order_by(Scan.created_at.desc()).first()
    if not scan or not scan.raw_config_path:
        return None
    try:
        return minio_service.get_object(scan.raw_config_path).decode("utf-8", errors="replace")
    except Exception:
        return None


@router.post("/groups/{group_id}/scan")
def scan_group(group_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    """Uploads all member device configs to Batfish as one snapshot and
    evaluates the group's behavioral checks. Devices with no collected
    config yet are skipped (reported in `skipped_devices`), never silently
    treated as compliant."""
    g = _get_group_or_404(db, group_id, tenant_id)
    memberships = db.query(NetworkGroupMember).filter(NetworkGroupMember.group_id == group_id).all()
    if not memberships:
        raise HTTPException(400, "Group has no member devices. Add devices before scanning.")

    device_configs: Dict[str, str] = {}
    skipped: List[str] = []
    for m in memberships:
        device = db.query(Device).filter(Device.id == m.device_id).first()
        if not device:
            continue
        raw = _latest_raw_config(db, device)
        if not raw:
            skipped.append(device.hostname or device.id)
            continue
        device_configs[device.hostname or device.id] = raw

    questions = [
        {
            "id": q.id, "name": q.name, "question_type": q.question_type,
            "params": q.params, "severity": q.severity, "enabled": q.enabled,
        }
        for q in db.query(BatfishQuestion).filter(
            BatfishQuestion.group_id == group_id, BatfishQuestion.enabled.is_(True)
        ).all()
    ]

    result = batfish_service.analyze_network_group(group_id, device_configs, questions)
    result_dict = result.to_dict()
    result_dict["skipped_devices"] = skipped
    result_dict["scanned_devices"] = list(device_configs.keys())

    g.last_batfish_status = result.status
    g.last_batfish_run_at = datetime.utcnow()
    g.last_batfish_result = result_dict
    db.commit()

    for finding in result.findings():
        control_id = finding.get("control_id", "")
        if control_id.startswith("CUSTOM-"):
            q_id = control_id.replace("CUSTOM-", "", 1)
            q = db.query(BatfishQuestion).filter(BatfishQuestion.id == q_id).first()
            if q:
                q.last_status = finding.get("batfish_status")
                q.last_result = finding
                q.last_run_at = datetime.utcnow()
    db.commit()

    return result_dict
