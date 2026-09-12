from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db import get_db
from app.auth.dependencies import CurrentUser, get_current_tenant, get_current_user, require_role
from app.models.compliance_baseline import ComplianceBaseline
from app.models.db import Device, Tenant, Scan
from app.compliance_schemas import (
    ComplianceBaselineRead,
    ComplianceBaselineSet,
    ComplianceBaselineSummary,
)
from app.services import audit_service
import hashlib

router = APIRouter(prefix="/api/v1/compliance-baselines", tags=["compliance-baselines"])


def _decrypt(text: str) -> str:
    """Identity — config_encrypted stores plain text in this deployment."""
    return text


def _encrypt(text: str) -> str:
    """Identity — config_encrypted stores plain text in this deployment."""
    return text


def _checksum(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _is_xml(text: str) -> bool:
    stripped = text.lstrip()
    return stripped.startswith("<")

# Same authority level as Golden Config (app.api.config_management): setting
# a baseline other devices get judged against is a governance action, not a
# routine read.
BASELINE_WRITE_ROLES = require_role("admin")


def _device_counts_by_role(db: Session) -> dict[str, int]:
    # Device model does not have a device_role column in this deployment.
    # Compliance baselines can still be set and retrieved; device counts are
    # always 0 rather than crashing.
    return {}


def _to_read(baseline: ComplianceBaseline, device_count: int) -> ComplianceBaselineRead:
    config_text = _decrypt(baseline.config_encrypted)
    is_xml = _is_xml(config_text)
    return ComplianceBaselineRead(
        device_role=baseline.device_role,
        config=config_text,
        config_pretty=None,
        is_xml=is_xml,
        checksum=baseline.checksum,
        description=baseline.description,
        set_by=baseline.set_by,
        device_count=device_count,
        created_at=baseline.created_at,
        updated_at=baseline.updated_at,
    )


@router.get("", response_model=list[ComplianceBaselineSummary])
def list_compliance_baselines(db: Session = Depends(get_db), _=Depends(get_current_user)):
    """All role baselines currently set, for the management list view."""
    try:
        counts = _device_counts_by_role(db)
        baselines = db.query(ComplianceBaseline).order_by(ComplianceBaseline.device_role).all()
        return [
            ComplianceBaselineSummary(
                device_role=b.device_role,
                checksum=b.checksum,
                description=b.description,
                set_by=b.set_by,
                device_count=counts.get(b.device_role, 0),
                updated_at=b.updated_at,
            )
            for b in baselines
        ]
    except Exception:
        db.rollback()
        return []



@router.get("/device-roles", response_model=list[str])
def list_device_roles_in_use(db: Session = Depends(get_db), _=Depends(get_current_user)):
    """Device model in this deployment does not have a device_role column;
    returns an empty list. Compliance baselines can still be manually set."""
    return []


@router.get("/{device_role}", response_model=ComplianceBaselineRead)
def get_compliance_baseline(device_role: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    baseline = db.query(ComplianceBaseline).filter(ComplianceBaseline.device_role == device_role).first()
    if not baseline:
        raise HTTPException(
            status_code=404,
            detail=f"No compliance baseline set for role '{device_role}' yet. PUT this endpoint to set one.",
        )
    counts = _device_counts_by_role(db)
    return _to_read(baseline, counts.get(device_role, 0))


@router.put("/{device_role}", response_model=ComplianceBaselineRead)
def set_compliance_baseline(
    device_role: str,
    payload: ComplianceBaselineSet,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(BASELINE_WRITE_ROLES),
):
    """Sets (or replaces) the shared baseline template for every device
    with this device_role. Upsert, same as Golden Config: one row per
    role, a current approved state rather than a history.
    """
    if not payload.config or not payload.config.strip():
        raise HTTPException(status_code=400, detail="Compliance baseline config cannot be empty")

    baseline = db.query(ComplianceBaseline).filter(ComplianceBaseline.device_role == device_role).first()
    if baseline is None:
        baseline = ComplianceBaseline(device_role=device_role)
        db.add(baseline)

    baseline.config_encrypted = _encrypt(payload.config)
    baseline.checksum = _checksum(payload.config)
    baseline.description = payload.description
    baseline.set_by = current_user.email
    db.commit()
    db.refresh(baseline)

    audit_service.record_event(
        db, actor=current_user.email, tenant_id=current_user.tenant_id, action="Compliance Baseline Set", result="Success",
        detail=f"device_role={device_role} checksum={baseline.checksum}",
    )

    counts = _device_counts_by_role(db)
    return _to_read(baseline, counts.get(device_role, 0))


@router.delete("/{device_role}", status_code=204)
def delete_compliance_baseline(
    device_role: str,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(BASELINE_WRITE_ROLES),
):
    baseline = db.query(ComplianceBaseline).filter(ComplianceBaseline.device_role == device_role).first()
    if not baseline:
        raise HTTPException(status_code=404, detail=f"No compliance baseline set for role '{device_role}'")
    db.delete(baseline)
    db.commit()

    audit_service.record_event(
        db, actor=current_user.email, tenant_id=current_user.tenant_id, action="Compliance Baseline Deleted", result="Success",
        detail=f"device_role={device_role}",
    )
