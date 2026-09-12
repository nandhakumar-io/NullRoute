"""Unified Control Library API.

CRUD + review workflow for UnifiedControl / FrameworkMapping / ConfigConcept
/ VendorConfigPattern / ControlReview, plus the "compile to Rego" trigger
that hands off to policy_compiler.py. Auth follows this codebase's
established pattern (Depends(get_current_user) at the router level,
Depends(require_role(...)) on restricted endpoints) -- see
routers/backups.py for the reference implementation this mirrors.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth.dependencies import CurrentUser, get_current_tenant, get_current_user, require_role
from app.db import get_db
from app.services import control_service, policy_compiler

router = APIRouter(tags=["controls"], dependencies=[Depends(get_current_user)])

MANAGE_CONTROLS = require_role("admin", "security_analyst")
EDIT_CONTROLS = require_role("admin")


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------

class FrameworkMappingIn(BaseModel):
    framework: str
    external_id: str
    confidence: Optional[float] = None


class ControlCreate(BaseModel):
    name: str
    objective: Optional[str] = None
    domain: Optional[str] = None
    source_text: Optional[str] = None
    normalized_description: Optional[str] = None
    source_document: Optional[str] = None
    framework_mappings: List[FrameworkMappingIn] = Field(default_factory=list)


class ControlUpdate(BaseModel):
    name: Optional[str] = None
    objective: Optional[str] = None
    domain: Optional[str] = None
    source_text: Optional[str] = None
    normalized_description: Optional[str] = None
    status: Optional[str] = None


class PatternIn(BaseModel):
    concept_id: Optional[str] = None
    concept_name: Optional[str] = None  # convenience: create the concept inline if concept_id is omitted
    vendor: str
    pattern: str
    example_snippet: Optional[str] = None


class ReviewDecisionIn(BaseModel):
    decision: str  # approved/rejected/corrected
    original_text: Optional[str] = None
    proposed_change: Optional[str] = None
    correction: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _control_dict(control) -> Dict[str, Any]:
    return {
        "id": control.id,
        "name": control.name,
        "objective": control.objective,
        "domain": control.domain,
        "source_text": control.source_text,
        "normalized_description": control.normalized_description,
        "status": control.status,
        "source_document": control.source_document,
        "created_by": control.created_by,
        "approved_by": control.approved_by,
        "approved_at": control.approved_at.isoformat() if control.approved_at else None,
        "created_at": control.created_at.isoformat() if control.created_at else None,
        "updated_at": control.updated_at.isoformat() if control.updated_at else None,
    }


def _mapping_dict(m) -> Dict[str, Any]:
    return {"id": m.id, "framework": m.framework, "external_id": m.external_id, "confidence": m.confidence}


def _concept_dict(c) -> Dict[str, Any]:
    return {"id": c.id, "concept_name": c.concept_name, "description": c.description}


def _pattern_dict(p) -> Dict[str, Any]:
    return {
        "id": p.id, "concept_id": p.concept_id, "vendor": p.vendor,
        "pattern": p.pattern, "example_snippet": p.example_snippet, "created_by": p.created_by,
    }


def _review_dict(r) -> Dict[str, Any]:
    return {
        "id": r.id, "control_id": r.control_id, "reviewer": r.reviewer,
        "original_text": r.original_text, "proposed_change": r.proposed_change,
        "decision": r.decision, "correction_json": r.correction_json,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


# ---------------------------------------------------------------------------
# UnifiedControl endpoints
# ---------------------------------------------------------------------------

@router.get("/api/controls")
def list_controls(
    domain: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    controls = control_service.list_controls(db, tenant_id, domain=domain, status=status, limit=min(limit, 500), offset=offset)
    return {"count": len(controls), "controls": [_control_dict(c) for c in controls]}


@router.post("/api/controls", dependencies=[Depends(MANAGE_CONTROLS)])
def create_control(
    payload: ControlCreate,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    control = control_service.create_control(
        db, tenant_id, payload.name,
        objective=payload.objective, domain=payload.domain, source_text=payload.source_text,
        normalized_description=payload.normalized_description, source_document=payload.source_document,
        created_by=user.username,
        framework_mappings=[m.model_dump() for m in payload.framework_mappings],
    )
    return _control_dict(control)


@router.get("/api/controls/reviews/pending")
def list_pending_reviews(db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    reviews = control_service.list_pending_reviews(db, tenant_id)
    return {"count": len(reviews), "reviews": [_review_dict(r) for r in reviews]}


@router.get("/api/controls/{control_id}")
def get_control(control_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    control = control_service.get_control(db, tenant_id, control_id)
    if not control:
        raise HTTPException(404, "Control not found")
    concepts = control_service.list_concepts(db, control_id)
    out = _control_dict(control)
    out["framework_mappings"] = [_mapping_dict(m) for m in control.framework_mappings]
    out["config_concepts"] = [_concept_dict(c) for c in concepts]
    return out


@router.patch("/api/controls/{control_id}", dependencies=[Depends(EDIT_CONTROLS)])
def update_control(
    control_id: str,
    payload: ControlUpdate,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    control = control_service.update_control(db, tenant_id, control_id, updates)
    if not control:
        raise HTTPException(404, "Control not found")
    return _control_dict(control)


@router.get("/api/controls/{control_id}/patterns")
def list_patterns(control_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    control = control_service.get_control(db, tenant_id, control_id)
    if not control:
        raise HTTPException(404, "Control not found")
    patterns = control_service.list_patterns(db, control_id)
    return {"count": len(patterns), "patterns": [_pattern_dict(p) for p in patterns]}


@router.post("/api/controls/{control_id}/patterns", dependencies=[Depends(MANAGE_CONTROLS)])
def add_pattern(
    control_id: str,
    payload: PatternIn,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    control = control_service.get_control(db, tenant_id, control_id)
    if not control:
        raise HTTPException(404, "Control not found")

    concept_id = payload.concept_id
    if not concept_id:
        if not payload.concept_name:
            raise HTTPException(400, "Either concept_id or concept_name is required")
        concept = control_service.add_concept(db, control_id, payload.concept_name)
        concept_id = concept.id

    pattern = control_service.add_pattern(
        db, concept_id, payload.vendor, payload.pattern,
        example_snippet=payload.example_snippet, created_by=user.username,
    )
    return _pattern_dict(pattern)


@router.post("/api/controls/{control_id}/compile", dependencies=[Depends(MANAGE_CONTROLS)])
async def compile_control(control_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    try:
        result = await policy_compiler.compile_and_reload(db, tenant_id, control_id)
    except policy_compiler.PolicyCompilationError as exc:
        raise HTTPException(400, str(exc))
    return result


@router.post("/api/controls/reviews/{control_id}/decide", dependencies=[Depends(MANAGE_CONTROLS)])
def decide_review(
    control_id: str,
    payload: ReviewDecisionIn,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
):
    """Record a human decision on a pending_review control. `control_id` is
    the UnifiedControl id -- a control can accumulate multiple ControlReview
    rows over its lifetime (each decision, e.g. a rejection followed later
    by an approved correction, is its own row), so this endpoint always
    creates a new review record rather than mutating one.
    """
    if payload.decision not in ("approved", "rejected", "corrected"):
        raise HTTPException(400, "decision must be one of approved/rejected/corrected")
    if not control_service.get_control(db, tenant_id, control_id):
        raise HTTPException(404, "Control not found")

    review = control_service.submit_review(
        db, tenant_id, control_id, user.username, payload.decision,
        original_text=payload.original_text, proposed_change=payload.proposed_change,
        correction=payload.correction,
    )
    return _review_dict(review)