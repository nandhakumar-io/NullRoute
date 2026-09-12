"""
Control Layer service — CRUD helpers for UnifiedControl, FrameworkMapping,
ConfigConcept, VendorConfigPattern, and ControlReview.

Also exposes `get_framework_matrix(control_ids)` which resolves a list of
OPA control IDs to their multi-framework external IDs, used by the report
renderer to build the compliance matrix table.

All write operations are guarded behind explicit tenant_id so rows from one
tenant are never visible or writable to another (Phase 5 rule).
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.db import (ConfigConcept, ControlReview, FrameworkMapping,
                            UnifiedControl, VendorConfigPattern)


# ---------------------------------------------------------------------------
# UnifiedControl helpers
# ---------------------------------------------------------------------------

def list_controls(
    db: Session,
    tenant_id: str,
    domain: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[UnifiedControl]:
    q = db.query(UnifiedControl).filter(UnifiedControl.tenant_id == tenant_id)
    if domain:
        q = q.filter(UnifiedControl.domain == domain)
    if status:
        q = q.filter(UnifiedControl.status == status)
    return q.order_by(UnifiedControl.created_at.desc()).offset(offset).limit(limit).all()


def get_control(db: Session, tenant_id: str, control_id: str) -> Optional[UnifiedControl]:
    return (
        db.query(UnifiedControl)
        .filter(UnifiedControl.tenant_id == tenant_id, UnifiedControl.id == control_id)
        .first()
    )


def create_control(
    db: Session,
    tenant_id: str,
    name: str,
    *,
    objective: Optional[str] = None,
    domain: Optional[str] = None,
    source_text: Optional[str] = None,
    normalized_description: Optional[str] = None,
    source_document: Optional[str] = None,
    created_by: Optional[str] = None,
    status: str = "pending_review",
    framework_mappings: Optional[List[Dict[str, Any]]] = None,
) -> UnifiedControl:
    control = UnifiedControl(
        tenant_id=tenant_id,
        name=name,
        objective=objective,
        domain=domain,
        source_text=source_text,
        normalized_description=normalized_description,
        source_document=source_document,
        created_by=created_by,
        status=status,
    )
    db.add(control)
    db.flush()  # get id before adding children

    for fm in (framework_mappings or []):
        db.add(FrameworkMapping(
            control_id=control.id,
            framework=fm["framework"],
            external_id=fm["external_id"],
            confidence=fm.get("confidence"),
        ))

    db.commit()
    db.refresh(control)
    return control


def update_control(
    db: Session,
    tenant_id: str,
    control_id: str,
    updates: Dict[str, Any],
) -> Optional[UnifiedControl]:
    control = get_control(db, tenant_id, control_id)
    if not control:
        return None
    allowed = {
        "name", "objective", "domain", "source_text",
        "normalized_description", "status", "approved_by",
    }
    for key, value in updates.items():
        if key in allowed:
            setattr(control, key, value)
    if updates.get("status") == "approved" and not control.approved_at:
        control.approved_at = datetime.utcnow()
    db.commit()
    db.refresh(control)
    return control


# ---------------------------------------------------------------------------
# FrameworkMapping helpers
# ---------------------------------------------------------------------------

def add_framework_mapping(
    db: Session,
    control_id: str,
    framework: str,
    external_id: str,
    confidence: Optional[float] = None,
) -> FrameworkMapping:
    mapping = FrameworkMapping(
        control_id=control_id,
        framework=framework,
        external_id=external_id,
        confidence=confidence,
    )
    db.add(mapping)
    db.commit()
    db.refresh(mapping)
    return mapping


def get_framework_matrix(
    db: Session, tenant_id: str, control_ids: Optional[List[str]] = None
) -> Dict[str, Dict[str, str]]:
    """Return a nested dict: {control_id: {framework: external_id, ...}, ...}
    Used by the report renderer to build the multi-framework compliance matrix.
    When control_ids is None, returns the matrix for ALL approved controls in
    the tenant.
    """
    q = (
        db.query(FrameworkMapping)
        .join(UnifiedControl, FrameworkMapping.control_id == UnifiedControl.id)
        .filter(UnifiedControl.tenant_id == tenant_id)
    )
    if control_ids:
        q = q.filter(FrameworkMapping.control_id.in_(control_ids))

    matrix: Dict[str, Dict[str, str]] = {}
    for mapping in q.all():
        matrix.setdefault(mapping.control_id, {})[mapping.framework] = mapping.external_id
    return matrix


# ---------------------------------------------------------------------------
# ConfigConcept helpers
# ---------------------------------------------------------------------------

def list_concepts(db: Session, control_id: str) -> List[ConfigConcept]:
    return db.query(ConfigConcept).filter(ConfigConcept.control_id == control_id).all()


def add_concept(
    db: Session,
    control_id: str,
    concept_name: str,
    description: Optional[str] = None,
) -> ConfigConcept:
    concept = ConfigConcept(control_id=control_id, concept_name=concept_name, description=description)
    db.add(concept)
    db.commit()
    db.refresh(concept)
    return concept


# ---------------------------------------------------------------------------
# VendorConfigPattern helpers
# ---------------------------------------------------------------------------

def list_patterns(db: Session, control_id: str) -> List[VendorConfigPattern]:
    """Return all VendorConfigPatterns for every ConfigConcept of a control."""
    concepts = list_concepts(db, control_id)
    concept_ids = [c.id for c in concepts]
    if not concept_ids:
        return []
    return (
        db.query(VendorConfigPattern)
        .filter(VendorConfigPattern.concept_id.in_(concept_ids))
        .all()
    )


def add_pattern(
    db: Session,
    concept_id: str,
    vendor: str,
    pattern: str,
    example_snippet: Optional[str] = None,
    created_by: Optional[str] = None,
) -> VendorConfigPattern:
    vp = VendorConfigPattern(
        concept_id=concept_id,
        vendor=vendor,
        pattern=pattern,
        example_snippet=example_snippet,
        created_by=created_by,
    )
    db.add(vp)
    db.commit()
    db.refresh(vp)
    return vp


# ---------------------------------------------------------------------------
# ControlReview helpers
# ---------------------------------------------------------------------------

def list_pending_reviews(db: Session, tenant_id: str) -> List[ControlReview]:
    """Return ControlReviews for pending_review controls in this tenant."""
    return (
        db.query(ControlReview)
        .join(UnifiedControl, ControlReview.control_id == UnifiedControl.id)
        .filter(
            UnifiedControl.tenant_id == tenant_id,
            UnifiedControl.status == "pending_review",
        )
        .order_by(ControlReview.created_at.asc())
        .all()
    )


def submit_review(
    db: Session,
    tenant_id: str,
    control_id: str,
    reviewer: str,
    decision: str,
    original_text: Optional[str] = None,
    proposed_change: Optional[str] = None,
    correction: Optional[Dict[str, Any]] = None,
) -> ControlReview:
    """Record a human review decision.  When decision=='approved' the control
    status advances to 'approved'; 'rejected' leaves it in pending_review for
    re-extraction; 'corrected' stores the diff and advances to 'approved'.
    """
    review = ControlReview(
        control_id=control_id,
        reviewer=reviewer,
        original_text=original_text,
        proposed_change=proposed_change,
        decision=decision,
        correction_json=correction,
    )
    db.add(review)
    db.flush()

    control = get_control(db, tenant_id, control_id)
    if control and decision in ("approved", "corrected"):
        control.status = "approved"
        control.approved_by = reviewer
        control.approved_at = datetime.utcnow()
        if correction and isinstance(correction, dict):
            for field, value in correction.items():
                if hasattr(control, field):
                    setattr(control, field, value)

    db.commit()
    db.refresh(review)
    return review
