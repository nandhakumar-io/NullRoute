"""
Model Registry Service - Loop 2 (Model Lifecycle Management)
"""
from typing import Any, Dict
from datetime import datetime
from sqlalchemy.orm import Session

from app.models.db import ModelRegistryEntry
from app.services import audit_service
from app.ai import model_registry as ai_model_registry


# Configurable defaults for regression gates
MIN_MACRO_F1 = 0.85
MAX_MACRO_F1_REGRESSION = 0.03
MIN_UNKNOWN_F1 = 0.90
MAX_UNKNOWN_F1_REGRESSION = 0.05


def create_candidate(
    db: Session,
    model_name: str,
    model_type: str,
    dataset_version: str,
    base_model_version: str,
    artifact_path: str,
    model_hash: str,
    metrics: Dict[str, float],
    training_job_id: str,
    user: Any
) -> ModelRegistryEntry:

    entry = ModelRegistryEntry(
        model_name=model_name,
        model_type=model_type,
        dataset_version=dataset_version,
        base_model_version=base_model_version,
        artifact_path=artifact_path,
        model_hash=model_hash,
        metrics=metrics,
        training_timestamp=datetime.utcnow(),
        status="CANDIDATE",
        created_by=user.username if hasattr(user, "username") and user.username else "system",
        training_job_id=training_job_id,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def approve_candidate(db: Session, model_id: str, user: Any, request: Any = None) -> ModelRegistryEntry:
    model = db.query(ModelRegistryEntry).filter(ModelRegistryEntry.id == model_id).first()
    if not model:
        raise ValueError(f"Model ID {model_id} not found")

    if model.status != "CANDIDATE":
        raise ValueError(f"Model status is {model.status}, expect CANDIDATE to approve")

    # REGRESSION GATES
    cand_metrics = model.metrics or {}
    cand_macro_f1 = cand_metrics.get("macro_f1", 0.0)
    cand_unk_f1 = cand_metrics.get("unknown_f1", 0.0)

    # Fetch current production model to compare
    prod = db.query(ModelRegistryEntry).filter(
        ModelRegistryEntry.model_type == model.model_type,
        ModelRegistryEntry.status == "PRODUCTION"
    ).order_by(ModelRegistryEntry.training_timestamp.desc()).first()

    if prod:
        prod_metrics = prod.metrics or {}
        prod_macro_f1 = prod_metrics.get("macro_f1", 0.0)
        prod_unk_f1 = prod_metrics.get("unknown_f1", 0.0)
        
        # Check regression limits
        if prod_macro_f1 - cand_macro_f1 > MAX_MACRO_F1_REGRESSION:
            model.status = "REJECTED"
            db.commit()
            raise ValueError(f"Candidate rejected: MACRO F1 regression ({cand_macro_f1} vs prod {prod_macro_f1}) exceeds {MAX_MACRO_F1_REGRESSION}")
            
        if prod_unk_f1 - cand_unk_f1 > MAX_UNKNOWN_F1_REGRESSION:
            model.status = "REJECTED"
            db.commit()
            raise ValueError(f"Candidate rejected: UNKNOWN F1 regression ({cand_unk_f1} vs prod {prod_unk_f1}) exceeds {MAX_UNKNOWN_F1_REGRESSION}")

    # Check absolute floors
    if cand_macro_f1 < MIN_MACRO_F1:
        model.status = "REJECTED"
        db.commit()
        raise ValueError(f"Candidate rejected: MACRO F1 {cand_macro_f1} < {MIN_MACRO_F1}")

    model.status = "APPROVED"
    model.approved_by = user.username if hasattr(user, "username") and user.username else "admin"
    model.approved_at = datetime.utcnow()
    db.commit()
    
    audit_service.record_from_user(
        db, user, action="training.model.approve", request=request, result="SUCCESS",
        object_type="model", object_id=model.id,
        old_value={"status": "CANDIDATE"},
        new_value={"status": "APPROVED", "approved_by": model.approved_by},
    )
    return model


def promote_to_production(db: Session, model_id: str, user: Any, request: Any = None) -> ModelRegistryEntry:
    model = db.query(ModelRegistryEntry).filter(ModelRegistryEntry.id == model_id).first()
    if not model or model.status != "APPROVED":
        raise ValueError("Only APPROVED models can be promoted to PRODUCTION")
        
    # Archive current production models of same type
    prods = db.query(ModelRegistryEntry).filter(
        ModelRegistryEntry.model_type == model.model_type,
        ModelRegistryEntry.status == "PRODUCTION"
    ).all()
    for p in prods:
        p.status = "ARCHIVED"
        
    model.status = "PRODUCTION"
    db.commit()
    
    audit_service.record_from_user(
        db, user, action="training.model.promote", request=request, result="SUCCESS",
        object_type="model", object_id=model.id,
        old_value={"status": "APPROVED"},
        new_value={"status": "PRODUCTION"},
    )

    # Reload the in-process AI registry immediately so the next inference call
    # uses the newly promoted PRODUCTION classifier/embedder rather than a
    # stale in-memory model (spec section 11/12: production inference must
    # resolve the exact production model from the registry).
    ai_model_registry.reload_from_registry(db)
    return model


def rollback(db: Session, previous_model_id: str, user: Any, request: Any = None) -> ModelRegistryEntry:
    target = db.query(ModelRegistryEntry).filter(ModelRegistryEntry.id == previous_model_id).first()
    if not target or target.status not in ("ARCHIVED", "APPROVED"):
        raise ValueError("Can only rollback to an ARCHIVED or APPROVED model")

    # Capture old state BEFORE any mutation — a prior version of this function
    # recorded target.status into old_value *after* setting it to PRODUCTION,
    # which made the audit log always show old_value == new_value == PRODUCTION
    # and lost the true previous production model's identity (spec section 13).
    old_target_status = target.status
    old_production_model = db.query(ModelRegistryEntry).filter(
        ModelRegistryEntry.model_type == target.model_type,
        ModelRegistryEntry.status == "PRODUCTION"
    ).first()
    old_production_model_id = old_production_model.id if old_production_model else None

    prods = db.query(ModelRegistryEntry).filter(
        ModelRegistryEntry.model_type == target.model_type,
        ModelRegistryEntry.status == "PRODUCTION"
    ).all()
    for p in prods:
        # Currently production gets archived
        p.status = "ARCHIVED"

    target.status = "PRODUCTION"
    db.commit()

    audit_service.record_from_user(
        db, user, action="training.model.rollback", request=request, result="SUCCESS",
        object_type="model", object_id=target.id,
        old_value={"status": old_target_status, "previous_production_model_id": old_production_model_id},
        new_value={"status": "PRODUCTION"},
    )

    # Reload the in-process AI registry so the very next inference call uses
    # the rolled-back model, not the model that was production a moment ago.
    ai_model_registry.reload_from_registry(db)
    return target
