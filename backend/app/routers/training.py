from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.db import AuditLog, CommandMapping
from app.schemas import CommandMappingOut, MappingReviewIn

from app.auth.dependencies import get_current_tenant, get_current_user, require_role

router = APIRouter(prefix="/api/training", tags=["training"], dependencies=[Depends(get_current_user)])


def _tenant_scoped_mappings_query(db: Session, tenant_id: str):
    return (
        db.query(CommandMapping)
        .filter((CommandMapping.tenant_id == tenant_id) | (CommandMapping.tenant_id.is_(None)))
    )


@router.get("/pending", response_model=List[CommandMappingOut])
def list_pending(db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    return (
        _tenant_scoped_mappings_query(db, tenant_id)
        .filter(CommandMapping.status == "pending")
        .order_by(CommandMapping.created_at.desc())
        .all()
    )


@router.get("/approved", response_model=List[CommandMappingOut])
def list_approved(db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    return (
        _tenant_scoped_mappings_query(db, tenant_id)
        .filter(CommandMapping.status == "approved")
        .order_by(CommandMapping.created_at.desc())
        .all()
    )


@router.post("/{mapping_id}/review", response_model=CommandMappingOut)
def review_mapping(
    mapping_id: str,
    payload: MappingReviewIn,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    _user=Depends(require_role("admin", "security_analyst")),
):
    mapping = (
        _tenant_scoped_mappings_query(db, tenant_id)
        .filter(CommandMapping.id == mapping_id)
        .first()
    )
    if not mapping:
        raise HTTPException(404, "Mapping not found")

    if payload.action == "approve" or payload.action == "correct":
        mapping.status = "approved"
        if payload.normalized_parameter:
            mapping.normalized_parameter = payload.normalized_parameter
        mapping.confidence = max(mapping.confidence, 0.95)  # human-confirmed
        
        import os, json
        from app.ai import model_registry
        dataset_path = "/home/kenpachi-zaraki/NetSecAuditor/backend/ai_reference_dataset.json"
        
        new_intent = mapping.normalized_parameter or mapping.ai_suggested_meaning
        if new_intent and os.path.exists(dataset_path):
            try:
                with open(dataset_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                data.append({
                    "text": mapping.raw_command_pattern,
                    "intent": new_intent,
                    "vendor": mapping.vendor
                })
                with open(dataset_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                
                reg = model_registry.initialize()
                if reg.embedder and reg.embedder.reference_dataset_path:
                    from app.ai.embeddings import _load_reference_dataset
                    reg.embedder.examples = _load_reference_dataset(reg.embedder.reference_dataset_path)
            except Exception as e:
                import logging
                logging.error(f"Failed to inject training data: {e}")
    elif payload.action == "reject":
        mapping.status = "rejected"
    else:
        raise HTTPException(400, "action must be 'approve', 'correct', or 'reject'")

    from datetime import datetime
    mapping.reviewed_by = payload.reviewer
    mapping.reviewed_at = datetime.utcnow()
    db.add(AuditLog(actor=payload.reviewer, action=f"training.{payload.action}",
                     resource=mapping_id, details={"normalized_parameter": mapping.normalized_parameter}))
    db.commit()
    db.refresh(mapping)
    return mapping
