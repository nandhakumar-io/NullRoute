"""
Human-in-the-Loop (HITL) Service - Loop 1 (RAG Validation)
"""
from typing import Any, Dict, Optional
import re
from datetime import datetime

from sqlalchemy.orm import Session
from app.models.db import CommandMapping, TrainingExample
from app.services import audit_service, vector_search


def redact_secrets(raw_config: str) -> str:
    """Strip out common credential patterns before persisting to training data."""
    redacted = raw_config
    # Redact common password patterns
    redacted = re.sub(
        r"(password\s+)(0|7|8|encrypted|clear)?(\s+)?\S+",
        r"\1\2 *********",
        redacted,
        flags=re.IGNORECASE
    )
    redacted = re.sub(
        r"(secret\s+)(0|5|8|9)?(\s+)?\S+",
        r"\1\2 *********",
        redacted,
        flags=re.IGNORECASE
    )
    redacted = re.sub(
        r"(community\s+)\S+",
        r"\1*********",
        redacted,
        flags=re.IGNORECASE
    )
    redacted = re.sub(
        r"(key\s+string\s+)(0|7)?(\s+)?\S+",
        r"\1\2 *********",
        redacted,
        flags=re.IGNORECASE
    )
    redacted = re.sub(
        r"(snmp-server\s+community\s+)\S+",
        r"\1*********",
        redacted,
        flags=re.IGNORECASE
    )
    return redacted


def _persist_training_example(
    db: Session,
    mapping: CommandMapping,
    human_action: str,
    normalized_facts: Dict[str, Any],
    correction_reason: Optional[str],
    user: Any
) -> TrainingExample:
    """Create the full normalized TrainingExample from the mapping action."""
    # The scan tracking for the AI analysis is typically stored separately or we can just fetch it 
    # but based on the problem statement, we should grab the raw config pattern and redact it.
    
    # We may not have a source_scan_id or device_device_id available on the CommandMapping natively
    # but we will just write the row with what we have.
    raw_config = mapping.raw_command_pattern
    
    import hashlib
    raw_hash = hashlib.sha256(raw_config.encode("utf-8")).hexdigest()

    te = TrainingExample(
        tenant_id=mapping.tenant_id,
        source_mapping_id=mapping.id,
        raw_config_hash=raw_hash,
        raw_config_redacted=redact_secrets(raw_config),
        vendor=mapping.vendor,
        intent=None, # if we had intent we'd set it, but we set normalized_facts instead
        normalized_facts=normalized_facts,
        human_action=human_action,
        correction_reason=correction_reason,
        created_by=user.username if hasattr(user, "username") and user.username else "system",
        created_at=datetime.utcnow(),
    )
    
    # If the facts suggest an intent, we could extract it from `normalized_facts.get("intent")`
    if "intent" in normalized_facts:
        te.intent = normalized_facts["intent"]

    db.add(te)
    db.flush()
    return te


def approve_mapping(
    db: Session,
    mapping: CommandMapping,
    normalized_facts: Dict[str, Any],
    correction_reason: Optional[str],
    user: Any,
    request: Any = None
) -> CommandMapping:
    prior = {
        "status": mapping.status,
        "normalized_parameter": mapping.normalized_parameter,
        "confidence": mapping.confidence,
    }

    mapping.status = "approved"
    if normalized_facts:
        # Just grab the first param as a fallback for the old string field, but 
        # the real data goes to the training example.
        if "facts" in normalized_facts and isinstance(normalized_facts["facts"], list) and len(normalized_facts["facts"]) > 0:
            mapping.normalized_parameter = normalized_facts["facts"][0].get("parameter", mapping.normalized_parameter)
    
    mapping.confidence = max(mapping.confidence or 0.0, 0.95)
    mapping.reviewed_by = user.username if hasattr(user, "username") and user.username else "admin"
    mapping.reviewed_at = datetime.utcnow()

    # Create the training example
    te = _persist_training_example(db, mapping, "APPROVED", normalized_facts, correction_reason, user)

    # Generate the embedding and store it in pgvector
    vector = vector_search.embed_text(mapping.raw_command_pattern)
    vector_search.store_embedding(db, mapping.id, vector)
    
    db.commit()
    db.refresh(mapping)

    audit_service.record_from_user(
        db, user, action="training.mapping.approve", request=request, result="SUCCESS",
        object_type="command_mapping", object_id=mapping.id,
        old_value=prior,
        new_value={"status": mapping.status, "reviewed_by": mapping.reviewed_by},
    )
    return mapping


def correct_mapping(
    db: Session,
    mapping: CommandMapping,
    normalized_facts: Dict[str, Any],
    correction_reason: Optional[str],
    user: Any,
    request: Any = None
) -> CommandMapping:
    prior = {
        "status": mapping.status,
        "normalized_parameter": mapping.normalized_parameter,
    }

    mapping.status = "approved"
    if normalized_facts:
        if "facts" in normalized_facts and isinstance(normalized_facts["facts"], list) and len(normalized_facts["facts"]) > 0:
            mapping.normalized_parameter = normalized_facts["facts"][0].get("parameter", mapping.normalized_parameter)
    
    mapping.confidence = max(mapping.confidence or 0.0, 0.95)
    mapping.reviewed_by = user.username if hasattr(user, "username") and user.username else "admin"
    mapping.reviewed_at = datetime.utcnow()

    te = _persist_training_example(db, mapping, "CORRECTED", normalized_facts, correction_reason, user)

    vector = vector_search.embed_text(mapping.raw_command_pattern)
    vector_search.store_embedding(db, mapping.id, vector)

    db.commit()
    db.refresh(mapping)

    audit_service.record_from_user(
        db, user, action="training.mapping.correct", request=request, result="SUCCESS",
        object_type="command_mapping", object_id=mapping.id,
        old_value=prior,
        new_value={"status": mapping.status, "reviewed_by": mapping.reviewed_by},
    )
    return mapping


def reject_mapping(
    db: Session,
    mapping: CommandMapping,
    correction_reason: Optional[str],
    user: Any,
    request: Any = None
) -> CommandMapping:
    prior = {"status": mapping.status}
    
    mapping.status = "rejected"
    mapping.reviewed_by = user.username if hasattr(user, "username") and user.username else "admin"
    mapping.reviewed_at = datetime.utcnow()

    te = _persist_training_example(db, mapping, "REJECTED", {}, correction_reason, user)
    te.validation_status = "EXCLUDED"

    db.commit()
    db.refresh(mapping)

    audit_service.record_from_user(
        db, user, action="training.mapping.reject", request=request, result="SUCCESS",
        object_type="command_mapping", object_id=mapping.id,
        old_value=prior,
        new_value={"status": mapping.status, "reviewed_by": mapping.reviewed_by},
    )
    return mapping
