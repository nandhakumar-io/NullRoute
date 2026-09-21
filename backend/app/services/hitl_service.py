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


def _admin_auto_validate_enabled() -> bool:
    """HITL_ADMIN_AUTO_VALIDATE (default true): an admin's own approve/correct
    is treated as the second validation gate too, so their decisions flow
    straight into datasets. Set to false to force every example -- including
    admin-reviewed ones -- through the explicit validate step."""
    import os
    return os.getenv("HITL_ADMIN_AUTO_VALIDATE", "true").strip().lower() in ("1", "true", "yes", "on")


def _is_admin(user: Any) -> bool:
    roles = getattr(user, "roles", None) or []
    return any(r in ("admin", "TENANT_ADMIN", "SUPER_ADMIN") for r in roles)


def _maybe_auto_validate(te: TrainingExample, user: Any) -> None:
    """Admin approve/correct skips the second gate (when enabled). Analyst
    reviews always stay PENDING until an admin/analyst validates them, and
    REJECTED examples are never auto-validated (no usable facts)."""
    if te.human_action in ("APPROVED", "CORRECTED") and _is_admin(user) and _admin_auto_validate_enabled():
        te.validation_status = "VALIDATED"


def _derive_intent(mapping: CommandMapping, normalized_facts: Dict[str, Any]) -> Optional[str]:
    """Best-effort intent label for a TrainingExample.

    Prefers an explicit "intent" key when the caller supplied one (e.g. the
    AIAnalysis category from the training-feedback endpoint). Otherwise
    falls back to the top-level segment of the mapping's normalized
    parameter path (e.g. "interfaces.port_security_enabled" -> "interfaces"),
    which is one of the known intent categories, not a raw parameter path.
    Never returns the full parameter path itself as the intent -- doing so
    pollutes the label space training reads from (13 known intents; a
    parameter path is not one of them).
    """
    intent = normalized_facts.get("intent") if normalized_facts else None
    if intent:
        return intent
    param = mapping.normalized_parameter
    if param:
        return param.split(".")[0]
    return None


def _persist_training_example(
    db: Session,
    mapping: CommandMapping,
    human_action: str,
    normalized_facts: Dict[str, Any],
    correction_reason: Optional[str],
    user: Any
) -> TrainingExample:
    """Create the full normalized TrainingExample from the mapping action."""
    # We may not have a source_scan_id or source_device_id available on the
    # CommandMapping natively, so we write the row with what we have.
    raw_config = mapping.raw_command_pattern

    import hashlib
    raw_hash = hashlib.sha256(raw_config.encode("utf-8")).hexdigest()

    # A plain approve/correct with no explicit facts payload must still
    # produce a *usable* training row, not an empty one: fall back to the
    # mapping's own normalized_parameter/example_value so normalized_facts
    # is never left as {} when the mapping itself carries a real decision.
    facts = dict(normalized_facts or {})
    if "facts" not in facts and mapping.normalized_parameter:
        facts["facts"] = [{"parameter": mapping.normalized_parameter, "value": mapping.example_value}]

    te = TrainingExample(
        tenant_id=mapping.tenant_id,
        source_mapping_id=mapping.id,
        raw_config_hash=raw_hash,
        raw_config_redacted=redact_secrets(raw_config),
        vendor=mapping.vendor,
        intent=_derive_intent(mapping, facts),
        normalized_facts=facts,
        human_action=human_action,
        correction_reason=correction_reason,
        created_by=user.username if hasattr(user, "username") and user.username else "system",
        created_at=datetime.utcnow(),
    )

    db.add(te)
    db.flush()
    return te


def _embed_and_store(db: Session, mapping: CommandMapping) -> None:
    """Embed the REDACTED command text (never the raw text -- secrets must
    never leave the process toward a remote embedding endpoint) and record
    on the mapping whether a real vector was actually stored, so callers can
    tell a genuine embedding update apart from a silent no-op (no embedder
    loaded)."""
    from app.ai import model_registry

    redacted = redact_secrets(mapping.raw_command_pattern)
    vector = vector_search.embed_text(redacted)
    stored = vector_search.store_embedding(db, mapping.id, vector)
    if stored:
        registry = model_registry.get_registry()
        mapping.embedding_backend = registry.embedder.backend_name if registry.embedder else None
    else:
        mapping.embedding_backend = None
        import logging
        logging.getLogger(__name__).warning(
            "No embedding stored for CommandMapping %s -- no embedder is currently loaded; "
            "similarity search for this mapping will fall back to token overlap.",
            mapping.id,
        )


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
    _maybe_auto_validate(te, user)

    # Generate the embedding (from redacted text) and store it in pgvector
    _embed_and_store(db, mapping)
    
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
            fact0 = normalized_facts["facts"][0]
            mapping.normalized_parameter = fact0.get("parameter", mapping.normalized_parameter)
            # A correction's whole point is that the AI's original
            # example_value was wrong -- persist the reviewer's real value
            # too, not just the parameter name, so the mapping (and any UI
            # re-reading it) reflects the corrected ground truth.
            if fact0.get("value") not in (None, ""):
                mapping.example_value = fact0["value"]

    mapping.confidence = max(mapping.confidence or 0.0, 0.95)
    mapping.reviewed_by = user.username if hasattr(user, "username") and user.username else "admin"
    mapping.reviewed_at = datetime.utcnow()

    te = _persist_training_example(db, mapping, "CORRECTED", normalized_facts, correction_reason, user)
    _maybe_auto_validate(te, user)

    _embed_and_store(db, mapping)

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