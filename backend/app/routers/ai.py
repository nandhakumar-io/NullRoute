from typing import Optional
from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy.orm import Session

from app.ai.model_registry import get_registry
from app.ai.schemas import AIHealth, AIModelInfo, AIModelsOut
from app.db import get_db
from app.models.db import AIAnalysis, CommandMapping, Device, Scan

from app.auth.dependencies import get_current_tenant, get_current_user, require_role

router = APIRouter(prefix="/api", tags=["ai"], dependencies=[Depends(get_current_user)])


@router.get("/ai/review-queue")
def get_review_queue(
    limit: int = 100,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    """Section 10: unified Review Queue.

    Every AIAnalysis row across every scan (not just one scan's page) that
    the hybrid decision engine flagged `requires_review`, newest first,
    with enough scan/device context to jump straight to the source. This
    is advisory-only surfacing of existing rows -- it computes nothing and
    never turns a review flag into a compliance decision itself."""
    rows = (
        db.query(AIAnalysis, Scan, Device)
        .join(Scan, Scan.id == AIAnalysis.scan_id)
        .outerjoin(Device, Device.id == AIAnalysis.device_id)
        .filter(AIAnalysis.requires_review.is_(True))
        .filter((AIAnalysis.tenant_id == tenant_id) | (AIAnalysis.tenant_id.is_(None)))
        .order_by(AIAnalysis.created_at.desc())
        .limit(min(limit, 500))
        .all()
    )
    return {
        "count": len(rows),
        "items": [
            {
                "id": r.id,
                "scan_id": r.scan_id,
                "device_id": r.device_id,
                "device_hostname": device.hostname if device else None,
                "vendor": device.vendor if device else None,
                "intent": r.intent,
                "classifier_confidence": r.classifier_confidence,
                "semantic_similarity": r.semantic_similarity,
                "nearest_intent": r.nearest_intent,
                "nearest_vendor": r.nearest_vendor,
                "models_agree": r.models_agree,
                "decision": r.decision,
                "reason": r.reason,
                "model_version": r.model_version,
                "inference_latency_ms": r.inference_latency_ms,
                "created_at": r.created_at,
            }
            for r, scan, device in rows
        ],
    }


@router.get("/scans/{scan_id}/ai")
def get_scan_ai_analysis(scan_id: str, db: Session = Depends(get_db)):
    """All trained-AI (DistilBERT + MiniLM) interpretations recorded for
    this scan's unknown/AI-normalized commands. Never a compliance
    PASS/FAIL — see app/ai/decision_engine.py."""
    scan = db.query(Scan).get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    rows = (
        db.query(AIAnalysis)
        .filter(AIAnalysis.scan_id == scan_id)
        .order_by(AIAnalysis.created_at.asc())
        .all()
    )
    return {
        "scan_id": scan_id,
        "count": len(rows),
        "requires_review_count": sum(1 for r in rows if r.requires_review),
        "analyses": [
            {
                "id": r.id,
                "raw_command_hash": r.raw_command_hash,
                "intent": r.intent,
                "classifier_confidence": r.classifier_confidence,
                "semantic_similarity": r.semantic_similarity,
                "nearest_intent": r.nearest_intent,
                "nearest_vendor": r.nearest_vendor,
                "models_agree": r.models_agree,
                "decision": r.decision,
                "requires_review": r.requires_review,
                "reason": r.reason,
                "model_version": r.model_version,
                "inference_latency_ms": r.inference_latency_ms,
                "created_at": r.created_at,
            }
            for r in rows
        ],
    }


@router.get("/ai/health", response_model=AIHealth)
def ai_health():
    registry = get_registry()
    return AIHealth(
        ai_enabled=registry.enabled,
        classifier_loaded=registry.classifier is not None,
        embedder_loaded=registry.embedder is not None,
        classifier_backend=registry.classifier.backend_name if registry.classifier else "none",
        embedder_backend=registry.embedder.backend_name if registry.embedder else "none",
        model_version=registry.model_version,
        reference_dataset=registry.embedder.reference_dataset_path if registry.embedder else None,
        reference_examples=len(registry.embedder.examples) if registry.embedder else 0,
    )


@router.get("/ai/models", response_model=AIModelsOut)
def ai_models():
    registry = get_registry()
    models = [
        AIModelInfo(
            component="classifier",
            path=None if not registry.classifier else getattr(registry.classifier, "model_version", None),
            backend=registry.classifier.backend_name if registry.classifier else "none",
            loaded=registry.classifier is not None,
            version=registry.classifier.model_version if registry.classifier else "n/a",
        ),
        AIModelInfo(
            component="embedder",
            path=registry.embedder.reference_dataset_path if registry.embedder else None,
            backend=registry.embedder.backend_name if registry.embedder else "none",
            loaded=registry.embedder is not None,
            version=registry.embedder.model_version if registry.embedder else "n/a",
        ),
    ]
    return AIModelsOut(
        models=models,
        thresholds={
            "classifier_confidence": registry.thresholds.classifier_confidence,
            "semantic_similarity": registry.thresholds.semantic_similarity,
        },
    )


@router.post("/ai/training-feedback")
def submit_training_feedback(
    scan_id: str = Body(...),
    analysis_id: str = Body(...),
    action: str = Body(..., description="One of: approve, correct, reject"),
    corrected_parameter: Optional[str] = Body(default=None, description="For 'correct': the accurate normalized_parameter string"),
    correction_reason: Optional[str] = Body(default=None),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user=Depends(get_current_user),
):
    """HITL inline feedback — thumbs up/down/edit on an AI interpretation.

    Records the operator action, updates the CommandMapping status, and
    re-embeds the raw command into pgvector so future LLM lookups learn
    from this correction immediately (RAG active learning loop)."""
    from app.services import hitl_service, vector_search

    # Resolve the AIAnalysis → find the linked CommandMapping (same raw hash)
    analysis = db.query(AIAnalysis).filter(
        AIAnalysis.id == analysis_id,
        AIAnalysis.scan_id == scan_id,
    ).first()
    if not analysis:
        raise HTTPException(404, "AI analysis record not found")

    mapping = db.query(CommandMapping).filter(
        CommandMapping.raw_command_hash == analysis.raw_command_hash,
        CommandMapping.tenant_id == tenant_id,
    ).first()

    if not mapping:
        raise HTTPException(404, "No command mapping found for this AI analysis — cannot record feedback")

    action = action.lower().strip()

    if action == "approve":
        hitl_service.approve_mapping(
            db, mapping,
            normalized_facts={"intent": analysis.intent},
            correction_reason=correction_reason,
            user=user,
        )
    elif action == "correct":
        if not corrected_parameter:
            raise HTTPException(422, "corrected_parameter is required for action='correct'")
        hitl_service.correct_mapping(
            db, mapping,
            normalized_facts={"intent": corrected_parameter},
            correction_reason=correction_reason or f"User corrected '{analysis.intent}' → '{corrected_parameter}'",
            user=user,
        )
    elif action == "reject":
        hitl_service.reject_mapping(
            db, mapping,
            correction_reason=correction_reason,
            user=user,
        )
    else:
        raise HTTPException(422, f"Unknown action '{action}'. Use: approve, correct, reject")

    return {
        "status": "recorded",
        "action": action,
        "mapping_id": mapping.id,
        "analysis_id": analysis_id,
        "message": "Feedback recorded and pgvector embedding updated.",
    }


@router.get("/devices/{device_id}/telemetry")
def get_device_snmp_telemetry(
    device_id: str,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    """On-demand SNMP telemetry poll: CPU, memory, and interface stats.

    Community string is resolved from OpenBao via the device's stored
    credential ref. If no SNMP credential is on file or the device is
    unreachable, returns status='unavailable' rather than raising."""
    from app.services import openbao_service, snmp_service
    from app.models.db import DeviceCredentialRef

    device = db.query(Device).filter(Device.id == device_id, Device.tenant_id == tenant_id).first()
    if not device:
        raise HTTPException(404, "Device not found")

    host = device.management_address or device.hostname
    if not host:
        return snmp_service.SnmpTelemetry(
            status="unavailable", device_id=device_id,
            error="Device has no management address configured"
        ).to_dict()

    # Resolve SNMP credential from OpenBao (community string stored as secret)
    community = "public"
    port = 161
    try:
        ref_row = db.query(DeviceCredentialRef).filter(
            DeviceCredentialRef.device_id == device_id,
            DeviceCredentialRef.tenant_id == tenant_id,
        ).order_by(DeviceCredentialRef.created_at.desc()).first()
        if ref_row:
            creds = openbao_service.get_device_credentials(tenant_id, ref_row.credential_ref)
            if creds.secret.get("snmp_community"):
                community = creds.secret["snmp_community"]
            if creds.secret.get("snmp_port"):
                port = int(creds.secret["snmp_port"])
            del creds  # RULE 6: never hold credentials beyond this scope
    except openbao_service.OpenBaoError:
        pass  # Use default public community if no secure credential found

    telemetry = snmp_service.collect_telemetry(
        device_id=device_id,
        management_address=host,
        community=community,
        port=port,
    )
    return telemetry.to_dict()