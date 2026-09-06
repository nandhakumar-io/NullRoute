from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.ai.model_registry import get_registry
from app.ai.normalize import compute_coverage, interpret_block, retrieve_similar_mappings, to_normalized_parameters
from app.ai.schemas import AIHealth, AIModelInfo, AIModelsOut
from app.db import get_db
from app.models.db import AIAnalysis, Scan
from app.services.parsers import parse_config
from app.services.vendor_detect import detect_vendor

from app.auth.dependencies import get_current_tenant, get_current_user, CurrentUser, require_permission

router = APIRouter(prefix="/api", tags=["ai"], dependencies=[Depends(get_current_user)])


class NormalizationPreviewIn(BaseModel):
    raw_config: str
    vendor: str | None = None


@router.post("/normalize/preview")
async def normalize_preview(
    body: NormalizationPreviewIn,
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
):
    """Debug/preview utility (problem statement item 16): runs the full
    deterministic + AI/RAG normalization pipeline over a supplied raw
    configuration WITHOUT persisting a Scan/Device, and returns the
    vendor, detected sections, extracted facts, preserved unknown
    evidence, and a coverage report proving zero information loss. Never
    used for compliance decisions -- purely a normalization sanity/debug
    tool for reviewers and CI (see tests/test_normalization_pipeline.py).
    """
    vendor = body.vendor or detect_vendor(body.raw_config).vendor
    baseline = parse_config(vendor, body.raw_config)

    unknown_blocks = baseline.extra_parameters.pop("_unknown_blocks", [])
    for block_text in unknown_blocks[:60]:
        retrieved = await retrieve_similar_mappings(db, tenant_id, vendor, block_text)
        block_result = await interpret_block(vendor, block_text, retrieved)
        for norm_param in to_normalized_parameters(block_result):
            baseline.provenance.append(norm_param)
    if len(unknown_blocks) > 60:
        baseline.extra_parameters["_uncapped_unknown_blocks"] = unknown_blocks[60:]

    coverage = compute_coverage(baseline)
    return {
        "vendor": vendor,
        "sections": sorted({p.normalized_parameter.split(".")[0] for p in baseline.provenance}),
        "facts": [
            {
                "raw_command": p.raw_command,
                "normalized_parameter": p.normalized_parameter,
                "value": p.value,
                "confidence": p.confidence,
                "source": p.source,
                "model_version": p.model_version,
                "human_validated": p.human_validated,
            }
            for p in baseline.provenance
            if p.normalized_parameter != "extra_parameters.unknown_evidence"
        ],
        "unknown": [
            p.raw_command for p in baseline.provenance
            if p.normalized_parameter == "extra_parameters.unknown_evidence"
        ] + baseline.extra_parameters.get("_uncapped_unknown_blocks", []),
        "coverage": coverage,
    }


@router.get("/scans/{scan_id}/ai")
def get_scan_ai_analysis(scan_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    """All trained-AI (DistilBERT + MiniLM) interpretations recorded for
    this scan's unknown/AI-normalized commands. Never a compliance
    PASS/FAIL — see app/ai/decision_engine.py."""
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.tenant_id == tenant_id).first()
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
def ai_models(db: Session = Depends(get_db)):
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


@router.get("/ai/registry/models")
def list_registry_models(db: Session = Depends(get_db)):
    from app.models.db import ModelRegistryEntry
    return db.query(ModelRegistryEntry).order_by(ModelRegistryEntry.training_timestamp.desc()).all()


@router.post("/ai/registry/models/{model_id}/approve")
def approve_model(
    model_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("APPROVE_AI_MAPPING"))
):
    from app.services import model_registry_service
    try:
        return model_registry_service.approve_candidate(db, model_id, user, request)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/ai/registry/models/{model_id}/reject")
def reject_model(
    model_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("APPROVE_AI_MAPPING"))
):
    from app.models.db import ModelRegistryEntry
    from app.services import audit_service
    m = db.query(ModelRegistryEntry).filter(ModelRegistryEntry.id == model_id).first()
    if not m:
        raise HTTPException(404, "Model not found")
    prior = {"status": m.status}
    m.status = "REJECTED"
    db.commit()
    audit_service.record_from_user(db, user, action="training.model.reject", request=request, result="SUCCESS",
                                   object_type="model", object_id=model_id, old_value=prior, new_value={"status": m.status})
    return m


@router.post("/ai/registry/models/{model_id}/promote")
def promote_model(
    model_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("ADMIN"))
):
    from app.services import model_registry_service
    try:
        return model_registry_service.promote_to_production(db, model_id, user, request)
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/ai/registry/models/{model_id}/rollback")
def rollback_model(
    model_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_permission("ADMIN"))
):
    from app.services import model_registry_service
    try:
        return model_registry_service.rollback(db, model_id, user, request)
    except ValueError as e:
        raise HTTPException(400, str(e))