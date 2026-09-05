from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.ai.model_registry import get_registry
from app.ai.schemas import AIHealth, AIModelInfo, AIModelsOut
from app.db import get_db
from app.models.db import AIAnalysis, Scan

from app.auth.dependencies import get_current_tenant, get_current_user

router = APIRouter(prefix="/api", tags=["ai"], dependencies=[Depends(get_current_user)])


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