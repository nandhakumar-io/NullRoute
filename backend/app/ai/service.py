"""
Service-layer entry point for the trained-AI pipeline. Orchestrates:

    classifier.classify() -> embeddings.nearest() -> decision_engine.decide()

and returns a single AIAnalysisResult. This is what services/pipeline.py
(Phase 2) and the /api/ai/* routers call — nothing outside this module
should touch classifier.py/embeddings.py/decision_engine.py directly.

AI can only ever produce an *interpretation* (intent + confidence +
review flag). It is never permitted to set a Scan's opa_decision,
batfish_status, risk_level, or final_decision.
"""
from __future__ import annotations

import time

from app.ai import classifier as classifier_mod
from app.ai import embeddings as embeddings_mod
from app.ai.decision_engine import decide
from app.ai.model_registry import AIRegistry, get_registry
from app.ai.schemas import UNKNOWN_INTENT, AIAnalysisResult, ClassifierResult, EmbeddingMatch


def analyze_command(raw_command: str, registry: AIRegistry = None) -> AIAnalysisResult:
    registry = registry or get_registry()
    start = time.perf_counter()

    if not registry.enabled or registry.classifier is None or registry.embedder is None:
        latency_ms = (time.perf_counter() - start) * 1000.0
        return AIAnalysisResult(
            raw_command=raw_command,
            intent=UNKNOWN_INTENT,
            classifier_confidence=0.0,
            semantic_similarity=0.0,
            nearest_intent=UNKNOWN_INTENT,
            nearest_vendor=None,
            models_agree=False,
            decision="UNKNOWN",
            requires_review=True,
            model_version="ai-disabled",
            inference_latency_ms=round(latency_ms, 3),
            reason="AI_ENABLED is false; command was not interpreted by the trained-AI pipeline.",
        )

    classifier_result, classifier_latency_ms = classifier_mod.classify(registry.classifier, raw_command)
    embedding_match, embedding_latency_ms = embeddings_mod.nearest(registry.embedder, raw_command)
    total_latency_ms = classifier_latency_ms + embedding_latency_ms

    return decide(
        raw_command=raw_command,
        classifier=classifier_result,
        embedding=embedding_match,
        thresholds=registry.thresholds,
        model_version=registry.model_version,
        inference_latency_ms=round(total_latency_ms, 3),
    )
