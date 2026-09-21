"""
Service-layer entry point for the trained-AI pipeline. Orchestrates:

    classifier.classify() -> embeddings.nearest() -> decision_engine.decide()

(batched form: analyze_commands()/analyze_commands_detailed(), which run the
same three steps over many texts with true batched DistilBERT/MiniLM calls.)

and returns a single AIAnalysisResult. This is what services/pipeline.py
(Phase 2) and the /api/ai/* routers call — nothing outside this module
should touch classifier.py/embeddings.py/decision_engine.py directly.

AI can only ever produce an *interpretation* (intent + confidence +
review flag). It is never permitted to set a Scan's opa_decision,
batfish_status, risk_level, or final_decision.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, replace
from typing import Dict, List, Optional, Tuple

from app.ai import classifier as classifier_mod
from app.ai import embeddings as embeddings_mod
from app.ai import inference_cache
from app.ai.decision_engine import decide
from app.ai.model_registry import AIRegistry, get_registry
from app.ai.schemas import UNKNOWN_INTENT, AIAnalysisResult, ClassifierResult, EmbeddingMatch

# ClassifierResult.model_version the remote backend reports when the request
# failed -- a degraded placeholder that must never be cached as a real result.
_REMOTE_ERROR_VERSION = "remote-error"


def _disabled_result(raw_command: str, latency_ms: float) -> AIAnalysisResult:
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


@dataclass
class BatchAnalysis:
    """DistilBERT+MiniLM+decision result for one text, plus the MiniLM vector
    so the RAG retrieval step can reuse it instead of embedding the same text
    a second time."""
    result: AIAnalysisResult
    vector: Optional[List[float]] = None
    classifier_result: Optional[ClassifierResult] = None
    embedding_match: Optional[EmbeddingMatch] = None
    from_cache: bool = False


@dataclass
class BatchStats:
    texts: int = 0
    unique_texts: int = 0
    classifier_computed: int = 0
    classifier_cache_hits: int = 0
    classifier_batch_calls: int = 0
    embedder_computed: int = 0
    embedder_cache_hits: int = 0
    embedder_batch_calls: int = 0
    classifier_ms: float = 0.0
    embedder_ms: float = 0.0


def analyze_commands_detailed(
    raw_commands: List[str], registry: AIRegistry = None,
) -> Tuple[List[BatchAnalysis], BatchStats]:
    """Batched equivalent of calling analyze_command() on every text.

    Result i corresponds to raw_commands[i]. Identical texts are computed
    once; DistilBERT runs as true batches and MiniLM as one batched encode
    for everything not already cached (versioned cache, see
    inference_cache.py). The decision logic is the unchanged decide().
    """
    registry = registry or get_registry()
    stats = BatchStats(texts=len(raw_commands))
    if not raw_commands:
        return [], stats

    if not registry.enabled or registry.classifier is None or registry.embedder is None:
        return [BatchAnalysis(result=_disabled_result(t, 0.0)) for t in raw_commands], stats

    clf, emb = registry.classifier, registry.embedder
    cache = inference_cache.get_cache()

    unique: List[str] = list(dict.fromkeys(raw_commands))
    stats.unique_texts = len(unique)

    # -- classifier: cache, then one batched call for the misses ------------
    clf_results: Dict[str, ClassifierResult] = {}
    clf_hit: Dict[str, bool] = {}
    clf_missing: List[str] = []
    for t in unique:
        cached = inference_cache.MISS
        if cache is not None:
            cached = cache.get(inference_cache.NS_CLASSIFIER,
                               inference_cache.classifier_key(clf.backend_name, clf.model_version, registry.model_version, t))
        if cached is inference_cache.MISS:
            clf_missing.append(t)
        else:
            clf_results[t] = ClassifierResult(**cached)
            clf_hit[t] = True
            stats.classifier_cache_hits += 1
    if clf_missing:
        computed, clf_ms = classifier_mod.classify_batch(clf, clf_missing)
        stats.classifier_ms = clf_ms
        stats.classifier_computed = len(clf_missing)
        stats.classifier_batch_calls = 1
        for t, res in zip(clf_missing, computed):
            clf_results[t] = res
            clf_hit[t] = False
            if cache is not None and res.model_version != _REMOTE_ERROR_VERSION:
                cache.put(inference_cache.NS_CLASSIFIER,
                          inference_cache.classifier_key(clf.backend_name, clf.model_version, registry.model_version, t),
                          res.model_dump())

    # -- embeddings: cache, then one batched encode for the misses ----------
    vectors: Dict[str, Optional[List[float]]] = {}
    emb_hit: Dict[str, bool] = {}
    emb_missing: List[str] = []
    for t in unique:
        cached = inference_cache.MISS
        if cache is not None and emb.encode_fn is not None:
            cached = cache.get(inference_cache.NS_EMBEDDING,
                               inference_cache.embedding_key(emb.backend_name, emb.model_version, registry.model_version, t))
        if cached is inference_cache.MISS:
            emb_missing.append(t)
        else:
            vectors[t] = cached
            emb_hit[t] = True
            stats.embedder_cache_hits += 1
    if emb_missing:
        computed_vecs, emb_ms = embeddings_mod.embed_batch(emb, emb_missing)
        stats.embedder_ms = emb_ms
        stats.embedder_computed = len(emb_missing)
        stats.embedder_batch_calls = 1 if emb.encode_fn is not None else 0
        for t, vec in zip(emb_missing, computed_vecs):
            vectors[t] = vec
            emb_hit[t] = False
            # Empty vector = the remote endpoint failed for this text; never cache that.
            if cache is not None and vec:
                cache.put(inference_cache.NS_EMBEDDING,
                          inference_cache.embedding_key(emb.backend_name, emb.model_version, registry.model_version, t),
                          vec)

    # -- decision (unchanged decide()) ---------------------------------------
    n_computed = max(1, len([t for t in unique if not (clf_hit[t] and emb_hit[t])]))
    per_item_ms = (stats.classifier_ms + stats.embedder_ms) / n_computed
    by_text: Dict[str, BatchAnalysis] = {}
    for t in unique:
        match = embeddings_mod.nearest_from_vector(emb, t, vectors.get(t))
        both_cached = clf_hit[t] and emb_hit[t]
        result = decide(
            raw_command=t,
            classifier=clf_results[t],
            embedding=match,
            thresholds=registry.thresholds,
            model_version=registry.model_version,
            inference_latency_ms=0.0 if both_cached else round(per_item_ms, 3),
        )
        by_text[t] = BatchAnalysis(
            result=result, vector=vectors.get(t), classifier_result=clf_results[t],
            embedding_match=match, from_cache=both_cached,
        )
    # Each occurrence gets its own result object so callers can't alias each other.
    return [replace(by_text[t], result=by_text[t].result.model_copy()) for t in raw_commands], stats


def analyze_commands(raw_commands: List[str], registry: AIRegistry = None) -> List[AIAnalysisResult]:
    """Batched analyze_command(); result i corresponds to raw_commands[i]."""
    detailed, _ = analyze_commands_detailed(raw_commands, registry)
    return [d.result for d in detailed]


def analyze_command(raw_command: str, registry: AIRegistry = None) -> AIAnalysisResult:
    """Single-text entry point (unchanged contract). Delegates to the batched
    implementation with a batch of one, so single and bulk requests share one
    code path and single requests are processed immediately (no batching
    window, no added latency)."""
    return analyze_commands([raw_command], registry)[0]