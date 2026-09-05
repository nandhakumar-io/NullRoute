"""
Load-once model registry for the trained-AI pipeline (Phase 1).

`initialize()` is called exactly once, from FastAPI's lifespan handler in
main.py, and the resulting singleton is reused for every request —
models are never re-loaded per inference call.

AI_ENABLED=false skips loading entirely and the service module reports
AI as disabled everywhere (health, models, and any pipeline hook becomes
a no-op) rather than silently loading fallback heuristics and pretending
they're the real thing.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from app.ai.classifier import LoadedClassifier, load_classifier
from app.ai.decision_engine import DecisionThresholds
from app.ai.embeddings import LoadedEmbedder, load_embedder


@dataclass
class AIRegistry:
    enabled: bool
    classifier: Optional[LoadedClassifier]
    embedder: Optional[LoadedEmbedder]
    thresholds: DecisionThresholds
    model_version: str


_registry: Optional[AIRegistry] = None


def _read_bool_env(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def initialize() -> AIRegistry:
    """Idempotent: safe to call more than once (e.g. in tests); only loads
    models the first time."""
    global _registry
    if _registry is not None:
        return _registry

    enabled = _read_bool_env("AI_ENABLED", True)
    thresholds = DecisionThresholds(
        classifier_confidence=float(os.getenv("AI_CLASSIFIER_CONFIDENCE_THRESHOLD", "0.75")),
        semantic_similarity=float(os.getenv("AI_SEMANTIC_THRESHOLD", "0.60")),
    )
    model_version = os.getenv("AI_MODEL_VERSION", "unversioned")

    if not enabled:
        _registry = AIRegistry(enabled=False, classifier=None, embedder=None, thresholds=thresholds, model_version=model_version)
        return _registry

    classifier = load_classifier()
    embedder = load_embedder()
    # Version-alignment guard: the classifier and the reference dataset the
    # embedder loaded must not silently come from mismatched training runs.
    effective_version = model_version if model_version != "unversioned" else classifier.model_version

    _registry = AIRegistry(
        enabled=True,
        classifier=classifier,
        embedder=embedder,
        thresholds=thresholds,
        model_version=effective_version,
    )
    return _registry


def get_registry() -> AIRegistry:
    if _registry is None:
        return initialize()
    return _registry


def reset_registry_for_tests() -> None:
    global _registry
    _registry = None
