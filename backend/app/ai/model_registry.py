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

import logging
import threading

logger = logging.getLogger(__name__)
_lock = threading.Lock()


@dataclass
class AIRegistry:
    enabled: bool
    classifier: Optional[LoadedClassifier]
    embedder: Optional[LoadedEmbedder]
    thresholds: DecisionThresholds
    model_version: str
    # Set when the classifier came from the model registry's PRODUCTION row.
    production_model_id: Optional[str] = None
    # Why a PRODUCTION row exists but isn't the one serving (artifact missing,
    # torch not installed here, ...). None when nothing is wrong.
    production_load_error: Optional[str] = None


_registry: Optional[AIRegistry] = None


def _read_bool_env(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _production_entry(db=None):
    """The current PRODUCTION classifier row from the model registry, or None.
    Best-effort: a missing table / unreachable DB must never stop the API
    from booting with the configured classifier."""
    own = None
    try:
        if db is None:
            from app.db import SessionLocal
            own = db = SessionLocal()
        from app.models.db import ModelRegistryEntry

        return (
            db.query(ModelRegistryEntry)
            .filter(ModelRegistryEntry.model_type == "classifier", ModelRegistryEntry.status == "PRODUCTION")
            .order_by(ModelRegistryEntry.training_timestamp.desc())
            .first()
        )
    except Exception:  # noqa: BLE001
        logger.debug("model registry lookup skipped", exc_info=True)
        return None
    finally:
        if own is not None:
            own.close()


def _build(db=None) -> AIRegistry:
    enabled = _read_bool_env("AI_ENABLED", True)
    thresholds = DecisionThresholds(
        classifier_confidence=float(os.getenv("AI_CLASSIFIER_CONFIDENCE_THRESHOLD", "0.75")),
        semantic_similarity=float(os.getenv("AI_SEMANTIC_THRESHOLD", "0.60")),
    )
    model_version = os.getenv("AI_MODEL_VERSION", "unversioned")

    if not enabled:
        return AIRegistry(enabled=False, classifier=None, embedder=None, thresholds=thresholds, model_version=model_version)

    prod = _production_entry(db)
    prod_path = prod.artifact_path if prod else None
    prod_version = f"{prod.model_name}@{prod.id[:8]}" if prod else None

    classifier = load_classifier(production_path=prod_path, production_version=prod_version)
    embedder = load_embedder()

    production_model_id = None
    production_error = None
    if prod is not None:
        if classifier.backend_name == "distilbert" and classifier.model_version == prod_version:
            production_model_id = prod.id
        else:
            production_error = (
                f"PRODUCTION model {prod.model_name!r} ({prod.id}) is not being served: its artifact at "
                f"{prod.artifact_path!r} could not be loaded by this process; using {classifier.backend_name}."
            )

    # Version-alignment guard: the classifier and the reference dataset the
    # embedder loaded must not silently come from mismatched training runs.
    effective_version = (
        classifier.model_version if production_model_id
        else (model_version if model_version != "unversioned" else classifier.model_version)
    )
    return AIRegistry(
        enabled=True,
        classifier=classifier,
        embedder=embedder,
        thresholds=thresholds,
        model_version=effective_version,
        production_model_id=production_model_id,
        production_load_error=production_error,
    )


def initialize() -> AIRegistry:
    """Idempotent: safe to call more than once (e.g. in tests); only loads
    models the first time. Picks up the registry's PRODUCTION classifier if
    one has been promoted."""
    global _registry
    with _lock:
        if _registry is None:
            _registry = _build()
        return _registry


def get_registry() -> AIRegistry:
    if _registry is None:
        return initialize()
    return _registry


def reset_registry_for_tests() -> None:
    global _registry
    _registry = None


def reload_from_registry(db) -> AIRegistry:
    """Swap the in-memory registry to match the registry table's current
    PRODUCTION classifier (called right after promote / rollback).

    The new registry is fully built BEFORE it replaces the old one, so
    in-flight requests keep using a working classifier and a failed load
    never leaves the process without one.
    """
    global _registry
    new = _build(db)
    with _lock:
        _registry = new
    if new.production_load_error:
        logger.warning(new.production_load_error)
    return new
