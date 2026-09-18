"""
Pydantic contracts for the trained-AI classification/decision pipeline
(Phase 1). This is a SEPARATE concern from `app/ai/normalize.py` (the
Ollama/RAG LLM normalizer used for unknown config lines during parsing);
this module wraps the trained DistilBERT intent classifier and the
all-MiniLM-L6-v2 semantic embedding model behind a hybrid decision engine.

Hard rule (see decision_engine.py): this module NEVER produces a
compliance PASS/FAIL. It only identifies/interprets configuration intent
and flags UNKNOWN/disagreement for human review.
"""
from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

UNKNOWN_INTENT = "UNKNOWN"


class ClassifierResult(BaseModel):
    intent: str
    confidence: float
    model_version: str
    model_config = ConfigDict(protected_namespaces=())


class EmbeddingMatch(BaseModel):
    nearest_intent: str
    nearest_vendor: Optional[str] = None
    similarity: float


class AIAnalysisResult(BaseModel):
    """Full hybrid decision output for one raw configuration line/command."""

    raw_command: str
    intent: str
    classifier_confidence: float
    semantic_similarity: float
    nearest_intent: str
    nearest_vendor: Optional[str] = None
    models_agree: bool
    decision: str  # KNOWN_CANDIDATE | UNKNOWN | REQUIRES_REVIEW
    requires_review: bool
    model_version: str
    inference_latency_ms: float
    reason: str
    model_config = ConfigDict(protected_namespaces=())


class AIHealth(BaseModel):
    ai_enabled: bool
    classifier_loaded: bool
    embedder_loaded: bool
    classifier_backend: str
    embedder_backend: str
    model_version: str
    reference_dataset: Optional[str] = None
    reference_examples: int = 0
    model_config = ConfigDict(protected_namespaces=())


class AIModelInfo(BaseModel):
    component: str
    path: Optional[str] = None
    backend: str
    loaded: bool
    version: str


class AIModelsOut(BaseModel):
    models: List[AIModelInfo]
    thresholds: dict = Field(default_factory=dict)


class ConfidenceTrendPoint(BaseModel):
    """One day's aggregate classifier behavior, for the reviewer-facing
    'is the model drifting' chart. Computed purely from AIAnalysis rows
    already recorded during scans — never a synthetic/estimated value."""

    date: str  # YYYY-MM-DD
    analysis_count: int
    avg_classifier_confidence: float
    avg_semantic_similarity: float
    requires_review_rate: float  # 0-1, share of that day's analyses flagged for review
    below_threshold_rate: float  # 0-1, share below the configured confidence threshold


class ModelHistoryPoint(BaseModel):
    """One model-registry lifecycle event, for correlating a confidence dip
    on the trend chart with an actual retrain/promotion."""

    model_id: str
    model_version: Optional[str] = None
    status: str
    accuracy: Optional[float] = None
    dataset_version: str
    training_timestamp: Optional[str] = None
    model_config = ConfigDict(protected_namespaces=())


class ConfidenceTrendOut(BaseModel):
    current_model_version: str
    confidence_threshold: float
    # True once the most recent window's average confidence has dropped
    # more than `drift_alert_delta` below the earliest window in range —
    # a plain-language drift signal, not just a chart the reviewer has to
    # eyeball.
    drift_detected: bool
    drift_alert_delta: float = 0.10
    points: List[ConfidenceTrendPoint]
    model_history: List[ModelHistoryPoint]