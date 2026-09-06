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

from pydantic import BaseModel, Field, ConfigDict

UNKNOWN_INTENT = "UNKNOWN"


class ClassifierResult(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    intent: str
    confidence: float
    model_version: str


class EmbeddingMatch(BaseModel):
    nearest_intent: str
    nearest_vendor: Optional[str] = None
    similarity: float


class AIAnalysisResult(BaseModel):
    """Full hybrid decision output for one raw configuration line/command."""
    model_config = ConfigDict(protected_namespaces=())

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


class AIHealth(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    ai_enabled: bool
    classifier_loaded: bool
    embedder_loaded: bool
    classifier_backend: str
    embedder_backend: str
    model_version: str
    reference_dataset: Optional[str] = None
    reference_examples: int = 0


class AIModelInfo(BaseModel):
    component: str
    path: Optional[str] = None
    backend: str
    loaded: bool
    version: str


class AIModelsOut(BaseModel):
    models: List[AIModelInfo]
    thresholds: dict = Field(default_factory=dict)
