"""
Hybrid decision engine combining the DistilBERT classifier's predicted
intent with the MiniLM embedding model's nearest-neighbor intent.

RULE (non-negotiable, per problem statement Phase 1 / architectural rule 3):
this engine NEVER produces a compliance PASS/FAIL decision. It only
decides how much to trust an *intent interpretation*:

    KNOWN_CANDIDATE  -- both models agree on a known class with sufficient
                        confidence; safe to feed downstream as an
                        interpretation candidate (still subject to OPA).
    REQUIRES_REVIEW  -- models disagree, one is UNKNOWN, or confidence is
                        below threshold; a human must confirm via the
                        Training Center before this is trusted.
    UNKNOWN          -- both models agree the intent is unrecognized.

Decision hierarchy is evaluated in this exact order (see schemas.py /
AIAnalysisResult for the output shape):

  1. classifier == UNKNOWN and semantic == UNKNOWN         -> UNKNOWN
  2. exactly one of classifier/semantic == UNKNOWN          -> REQUIRES_REVIEW
  3. both known and equal and both thresholds met            -> KNOWN_CANDIDATE
  4. both known but classifier != semantic nearest_intent     -> REQUIRES_REVIEW
  5. classifier confidence below AI_CLASSIFIER_CONFIDENCE_THRESHOLD
                                                              -> REQUIRES_REVIEW
"""
from __future__ import annotations

from dataclasses import dataclass

from app.ai.schemas import UNKNOWN_INTENT, AIAnalysisResult, ClassifierResult, EmbeddingMatch


@dataclass
class DecisionThresholds:
    classifier_confidence: float
    semantic_similarity: float


def decide(
    raw_command: str,
    classifier: ClassifierResult,
    embedding: EmbeddingMatch,
    thresholds: DecisionThresholds,
    model_version: str,
    inference_latency_ms: float,
) -> AIAnalysisResult:
    classifier_unknown = classifier.intent.upper() == UNKNOWN_INTENT
    semantic_unknown = embedding.nearest_intent.upper() == UNKNOWN_INTENT or embedding.similarity < thresholds.semantic_similarity

    models_agree = (not classifier_unknown) and (not semantic_unknown) and (classifier.intent.upper() == embedding.nearest_intent.upper())

    # Rule 1: both UNKNOWN
    if classifier_unknown and semantic_unknown:
        decision, requires_review, reason = (
            UNKNOWN_INTENT,
            True,
            "Both the classifier and the semantic model judged this an unrecognized configuration intent.",
        )
    # Rule 2: exactly one UNKNOWN
    elif classifier_unknown != semantic_unknown:
        decision, requires_review, reason = (
            "REQUIRES_REVIEW",
            True,
            "Classifier and semantic model disagree on whether this intent is known (one predicts UNKNOWN).",
        )
    # Rule 4: both known, but disagree on which known class
    elif classifier.intent.upper() != embedding.nearest_intent.upper():
        decision, requires_review, reason = (
            "REQUIRES_REVIEW",
            True,
            f"Classifier predicted '{classifier.intent}' but the nearest semantic match is "
            f"'{embedding.nearest_intent}' — known-class disagreement.",
        )
    # Rule 5: classifier confidence below threshold
    elif classifier.confidence < thresholds.classifier_confidence:
        decision, requires_review, reason = (
            "REQUIRES_REVIEW",
            True,
            f"Classifier confidence {classifier.confidence:.2f} is below the configured threshold "
            f"{thresholds.classifier_confidence:.2f}.",
        )
    # Rule 3: agreement + thresholds met
    else:
        decision, requires_review, reason = (
            "KNOWN_CANDIDATE",
            False,
            f"Classifier and semantic model agree on intent '{classifier.intent}' with sufficient confidence.",
        )

    return AIAnalysisResult(
        raw_command=raw_command,
        intent=classifier.intent if not classifier_unknown else (embedding.nearest_intent if not semantic_unknown else UNKNOWN_INTENT),
        classifier_confidence=classifier.confidence,
        semantic_similarity=embedding.similarity,
        nearest_intent=embedding.nearest_intent,
        nearest_vendor=embedding.nearest_vendor,
        models_agree=models_agree,
        decision=decision,
        requires_review=requires_review,
        model_version=model_version,
        inference_latency_ms=inference_latency_ms,
        reason=reason,
    )
