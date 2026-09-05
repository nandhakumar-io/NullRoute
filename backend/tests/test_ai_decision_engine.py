from app.ai.decision_engine import DecisionThresholds, decide
from app.ai.schemas import UNKNOWN_INTENT, ClassifierResult, EmbeddingMatch

THRESHOLDS = DecisionThresholds(classifier_confidence=0.75, semantic_similarity=0.60)


def test_known_known_agreement():
    classifier = ClassifierResult(intent="ssh_management", confidence=0.9, model_version="v1")
    embedding = EmbeddingMatch(nearest_intent="ssh_management", nearest_vendor="cisco", similarity=0.8)
    result = decide("ip ssh version 2", classifier, embedding, THRESHOLDS, "v1", 1.0)
    assert result.decision == "KNOWN_CANDIDATE"
    assert result.requires_review is False
    assert result.models_agree is True


def test_unknown_unknown():
    classifier = ClassifierResult(intent=UNKNOWN_INTENT, confidence=0.2, model_version="v1")
    embedding = EmbeddingMatch(nearest_intent=UNKNOWN_INTENT, nearest_vendor=None, similarity=0.1)
    result = decide("some weird command", classifier, embedding, THRESHOLDS, "v1", 1.0)
    assert result.decision == UNKNOWN_INTENT
    assert result.requires_review is True


def test_known_unknown_disagreement():
    classifier = ClassifierResult(intent="snmp_config", confidence=0.9, model_version="v1")
    embedding = EmbeddingMatch(nearest_intent=UNKNOWN_INTENT, nearest_vendor=None, similarity=0.2)
    result = decide("snmp-server community public", classifier, embedding, THRESHOLDS, "v1", 1.0)
    assert result.decision == "REQUIRES_REVIEW"
    assert result.requires_review is True


def test_known_class_disagreement():
    classifier = ClassifierResult(intent="ssh_management", confidence=0.9, model_version="v1")
    embedding = EmbeddingMatch(nearest_intent="telnet_management", nearest_vendor="cisco", similarity=0.85)
    result = decide("some ambiguous line", classifier, embedding, THRESHOLDS, "v1", 1.0)
    assert result.decision == "REQUIRES_REVIEW"
    assert result.models_agree is False


def test_low_classifier_confidence():
    classifier = ClassifierResult(intent="aaa_config", confidence=0.4, model_version="v1")
    embedding = EmbeddingMatch(nearest_intent="aaa_config", nearest_vendor="juniper", similarity=0.9)
    result = decide("aaa new-model", classifier, embedding, THRESHOLDS, "v1", 1.0)
    assert result.decision == "REQUIRES_REVIEW"
    assert result.requires_review is True


def test_ai_never_returns_compliance_verdict():
    """The AI decision vocabulary must never overlap with OPA/Batfish's
    PASS/FAIL/BLOCK compliance vocabulary (architectural rule 3)."""
    classifier = ClassifierResult(intent="ssh_management", confidence=0.95, model_version="v1")
    embedding = EmbeddingMatch(nearest_intent="ssh_management", nearest_vendor="cisco", similarity=0.9)
    result = decide("ip ssh version 2", classifier, embedding, THRESHOLDS, "v1", 1.0)
    assert result.decision not in ("PASS", "FAIL", "BLOCK")
