"""
DistilBERT network-configuration-intent classifier.

Loaded ONCE (see model_registry.py, wired into FastAPI's lifespan in
main.py) and reused for every inference call — never re-loaded per
request.

Offline-safe: if `transformers`/`torch` aren't installed or
AI_CLASSIFIER_MODEL_PATH doesn't point at a real fine-tuned checkpoint,
this falls back to a deterministic keyword-rule classifier so the rest of
the pipeline (decision engine, persistence, endpoints) is still fully
exercisable in this environment. In production, AI_ENABLED=true plus a
real AI_CLASSIFIER_MODEL_PATH loads the real fine-tuned DistilBERT model.
The fallback never fabricates a confidence above what the heuristic can
justify, and always reports its true backend via `backend_name`.
"""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from app.ai.schemas import UNKNOWN_INTENT, ClassifierResult

# Known network-configuration intents the classifier was fine-tuned on.
# Must stay version-aligned with AI_REFERENCE_DATASET (see embeddings.py).
KNOWN_INTENTS: List[str] = [
    "ssh_management", "telnet_management", "http_management",
    "logging_config", "ntp_config", "aaa_config",
    "password_policy", "snmp_config", "interface_security",
    "banner_config", "acl_config", "vlan_config", "routing_config",
]

_KEYWORD_RULES: Dict[str, List[str]] = {
    "ssh_management": ["ssh"],
    "telnet_management": ["telnet"],
    "http_management": ["http", "https", "web-management"],
    "logging_config": ["logging", "syslog"],
    "ntp_config": ["ntp"],
    "aaa_config": ["aaa", "tacacs", "radius"],
    "password_policy": ["password", "passwd", "secret"],
    "snmp_config": ["snmp"],
    "interface_security": ["switchport", "port-security", "interface"],
    "banner_config": ["banner"],
    "acl_config": ["access-list", "acl", "policy-map", "filter"],
    "vlan_config": ["vlan"],
    "routing_config": ["router", "route", "bgp", "ospf", "static-route"],
}


@dataclass
class LoadedClassifier:
    backend_name: str  # "distilbert" | "keyword-fallback"
    model_version: str
    predict_fn: object  # callable[[str], ClassifierResult]


def _keyword_predict(model_version: str):
    def predict(text: str) -> ClassifierResult:
        lowered = text.lower()
        best_intent = UNKNOWN_INTENT
        best_hits = 0
        for intent, keywords in _KEYWORD_RULES.items():
            hits = sum(1 for kw in keywords if kw in lowered)
            if hits > best_hits:
                best_hits = hits
                best_intent = intent
        confidence = 0.0 if best_hits == 0 else min(0.55 + 0.15 * best_hits, 0.9)
        return ClassifierResult(
            intent=best_intent if best_hits else UNKNOWN_INTENT,
            confidence=round(confidence, 3),
            model_version=model_version,
        )
    return predict


def _try_load_distilbert(model_path: str) -> Optional[LoadedClassifier]:
    try:
        import torch  # noqa: F401
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ImportError:
        return None
    if not model_path or not os.path.isdir(model_path):
        return None
    try:
        tokenizer = AutoTokenizer.from_pretrained(model_path)
        model = AutoModelForSequenceClassification.from_pretrained(model_path)
        model.eval()
        id2label = model.config.id2label

        def predict(text: str) -> ClassifierResult:
            import torch as _torch
            inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=64)
            with _torch.no_grad():
                logits = model(**inputs).logits
                probs = _torch.softmax(logits, dim=-1)[0]
                top_idx = int(_torch.argmax(probs).item())
                confidence = float(probs[top_idx].item())
            label = id2label.get(top_idx, UNKNOWN_INTENT)
            return ClassifierResult(intent=label, confidence=round(confidence, 4), model_version=model_path)

        return LoadedClassifier(backend_name="distilbert", model_version=model_path, predict_fn=predict)
    except Exception:
        return None


def load_classifier() -> LoadedClassifier:
    """Load once at application startup (see model_registry.py)."""
    model_path = os.getenv("AI_CLASSIFIER_MODEL_PATH", "")
    loaded = _try_load_distilbert(model_path)
    if loaded is not None:
        return loaded
    fallback_version = os.getenv("AI_MODEL_VERSION", "keyword-fallback-v1")
    return LoadedClassifier(
        backend_name="keyword-fallback",
        model_version=fallback_version,
        predict_fn=_keyword_predict(fallback_version),
    )


def classify(loaded: LoadedClassifier, text: str) -> Tuple[ClassifierResult, float]:
    start = time.perf_counter()
    result = loaded.predict_fn(text)
    latency_ms = (time.perf_counter() - start) * 1000.0
    return result, latency_ms
