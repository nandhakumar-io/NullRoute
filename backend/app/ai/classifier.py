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
            inputs.pop("token_type_ids", None)
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


def _try_load_huggingface_distilbert() -> Optional[LoadedClassifier]:
    """Load the real fine-tuned checkpoint straight from a private Hugging
    Face repo, using HF_DISTILBERT_MODEL / HF_TOKEN / HF_MODEL_REVISION.

    These env vars have existed in .env since day one, but nothing in this
    module ever read them -- AI_CLASSIFIER_MODEL_PATH only accepted a local
    directory, so this path silently fell through to the remote-inference
    URL (if set) or the keyword fallback, and the real trained model was
    never actually loaded. `transformers.AutoTokenizer/AutoModel...
    from_pretrained` accept a hub repo id directly (no separate
    snapshot_download step needed), so this only needs the token/revision
    threaded through.
    """
    repo_id = os.getenv("HF_DISTILBERT_MODEL", "")
    if not repo_id:
        return None
    try:
        import torch  # noqa: F401
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ImportError:
        return None

    token = os.getenv("HF_TOKEN") or None
    revision = os.getenv("HF_MODEL_REVISION") or None
    try:
        tokenizer = AutoTokenizer.from_pretrained(repo_id, token=token, revision=revision)
        model = AutoModelForSequenceClassification.from_pretrained(repo_id, token=token, revision=revision)
        model.eval()
        id2label = model.config.id2label

        def predict(text: str) -> ClassifierResult:
            import torch as _torch
            inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=64)
            inputs.pop("token_type_ids", None)
            with _torch.no_grad():
                logits = model(**inputs).logits
                probs = _torch.softmax(logits, dim=-1)[0]
                top_idx = int(_torch.argmax(probs).item())
                confidence = float(probs[top_idx].item())
            label = id2label.get(top_idx, UNKNOWN_INTENT)
            return ClassifierResult(intent=label, confidence=round(confidence, 4), model_version=repo_id)

        version = f"{repo_id}@{revision}" if revision else repo_id
        return LoadedClassifier(backend_name="distilbert", model_version=version, predict_fn=predict)
    except Exception:
        return None


def _try_load_remote_classifier(remote_url: str) -> Optional[LoadedClassifier]:
    """Optional remote inference mode: instead of loading DistilBERT into
    this process, call an HTTP inference endpoint (self-hosted TGI/Triton/
    text-classification server, or a teammate's GPU box) that returns
    {"intent", "confidence", "model_version"} for POST {"text": ...}.

    Loaded once (the predict_fn closure is reused for every request, same
    as the local-model path) -- this only changes WHERE inference runs,
    not the load-once contract. If the endpoint errors or times out at
    call time, degrades to the same deterministic keyword fallback used
    offline rather than failing the scan pipeline on a network blip.
    """
    if not remote_url:
        return None
    import httpx

    timeout = float(os.getenv("AI_REMOTE_TIMEOUT_SECONDS", "10"))
    api_key = os.getenv("AI_REMOTE_API_KEY")
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    fallback_version = os.getenv("AI_MODEL_VERSION", "keyword-fallback-v1")
    fallback_predict = _keyword_predict(fallback_version)

    def predict(text: str) -> ClassifierResult:
        try:
            resp = httpx.post(remote_url, json={"text": text}, headers=headers, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            return ClassifierResult(
                intent=data.get("intent", UNKNOWN_INTENT),
                confidence=round(float(data.get("confidence", 0.0)), 4),
                model_version=data.get("model_version", remote_url),
            )
        except Exception:
            return fallback_predict(text)

    return LoadedClassifier(backend_name="distilbert-remote", model_version=remote_url, predict_fn=predict)


def load_classifier() -> LoadedClassifier:
    """Load once at application startup (see model_registry.py).

    Resolution order: HF_DISTILBERT_MODEL (real fine-tuned checkpoint,
    downloaded straight from the private Hugging Face repo) ->
    AI_CLASSIFIER_REMOTE_URL (remote HTTP inference) ->
    AI_CLASSIFIER_MODEL_PATH (local DistilBERT checkpoint) -> deterministic
    keyword fallback. Only one backend is ever active per process.

    HF is tried first: it's the one env-configured path that actually
    points at the real trained model, whereas the remote-inference URL
    depends on an external box being reachable and silently degrades to
    the keyword fallback (with confidence 0.0 on anything it doesn't
    recognize) if it isn't.
    """
    hf_loaded = _try_load_huggingface_distilbert()
    if hf_loaded is not None:
        return hf_loaded

    remote_url = os.getenv("AI_CLASSIFIER_REMOTE_URL", "")
    remote = _try_load_remote_classifier(remote_url)
    if remote is not None:
        return remote

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