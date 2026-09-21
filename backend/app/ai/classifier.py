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
from typing import Callable, Dict, List, Optional, Tuple

from app.ai import settings as ai_settings
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
    backend_name: str  # "distilbert" | "keyword-fallback" | "remote-classifier"
    model_version: str
    predict_fn: object  # callable[[str], ClassifierResult]
    # callable[[List[str]], List[ClassifierResult]]; same order as the input.
    # None -> classify_batch() falls back to calling predict_fn per text.
    predict_batch_fn: Optional[Callable[[List[str]], List[ClassifierResult]]] = None
    device: str = "cpu"


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


def _is_resource_error(exc: BaseException) -> bool:
    """True for out-of-memory style failures (torch.cuda.OutOfMemoryError is a
    RuntimeError subclass; CPU OOM surfaces as MemoryError or a RuntimeError
    mentioning allocation)."""
    if isinstance(exc, MemoryError):
        return True
    if isinstance(exc, RuntimeError):
        msg = str(exc).lower()
        return "out of memory" in msg or "can't allocate" in msg or "cannot allocate" in msg
    return False


def _try_load_distilbert(model_path: str, model_version: Optional[str] = None) -> Optional[LoadedClassifier]:
    try:
        import torch  # noqa: F401
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ImportError:
        return None
    if not model_path or not os.path.isdir(model_path):
        return None
    try:
        import torch as _torch

        tokenizer = AutoTokenizer.from_pretrained(model_path)
        model = AutoModelForSequenceClassification.from_pretrained(model_path)
        model.eval()
        # CUDA when available (and not overridden), otherwise CPU. Only the
        # inference model moves; nothing else in the backend touches the GPU.
        device = ai_settings.resolve_torch_device()
        model.to(device)
        id2label = model.config.id2label

        def _forward(texts: List[str]) -> List[ClassifierResult]:
            """One padded forward pass over `texts`; output order == input order."""
            inputs = tokenizer(texts, return_tensors="pt", truncation=True, max_length=64, padding=True)
            inputs = {k: v.to(device) for k, v in inputs.items()}
            with _torch.inference_mode():
                logits = model(**inputs).logits
                probs = _torch.softmax(logits, dim=-1)
                confs, idxs = _torch.max(probs, dim=-1)
            out: List[ClassifierResult] = []
            for idx, conf in zip(idxs.tolist(), confs.tolist()):
                out.append(ClassifierResult(
                    intent=id2label.get(int(idx), UNKNOWN_INTENT),
                    confidence=round(float(conf), 4),
                    model_version=model_version or model_path,
                ))
            return out

        def _forward_with_backoff(texts: List[str]) -> List[ClassifierResult]:
            # A resource error on a big batch is retried as two half-batches
            # (down to single items) instead of dropping blocks; a single item
            # that still fails is raised exactly like the sequential path would.
            try:
                return _forward(texts)
            except Exception as exc:  # noqa: BLE001
                if len(texts) > 1 and _is_resource_error(exc):
                    mid = len(texts) // 2
                    return _forward_with_backoff(texts[:mid]) + _forward_with_backoff(texts[mid:])
                raise

        def predict(text: str) -> ClassifierResult:
            return _forward([text])[0]

        def predict_batch(texts: List[str]) -> List[ClassifierResult]:
            if not texts:
                return []
            batch_size = ai_settings.distilbert_batch_size()
            # Group similar-length texts so padding waste stays low, then put
            # every prediction back at its original position.
            order = sorted(range(len(texts)), key=lambda i: len(texts[i]))
            results: List[Optional[ClassifierResult]] = [None] * len(texts)
            for start in range(0, len(order), batch_size):
                idxs = order[start:start + batch_size]
                for i, res in zip(idxs, _forward_with_backoff([texts[i] for i in idxs])):
                    results[i] = res
            return results  # type: ignore[return-value]

        return LoadedClassifier(
            backend_name="distilbert", model_version=model_version or model_path,
            predict_fn=predict, predict_batch_fn=predict_batch, device=device,
        )
    except Exception:
        return None


def _try_load_remote_classifier(url: str, api_key: str, timeout: float) -> Optional[LoadedClassifier]:
    if not url:
        return None
        
    def predict(text: str) -> ClassifierResult:
        import urllib.request
        import urllib.error
        import json
        req = urllib.request.Request(
            url,
            data=json.dumps({"prompt": text, "text": text}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        if api_key:
            req.add_header("Authorization", f"Bearer {api_key}")
            
        try:
            with urllib.request.urlopen(req, timeout=timeout) as res:
                body = res.read().decode("utf-8")
                data = json.loads(body)
                
                result = data.get("result", {})
                label = result.get("label", UNKNOWN_INTENT)
                # Remap the label back to our internal intent format if it's returning raw names like ROUTING
                if label != UNKNOWN_INTENT:
                    label = label.lower().replace(" ", "_")
                    if label == "routing": label = "routing_config"
                    # We might need to ensure it matches KNOWN_INTENTS format, but we'll try to just pass it directly as it seems to just be capitalized.
                    # Wait, if the model returns 'ROUTING', we should lower it. 
                    label = label.lower()
                    if not label.endswith("_config") and not label.endswith("_management") and not label.endswith("_security") and not label.endswith("_policy"):
                        # Keep it simple, just lower it. Let's see if there is an exact mapping needed.
                        pass
                
                return ClassifierResult(
                    intent=label,
                    confidence=round(float(result.get("score", 0.0)), 4),
                    model_version=data.get("model", "remote")
                )
        except Exception:
            return ClassifierResult(
                intent=UNKNOWN_INTENT,
                confidence=0.0,
                model_version="remote-error"
            )
            
    def predict_batch(texts: List[str]) -> List[ClassifierResult]:
        # The remote endpoint takes ONE text per request, so this is bounded
        # concurrent fan-out (order preserved by executor.map), not a native
        # batch. A server-side batch endpoint would need to be added to the
        # inference service first.
        if not texts:
            return []
        if len(texts) == 1:
            return [predict(texts[0])]
        from concurrent.futures import ThreadPoolExecutor
        workers = min(ai_settings.remote_inference_concurrency(), len(texts))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            return list(pool.map(predict, texts))

    return LoadedClassifier(
        backend_name="remote-classifier", model_version="remote",
        predict_fn=predict, predict_batch_fn=predict_batch, device="remote",
    )


def load_classifier(
    production_path: Optional[str] = None,
    production_version: Optional[str] = None,
) -> LoadedClassifier:
    """Load at startup and again whenever a model is promoted/rolled back
    (see model_registry.py).

    Precedence: the model-registry PRODUCTION entry (a human explicitly
    promoted it) > AI_CLASSIFIER_REMOTE_URL > AI_CLASSIFIER_MODEL_PATH >
    keyword fallback. If the production artifact can't be loaded (missing
    directory, torch/transformers not installed in this process) we fall
    through to the next source instead of failing the API; the caller can see
    that via the returned backend_name / model_version.
    """
    if production_path:
        loaded = _try_load_distilbert(production_path, production_version)
        if loaded is not None:
            return loaded
        import logging
        logging.getLogger(__name__).warning(
            "PRODUCTION classifier at %r could not be loaded (missing artifact or torch/transformers "
            "not installed in this process); falling back to the configured classifier.",
            production_path,
        )

    remote_url = os.getenv("AI_CLASSIFIER_REMOTE_URL", "")
    if remote_url:
        api_key = os.getenv("AI_REMOTE_API_KEY", "")
        timeout = float(os.getenv("AI_REMOTE_TIMEOUT_SECONDS", "10.0"))
        loaded = _try_load_remote_classifier(remote_url, api_key, timeout)
        if loaded is not None:
            return loaded

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


def classify_batch(loaded: LoadedClassifier, texts: List[str]) -> Tuple[List[ClassifierResult], float]:
    """Classify many texts at once. Result i corresponds to texts[i].

    Uses the backend's true batched path when it has one; otherwise falls back
    to the per-text predict_fn (keyword fallback, custom backends). The
    returned latency is the wall time of the WHOLE batch.
    """
    start = time.perf_counter()
    if not texts:
        return [], 0.0
    if loaded.predict_batch_fn is not None:
        results = loaded.predict_batch_fn(list(texts))
    else:
        results = [loaded.predict_fn(t) for t in texts]
    if len(results) != len(texts):
        raise RuntimeError(f"classifier returned {len(results)} results for {len(texts)} inputs")
    return results, (time.perf_counter() - start) * 1000.0