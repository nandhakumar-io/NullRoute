"""
Tunables for the staged AI inference pipeline.

Read lazily (on every call) instead of at import time so deployments can
change them via env without a code change and tests can monkeypatch them.

Existing thresholds are deliberately NOT re-declared here -- they keep their
current names and owners:

  AI_CLASSIFIER_CONFIDENCE_THRESHOLD / AI_SEMANTIC_THRESHOLD  -> model_registry.py
  AI_CONFIDENCE_THRESHOLD (LLM interpretation confidence)      -> normalize.py
  AI_LLM_CONCURRENCY / AI_LLM_TIMEOUT_SECONDS / AI_LLM_MAX_ATTEMPTS -> normalize.py
"""
from __future__ import annotations

import os


def _int_env(name: str, default: int, minimum: int = 1) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        return default


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def distilbert_batch_size() -> int:
    """Max texts per DistilBERT forward pass (local torch backend)."""
    return _int_env("AI_DISTILBERT_BATCH_SIZE", 32)


def minilm_batch_size() -> int:
    """Max texts per MiniLM encode() call (local sentence-transformers backend)."""
    return _int_env("AI_MINILM_BATCH_SIZE", 32)


def remote_inference_concurrency() -> int:
    """Concurrent requests to a *remote* classifier/embedder endpoint.

    The remote endpoints only accept one text per request (see
    classifier._try_load_remote_classifier), so a batch is fanned out over a
    bounded thread pool rather than pretending to be a native batch.
    """
    return _int_env("AI_REMOTE_INFERENCE_CONCURRENCY", 8)


def device_preference() -> str:
    """'auto' (CUDA when available, else CPU), 'cpu' or 'cuda'."""
    return (os.getenv("AI_DEVICE") or "auto").strip().lower()


def normalize_chunk_size() -> int:
    """Unique unknown lines processed per stage before a pause/stop checkpoint.

    Defaults to the pipeline's pre-existing checkpoint granularity (40).
    """
    return _int_env("AI_NORMALIZE_CHUNK_SIZE", 40)


def cache_enabled() -> bool:
    return _bool_env("AI_INFERENCE_CACHE_ENABLED", True)


def cache_max_entries() -> int:
    return _int_env("AI_INFERENCE_CACHE_MAX_ENTRIES", 20000)


def retrieval_shortcut_enabled() -> bool:
    """Opt-in: reuse an exact, human-approved CommandMapping instead of
    calling the LLM. OFF by default -- CommandMapping keeps ``example_value``
    as a string and only the first fact of a multi-fact correction, so the
    reused result is not guaranteed identical to what the LLM would have
    produced. Enable only after validating against your evaluation set.
    """
    return _bool_env("AI_RETRIEVAL_SHORTCUT_ENABLED", False)


def resolve_torch_device() -> str:
    """Pick the torch device string. Never raises; never requires CUDA."""
    pref = device_preference()
    if pref == "cpu":
        return "cpu"
    try:
        import torch
        if torch.cuda.is_available():
            return "cuda"
    except Exception:  # noqa: BLE001 - torch missing/broken -> CPU path
        pass
    return "cpu"