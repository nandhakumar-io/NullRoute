"""
Version-aware, bounded, in-process cache for AI inference results.

There was no AI cache in the codebase before this module, so this is the one
cache for the whole staged pipeline. It has three namespaces:

  classifier      DistilBERT result for one text
  embedding       MiniLM vector for one text
  interpretation  validated LLM interpretation of one unknown line

Correctness rules (see key builders below):

* Every key embeds the versions that produced the value (classifier / embedder
  / registry model version, LLM model, prompt+schema fingerprint, parser
  version). A model, prompt or schema change therefore changes the key and the
  old entry is simply never looked up again -- there is no stale read to guard
  against, and no explicit invalidation step that could be forgotten.
* The interpretation key also embeds a fingerprint of the retrieved RAG
  knowledge and the tenant. A human approving/correcting a CommandMapping
  changes what retrieval returns, so the key changes and the HITL learning
  loop is never short-circuited by a cached pre-correction answer; one
  tenant's cached interpretation is never served to another.
* Only *successful, validated, confident* results are stored (enforced by the
  callers in staged.py / service.py). Failures, degraded fallbacks and
  low-confidence/uncertain interpretations are never cached.
* Values are deep-copied in and out so a consumer mutating a result cannot
  corrupt the cache.

The cache is per process (one per uvicorn/worker process). It is a throughput
optimisation only: dropping it (restart, AI_INFERENCE_CACHE_ENABLED=false)
never changes results.
"""
from __future__ import annotations

import copy
import hashlib
import json
import threading
from collections import OrderedDict
from typing import Any, Dict, Optional, Tuple

from app.ai import settings as ai_settings

NS_CLASSIFIER = "classifier"
NS_EMBEDDING = "embedding"
NS_INTERPRETATION = "interpretation"

_MISS = object()


def make_key(*parts: Any) -> str:
    """Stable digest of `parts` (order-sensitive, JSON-canonical)."""
    payload = json.dumps(list(parts), ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class InferenceCache:
    def __init__(self, max_entries: int = 20000) -> None:
        self._max = max(1, int(max_entries))
        self._data: "OrderedDict[Tuple[str, str], Any]" = OrderedDict()
        self._lock = threading.Lock()
        self._hits: Dict[str, int] = {}
        self._misses: Dict[str, int] = {}

    def get(self, namespace: str, key: str) -> Any:
        """Return a copy of the cached value, or the module-level MISS sentinel."""
        with self._lock:
            entry = self._data.get((namespace, key), _MISS)
            if entry is _MISS:
                self._misses[namespace] = self._misses.get(namespace, 0) + 1
                return _MISS
            self._data.move_to_end((namespace, key))
            self._hits[namespace] = self._hits.get(namespace, 0) + 1
            return copy.deepcopy(entry)

    def put(self, namespace: str, key: str, value: Any) -> None:
        with self._lock:
            self._data[(namespace, key)] = copy.deepcopy(value)
            self._data.move_to_end((namespace, key))
            while len(self._data) > self._max:
                self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
            self._hits.clear()
            self._misses.clear()

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "entries": len(self._data),
                "max_entries": self._max,
                "hits": dict(self._hits),
                "misses": dict(self._misses),
            }

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)


MISS = _MISS

_cache: Optional[InferenceCache] = None
_cache_lock = threading.Lock()


def get_cache() -> Optional[InferenceCache]:
    """The process-wide cache, or None when AI_INFERENCE_CACHE_ENABLED=false."""
    global _cache
    if not ai_settings.cache_enabled():
        return None
    with _cache_lock:
        if _cache is None:
            _cache = InferenceCache(ai_settings.cache_max_entries())
        return _cache


def reset_cache_for_tests() -> None:
    global _cache
    with _cache_lock:
        _cache = None


# --------------------------------------------------------------------------
# Key builders. Everything the model output depends on goes into the key.
# --------------------------------------------------------------------------

def classifier_key(backend: str, model_version: str, registry_version: str, text: str) -> str:
    return make_key("clf", backend, model_version, registry_version, text)


def embedding_key(backend: str, model_version: str, registry_version: str, text: str) -> str:
    return make_key("emb", backend, model_version, registry_version, text)


def interpretation_key(
    *,
    tenant_id: Optional[str],
    vendor: str,
    line: str,
    llm_model: str,
    prompt_fingerprint: str,
    parser_version: str,
    classifier_version: str,
    embedder_version: str,
    registry_version: str,
    retrieval_fingerprint: str,
) -> str:
    return make_key(
        "interp", tenant_id, vendor, line, llm_model, prompt_fingerprint, parser_version,
        classifier_version, embedder_version, registry_version, retrieval_fingerprint,
    )