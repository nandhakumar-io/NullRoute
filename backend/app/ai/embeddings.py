"""
all-MiniLM-L6-v2 semantic embedding model, used to find the nearest known
intent/vendor example in a version-aligned reference dataset
(AI_REFERENCE_DATASET / AI_REFERENCE_EMBEDDINGS).

Loaded ONCE at startup (see model_registry.py) and reused.

Offline-safe: if `sentence-transformers`/`torch` aren't installed, or the
reference dataset/embeddings files aren't present, falls back to a
deterministic token-overlap similarity (same style as
`app/ai/normalize.py`'s existing offline heuristic) so the rest of the
pipeline still runs end-to-end. The fallback is clearly reported via
`backend_name` and never silently reports a bogus reference dataset.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from app.ai.schemas import UNKNOWN_INTENT, EmbeddingMatch


@dataclass
class ReferenceExample:
    text: str
    intent: str
    vendor: Optional[str] = None
    vector: Optional[List[float]] = None


@dataclass
class LoadedEmbedder:
    backend_name: str  # "minilm" | "token-overlap-fallback"
    model_version: str
    reference_dataset_path: Optional[str]
    examples: List[ReferenceExample] = field(default_factory=list)
    encode_fn: Optional[object] = None  # callable[[str], list[float]] when backend is minilm


def _load_reference_dataset(path: str) -> List[ReferenceExample]:
    if not path or not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        return [
            ReferenceExample(text=r["text"], intent=r.get("intent", UNKNOWN_INTENT), vendor=r.get("vendor"))
            for r in raw
        ]
    except Exception:
        return []


def _try_load_minilm(model_path: str, dataset_path: str, embeddings_path: Optional[str]) -> Optional[LoadedEmbedder]:
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError:
        return None
    if not model_path:
        return None
    try:
        model = SentenceTransformer(model_path)
        examples = _load_reference_dataset(dataset_path)
        if not examples:
            return None

        if embeddings_path and os.path.isfile(embeddings_path):
            import numpy as np
            vectors = np.load(embeddings_path)
            for ex, vec in zip(examples, vectors):
                ex.vector = vec.tolist()
        else:
            vectors = model.encode([e.text for e in examples], normalize_embeddings=True)
            for ex, vec in zip(examples, vectors):
                ex.vector = vec.tolist() if hasattr(vec, "tolist") else list(vec)

        def encode(text: str) -> List[float]:
            vec = model.encode([text], normalize_embeddings=True)[0]
            return vec.tolist() if hasattr(vec, "tolist") else list(vec)

        return LoadedEmbedder(
            backend_name="minilm",
            model_version=model_path,
            reference_dataset_path=dataset_path,
            examples=examples,
            encode_fn=encode,
        )
    except Exception:
        return None


def _try_load_remote_minilm(remote_url: str, dataset_path: str, embeddings_path: Optional[str]) -> Optional[LoadedEmbedder]:
    """Optional remote inference mode for MiniLM: instead of loading
    sentence-transformers into this process, call an HTTP embedding
    endpoint (self-hosted text-embeddings-inference server, or a
    teammate's GPU box) that returns {"embedding": [...]} for
    POST {"text": ...}.

    The reference dataset's vectors are still computed once at load time
    (via the same remote endpoint if no precomputed AI_REFERENCE_EMBEDDINGS
    file is given) and cached in memory for the life of the process --
    this changes WHERE inference runs, not the load-once contract.
    """
    if not remote_url:
        return None
    import httpx

    timeout = float(os.getenv("AI_REMOTE_TIMEOUT_SECONDS", "10"))
    api_key = os.getenv("AI_REMOTE_API_KEY")
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}

    def _remote_encode_raw(text_in: str) -> List[float]:
        resp = httpx.post(remote_url, json={"text": text_in}, headers=headers, timeout=timeout)
        resp.raise_for_status()
        return list(resp.json()["embedding"])

    examples = _load_reference_dataset(dataset_path)
    if not examples:
        return None

    if embeddings_path and os.path.isfile(embeddings_path):
        import numpy as np
        vectors = np.load(embeddings_path)
        for ex, vec in zip(examples, vectors):
            ex.vector = vec.tolist()
    else:
        try:
            for ex in examples:
                ex.vector = _remote_encode_raw(ex.text)
        except Exception:
            # Remote endpoint unreachable while building the reference set
            # -- don't half-populate vectors; let the caller fall through
            # to the offline token-overlap backend instead.
            return None

    def encode(text_in: str) -> List[float]:
        try:
            return _remote_encode_raw(text_in)
        except Exception:
            # Mirrors classifier.py's remote fallback: a network blip on a
            # single query shouldn't fail the whole normalization pipeline.
            # Returning a zero vector makes this query rank last rather
            # than raising, which the caller (nearest()) handles gracefully.
            return [0.0] * len(examples[0].vector or [1.0])

    return LoadedEmbedder(
        backend_name="minilm-remote",
        model_version=remote_url,
        reference_dataset_path=dataset_path,
        examples=examples,
        encode_fn=encode,
    )


def load_embedder() -> LoadedEmbedder:
    model_path = os.getenv("AI_EMBEDDING_MODEL_PATH", "")
    dataset_path = os.getenv("AI_REFERENCE_DATASET", "")
    embeddings_path = os.getenv("AI_REFERENCE_EMBEDDINGS") or None
    remote_url = os.getenv("AI_EMBEDDING_REMOTE_URL", "")

    remote = _try_load_remote_minilm(remote_url, dataset_path, embeddings_path)
    if remote is not None:
        return remote

    loaded = _try_load_minilm(model_path, dataset_path, embeddings_path)
    if loaded is not None:
        return loaded

    fallback_version = os.getenv("AI_MODEL_VERSION", "keyword-fallback-v1")
    examples = _load_reference_dataset(dataset_path)
    return LoadedEmbedder(
        backend_name="token-overlap-fallback",
        model_version=fallback_version,
        reference_dataset_path=dataset_path or None,
        examples=examples,
        encode_fn=None,
    )


def _tokens(text: str) -> set:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def _cosine(a: List[float], b: List[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(y * y for y in b) ** 0.5
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def nearest(loaded: LoadedEmbedder, text: str) -> Tuple[EmbeddingMatch, float]:
    start = time.perf_counter()
    if not loaded.examples:
        latency_ms = (time.perf_counter() - start) * 1000.0
        return EmbeddingMatch(nearest_intent=UNKNOWN_INTENT, nearest_vendor=None, similarity=0.0), latency_ms

    if loaded.backend_name in ("minilm", "minilm-remote") and loaded.encode_fn is not None:
        query_vec = loaded.encode_fn(text)
        best = max(loaded.examples, key=lambda e: _cosine(query_vec, e.vector or []))
        similarity = _cosine(query_vec, best.vector or [])
    else:
        q_tokens = _tokens(text)
        best, best_score = None, -1.0
        for ex in loaded.examples:
            overlap = len(q_tokens & _tokens(ex.text))
            union = len(q_tokens | _tokens(ex.text)) or 1
            score = overlap / union
            if score > best_score:
                best, best_score = ex, score
        similarity = max(best_score, 0.0)
        if best is None:
            latency_ms = (time.perf_counter() - start) * 1000.0
            return EmbeddingMatch(nearest_intent=UNKNOWN_INTENT, nearest_vendor=None, similarity=0.0), latency_ms

    latency_ms = (time.perf_counter() - start) * 1000.0
    return EmbeddingMatch(
        nearest_intent=best.intent,
        nearest_vendor=best.vendor,
        similarity=round(float(similarity), 4),
    ), latency_ms
