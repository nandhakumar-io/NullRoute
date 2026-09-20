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


def _try_load_remote_embedder(url: str, api_key: str, timeout: float, dataset_path: str, embeddings_path: Optional[str]) -> Optional[LoadedEmbedder]:
    if not url:
        return None
        
    examples = _load_reference_dataset(dataset_path)
    # NOTE: we allow empty examples — the reference dataset is only needed for
    # embeddings.nearest() (intent-classification), not for embed_text() calls
    # made by vector_search.find_similar_mappings() for HITL RAG retrieval.
    # Bailing here when AI_REFERENCE_DATASET is blank blocks all remote
    # embedding calls, which is the wrong trade-off.
        
    if embeddings_path and os.path.isfile(embeddings_path):
        try:
            import numpy as np
            vectors = np.load(embeddings_path)
            for ex, vec in zip(examples, vectors):
                ex.vector = vec.tolist()
        except:
            pass
            
    def encode(text: str) -> List[float]:
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
                return data.get("embedding", [])
        except Exception:
            return []

    # If we didn't load from a numpy file, encode each reference example via the API
    # Since this blocks startup, let's just make sure we do it.
    if examples and not examples[0].vector:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            vectors = list(executor.map(encode, [ex.text for ex in examples]))
            for ex, vec in zip(examples, vectors):
                ex.vector = vec
            
    return LoadedEmbedder(
        backend_name="remote-minilm",
        model_version="remote",
        reference_dataset_path=dataset_path,
        examples=examples,
        encode_fn=encode,
    )


def load_embedder() -> LoadedEmbedder:
    model_path = os.getenv("AI_EMBEDDING_MODEL_PATH") or ""
    
    # Use relative resolution so it works both in /app (Docker) and locally
    default_dataset = os.path.join(os.path.dirname(__file__), "..", "..", "ai_reference_dataset.json")
    dataset_path = os.getenv("AI_REFERENCE_DATASET") or default_dataset
    
    embeddings_path = os.getenv("AI_REFERENCE_EMBEDDINGS") or None

    remote_url = os.getenv("AI_EMBEDDING_REMOTE_URL") or ""
    if remote_url:
        api_key = os.getenv("AI_REMOTE_API_KEY", "")
        timeout = float(os.getenv("AI_REMOTE_TIMEOUT_SECONDS", "10.0"))
        loaded = _try_load_remote_embedder(remote_url, api_key, timeout, dataset_path, embeddings_path)
        if loaded is not None:
            return loaded

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

    if loaded.encode_fn is not None:
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
