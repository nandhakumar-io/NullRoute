"""Real pgvector-backed semantic retrieval for the CommandMapping knowledge
base (Training Center).

Pipeline:

    CommandMapping -> embedding -> pgvector -> cosine similarity -> similar approved mappings

On PostgreSQL, embeddings are stored in a native `vector(384)` column (see
alembic migration `g1h2i3j4k5l6_pgvector_command_mapping_embeddings.py`)
with an ivfflat cosine index, and retrieval uses pgvector's `<=>`
cosine-distance operator directly via a small parameterized raw-SQL query.
Raw SQL (rather than the ORM's ".cosine_distance()" comparator) is used
deliberately: the `embedding` column is declared as generic `JSON` at the
ORM level so the exact same model still works unmodified against SQLite
(local/offline dev + tests, see app/db.py) -- Postgres-only behavior lives
here, explicitly, instead of in a dialect-conditional ORM column type.

On SQLite (no pgvector extension), this degrades to an in-process cosine
similarity over the JSON-stored float list -- same math, same ranking,
just without the index -- and, if no embedding was ever generated for a
row (e.g. rows created before this feature existed), to token overlap.
Every result reports which of the three it actually used via `backend`,
so nothing is silently misrepresented as a real vector search.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.ai import model_registry

EMBEDDING_DIM = 384


def embed_text(text_in: str) -> Optional[List[float]]:
    """Encodes `text_in` with whatever embedder is currently loaded --
    local MiniLM, a remote MiniLM inference endpoint (AI_EMBEDDING_REMOTE_URL,
    see app/ai/embeddings.py), or neither, in which case this returns None
    and callers fall back to token-overlap similarity."""
    registry = model_registry.get_registry()
    if not registry.enabled or registry.embedder is None:
        return None
    embedder = registry.embedder
    if embedder.backend_name not in ("minilm", "minilm-remote", "remote-minilm") or embedder.encode_fn is None:
        return None
    try:
        return embedder.encode_fn(text_in)
    except Exception:
        return None


def _tokens(s: Optional[str]) -> set:
    return set(re.findall(r"[a-z0-9]+", (s or "").lower()))


def _cosine(a: List[float], b: List[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(y * y for y in b) ** 0.5
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def store_embedding(db: Session, mapping_id: str, vector: Optional[List[float]]) -> bool:
    """Persists `vector` for a CommandMapping row. Returns True iff a
    vector was actually written -- callers must not report the embedding as
    updated when this returns False (e.g. no embedder was loaded and
    embed_text() returned None).

    On Postgres this writes through an explicit `CAST(:vec AS vector(384))`
    via raw SQL, so the physical column (a real pgvector `vector`, per the
    migration) is populated correctly regardless of how the ORM's generic
    JSON column type would otherwise bind it. On SQLite it's a normal
    ORM-shaped JSON list write.
    """
    if vector is None or not mapping_id:
        return False
    bind = db.get_bind()
    if bind.dialect.name == "postgresql":
        db.execute(
            text(f"UPDATE command_mappings SET embedding = CAST(:vec AS vector({EMBEDDING_DIM})) WHERE id = :id"),
            {"vec": json.dumps(vector), "id": mapping_id},
        )
    else:
        from app.models.db import CommandMapping
        row = db.get(CommandMapping, mapping_id)
        if row is not None:
            row.embedding = vector
    return True


def _row_dict(r: Dict[str, Any], similarity: float, backend: str) -> Dict[str, Any]:
    return {
        "id": r["id"],
        "vendor": r["vendor"],
        "raw_command_pattern": r["raw_command_pattern"],
        "normalized_parameter": r["normalized_parameter"],
        "example_value": r["example_value"],
        "confidence": r["confidence"],
        "status": r["status"],
        "model_version": r.get("model_version"),
        "similarity": round(float(similarity), 4),
        "backend": backend,
    }


def find_similar_mappings(
    db: Session,
    tenant_id: Optional[str],
    query_text: str,
    vendor: Optional[str] = None,
    status: str = "approved",
    top_k: int = 5,
    query_vector: Optional[List[float]] = None,
) -> List[Dict[str, Any]]:
    """CommandMapping -> embedding -> pgvector -> cosine similarity ->
    similar `status` mappings, scoped to `tenant_id` (plus tenant-agnostic
    seeded mappings, tenant_id IS NULL) and optionally `vendor` -- same
    tenant-isolation boundary as every other CommandMapping query in this
    codebase (Phase 5)."""
    if query_vector is None:
        query_vector = embed_text(query_text)
    bind = db.get_bind()

    if query_vector and bind.dialect.name == "postgresql":
        where = ["status = :status", "(tenant_id = :tenant_id OR tenant_id IS NULL)", "embedding IS NOT NULL"]
        params: Dict[str, Any] = {
            "status": status, "tenant_id": tenant_id, "top_k": top_k,
            "vec": json.dumps(query_vector),
        }
        if vendor:
            where.append("vendor = :vendor")
            params["vendor"] = vendor

        sql = text(f"""
            SELECT id, vendor, raw_command_pattern, normalized_parameter, example_value,
                   confidence, status, model_version,
                   1 - (embedding <=> CAST(:vec AS vector({EMBEDDING_DIM}))) AS similarity
            FROM command_mappings
            WHERE {' AND '.join(where)}
            ORDER BY embedding <=> CAST(:vec AS vector({EMBEDDING_DIM}))
            LIMIT :top_k
        """)
        rows = db.execute(sql, params).mappings().all()
        return [_row_dict(dict(r), r["similarity"], "pgvector-cosine") for r in rows]

    # SQLite (no pgvector extension) or no embedder loaded -- rank the same
    # candidate set in Python instead. Still real cosine similarity when we
    # have vectors to compare; only falls further back to token overlap for
    # rows that predate embedding generation.
    from app.models.db import CommandMapping

    q = db.query(CommandMapping).filter(CommandMapping.status == status).filter(
        (CommandMapping.tenant_id == tenant_id) | (CommandMapping.tenant_id.is_(None))
    )
    if vendor:
        q = q.filter(CommandMapping.vendor == vendor)
    candidates = q.limit(500).all()  # bounded: this is a fallback path, not meant for huge fleets

    scored: List[tuple] = []
    if query_vector is not None:
        for c in candidates:
            if isinstance(c.embedding, list) and c.embedding:
                scored.append((_cosine(query_vector, c.embedding), c, "cosine-python-fallback"))
    if not scored:
        q_tokens = _tokens(query_text)
        for c in candidates:
            c_tokens = _tokens(c.raw_command_pattern)
            union = len(q_tokens | c_tokens) or 1
            scored.append((len(q_tokens & c_tokens) / union, c, "token-overlap-fallback"))

    scored.sort(key=lambda t: t[0], reverse=True)
    return [
        _row_dict({
            "id": c.id, "vendor": c.vendor, "raw_command_pattern": c.raw_command_pattern,
            "normalized_parameter": c.normalized_parameter, "example_value": c.example_value,
            "confidence": c.confidence, "status": c.status, "model_version": c.model_version,
        }, sim, backend)
        for sim, c, backend in scored[:top_k]
    ]