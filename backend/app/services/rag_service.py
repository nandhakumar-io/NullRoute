"""Retrieval-Augmented-Generation scaffold for the dashboard's "Ask
NetSecAuditor" chat panel.

Today this runs a lightweight, dependency-free lexical retriever (TF
overlap + a couple of boosts) over `RagDocument` rows built from the
platform's own data -- findings, devices, network-group Batfish results,
and anything manually ingested. It deliberately returns an *extractive*
answer (the most relevant snippets, cited) rather than a generated one,
because there's no LLM call wired in yet.

To upgrade to real RAG later, only two functions need new internals, not a
new call path:
  - `search()`      -> swap the lexical scoring for cosine similarity over
                        `RagDocument.embedding` (populate it via an
                        embeddings API in `index_document`), e.g. pgvector.
  - `answer_query()` -> replace `_extractive_answer()` with a call to an
                        LLM, passing the same retrieved `search()` results
                        as context. The router, models, and query log are
                        already shaped for that swap.
"""
from __future__ import annotations

import logging
import re
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.db import (BatfishQuestion, Device, Finding, NetworkGroup,
                            RagDocument, RagQueryLog, Scan)

logger = logging.getLogger("rag_service")

_STOPWORDS = {
    "the", "a", "an", "is", "are", "was", "were", "of", "to", "in", "on", "for",
    "and", "or", "what", "which", "how", "does", "do", "did", "has", "have",
    "with", "this", "that", "it", "as", "be", "any", "my", "our", "we", "you",
    "at", "by", "from", "there", "us", "please", "show", "tell", "me",
}


def _stem(word: str) -> str:
    """Very small suffix strip so "findings" matches "finding", "devices"
    matches "device", etc. Not a real stemmer (no Porter rules) -- just
    enough to stop plural/singular mismatches from tanking lexical overlap,
    which was silently starving the "Ask NetSecAuditor" panel of hits it
    should have found."""
    for suffix in ("ies",):
        if word.endswith(suffix) and len(word) > 4:
            return word[: -len(suffix)] + "y"
    for suffix in ("es", "s"):
        if word.endswith(suffix) and len(word) > 3 and not word.endswith("ss"):
            return word[: -len(suffix)]
    return word


def _tokenize(text: str) -> List[str]:
    words = re.findall(r"[a-z0-9][a-z0-9._-]*", (text or "").lower())
    return [_stem(w) for w in words if w not in _STOPWORDS and len(w) > 1]


def upsert_document(db: Session, tenant_id: str, source_type: str, source_id: Optional[str],
                     title: str, content: str, doc_metadata: Optional[Dict[str, Any]] = None) -> RagDocument:
    """Create or refresh the RagDocument for a given (source_type, source_id).
    Called from reindex_tenant() today; call this directly from other
    services (e.g. right after a scan completes, or a manual doc upload)
    to keep the corpus current incrementally instead of full re-scans."""
    existing = None
    if source_id:
        existing = db.query(RagDocument).filter(
            RagDocument.tenant_id == tenant_id, RagDocument.source_type == source_type,
            RagDocument.source_id == source_id,
        ).first()
    if existing:
        existing.title = title
        existing.content = content
        existing.doc_metadata = doc_metadata
        existing.updated_at = datetime.utcnow()
        db.commit()
        return existing
    doc = RagDocument(
        tenant_id=tenant_id, source_type=source_type, source_id=source_id,
        title=title, content=content, doc_metadata=doc_metadata,
    )
    db.add(doc)
    db.commit()
    db.refresh(doc)
    return doc


def reindex_tenant(db: Session, tenant_id: str, limit_per_type: int = 500) -> Dict[str, int]:
    """Rebuild the RAG corpus for a tenant from current DB state: recent
    failing findings, all devices, and network-group Batfish results.
    Cheap enough to run on demand (button in the UI) rather than needing a
    background job for the MVP; swap for incremental upserts once corpus
    size makes a full rebuild too slow."""
    counts = {"findings": 0, "devices": 0, "network_groups": 0}

    findings = (
        db.query(Finding)
        .join(Scan, Scan.id == Finding.scan_id)
        .filter(Scan.tenant_id == tenant_id, Finding.result == "FAIL")
        .order_by(Finding.created_at.desc())
        .limit(limit_per_type)
        .all()
    )
    for f in findings:
        content = (
            f"Finding {f.control_id} ({f.framework}) severity {f.severity}: {f.title}. "
            f"Expected: {f.expected_value}. Actual: {f.actual_value}. "
            f"Evidence: {f.evidence_line or 'n/a'}. Remediation: {f.remediation or 'n/a'}."
        )
        upsert_document(
            db, tenant_id, "finding", f.id, title=f"{f.control_id}: {f.title}", content=content,
            doc_metadata={"severity": f.severity, "framework": f.framework, "scan_id": f.scan_id},
        )
        counts["findings"] += 1

    devices = db.query(Device).filter(Device.tenant_id == tenant_id).limit(limit_per_type).all()
    for d in devices:
        content = (
            f"Device {d.hostname or d.id}, vendor {d.vendor}, management address {d.management_address}, "
            f"last compliance score {d.last_compliance_score}. Tags: {d.tags}."
        )
        upsert_document(
            db, tenant_id, "device", d.id, title=f"Device: {d.hostname or d.id}", content=content,
            doc_metadata={"vendor": d.vendor, "compliance_score": d.last_compliance_score},
        )
        counts["devices"] += 1

    groups = db.query(NetworkGroup).filter(NetworkGroup.tenant_id == tenant_id).limit(limit_per_type).all()
    for g in groups:
        result = g.last_batfish_result or {}
        checks = result.get("reachability_checks", [])
        failing = [c for c in checks if c.get("status") == "BATFISH_FAIL"]
        content = (
            f"Network group '{g.name}' last Batfish scan status: {g.last_batfish_status or 'never run'}. "
            f"{len(failing)} failing check(s) out of {len(checks)}. "
            + " ".join(f"[{c.get('control_id')}] {c.get('title')}: {c.get('detail')}" for c in failing[:10])
        )
        upsert_document(
            db, tenant_id, "batfish_group", g.id, title=f"Network group: {g.name}", content=content,
            doc_metadata={"status": g.last_batfish_status, "failing_count": len(failing)},
        )
        counts["network_groups"] += 1

    return counts


def index_scan_results(db: Session, tenant_id: str, scan: "Scan", device: "Device") -> Dict[str, int]:
    """Incremental counterpart to reindex_tenant(): upsert just the
    documents affected by one freshly-completed scan (the device, plus any
    of *its* still-open failing findings) instead of rescanning the whole
    tenant. Called from pipeline.run_pipeline() right after a scan
    finishes, so newly-discovered findings are answerable in the RAG chat
    within the same request that created them -- no manual reindex click
    needed."""
    counts = {"findings": 0, "devices": 0}

    if device is not None:
        content = (
            f"Device {device.hostname or device.id}, vendor {device.vendor}, "
            f"management address {device.management_address}, "
            f"last compliance score {device.last_compliance_score}. Tags: {device.tags}."
        )
        upsert_document(
            db, tenant_id, "device", device.id, title=f"Device: {device.hostname or device.id}", content=content,
            doc_metadata={"vendor": device.vendor, "compliance_score": device.last_compliance_score},
        )
        counts["devices"] += 1

    findings = db.query(Finding).filter(Finding.scan_id == scan.id, Finding.result == "FAIL").all()
    for f in findings:
        content = (
            f"Finding {f.control_id} ({f.framework}) severity {f.severity}: {f.title}. "
            f"Expected: {f.expected_value}. Actual: {f.actual_value}. "
            f"Evidence: {f.evidence_line or 'n/a'}. Remediation: {f.remediation or 'n/a'}."
        )
        upsert_document(
            db, tenant_id, "finding", f.id, title=f"{f.control_id}: {f.title}", content=content,
            doc_metadata={"severity": f.severity, "framework": f.framework, "scan_id": f.scan_id},
        )
        counts["findings"] += 1

    return counts


def search(db: Session, tenant_id: str, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
    """Lexical retrieval: score every tenant document by token-overlap TF
    against the query, with a small boost for title matches. Deterministic
    and dependency-free -- the intended swap point for embedding-based
    cosine similarity (see module docstring)."""
    query_tokens = _tokenize(query)
    if not query_tokens:
        return []
    query_counter = Counter(query_tokens)

    docs = db.query(RagDocument).filter(RagDocument.tenant_id == tenant_id).all()
    scored: List[tuple] = []
    for doc in docs:
        content_tokens = _tokenize(doc.content)
        title_tokens = set(_tokenize(doc.title))
        if not content_tokens:
            continue
        content_counter = Counter(content_tokens)
        overlap_score = sum(min(query_counter[t], content_counter[t]) for t in query_counter)
        title_boost = 2 * sum(1 for t in query_tokens if t in title_tokens)
        score = overlap_score + title_boost
        if score > 0:
            scored.append((score, doc))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [
        {
            "document_id": doc.id, "source_type": doc.source_type, "source_id": doc.source_id,
            "title": doc.title, "content": doc.content, "metadata": doc.doc_metadata, "score": score,
        }
        for score, doc in scored[:top_k]
    ]


def _extractive_answer(question: str, hits: List[Dict[str, Any]]) -> str:
    if not hits:
        return (
            "I couldn't find anything in the indexed compliance data relevant to that question. "
            "Try reindexing (a scan/device may not be indexed yet) or rephrase the question."
        )
    lines = [f"Based on {len(hits)} relevant record(s) in your compliance data:"]
    for h in hits:
        lines.append(f"- [{h['source_type']}] {h['title']}: {h['content'][:280]}")
    return "\n".join(lines)


async def answer_query(db: Session, tenant_id: str, question: str, asked_by: Optional[str] = None,
                        top_k: int = 5) -> Dict[str, Any]:
    """The single entry point the /api/rag/query endpoint calls. Returns an
    extractive answer + cited sources today; once an LLM is wired in,
    replace the `_extractive_answer(question, hits)` call below with a
    generation call fed `hits` as context -- everything else (retrieval,
    logging) stays the same."""
    hits = search(db, tenant_id, question, top_k=top_k)
    if not hits and db.query(RagDocument.id).filter(RagDocument.tenant_id == tenant_id).first() is None:
        # Nothing has ever been indexed for this tenant (fresh install, or a
        # tenant that predates incremental indexing). Rather than surfacing
        # the generic "try reindexing" fallback, do the reindex ourselves
        # once and retry -- this is what makes the first question in a new
        # session actually answerable instead of always needing a manual
        # button click first.
        try:
            reindex_tenant(db, tenant_id)
            hits = search(db, tenant_id, question, top_k=top_k)
        except Exception:
            logger.exception("auto-reindex-on-empty-corpus failed for tenant %s", tenant_id)
    answer = _extractive_answer(question, hits)

    log = RagQueryLog(
        tenant_id=tenant_id, question=question, answer=answer,
        source_document_ids=[h["document_id"] for h in hits], asked_by=asked_by,
    )
    db.add(log)
    db.commit()
    db.refresh(log)

    return {"query_id": log.id, "answer": answer, "sources": hits}
