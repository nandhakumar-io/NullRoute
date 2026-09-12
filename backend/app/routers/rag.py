"""Endpoints backing the dashboard's "Ask NetSecAuditor" chat panel. See
services/rag_service.py for the retrieval design and the intended
embedding/LLM upgrade path.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth.dependencies import (CurrentUser, get_current_tenant,
                                    get_current_user)
from app.db import get_db
from app.models.db import RagDocument, RagQueryLog
from app.services import rag_service

router = APIRouter(prefix="/api/rag", tags=["rag"], dependencies=[Depends(get_current_user)])


class QueryRequest(BaseModel):
    question: str
    top_k: int = 5


class SourceOut(BaseModel):
    document_id: str
    source_type: str
    source_id: Optional[str] = None
    title: str
    content: str
    metadata: Optional[Dict[str, Any]] = None
    score: float


class QueryResponse(BaseModel):
    query_id: str
    answer: str
    sources: List[SourceOut]


class ManualDocCreate(BaseModel):
    title: str
    content: str


@router.post("/query", response_model=QueryResponse)
async def query_rag(body: QueryRequest, db: Session = Depends(get_db),
                     tenant_id: str = Depends(get_current_tenant), user: CurrentUser = Depends(get_current_user)):
    if not body.question or not body.question.strip():
        raise HTTPException(400, "question must not be empty")
    result = await rag_service.answer_query(
        db, tenant_id, body.question.strip(),
        asked_by=getattr(user, "id", None) or getattr(user, "username", None),
        top_k=max(1, min(body.top_k, 20)),
    )
    return result


@router.post("/reindex")
def reindex(db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    """Rebuild the RAG corpus from current findings/devices/network-group
    Batfish results for this tenant. Safe to call repeatedly (upserts)."""
    counts = rag_service.reindex_tenant(db, tenant_id)
    return {"reindexed": counts}


@router.post("/documents")
def add_document(body: ManualDocCreate, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    """Manually ingest a document (policy, runbook, past incident notes...)
    into the RAG corpus so the chat can answer questions about it too."""
    doc = rag_service.upsert_document(db, tenant_id, source_type="manual_upload", source_id=None,
                                       title=body.title, content=body.content)
    return {"id": doc.id, "title": doc.title}


@router.get("/documents")
def list_documents(source_type: Optional[str] = None, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    q = db.query(RagDocument).filter(RagDocument.tenant_id == tenant_id)
    if source_type:
        q = q.filter(RagDocument.source_type == source_type)
    docs = q.order_by(RagDocument.updated_at.desc()).limit(200).all()
    return [{"id": d.id, "source_type": d.source_type, "title": d.title, "updated_at": d.updated_at} for d in docs]


@router.get("/history")
def query_history(limit: int = 20, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    logs = db.query(RagQueryLog).filter(RagQueryLog.tenant_id == tenant_id).order_by(
        RagQueryLog.created_at.desc()
    ).limit(min(limit, 100)).all()
    return [{"id": l.id, "question": l.question, "answer": l.answer, "created_at": l.created_at} for l in logs]
