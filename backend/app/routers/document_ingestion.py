"""Document ingestion API -- upload a PDF/HTML/XCCDF framework document and
run extraction as a background task, with a polling endpoint for progress.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.auth.dependencies import CurrentUser, get_current_tenant, get_current_user, require_role
from app.db import SessionLocal, get_db
from app.services import document_ingestion_service

router = APIRouter(tags=["document_ingestion"], dependencies=[Depends(get_current_user)])

MANAGE_CONTROLS = require_role("admin", "security_analyst")

MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # 25MB -- framework PDFs (e.g. full DISA STIG guides) can be large
ALLOWED_EXTENSIONS = (".pdf", ".html", ".htm", ".xccdf", ".xml", ".txt")
UPLOAD_DIR = os.getenv("INGESTION_UPLOAD_DIR", "/tmp/document_ingestion")


def _job_dict(job) -> Dict[str, Any]:
    return {
        "id": job.id,
        "filename": job.filename,
        "status": job.status,
        "llm_used": job.llm_used,
        "controls_created": job.controls_created,
        "sections_found": job.sections_found,
        "warning": job.warning,
        "error": job.error,
        "created_by": job.created_by,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
    }


async def _run_job_in_own_session(job_id: str) -> None:
    """BackgroundTasks run after the response is sent, on a different
    async context than the request's `db` dependency -- open a fresh
    session for the job rather than reusing (and potentially closing
    underneath) the request-scoped one, matching how run_pipeline-style
    background work is handled elsewhere in this codebase.
    """
    db = SessionLocal()
    try:
        await document_ingestion_service.run_ingestion_job(db, job_id)
    finally:
        db.close()


@router.post("/api/controls/ingest-document")
async def ingest_document(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    tenant_id: str = Depends(get_current_tenant),
    user: CurrentUser = Depends(get_current_user),
    _auth=Depends(MANAGE_CONTROLS),
):
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(400, f"Unsupported file type {ext!r}; allowed: {', '.join(ALLOWED_EXTENSIONS)}")

    raw_bytes = await file.read()
    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "Document too large (max 25MB)")

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    job = document_ingestion_service.create_job(db, tenant_id, file.filename or "document", "", user.username)

    dest_path = os.path.join(UPLOAD_DIR, f"{job.id}{ext}")
    with open(dest_path, "wb") as f:
        f.write(raw_bytes)
    job.source_path = dest_path
    db.commit()

    background_tasks.add_task(_run_job_in_own_session, job.id)
    return _job_dict(job)


@router.get("/api/controls/ingest-document/{job_id}")
def get_ingestion_status(job_id: str, db: Session = Depends(get_db), tenant_id: str = Depends(get_current_tenant)):
    job = document_ingestion_service.get_job(db, tenant_id, job_id)
    if not job:
        raise HTTPException(404, "Ingestion job not found")
    return _job_dict(job)