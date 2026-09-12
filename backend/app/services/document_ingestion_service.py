"""Document ingestion service — parses an uploaded compliance-framework
document (PDF/HTML/XCCDF), chunks it by section, and calls the configured
LLM to extract candidate UnifiedControl rows (status=pending_review, so a
human always reviews before they can drive the policy compiler -- see
control_service.submit_review / ControlReview).

LLM backend: reuses OLLAMA_BASE_URL, the same env var already used
elsewhere in this codebase for local LLM inference. When Ollama is
unreachable, this module degrades gracefully to section-header-only
chunking (each detected section becomes a pending_review control with
source_text populated but normalized_description left blank and a
warning surfaced on the job) -- it never fails the whole ingestion.

Parsing libraries (pdfplumber, beautifulsoup4) are soft-imported, matching
this codebase's existing convention for optional heavy dependencies
(see transformers/torch and pysnmp/ncclient/pygnmi in requirements.txt):
the module boots and degrades cleanly without them installed.
"""
from __future__ import annotations

import logging
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy.orm import Session

from app.models.db import DocumentIngestionJob
from app.services import control_service

logger = logging.getLogger("document_ingestion_service")

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_INGESTION_MODEL", os.getenv("OLLAMA_MODEL", "llama3.1"))

try:
    import pdfplumber  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    pdfplumber = None

try:
    from bs4 import BeautifulSoup  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    BeautifulSoup = None

# Matches common framework section headings: "1.1 Ensure that...",
# "AC-17", "SRG-OS-000...", "3.4.2 Password Policy" etc.
_SECTION_HEADER_RE = re.compile(
    r"^(?:\d+(?:\.\d+)*\s+.{3,120}|[A-Z]{2,6}-\d{1,3}(?:\([a-z0-9]+\))?\s+.{3,120}|SRG-[A-Z0-9-]+\s+.{3,120})$",
    re.MULTILINE,
)


# ---------------------------------------------------------------------------
# Extraction: file -> raw text
# ---------------------------------------------------------------------------

def extract_text(path: str, content_type: Optional[str] = None) -> str:
    """Best-effort text extraction across PDF / HTML / XCCDF(XML) / plain
    text. Never raises -- falls back to reading the file as latin-1 bytes
    decoded so ingestion can always proceed to section chunking.
    """
    lower = path.lower()
    try:
        if lower.endswith(".pdf") or (content_type and "pdf" in content_type):
            if pdfplumber is None:
                logger.warning("pdfplumber not installed; falling back to raw byte scan for %s", path)
                return _read_raw(path)
            text_parts = []
            with pdfplumber.open(path) as pdf:
                for page in pdf.pages:
                    text_parts.append(page.extract_text() or "")
            return "\n".join(text_parts)

        if lower.endswith((".html", ".htm")) or (content_type and "html" in content_type):
            raw = _read_raw(path)
            if BeautifulSoup is None:
                logger.warning("beautifulsoup4 not installed; stripping tags with regex for %s", path)
                return re.sub(r"<[^>]+>", "\n", raw)
            soup = BeautifulSoup(raw, "html.parser")
            return soup.get_text("\n")

        if lower.endswith((".xccdf", ".xml")):
            # XCCDF is XML; without a schema-aware parser we still get
            # useful section boundaries by stripping tags but keeping
            # <title>/<rule id=...> hints for downstream chunking.
            raw = _read_raw(path)
            raw = re.sub(r"<title[^>]*>", "\n### ", raw)
            raw = re.sub(r"<Rule id=\"([^\"]+)\"", r"\n### \1", raw)
            return re.sub(r"<[^>]+>", " ", raw)

        return _read_raw(path)
    except Exception:  # noqa: BLE001 - extraction must never crash ingestion
        logger.exception("Text extraction failed for %s; falling back to raw read", path)
        return _read_raw(path)


def _read_raw(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:  # noqa: BLE001
        return ""


# ---------------------------------------------------------------------------
# Chunking: raw text -> sections
# ---------------------------------------------------------------------------

def chunk_by_section(text: str) -> List[Dict[str, str]]:
    """Split text into (heading, body) sections using detected header
    lines. Falls back to one big section if no headers are detected, so a
    document with an unrecognized structure still ingests as a single
    pending_review control rather than failing outright.
    """
    headers = list(_SECTION_HEADER_RE.finditer(text))
    if not headers:
        stripped = text.strip()
        if not stripped:
            return []
        return [{"heading": "Full Document", "body": stripped[:4000]}]

    sections = []
    for i, m in enumerate(headers):
        start = m.start()
        end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        heading = m.group(0).strip()
        body = text[start:end].strip()
        if body:
            sections.append({"heading": heading, "body": body[:4000]})
    return sections


# ---------------------------------------------------------------------------
# LLM extraction: section -> structured control fields
# ---------------------------------------------------------------------------

async def _llm_available() -> bool:
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{OLLAMA_BASE_URL}/api/tags")
            return resp.status_code == 200
    except httpx.HTTPError:
        return False


_EXTRACTION_PROMPT = """You are extracting a single normalized security control from a section of a \
compliance framework document (SCF/UCF/OSCAL/CIS/NIST/DISA-STIG style).

Return ONLY a JSON object with these keys, no markdown fences, no prose:
{{"name": "short control name", "objective": "one sentence describing the security objective", \
"domain": "one of: management, logging, aaa, snmp, password, network, encryption, other", \
"normalized_description": "2-3 sentence vendor-neutral description of what must be configured"}}

Section heading: {heading}
Section text:
{body}
"""


async def extract_control_fields_via_llm(heading: str, body: str) -> Optional[Dict[str, Any]]:
    """Call the configured LLM to extract structured control fields from one
    section. Returns None (never raises) on any failure so the caller can
    fall back to header-only extraction.
    """
    import json as _json

    prompt = _EXTRACTION_PROMPT.format(heading=heading, body=body[:3000])
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False, "format": "json"},
            )
            resp.raise_for_status()
            data = resp.json()
            raw = data.get("response", "")
            parsed = _json.loads(raw)
            if not isinstance(parsed, dict) or "name" not in parsed:
                return None
            return parsed
    except Exception:  # noqa: BLE001 - LLM extraction must never crash ingestion
        logger.warning("LLM extraction failed for section %r", heading, exc_info=True)
        return None


# ---------------------------------------------------------------------------
# Job orchestration
# ---------------------------------------------------------------------------

def create_job(db: Session, tenant_id: str, filename: str, source_path: str, created_by: Optional[str]) -> DocumentIngestionJob:
    job = DocumentIngestionJob(
        tenant_id=tenant_id,
        filename=filename,
        source_path=source_path,
        status="queued",
        created_by=created_by,
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def get_job(db: Session, tenant_id: str, job_id: str) -> Optional[DocumentIngestionJob]:
    return (
        db.query(DocumentIngestionJob)
        .filter(DocumentIngestionJob.tenant_id == tenant_id, DocumentIngestionJob.id == job_id)
        .first()
    )


async def run_ingestion_job(db: Session, job_id: str) -> None:
    """The actual ingestion pipeline, meant to be run as a FastAPI
    BackgroundTask (see routers/document_ingestion.py). Opens its own
    lifecycle against the passed session; the router is responsible for
    handing this a session it doesn't need back.
    """
    job = db.query(DocumentIngestionJob).filter(DocumentIngestionJob.id == job_id).first()
    if not job:
        logger.error("run_ingestion_job: job %s not found", job_id)
        return

    job.status = "parsing"
    job.started_at = datetime.utcnow()
    db.commit()

    try:
        text = extract_text(job.source_path or "", None)
        sections = chunk_by_section(text)
        job.sections_found = len(sections)
        job.status = "extracting"
        db.commit()

        llm_up = await _llm_available()
        job.llm_used = llm_up
        if not llm_up:
            job.warning = (
                "OLLAMA_BASE_URL was unreachable; ingestion stored section headers only. "
                "No AI-extracted control fields -- review and complete each control manually."
            )

        created = 0
        for section in sections:
            fields: Optional[Dict[str, Any]] = None
            if llm_up:
                fields = await extract_control_fields_via_llm(section["heading"], section["body"])

            if fields:
                control_service.create_control(
                    db,
                    job.tenant_id,
                    fields.get("name") or section["heading"][:200],
                    objective=fields.get("objective"),
                    domain=fields.get("domain"),
                    source_text=section["body"],
                    normalized_description=fields.get("normalized_description"),
                    source_document=job.filename,
                    created_by=job.created_by,
                    status="pending_review",
                )
            else:
                # Header-only fallback -- still a real pending_review row,
                # just without AI-normalized fields (RULE: no silent
                # failures -- something is always stored and reviewable).
                control_service.create_control(
                    db,
                    job.tenant_id,
                    section["heading"][:200],
                    source_text=section["body"],
                    source_document=job.filename,
                    created_by=job.created_by,
                    status="pending_review",
                )
            created += 1

        job.controls_created = created
        job.status = "completed"
        job.completed_at = datetime.utcnow()
        db.commit()
    except Exception as exc:  # noqa: BLE001 - job must record failure, not crash the worker/background task
        logger.exception("Ingestion job %s failed", job_id)
        job.status = "failed"
        job.error = str(exc)[:2000]
        job.completed_at = datetime.utcnow()
        db.commit()