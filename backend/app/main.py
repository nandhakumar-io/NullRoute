import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.ai.model_registry import initialize as init_ai_registry
from app.db import init_db
from app.services.telemetry import instrument_app
from app.routers import (ai, alerts, change_request, compliance, credentials, devices,
                          drift, evidence, exceptions, knowledge, scans, schedules, topology, training)

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Load the trained-AI models (DistilBERT classifier + MiniLM embedder)
    # exactly once here — never per-request. See app/ai/model_registry.py.
    init_ai_registry()
    yield


app = FastAPI(
    title="AI-Driven Multi-Vendor Network Security Compliance Auditor",
    description="SIH Problem Statement 26155 — vendor-agnostic config compliance platform.",
    version="0.1.0",
    lifespan=lifespan,
)

# Phase 17 -- HTTP-level tracing. No-op unless OTEL_ENABLED=true and the
# opentelemetry packages are installed (see app/telemetry.py).
instrument_app(app)

# --- CORS (spec section 54: audit CORS) -----------------------------------
# SECURITY FIX: this previously hard-coded allow_origins=["*"] together
# with allow_credentials=True. That combination is a real vulnerability,
# not just a lint warning: per the Fetch/CORS spec a wildcard origin can
# never legitimately be paired with credentialed requests, and Starlette's
# CORSMiddleware handles that pairing by echoing the *actual* request
# Origin header back (rather than the literal "*") whenever
# allow_credentials=True -- which means "*" here doesn't restrict anything
# at all, it grants every origin on the internet permission to make
# authenticated (cookie/Authorization-header-bearing) cross-origin
# requests against this API. Bearer tokens are typically read from
# JavaScript and attached explicitly rather than sent automatically like a
# cookie, which limits real-world exploitability here, but the
# configuration itself is wrong regardless of how it happens to be
# consumed today, and it fails CORS_ENABLED audits.
#
# Fixed by requiring explicit origins via CORS_ALLOWED_ORIGINS (comma-
# separated). Defaults to no allowed origins (same-origin/reverse-proxy
# only) rather than defaulting back to "*". If an operator explicitly
# configures "*" (e.g. a fully public read-only demo), credentials are
# force-disabled so the invalid wildcard+credentials combination can never
# occur, matching what browsers already enforce.
_cors_origins_raw = os.getenv("CORS_ALLOWED_ORIGINS", "").strip()
_cors_origins = [o.strip() for o in _cors_origins_raw.split(",") if o.strip()]
_cors_allow_credentials = True
if not _cors_origins:
    logging.getLogger("main").warning(
        "CORS_ALLOWED_ORIGINS is not set; no cross-origin browser requests will be "
        "permitted (same-origin / reverse-proxy access still works). Set "
        "CORS_ALLOWED_ORIGINS to a comma-separated list of allowed origins for the "
        "frontend's actual origin(s) in a real deployment."
    )
elif _cors_origins == ["*"]:
    logging.getLogger("main").warning(
        "CORS_ALLOWED_ORIGINS=* -- allowing every origin. Disabling allow_credentials "
        "because wildcard-origin + credentialed CORS requests is never a valid "
        "combination (browsers reject it, and permitting it server-side would grant "
        "every origin credentialed access)."
    )
    _cors_allow_credentials = False

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_cors_allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(devices.router)
app.include_router(scans.router)
app.include_router(training.router)
app.include_router(compliance.router)
app.include_router(knowledge.router)
app.include_router(evidence.router)
app.include_router(ai.router)
app.include_router(credentials.router)
app.include_router(topology.router)
app.include_router(drift.router)
app.include_router(schedules.router)
app.include_router(alerts.router)
app.include_router(change_request.router)
app.include_router(exceptions.router)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def root():
    return {
        "service": "compliance-auditor-api",
        "problem_statement": "SIH-26155",
        "docs": "/docs",
    }