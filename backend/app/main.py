import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
# override=False (the default) is deliberate: an already-set environment
# variable -- e.g. DATABASE_URL exported by the shell, set in
# docker-compose, or monkeypatched by a pytest fixture -- must always win
# over whatever is checked into backend/.env. This was previously
# `override=True`, which silently clobbered every test fixture's
# `monkeypatch.setenv("DATABASE_URL", "sqlite:///...")` (set immediately
# before `from app.main import app`) back to backend/.env's real Postgres
# URL. Every "isolated" sqlite-backed test across the suite was actually
# running against the shared Postgres database, causing order-dependent
# failures (e.g. a UNIQUE/dedup check tripping on a row a previous test
# run left behind) that looked like real application bugs.
load_dotenv(".env")

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.ai.model_registry import initialize as init_ai_registry
from app.db import init_db
from app.routers import (
    ai, compliance, devices, evidence, knowledge, scans, training,
    topology, schedules, network_scan, audit, advanced_drift,
    change_request, compliance_baselines, config_search,
    alerts, credentials, datasets, device_gateway, drift,
    exceptions, system_health, training_jobs, streaming, gns3,
    backups, controls, vulnerabilities, document_ingestion, report_verification,
    metrics, event_triggers, topology_groups, rag, custom_controls,
)

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

# CORS_ALLOWED_ORIGINS (spec section 54: audit CORS). A literal "*" can't
# legally be paired with allow_credentials=True per the CORS spec --
# Starlette's CORSMiddleware handles that combination by echoing back
# whatever Origin header the request sent, which silently grants every
# origin on the internet permission to make credentialed requests. This was
# previously hard-coded as allow_origin_regex=".*" + allow_credentials=True,
# which is exactly that unrestricted-wildcard-with-credentials bug (see
# tests/test_cors_configuration.py). Behavior now:
#   - unset / empty  -> no cross-origin access granted at all
#   - "*"            -> wildcard access, but credentials forced OFF
#   - a comma-separated allow-list -> only those origins, WITH credentials
_cors_env = os.environ.get("CORS_ALLOWED_ORIGINS", "").strip()
if _cors_env == "*":
    # Wildcard: grant cross-origin access to all origins, but MUST NOT
    # pair with credentials (CORS spec prohibits it; Starlette echoes back
    # the actual Origin header in that case, silently granting all origins).
    _cors_origins: list[str] = ["*"]
    _cors_credentials = False
elif _cors_env:
    # Explicit allow-list: only those origins, with credentials allowed.
    _cors_origins = [o.strip() for o in _cors_env.split(",") if o.strip()]
    _cors_credentials = True
else:
    # No CORS_ALLOWED_ORIGINS configured -> no cross-origin access at all.
    # Credentials must also be False here: Starlette echoes the request
    # Origin back as allow-origin when credentials=True even with an empty
    # allow_origins list, which defeats the "no cross-origin" intent.
    _cors_origins = []
    _cors_credentials = False

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_cors_credentials,
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
app.include_router(topology.router)
app.include_router(topology_groups.router)
app.include_router(rag.router)
app.include_router(schedules.router)
app.include_router(network_scan.router)
app.include_router(audit.router)
app.include_router(advanced_drift.router)
app.include_router(change_request.router)
app.include_router(compliance_baselines.router)
app.include_router(config_search.router)
app.include_router(alerts.router)
app.include_router(credentials.router)
app.include_router(datasets.router)
app.include_router(device_gateway.router)
app.include_router(drift.router)
app.include_router(exceptions.router)
app.include_router(system_health.router)
app.include_router(training_jobs.router)
app.include_router(streaming.router)
app.include_router(gns3.router)
app.include_router(backups.router)
app.include_router(controls.router)
app.include_router(vulnerabilities.router)
app.include_router(document_ingestion.router)
app.include_router(report_verification.router)
app.include_router(metrics.router)
app.include_router(event_triggers.router)
app.include_router(event_triggers.webhook_router)
app.include_router(custom_controls.router)

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