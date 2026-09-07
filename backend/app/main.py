import logging
from contextlib import asynccontextmanager

from dotenv import load_dotenv
load_dotenv(".env", override=True)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.ai.model_registry import initialize as init_ai_registry
from app.db import init_db
from app.routers import (
    ai, compliance, devices, evidence, knowledge, scans, training,
    topology, schedules, network_scan, audit, advanced_drift,
    change_request, compliance_baselines, config_search,
    alerts, credentials, datasets, device_gateway, drift,
    exceptions, system_health, training_jobs, streaming, gns3
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tightened via reverse proxy / Keycloak in production deployment
    allow_credentials=True,
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