import asyncio
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
logger = logging.getLogger("app.main")

# RUN_EMBEDDED_WORKERS -- every background worker (scheduled audits, HITL
# training jobs, metrics polling, vuln sync, evidence verification, network
# scans) is designed to run as its own long-lived process (see the docstrings
# in app/workers/*.py and the dedicated services in docker-compose.yml).
# That's correct for docker-compose, but local/dev runs of
# `uvicorn app.main:app --reload` (backend/run.sh) never start those
# containers, so nothing ever executed: schedules and training jobs sat
# QUEUED forever even though the API said everything worked. Default this ON
# so a single `uvicorn`/`run.sh` process is fully functional out of the box;
# docker-compose.yml sets RUN_EMBEDDED_WORKERS=false on the `backend` service
# so the dedicated worker containers there are the only ones running each
# loop (never both at once).
RUN_EMBEDDED_WORKERS = os.getenv("RUN_EMBEDDED_WORKERS", "true").lower() == "true"

_embedded_worker_tasks: list[asyncio.Task] = []


def _start_embedded_workers() -> None:
    if not RUN_EMBEDDED_WORKERS:
        logger.info("RUN_EMBEDDED_WORKERS=false -- expecting dedicated worker containers/processes.")
        return

    from app.workers import (
        scheduler_worker, training_worker, metrics_poller_worker,
        vuln_sync_worker, evidence_verification_worker, network_scan_worker,
    )

    # Each of these is the exact same loop function the standalone
    # `python -m app.workers.X` entrypoint runs -- no second implementation.
    targets = [
        ("scheduler", scheduler_worker._loop),
        ("training", training_worker.main),
        ("metrics-poller", metrics_poller_worker._loop),
        ("vuln-sync", vuln_sync_worker._loop),
        ("evidence-verification", evidence_verification_worker._loop),
        ("network-scan", network_scan_worker._loop),
    ]
    for name, coro_fn in targets:
        async def _guarded(fn=coro_fn, label=name) -> None:
            try:
                await fn()
            except Exception:  # noqa: BLE001 - one worker crashing must never take down the API
                logger.exception("Embedded worker %s crashed", label)

        task = asyncio.create_task(_guarded(), name=f"embedded-worker-{name}")
        _embedded_worker_tasks.append(task)
    logger.info("Started %d embedded background workers in-process: %s",
                len(_embedded_worker_tasks), ", ".join(t.get_name() for t in _embedded_worker_tasks))


async def _stop_embedded_workers() -> None:
    for task in _embedded_worker_tasks:
        task.cancel()
    for task in _embedded_worker_tasks:
        try:
            await task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
    _embedded_worker_tasks.clear()


def _reconcile_scans_on_startup() -> None:
    """Scan pipelines are in-process tasks, so a crash / hot reload / deploy
    silently kills them and leaves their rows "running" (or "stopping")
    forever. Move those to a resumable STOPPED/PAUSED state. Single-worker
    deployment assumption; set SCAN_RECONCILE_ON_STARTUP=false if you run
    several API workers against one database."""
    if os.environ.get("SCAN_RECONCILE_ON_STARTUP", "true").lower() in ("0", "false", "no"):
        return
    try:
        from app.db import SessionLocal
        from app.services import scan_runner

        db = SessionLocal()
        try:
            scan_runner.reconcile_stale(db, startup=True)
        finally:
            db.close()
    except Exception:  # noqa: BLE001 - never block startup on repair
        logging.getLogger("main").exception("scan reconciliation at startup failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Load the trained-AI models (DistilBERT classifier + MiniLM embedder)
    # exactly once here — never per-request. See app/ai/model_registry.py.
    init_ai_registry()
    _start_embedded_workers()
    _reconcile_scans_on_startup()
    try:
        yield
    finally:
        # Cancel in-flight scan pipelines first so each persists a
        # resumable STOPPED state instead of being left "running" forever.
        try:
            from app.services import scan_runner
            await scan_runner.shutdown()
        except Exception:  # noqa: BLE001
            logging.getLogger("main").exception("scan_runner shutdown failed")
        await _stop_embedded_workers()


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