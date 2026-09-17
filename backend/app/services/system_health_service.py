"""Aggregated System Health checks (Phase 11).

Every dependency the platform talks to gets its own best-effort probe here,
reusing each service module's existing `health()`/`health_check()` helper
where one already exists (opa_service, batfish_service, minio_service,
openbao_service, fabric_service) rather than re-implementing the check --
those functions already encode the right timeout/error handling for their
protocol. This module's job is only to:

  1. add the probes that didn't exist yet (Postgres, NATS, Keycloak, the
     Device Gateway consumer process, and the AI registry, wrapped in the
     same shape),
  2. run everything concurrently,
  3. classify each service as CORE (the platform cannot do its job without
     it) or OPTIONAL (an integration that degrades gracefully when absent),
  4. normalize every result to one of the statuses the UI understands:
     HEALTHY / DEGRADED / UNAVAILABLE / DISABLED / ERROR.

A service that is intentionally turned off (its `_ENABLED` flag is false)
is always reported DISABLED, never ERROR -- an operator who hasn't turned
on Fabric/Keycloak/OpenBao yet should not see a red error for something
they never asked to run.
"""
from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy import text

from app.db import engine

STATUS_HEALTHY = "HEALTHY"
STATUS_DEGRADED = "DEGRADED"
STATUS_UNAVAILABLE = "UNAVAILABLE"
STATUS_DISABLED = "DISABLED"
STATUS_ERROR = "ERROR"


@dataclass
class ServiceHealth:
    name: str
    category: str  # "core" | "optional"
    status: str
    latency_ms: Optional[float] = None
    detail: Optional[str] = None
    error: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "name": self.name,
            "category": self.category,
            "status": self.status,
            "latency_ms": self.latency_ms,
            "detail": self.detail,
            "error": self.error,
        }
        d.update(self.extra)
        return d


async def _timed(fn: Callable[[], Any]) -> tuple[Any, float]:
    start = time.monotonic()
    result = fn()
    if asyncio.iscoroutine(result):
        result = await result
    return result, round((time.monotonic() - start) * 1000, 1)


# ---------------------------------------------------------------------------
# Individual probes. Each returns a ServiceHealth and never raises -- any
# exception is caught and turned into an ERROR status so one failing probe
# can never take the whole system-health endpoint down.
# ---------------------------------------------------------------------------

def _check_postgres() -> ServiceHealth:
    start = time.monotonic()
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        latency = round((time.monotonic() - start) * 1000, 1)
        return ServiceHealth("PostgreSQL", "core", STATUS_HEALTHY, latency_ms=latency,
                              detail="Query round-trip succeeded")
    except Exception as e:  # noqa: BLE001
        return ServiceHealth("PostgreSQL", "core", STATUS_UNAVAILABLE, error=str(e))


async def _check_nats() -> ServiceHealth:
    nats_url = os.getenv("NATS_URL", "nats://nats:4222")
    start = time.monotonic()
    try:
        import nats

        nc = await nats.connect(nats_url, connect_timeout=3)
        try:
            js = nc.jetstream()
            stream_name = os.getenv("GATEWAY_STREAM_NAME", "NETSEC_DEVICE")
            extra: Dict[str, Any] = {}
            try:
                info = await js.stream_info(stream_name)
                extra["stream"] = stream_name
                extra["stream_messages"] = info.state.messages
            except Exception:
                # Stream not created yet (gateway never started) -- NATS
                # itself is still reachable, just report that separately.
                extra["stream"] = None
            latency = round((time.monotonic() - start) * 1000, 1)
            return ServiceHealth("NATS JetStream", "core", STATUS_HEALTHY, latency_ms=latency,
                                  detail="Connected", extra=extra)
        finally:
            await nc.close()
    except Exception as e:  # noqa: BLE001
        return ServiceHealth("NATS JetStream", "core", STATUS_UNAVAILABLE, error=str(e))


async def _check_opa() -> ServiceHealth:
    from app.services import opa_service

    result, latency = await _timed(opa_service.health_check)
    if result.get("healthy"):
        return ServiceHealth("OPA Policy Engine", "core", STATUS_HEALTHY,
                              latency_ms=result.get("latency_ms", latency),
                              detail="Authoritative deterministic policy decisions")
    return ServiceHealth("OPA Policy Engine", "core", STATUS_UNAVAILABLE,
                          error=result.get("error") or f"HTTP {result.get('status_code')}",
                          detail="Compliance decisions will fail closed (OPA_FAIL_MODE) "
                                 "until this is restored")


async def _check_batfish() -> ServiceHealth:
    from app.services import batfish_service

    result, latency = await _timed(lambda: batfish_service.health_check())
    status = result.get("status")
    if not result.get("enabled", True):
        return ServiceHealth("Batfish", "optional", STATUS_DISABLED,
                              detail="BATFISH_ENABLED=false")
    if status == "reachable":
        return ServiceHealth("Batfish", "optional", STATUS_HEALTHY, latency_ms=latency,
                              detail="Behavioral/reachability analysis available")
    return ServiceHealth("Batfish", "optional", STATUS_UNAVAILABLE, error=result.get("error"))


async def _check_minio() -> ServiceHealth:
    from app.services import minio_service

    result, latency = await _timed(lambda: minio_service.health())
    status = result.get("status")
    if status == "disabled":
        return ServiceHealth("MinIO", "optional", STATUS_DISABLED, detail="MINIO_ENABLED=false")
    if status == "available":
        if result.get("object_lock"):
            return ServiceHealth("MinIO", "optional", STATUS_HEALTHY, latency_ms=latency,
                                  detail=f"Bucket: {result.get('bucket')} (Object Lock/WORM enabled)")
        # Reachable and usable, but evidence/reports are being written
        # without the extra WORM tamper-protection layer -- real and worth
        # a yellow flag, not a red one (storage itself is fine).
        return ServiceHealth("MinIO", "optional", STATUS_DEGRADED, latency_ms=latency,
                              detail=f"Bucket: {result.get('bucket')}",
                              error=result.get("object_lock_warning", "Object Lock/WORM not enabled on this bucket"))
    if status == "misconfigured":
        return ServiceHealth("MinIO", "optional", STATUS_ERROR,
                              error=result.get("reason", "Missing MINIO_ACCESS_KEY/MINIO_SECRET_KEY"))
    return ServiceHealth("MinIO", "optional", STATUS_UNAVAILABLE, error=result.get("error"))


async def _check_openbao() -> ServiceHealth:
    from app.services import openbao_service

    result, latency = await _timed(lambda: openbao_service.health())
    status = result.get("status")
    if status == "disabled":
        return ServiceHealth("OpenBao", "core", STATUS_DISABLED, detail="OPENBAO_ENABLED=false")
    if status == "available":
        return ServiceHealth("OpenBao", "core", STATUS_HEALTHY, latency_ms=latency,
                              detail="Credential store reachable")
    if status == "misconfigured":
        return ServiceHealth("OpenBao", "core", STATUS_ERROR, error=result.get("reason"))
    return ServiceHealth("OpenBao", "core", STATUS_UNAVAILABLE, error=result.get("error"),
                          detail="Device credential retrieval will fail until restored")


async def _check_keycloak() -> ServiceHealth:
    from app.auth.jwt import AUTH_ENABLED, KEYCLOAK_ISSUER

    if not AUTH_ENABLED:
        return ServiceHealth("Keycloak", "optional", STATUS_DISABLED,
                              detail="AUTH_ENABLED=false (demo mode)")
    if not KEYCLOAK_ISSUER:
        return ServiceHealth("Keycloak", "optional", STATUS_ERROR,
                              error="AUTH_ENABLED=true but KEYCLOAK_ISSUER is not set")
    start = time.monotonic()
    try:
        import httpx

        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{KEYCLOAK_ISSUER}/.well-known/openid-configuration")
        latency = round((time.monotonic() - start) * 1000, 1)
        if resp.status_code == 200:
            return ServiceHealth("Keycloak", "optional", STATUS_HEALTHY, latency_ms=latency,
                                  detail="Realm discovery document reachable")
        return ServiceHealth("Keycloak", "optional", STATUS_UNAVAILABLE,
                              error=f"HTTP {resp.status_code}")
    except Exception as e:  # noqa: BLE001
        return ServiceHealth("Keycloak", "optional", STATUS_UNAVAILABLE, error=str(e))


async def _check_fabric() -> ServiceHealth:
    from app.services import fabric_service

    result = await fabric_service.health_check()
    if not result.get("enabled"):
        return ServiceHealth("Hyperledger Fabric", "optional", STATUS_DISABLED,
                              detail="FABRIC_ENABLED=false")
    if result.get("healthy"):
        return ServiceHealth("Hyperledger Fabric", "optional", STATUS_HEALTHY,
                              detail="Evidence anchoring available")
    return ServiceHealth("Hyperledger Fabric", "optional", STATUS_UNAVAILABLE,
                          error=result.get("error"),
                          detail="Evidence will be recorded off-chain only until restored")


async def _check_device_gateway() -> ServiceHealth:
    """The Device Gateway is a standalone NATS consumer process with no HTTP
    port (see docker-compose `device-gateway` / app.gateway.consumer), so it
    can't be probed directly. Best available signal without inventing one:
    whether its JetStream stream + durable consumers exist and NATS reports
    them attached. This proves the gateway has registered itself at least
    once; it is NOT a live per-second liveness check, and is reported as
    such rather than a plain up/down to avoid overclaiming."""
    nats_url = os.getenv("NATS_URL", "nats://nats:4222")
    stream_name = os.getenv("GATEWAY_STREAM_NAME", "NETSEC_DEVICE")
    try:
        import nats

        nc = await nats.connect(nats_url, connect_timeout=3)
        try:
            js = nc.jetstream()
            try:
                await js.stream_info(stream_name)
            except Exception:
                return ServiceHealth("Device Gateway", "core", STATUS_UNAVAILABLE,
                                      detail=f"'{stream_name}' stream not found -- the gateway "
                                             "process has not registered any consumers yet")
            consumers = await js.consumers_info(stream_name)
            if not consumers:
                return ServiceHealth("Device Gateway", "core", STATUS_UNAVAILABLE,
                                      detail="Stream exists but has no registered consumers")
            pending = sum(c.num_pending for c in consumers)
            return ServiceHealth(
                "Device Gateway", "core", STATUS_HEALTHY,
                detail=f"{len(consumers)} durable consumer(s) registered on {stream_name}",
                extra={"consumers": len(consumers), "pending_jobs": pending},
            )
        finally:
            await nc.close()
    except Exception as e:  # noqa: BLE001
        return ServiceHealth("Device Gateway", "core", STATUS_UNAVAILABLE, error=str(e))


async def _check_ai() -> ServiceHealth:
    """Combined summary kept for backward compatibility with existing
    dashboard consumers of the 'ai' key. Spec section 12 requires the four
    AI pipeline stages to be independently visible, not folded into one
    flag -- see _check_distilbert/_check_minilm/_check_ollama/_check_rag
    below, which are the ones the AI status panel should actually read."""
    from app.ai.model_registry import get_registry

    registry = get_registry()
    if not registry.enabled:
        return ServiceHealth("AI Service", "optional", STATUS_DISABLED, detail="AI_ENABLED=false")
    loaded = registry.classifier is not None and registry.embedder is not None
    if loaded:
        return ServiceHealth("AI Service", "optional", STATUS_HEALTHY,
                              detail=f"{registry.classifier.backend_name} + {registry.embedder.backend_name} loaded")
    if registry.classifier is not None or registry.embedder is not None:
        return ServiceHealth("AI Service", "optional", STATUS_DEGRADED,
                              detail="Only one of classifier/embedder is loaded -- see /api/ai/health for detail")
    return ServiceHealth("AI Service", "optional", STATUS_UNAVAILABLE,
                          detail="Neither model loaded -- see /api/ai/health for detail")


async def _check_distilbert() -> ServiceHealth:
    """Spec section 12: DistilBERT status must be independently exposed --
    it drives intent classification in app/ai/service.py::analyze_command
    and must never be conflated with the embedder or the Ollama/RAG path."""
    from app.ai.model_registry import get_registry

    registry = get_registry()
    if not registry.enabled:
        return ServiceHealth("DistilBERT (intent classifier)", "optional", STATUS_DISABLED, detail="AI_ENABLED=false")
    if registry.classifier is not None:
        return ServiceHealth("DistilBERT (intent classifier)", "optional", STATUS_HEALTHY,
                              detail=f"{registry.classifier.backend_name} loaded")
    return ServiceHealth("DistilBERT (intent classifier)", "optional", STATUS_UNAVAILABLE,
                          detail="Classifier not loaded -- analyze_command() falls back to UNKNOWN/requires_review")


async def _check_minilm() -> ServiceHealth:
    """Spec section 12: MiniLM (semantic embeddings) status, independent of
    DistilBERT and of the pgvector store it feeds."""
    from app.ai.model_registry import get_registry

    registry = get_registry()
    if not registry.enabled:
        return ServiceHealth("MiniLM (embeddings)", "optional", STATUS_DISABLED, detail="AI_ENABLED=false")
    if registry.embedder is not None:
        return ServiceHealth("MiniLM (embeddings)", "optional", STATUS_HEALTHY,
                              detail=f"{registry.embedder.backend_name} loaded")
    return ServiceHealth("MiniLM (embeddings)", "optional", STATUS_UNAVAILABLE,
                          detail="Embedder not loaded -- semantic retrieval falls back to keyword overlap")


async def _check_ollama() -> ServiceHealth:
    """Spec section 12: Ollama status. This is the path
    app/ai/normalize.py::interpret_line degrades away from on failure --
    when this is down, unknown-block interpretation runs the offline
    keyword heuristic and every fact is forced to human review (never a
    silent PASS -- see interpret_line's except-branch)."""
    import httpx

    from app.ai.normalize import LLM_MODEL, OLLAMA_HOST

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{OLLAMA_HOST}/api/tags")
            resp.raise_for_status()
            models = [m.get("name", "") for m in resp.json().get("models", [])]
            if any(LLM_MODEL in m for m in models):
                return ServiceHealth("AI Interpreter (Ollama)", "optional", STATUS_HEALTHY,
                                      detail=f"{LLM_MODEL} available at {OLLAMA_HOST}")
            return ServiceHealth("AI Interpreter (Ollama)", "optional", STATUS_DEGRADED,
                                  detail=f"Ollama reachable but {LLM_MODEL} not pulled -- interpret_line() will degrade per-call")
    except Exception as e:  # noqa: BLE001 -- health probe, never raises to caller
        return ServiceHealth("AI Interpreter (Ollama)", "optional", STATUS_UNAVAILABLE,
                              detail=f"Unreachable at {OLLAMA_HOST}: {e}. Unknown blocks route to offline heuristic + forced human review.")


async def _check_rag() -> ServiceHealth:
    """Spec section 12: RAG/pgvector retrieval status -- distinct from
    Ollama itself. Degrades to in-process cosine/substring match on SQLite
    or when the pgvector extension/index isn't present (see
    services/vector_search.py); that degrade is not silent to the caller,
    but it IS a materially weaker retrieval signal, so it's worth its own
    status line rather than being invisible inside 'postgres'."""
    try:
        from sqlalchemy import text

        from app.db import SessionLocal

        db = SessionLocal()
        try:
            db.execute(text("SELECT 1 FROM pg_extension WHERE extname = 'vector'"))
            row = db.execute(text("SELECT 1 FROM pg_extension WHERE extname = 'vector'")).first()
            if row:
                return ServiceHealth("RAG (pgvector)", "optional", STATUS_HEALTHY, detail="pgvector extension present")
            return ServiceHealth("RAG (pgvector)", "optional", STATUS_DEGRADED,
                                  detail="pgvector extension not found -- retrieval degrades to in-process cosine/substring match")
        finally:
            db.close()
    except Exception as e:  # noqa: BLE001 -- e.g. SQLite backend has no pg_extension catalog
        return ServiceHealth("RAG (pgvector)", "optional", STATUS_DEGRADED,
                              detail=f"Could not verify pgvector extension ({e}) -- assume in-process fallback retrieval")


_PROBES: List[tuple[str, Callable[[], Any]]] = [
    ("postgres", lambda: asyncio.to_thread(_check_postgres)),
    ("nats", _check_nats),
    ("opa", _check_opa),
    ("batfish", _check_batfish),
    ("minio", _check_minio),
    ("openbao", _check_openbao),
    ("keycloak", _check_keycloak),
    ("fabric", _check_fabric),
    ("device_gateway", _check_device_gateway),
    ("ai", _check_ai),
    ("ai_distilbert", _check_distilbert),
    ("ai_minilm", _check_minilm),
    ("ai_ollama", _check_ollama),
    ("ai_rag", _check_rag),
]


async def get_system_health() -> Dict[str, Any]:
    """Runs every probe concurrently and returns the aggregated view the
    System Health page renders. Never raises -- an individual probe
    exception is caught inside that probe; this function only fans out
    and collects."""
    results: Dict[str, ServiceHealth] = {}

    async def _run(key: str, fn: Callable[[], Any]) -> None:
        try:
            outcome = fn()
            if asyncio.iscoroutine(outcome):
                outcome = await outcome
            results[key] = outcome
        except Exception as e:  # noqa: BLE001 -- last-resort guard, probes already self-guard
            results[key] = ServiceHealth(key, "core", STATUS_ERROR, error=str(e))

    await asyncio.gather(*(_run(key, fn) for key, fn in _PROBES))

    services = [results[key].to_dict() for key, _ in _PROBES]
    core = [s for s in services if s["category"] == "core"]
    optional = [s for s in services if s["category"] == "optional"]

    core_down = [s for s in core if s["status"] in (STATUS_UNAVAILABLE, STATUS_ERROR)]
    overall = "HEALTHY" if not core_down else ("DEGRADED" if len(core_down) < len(core) else "UNAVAILABLE")

    return {
        "overall_status": overall,
        "core_services": core,
        "optional_integrations": optional,
        "checked_at": time.time(),
    }