import logging
import asyncio
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, BackgroundTasks, HTTPException, Depends
from pydantic import BaseModel, Field

from app import events
from app.services import pipeline
from app.db import get_db
from app.models.db import Scan

logger = logging.getLogger("streaming")
router = APIRouter(prefix="/api/streaming", tags=["Streaming & Events"])

class StreamingPayload(BaseModel):
    device_id: str
    raw_config: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_source: str = Field(description="e.g. syslog, ebpf, kafka")

async def _process_stream(payload: StreamingPayload, db_session) -> None:
    """
    Background worker that runs the compute-intensive pipeline synchronously/asynchronously 
    without holding the lightweight HTTP connection open.
    """
    logger.info(f"Processing background stream event from {payload.event_source} for {payload.device_id}")
    try:
        # Publish NATS observability metric so metrics dashboards know a live event is evaluating
        await events.publish("streaming.event.evaluating", {
            "device_id": payload.device_id,
            "event_source": payload.event_source,
            "timestamp": payload.timestamp.isoformat()
        })
        
        new_scan = Scan(device_id=payload.device_id, framework="ALL")
        db_session.add(new_scan)
        db_session.commit()
        
        # Fire off the heavy intent parsing + batfish + OPA + blockchain pipeline!
        await pipeline.run_pipeline(
            db=db_session,
            scan=new_scan,
            raw_text=payload.raw_config,
            framework="ALL"
        )
        
        await events.publish("streaming.event.completed", {
            "device_id": payload.device_id,
            "status": "success"
        })
    except Exception as e:
        logger.error(f"Streaming background pipeline failed: {str(e)}")
        await events.publish("streaming.event.failed", {
            "device_id": payload.device_id,
            "error": str(e)
        })

@router.post("/syslog")
async def ingest_syslog(payload: StreamingPayload, background_tasks: BackgroundTasks, db=Depends(get_db)):
    """Receives asynchronous configurations from network syslog traps."""
    payload.event_source = "syslog"
    await events.publish("streaming.event.received", {"device_id": payload.device_id, "source": "syslog"})
    background_tasks.add_task(_process_stream, payload, db)
    return {"status": "accepted", "message": "Syslog config drift intercepted in real-time. Background evaluation started."}

@router.post("/ebpf")
async def ingest_ebpf(payload: StreamingPayload, background_tasks: BackgroundTasks, db=Depends(get_db)):
    """Receives ultra low-latency telemetry from deployed eBPF linux agents or k8s Sidecars."""
    payload.event_source = "ebpf"
    await events.publish("streaming.event.received", {"device_id": payload.device_id, "source": "ebpf"})
    background_tasks.add_task(_process_stream, payload, db)
    return {"status": "accepted", "message": "eBPF real-time intent interception acknowledged. AI processing spawned."}
