"""Standalone Device Gateway process (Part 1 "NATS" / Part 15 deployment).

Run as its own container (see Dockerfile.gateway / docker-compose service
`device-gateway`), separate from the FastAPI API process, so the API never
holds a direct device connection (Part 1: "The FastAPI backend must NOT
directly connect to network devices once the gateway is implemented").

Uses durable JetStream pull consumers per request subject, one worker
coroutine per subject, with explicit ack/nak semantics:
  - success                    -> ack
  - transient failure (in the
    connectors.execute sense)  -> nak with backoff, retried up to
                                   GATEWAY_MAX_DELIVER times, then routed
                                   to netsec.device.error and terminated
  - validation failure
    (bad signature, replay,
    expired, ...)               -> ack immediately (retrying can't help;
                                    result is published to
                                    netsec.device.error)

No second message broker is introduced; this only adds consumers on the
existing NATS JetStream deployment.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os

from app.db import get_db
from app.gateway import metrics
from app.gateway.envelope import JobEnvelope
from app.gateway.publisher import ERROR_SUBJECT, SUBJECTS
from app.gateway.worker import process_job

logger = logging.getLogger("device_gateway.consumer")

NATS_URL = os.getenv("NATS_URL", "nats://nats:4222")
STREAM_NAME = os.getenv("GATEWAY_STREAM_NAME", "NETSEC_DEVICE")
MAX_DELIVER = int(os.getenv("GATEWAY_MAX_DELIVER", "3"))

# Non-retryable: retrying can never turn these into success.
_TERMINAL_ERROR_CODES = {
    "INVALID_JOB_SIGNATURE", "EXPIRED_JOB", "REPLAYED_JOB", "TENANT_MISMATCH",
    "APPROVAL_REQUIRED", "APPROVAL_INVALID", "DEVICE_NOT_FOUND",
    "MALFORMED_ENVELOPE", "OPERATION_UNSUPPORTED", "REQUESTER_INVALID",
    "PROTOCOL_UNSUPPORTED", "AUTHENTICATION_FAILED",
}

REQUEST_SUBJECTS = sorted({req for req, _res in SUBJECTS.values()})


async def _handle_message(msg) -> None:
    try:
        envelope = JobEnvelope.from_dict(json.loads(msg.data.decode("utf-8")))
    except (ValueError, json.JSONDecodeError) as e:
        logger.warning("Dropping unparseable job message: %s", e)
        await msg.ack()  # can never be retried into validity
        return

    db_gen = get_db()
    db = next(db_gen)
    try:
        result = process_job(db, envelope)
    finally:
        db_gen.close()

    nc = msg._client  # underlying nats.aio.client.Client, already connected
    js = nc.jetstream()

    if result.get("success"):
        _, result_subject = SUBJECTS.get(envelope.operation, (None, None))
        if result_subject:
            await js.publish(result_subject, json.dumps(result, default=str).encode("utf-8"))
        await msg.ack()
        return

    error_code = result.get("error_code")
    if error_code in _TERMINAL_ERROR_CODES or msg.metadata.num_delivered >= MAX_DELIVER:
        await js.publish(ERROR_SUBJECT, json.dumps(result, default=str).encode("utf-8"))
        await msg.ack()
    else:
        metrics.record_retry()
        await msg.nak(delay=min(2 ** msg.metadata.num_delivered, 30))


async def run_consumer() -> None:  # pragma: no cover -- exercised via _handle_message in tests, not a live broker
    import nats

    nc = await nats.connect(NATS_URL)
    js = nc.jetstream()
    await js.add_stream(name=STREAM_NAME, subjects=["netsec.device.>"])

    subs = []
    for subject in REQUEST_SUBJECTS:
        durable = f"gateway-{subject.replace('.', '-')}"
        sub = await js.pull_subscribe(subject, durable=durable, stream=STREAM_NAME)
        subs.append(sub)

    logger.info("Device Gateway consumer started on subjects: %s", REQUEST_SUBJECTS)
    try:
        while True:
            for sub in subs:
                try:
                    msgs = await sub.fetch(batch=1, timeout=1)
                except TimeoutError:
                    continue
                except Exception as e:  # noqa: BLE001 -- one subject's transient error shouldn't kill the loop
                    logger.warning("Fetch error on subject: %s", e)
                    continue
                for msg in msgs:
                    await _handle_message(msg)
    finally:
        await nc.drain()


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run_consumer())