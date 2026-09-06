"""Device Gateway observability (Part 1 "DEVICE GATEWAY OBSERVABILITY").

Plain in-memory counters, same lightweight style as
app/services/observability.py's counters. Never records credentials,
command output, or anything else that could leak secret material -- only
counts and durations, keyed by coarse dimensions (protocol, outcome).
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any, Dict

_lock = threading.Lock()
_jobs_received = 0
_jobs_completed = 0
_jobs_failed = 0
_device_connection_failures = 0
_retry_count = 0
_active_jobs = 0
_protocol_usage: Dict[str, int] = defaultdict(int)
_durations_ms: list = []


def record_job_received() -> None:
    global _jobs_received, _active_jobs
    with _lock:
        _jobs_received += 1
        _active_jobs += 1


def record_job_completed(protocol: str, duration_ms: float) -> None:
    global _jobs_completed, _active_jobs
    with _lock:
        _jobs_completed += 1
        _active_jobs = max(0, _active_jobs - 1)
        _protocol_usage[protocol] += 1
        _durations_ms.append(duration_ms)


def record_job_failed(protocol: str, duration_ms: float) -> None:
    global _jobs_failed, _active_jobs
    with _lock:
        _jobs_failed += 1
        _active_jobs = max(0, _active_jobs - 1)
        _protocol_usage[protocol] += 1
        _durations_ms.append(duration_ms)


def record_device_connection_failure() -> None:
    global _device_connection_failures
    with _lock:
        _device_connection_failures += 1


def record_retry() -> None:
    global _retry_count
    with _lock:
        _retry_count += 1


def snapshot() -> Dict[str, Any]:
    with _lock:
        avg = round(sum(_durations_ms) / len(_durations_ms), 2) if _durations_ms else 0.0
        return {
            "jobs_received": _jobs_received,
            "jobs_completed": _jobs_completed,
            "jobs_failed": _jobs_failed,
            "device_connection_failures": _device_connection_failures,
            "average_execution_time_ms": avg,
            "protocol_usage": dict(_protocol_usage),
            "retry_count": _retry_count,
            "active_jobs": _active_jobs,
        }