"""Base verification interface (spec sections 29-34).

pyATS/Genie is OPTIONAL supplemental evidence for post-deployment
verification of Cisco devices. It must never override OPA (authoritative
for compliance) or Batfish (authoritative for modeled network behavior)
-- a verifier's result is recorded alongside the deployment record and
surfaced as additional evidence, nothing more.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.models.db import Device
from app.services.openbao_service import DeviceCredentials

PYATS_UNSUPPORTED = "PYATS_UNSUPPORTED"
PYATS_DISABLED = "PYATS_DISABLED"
PYATS_UNAVAILABLE = "PYATS_UNAVAILABLE"
PYATS_FAILED = "PYATS_FAILED"
PYATS_OK = "PYATS_OK"


@dataclass
class VerificationResult:
    success: bool
    status: str = PYATS_FAILED
    engine: str = "pyats_genie"
    commands_run: List[str] = field(default_factory=list)
    parsed: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration_ms: float = 0.0
    completed_at: datetime = field(default_factory=datetime.utcnow)

    def as_metadata(self) -> Dict[str, Any]:
        """Deployment-record-safe metadata (never credentials)."""
        return {
            "engine": self.engine,
            "status": self.status,
            "commands_run": self.commands_run,
            "parsed": self.parsed,
            "error": self.error,
        }


class BaseVerifier(ABC):
    engine: str = "unknown"

    @abstractmethod
    def verify(self, device: Device, credentials: DeviceCredentials) -> VerificationResult:
        """Connect, run supported operational commands, return normalized
        structured verification data. Must never raise for expected
        failure modes -- catch and return success=False with `error` and
        an explicit `status` set."""
        raise NotImplementedError


def timed(fn):
    def _wrapped(self, device: Device, credentials: DeviceCredentials) -> VerificationResult:
        start = time.perf_counter()
        try:
            result = fn(self, device, credentials)
            result.duration_ms = round((time.perf_counter() - start) * 1000.0, 2)
            result.engine = self.engine
            return result
        except Exception as e:  # noqa: BLE001 -- verifiers must never crash the request handler
            return VerificationResult(
                success=False, status=PYATS_FAILED, engine=self.engine,
                duration_ms=round((time.perf_counter() - start) * 1000.0, 2),
                error=f"{type(e).__name__}: {e}",
            )
    return _wrapped