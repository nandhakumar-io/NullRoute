"""Base deployment interface (Phase 15).

Mirrors services/collectors/base.py's shape deliberately: deployment is
"collection in reverse" -- push config lines instead of reading them --
and reuses the SAME credential-handling discipline (RULE 6: credentials
never logged/returned/persisted) and the SAME per-vendor connection
profiles collectors already established.

Every transport-specific deployer implements
`push_config(device, credentials, config_lines) -> DeploymentResult`.
Deployers must never raise for expected failure modes (auth failure,
timeout, command rejected) -- catch and return success=False with `error`
set, so the orchestrator (services/deployment_service.py) can record a
FAILED DeploymentRecord instead of a 500.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from app.models.db import Device
from app.services.openbao_service import DeviceCredentials, redact_secret_values


@dataclass
class DeploymentResult:
    success: bool
    transport: str = "unknown"
    output: Optional[str] = None
    error: Optional[str] = None
    duration_ms: float = 0.0
    completed_at: datetime = field(default_factory=datetime.utcnow)


class BaseDeployer(ABC):
    transport: str = "unknown"

    @abstractmethod
    def push_config(self, device: Device, credentials: DeviceCredentials, config_lines: List[str]) -> DeploymentResult:
        raise NotImplementedError


def timed(fn):
    def _wrapped(self, device: Device, credentials: DeviceCredentials, config_lines: List[str]) -> DeploymentResult:
        start = time.perf_counter()
        try:
            result = fn(self, device, credentials, config_lines)
            result.duration_ms = round((time.perf_counter() - start) * 1000.0, 2)
            result.transport = self.transport
            return result
        except Exception as e:  # noqa: BLE001 -- deployers must never crash the request handler
            return DeploymentResult(
                success=False, transport=self.transport,
                duration_ms=round((time.perf_counter() - start) * 1000.0, 2),
                # Defense-in-depth (RULE 6): scrub any credential value that
                # ended up verbatim in a third-party exception message.
                error=redact_secret_values(f"{type(e).__name__}: {e}", getattr(credentials, "secret", None) or {}),
            )
    return _wrapped