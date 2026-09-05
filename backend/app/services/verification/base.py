"""Base interface for optional supplemental post-deployment verification
engines (spec sections 29-34, 44, 47).

This is deliberately NOT part of the compliance decision path. A
VerificationResult can only ever *add* corroborating operational-state
evidence to a DeploymentRecord; it can never override OPA, Batfish, or
the risk engine, and deployment_service.py must keep treating its own
post_verification_passed (hash + pipeline rerun) as authoritative even
when a supplemental verifier disagrees or is unavailable.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.models.db import Device
from app.services.openbao_service import DeviceCredentials

PYATS_OK = "PYATS_OK"
PYATS_DISABLED = "PYATS_DISABLED"
PYATS_UNAVAILABLE = "PYATS_UNAVAILABLE"
PYATS_UNSUPPORTED = "PYATS_UNSUPPORTED"
PYATS_FAILED = "PYATS_FAILED"


@dataclass
class VerificationResult:
    engine: str
    success: bool
    status: str = PYATS_DISABLED
    commands_run: List[str] = field(default_factory=list)
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    completed_at: datetime = field(default_factory=datetime.utcnow)

    def as_metadata(self) -> Dict[str, Any]:
        """Never includes credentials -- only what was checked and what
        came back (spec sections 47/53)."""
        return {
            "engine": self.engine,
            "status": self.status,
            "success": self.success,
            "commands_run": self.commands_run,
            "data": self.data,
            "error": self.error,
            "completed_at": self.completed_at.isoformat(),
        }


class BaseVerifier(ABC):
    engine: str = "unknown"

    @abstractmethod
    def verify(self, device: Device, credentials: DeviceCredentials) -> VerificationResult:
        """Which operational commands are appropriate is decided inside
        the verifier (e.g. from PYATS_VERIFY_COMMANDS), not by the
        caller -- deployment_service.py stays engine-agnostic (section 35)."""
        raise NotImplementedError
