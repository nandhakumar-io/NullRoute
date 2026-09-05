"""Shared result type + explicit status vocabulary for OpenConfig/gNMI
config-injection (spec sections 22-28).

RULE (section 27): if gNMI is disabled/unsupported/unavailable/schema-
mismatched, return one of these explicit statuses. Never silently fall
back to another transport during an approved gNMI deployment -- the
operator must deliberately choose another transport on a subsequent,
separate deploy call.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

# Explicit terminal statuses (section 27 + section 50 frontend states).
GNMI_OK = "GNMI_OK"
GNMI_DISABLED = "GNMI_DISABLED"
GNMI_UNSUPPORTED = "GNMI_UNSUPPORTED"
GNMI_UNAVAILABLE = "GNMI_UNAVAILABLE"
GNMI_SCHEMA_MISMATCH = "GNMI_SCHEMA_MISMATCH"
GNMI_FAILED = "GNMI_FAILED"

TERMINAL_STATUSES = {
    GNMI_OK, GNMI_DISABLED, GNMI_UNSUPPORTED, GNMI_UNAVAILABLE,
    GNMI_SCHEMA_MISMATCH, GNMI_FAILED,
}


@dataclass
class GnmiUpdate:
    """One requested path/value pair for a gNMI SetRequest. `model` names
    the OpenConfig module the path belongs to (e.g. 'openconfig-interfaces')
    so it can be checked against Capabilities() before Set() is attempted."""
    path: str
    value: Any
    model: str
    operation: str = "update"  # update | replace | delete (section 26)


@dataclass
class ConfigInjectionResult:
    success: bool
    status: str = GNMI_FAILED
    transport: str = "gnmi"
    target: Optional[str] = None
    model: Optional[str] = None
    paths: List[str] = field(default_factory=list)
    operation: Optional[str] = None
    request_hash: Optional[str] = None
    response_status: Optional[str] = None
    error: Optional[str] = None
    duration_ms: float = 0.0
    completed_at: datetime = field(default_factory=datetime.utcnow)

    def as_metadata(self) -> Dict[str, Any]:
        """Deployment-record-safe metadata -- NEVER includes credentials
        (RULE: never record credentials, section 26)."""
        return {
            "transport": self.transport,
            "target": self.target,
            "model": self.model,
            "paths": self.paths,
            "operation": self.operation,
            "request_hash": self.request_hash,
            "response_status": self.response_status,
            "gnmi_status": self.status,
        }