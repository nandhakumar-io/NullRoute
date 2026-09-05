"""Result/status types for the OpenConfig/gNMI config-injection adapter
(spec sections 22-28). Fixed status codes so callers (deployment_service,
frontend, tests) never have to string-match free-text errors.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

GNMI_OK = "GNMI_OK"
GNMI_DISABLED = "GNMI_DISABLED"
GNMI_UNSUPPORTED = "GNMI_UNSUPPORTED"
GNMI_UNAVAILABLE = "GNMI_UNAVAILABLE"
GNMI_SCHEMA_MISMATCH = "GNMI_SCHEMA_MISMATCH"
GNMI_FAILED = "GNMI_FAILED"

_ALLOWED_OPERATIONS = ("update", "replace", "delete")


@dataclass
class GnmiUpdate:
    path: str
    value: Any
    model: str
    operation: str  # "update" | "replace" | "delete"


@dataclass
class GnmiResult:
    success: bool
    status: str
    error: Optional[str] = None
    request_hash: Optional[str] = None
    data: Optional[Any] = None
