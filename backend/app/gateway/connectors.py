"""Protocol abstraction the gateway drives (Part 1 \"DeviceConnector\").

Reuses `app.services.collectors.*` (SSH/NETCONF/RESTCONF/gNMI/SNMP) --
RULE 11 applies here too: there is no second SSH/NETCONF/etc. implementation.
This module only adds the normalization + timeout/concurrency layer the
gateway itself needs on top of the existing per-transport collectors, plus
a MockConnector used by tests and local/offline development so CI never
needs a physical network device (Part 13).

GET_FACTS and GET_INTERFACES are now dispatched to the collector's dedicated
hooks (get_facts()/get_interfaces()) instead of falling through to
collect_config. Collectors that don't implement the hook raise
NotImplementedError, which triggers a graceful degradation to collect_config
so callers always get a result.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional

from app.gateway.errors import GatewayError, GatewayErrorCode
from app.models.db import Device
from app.services.collectors.registry import get_collector
from app.services.openbao_service import DeviceCredentials

GATEWAY_MOCK_CONNECTOR = os.getenv("GATEWAY_MOCK_CONNECTOR", "false").strip().lower() in ("1", "true", "yes")
CONNECT_TIMEOUT_SECONDS = float(os.getenv("GATEWAY_CONNECT_TIMEOUT_SECONDS", "10"))
COMMAND_TIMEOUT_SECONDS = float(os.getenv("GATEWAY_COMMAND_TIMEOUT_SECONDS", "30"))


@dataclass
class NormalizedResult:
    """Common result shape every protocol/operation is normalized into
    (Part 1). `raw_output_reference` points at MinIO for large payloads --
    the object itself is stored by the caller (worker.py), this dataclass
    only carries the key once known."""
    device_id: str
    protocol: str
    operation: str
    success: bool
    collected_at: datetime = field(default_factory=datetime.utcnow)
    raw_output_reference: Optional[str] = None
    normalized_data: Dict[str, Any] = field(default_factory=dict)
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    raw_config: Optional[str] = None  # in-memory only until persisted to MinIO; never logged/returned as-is
    duration_ms: float = 0.0


class MockConnector:
    """Deterministic offline stand-in for a real device, used by tests and
    by GATEWAY_MOCK_CONNECTOR=true local/offline development. Never touches
    the network."""

    transport = "mock"

    def run(self, device: Device, operation: str, credentials: DeviceCredentials) -> NormalizedResult:
        start = time.perf_counter()
        raw = (
            "hostname mock-device\n"
            "ssh version 2\n"
            "no ip http server\n"
            "ip http secure-server\n"
            "!\n"
        )
        # Return operation-appropriate mock data so tests can differentiate.
        if operation == "GET_FACTS":
            normalized = {
                "facts": {
                    "sys_name": "mock-device", "sys_descr": "Mock SNMP Agent",
                    "sys_object_id": "1.3.6.1.4.1.99999", "sys_uptime_ticks": "0",
                },
                "vendor": device.vendor or "mock", "hostname": "mock-device",
            }
        elif operation == "GET_INTERFACES":
            normalized = {
                "interfaces": [
                    {"if_index": "1", "name": "GigabitEthernet0/0", "admin_status": "up", "oper_status": "up", "speed_bps": "1000000000"},
                ],
                "interface_count": 1,
                "vendor": device.vendor or "mock", "hostname": "mock-device",
            }
        else:
            normalized = {"vendor": device.vendor or "mock", "facts": {"hostname": "mock-device"}}

        return NormalizedResult(
            device_id=device.id,
            protocol="mock",
            operation=operation,
            success=True,
            raw_config=raw if operation not in ("GET_FACTS", "GET_INTERFACES") else None,
            normalized_data=normalized,
            duration_ms=round((time.perf_counter() - start) * 1000.0, 2),
        )


def _map_structured_error(error: str, secret: dict) -> str:
    """Map a StructuredResult / CollectionResult error string onto a
    GatewayErrorCode without leaking credential material."""
    lowered = (error or "").lower()
    if "timeout" in lowered or "timed out" in lowered:
        return GatewayErrorCode.COMMAND_TIMEOUT
    elif "auth" in lowered:
        return GatewayErrorCode.AUTHENTICATION_FAILED
    elif "unreachable" in lowered or "connection" in lowered or "refused" in lowered:
        return GatewayErrorCode.DEVICE_UNREACHABLE
    return GatewayErrorCode.CONFIG_COLLECTION_FAILED


def _operation_to_collection(device: Device, operation: str, protocol: str, credentials: DeviceCredentials) -> NormalizedResult:
    """Dispatch an operation to the appropriate collector method.

    GET_FACTS and GET_INTERFACES call the dedicated structured hooks on the
    collector when available, falling back to collect_config when the hook
    raises NotImplementedError (e.g. NETCONF/RESTCONF collectors that don't
    implement them yet). All other read-only operations call collect_config.
    """
    start = time.perf_counter()
    try:
        collector = get_collector(device.vendor, transport=protocol)
    except ValueError as e:
        raise GatewayError(GatewayErrorCode.PROTOCOL_UNSUPPORTED, str(e)) from e

    # ------------------------------------------------------------------ #
    # Structured operation dispatch (GET_FACTS / GET_INTERFACES)          #
    # ------------------------------------------------------------------ #
    if operation in ("GET_FACTS", "GET_INTERFACES"):
        structured_result = None
        try:
            if operation == "GET_FACTS":
                structured_result = collector.get_facts(device, credentials)
            else:
                structured_result = collector.get_interfaces(device, credentials)
        except NotImplementedError:
            # Collector declared no implementation; fall through to
            # collect_config degradation below.
            pass

        if structured_result is not None:
            duration_ms = round((time.perf_counter() - start) * 1000.0, 2)
            if not structured_result.success:
                code = _map_structured_error(structured_result.error or "", credentials.secret)
                return NormalizedResult(
                    device_id=device.id, protocol=protocol, operation=operation,
                    success=False, duration_ms=duration_ms,
                    error_code=code.value if hasattr(code, "value") else str(code),
                    error_message=structured_result.error or "Structured operation failed",
                )
            # Merge operation-specific data together with identity info.
            normalized: Dict[str, Any] = {
                "vendor": structured_result.vendor,
                "hostname": structured_result.hostname,
            }
            normalized.update(structured_result.data)
            return NormalizedResult(
                device_id=device.id, protocol=protocol, operation=operation,
                success=True, normalized_data=normalized, duration_ms=duration_ms,
            )
        # NotImplementedError path: degrade to collect_config (fall through).

    # ------------------------------------------------------------------ #
    # Default: collect_config (AUDIT, FETCH_CONFIG, GET_VERSION,          #
    # GET_NEIGHBORS, and structured-op fallback)                          #
    # ------------------------------------------------------------------ #
    result = collector.collect_config(device, credentials)
    duration_ms = round((time.perf_counter() - start) * 1000.0, 2)

    if not result.success:
        # Map the collector's free-text error onto a safe, specific code
        # without ever forwarding secret-bearing text verbatim beyond what
        # the collector itself already redacted (RULE 6, enforced in
        # collectors/base.py's `timed` decorator).
        lowered = (result.error or "").lower()
        if "timeout" in lowered or "timed out" in lowered:
            code = GatewayErrorCode.COMMAND_TIMEOUT
        elif "auth" in lowered:
            code = GatewayErrorCode.AUTHENTICATION_FAILED
        elif "unreachable" in lowered or "connection" in lowered or "refused" in lowered:
            code = GatewayErrorCode.DEVICE_UNREACHABLE
        else:
            code = GatewayErrorCode.CONFIG_COLLECTION_FAILED
        return NormalizedResult(
            device_id=device.id, protocol=protocol, operation=operation,
            success=False, duration_ms=duration_ms,
            error_code=code.value,
            error_message=result.error or "Collection failed",
        )

    return NormalizedResult(
        device_id=device.id, protocol=protocol, operation=operation,
        success=True, raw_config=result.raw_config,
        normalized_data={"vendor": result.vendor, "hostname": result.hostname, "config_hash": result.config_hash},
        duration_ms=duration_ms,
    )


def execute(device: Device, operation: str, protocol: str, credentials: DeviceCredentials) -> NormalizedResult:
    """Single entry point the gateway worker calls. Chooses the mock
    connector when explicitly enabled (tests / offline dev); otherwise
    dispatches to the real collector registry."""
    if GATEWAY_MOCK_CONNECTOR or (device.vendor or "").lower() == "mock":
        return MockConnector().run(device, operation, credentials)
    return _operation_to_collection(device, operation, protocol, credentials)