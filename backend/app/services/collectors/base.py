"""Base collector interface (Phase 7).

Every transport-specific collector (ssh.py, netconf.py, restconf.py,
snmp.py) implements `collect_config(device, credentials) -> CollectionResult`.
Collection output feeds the SAME pipeline used by file uploads
(services/pipeline.run_pipeline) -- there is no second compliance
implementation for live-collected configs (RULE 11 / Phase 7 rule).

`credentials` is an app.services.openbao_service.DeviceCredentials instance
resolved by the caller (router) immediately before the call and allowed to
go out of scope immediately after -- collectors must never log, cache, or
return it (RULE 6).
"""
from __future__ import annotations

import hashlib
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.models.db import Device
from app.services.openbao_service import DeviceCredentials, redact_secret_values


@dataclass
class StructuredResult:
    """Result shape for operations that return structured facts rather than
    a raw configuration blob (GET_FACTS/GET_INTERFACES/GET_NEIGHBORS).
    Mirrors CollectionResult's success/error contract so gateway/connectors.py
    can handle both uniformly."""
    success: bool
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    collected_at: datetime = field(default_factory=datetime.utcnow)
    transport: str = "unknown"
    duration_ms: float = 0.0
    error: Optional[str] = None


@dataclass
class CollectionResult:
    success: bool
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    raw_config: Optional[str] = None
    collected_at: datetime = field(default_factory=datetime.utcnow)
    transport: str = "unknown"
    duration_ms: float = 0.0
    error: Optional[str] = None
    config_hash: Optional[str] = None

    def __post_init__(self):
        if self.success and self.raw_config and not self.config_hash:
            from app.services.config_merge import config_hash
            self.config_hash = config_hash(self.raw_config)


class BaseCollector(ABC):
    transport: str = "unknown"

    @abstractmethod
    def collect_config(self, device: Device, credentials: DeviceCredentials) -> CollectionResult:
        """Connect to the device, retrieve the running configuration as
        text, and return a CollectionResult. Must never raise for expected
        failure modes (auth failure, timeout, unreachable) -- catch and
        return success=False with `error` set, so callers can persist a
        collection-status row instead of a 500."""
        raise NotImplementedError

    def get_facts(self, device: Device, credentials: DeviceCredentials) -> StructuredResult:
        """Optional: return structured identity facts (hostname, vendor,
        version, uptime, ...) without necessarily fetching the full running
        config. Collectors that don't implement a cheaper/more accurate way
        to do this fall back to NotImplementedError, and
        gateway/connectors.py degrades to deriving facts from collect_config
        instead -- this is an *optimization/precision* hook, not a required
        override."""
        raise NotImplementedError

    def get_interfaces(self, device: Device, credentials: DeviceCredentials) -> StructuredResult:
        """Optional: return structured per-interface facts (name, admin/oper
        status, speed, IP address, ...). Same fallback contract as
        get_facts(). Only SSH and SNMP collectors implement this today;
        NETCONF/RESTCONF/gNMI can be added the same way once there's a
        vendor-agnostic YANG model mapping worth maintaining."""
        raise NotImplementedError

    def get_health_metrics(self, device: Device, credentials: DeviceCredentials) -> StructuredResult:
        """Optional: return live health/performance metrics -- CPU load,
        memory utilization, and per-interface traffic/error counters --
        distinct from get_facts()/get_interfaces() which are identity and
        admin/oper-status snapshots, not load metrics. Same fallback
        contract: collectors that don't implement this raise
        NotImplementedError and gateway/connectors.py degrades rather than
        erroring the whole operation. Currently only SNMP implements this
        (HOST-RESOURCES-MIB + IF-MIB high-capacity counters)."""
        raise NotImplementedError

    def get_neighbors(self, device: Device, credentials: DeviceCredentials) -> StructuredResult:
        """Optional: return this device's directly-observed Layer-2
        neighbors (local port -> remote system name + remote port) from a
        standards-based discovery protocol table (e.g. SNMP LLDP-MIB, or a
        vendor CLI's `show cdp/lldp neighbors detail`) -- NOT a subnet-IP
        guess. This is what makes routers/topology.py's link list "real"
        adjacency instead of the /24-co-membership inference in
        services/topology_service.infer_links(). Collectors that don't
        implement a discovery-protocol read raise NotImplementedError and
        the caller falls back to inferred-only links for that device.
        `data` shape: {"neighbors": [{"local_port": str, "remote_chassis_id":
        str|None, "remote_system_name": str|None, "remote_port_id": str|None,
        "remote_port_description": str|None, "protocol": "lldp"}]}."""
        raise NotImplementedError


def timed_structured(fn):
    """Same contract as `timed`, but for get_facts()/get_interfaces()
    implementations that return a StructuredResult instead of a
    CollectionResult."""

    def _wrapped(self, device: Device, credentials: DeviceCredentials) -> StructuredResult:
        start = time.perf_counter()
        try:
            result = fn(self, device, credentials)
            result.duration_ms = round((time.perf_counter() - start) * 1000.0, 2)
            result.transport = self.transport
            return result
        except Exception as e:  # noqa: BLE001
            return StructuredResult(
                success=False,
                vendor=device.vendor,
                hostname=device.hostname,
                transport=self.transport,
                duration_ms=round((time.perf_counter() - start) * 1000.0, 2),
                error=redact_secret_values(f"{type(e).__name__}: {e}", getattr(credentials, "secret", None) or {}),
            )

    return _wrapped


def timed(fn):
    """Decorator: wraps a collector's inner logic, converting exceptions
    into a failed CollectionResult and always recording duration_ms."""

    def _wrapped(self, device: Device, credentials: DeviceCredentials) -> CollectionResult:
        start = time.perf_counter()
        try:
            result = fn(self, device, credentials)
            result.duration_ms = round((time.perf_counter() - start) * 1000.0, 2)
            result.transport = self.transport
            return result
        except Exception as e:  # noqa: BLE001 -- collectors must never crash the request handler
            return CollectionResult(
                success=False,
                vendor=device.vendor,
                hostname=device.hostname,
                transport=self.transport,
                duration_ms=round((time.perf_counter() - start) * 1000.0, 2),
                # Defense-in-depth (RULE 6): scrub any credential value that
                # ended up verbatim in a third-party exception message
                # before it's ever persisted/returned. `credentials.secret`
                # is still in scope here even though this generic handler
                # doesn't otherwise touch it.
                error=redact_secret_values(f"{type(e).__name__}: {e}", getattr(credentials, "secret", None) or {}),
            )

    return _wrapped