"""
Vendor-neutral Security Baseline Model.

This is the canonical schema every proprietary configuration (Cisco IOS-XE,
Juniper Junos, FortiOS, PAN-OS, Arista EOS, SONiC, ...) is normalized into,
either by the deterministic parsers (services/parsers.py) or by the AI/RAG
normalization pipeline (ai/normalize.py) for syntax the parsers don't know.

The model is intentionally permissive/extensible: unknown top-level sections
are allowed via `extra_parameters` so new controls can be added without a
schema migration blocking the pipeline. Known, well-understood sections are
typed so the OPA/Rego + Python rule engine can evaluate them deterministically.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class DeviceInfo(BaseModel):
    vendor: str
    model: Optional[str] = None
    os: Optional[str] = None
    version: Optional[str] = None
    hostname: Optional[str] = None
    serial_number: Optional[str] = None


class SSHConfig(BaseModel):
    enabled: Optional[bool] = None
    version: Optional[int] = None
    idle_timeout: Optional[int] = None
    key_exchange_algorithms: Optional[List[str]] = None
    port: Optional[int] = None


class TelnetConfig(BaseModel):
    enabled: Optional[bool] = None


class HTTPConfig(BaseModel):
    enabled: Optional[bool] = None
    https_only: Optional[bool] = None
    port: Optional[int] = None


class ManagementConfig(BaseModel):
    ssh: SSHConfig = Field(default_factory=SSHConfig)
    telnet: TelnetConfig = Field(default_factory=TelnetConfig)
    http: HTTPConfig = Field(default_factory=HTTPConfig)
    console_timeout: Optional[int] = None
    banner_configured: Optional[bool] = None


class LoggingConfig(BaseModel):
    enabled: Optional[bool] = None
    remote_syslog: Optional[bool] = None
    syslog_servers: Optional[List[str]] = None
    log_level: Optional[str] = None
    ntp_synced: Optional[bool] = None


class AAAConfig(BaseModel):
    enabled: Optional[bool] = None
    authentication_method: Optional[str] = None
    accounting_enabled: Optional[bool] = None
    local_fallback: Optional[bool] = None


class PasswordPolicy(BaseModel):
    min_length: Optional[int] = None
    complexity_required: Optional[bool] = None
    max_age_days: Optional[int] = None
    encrypted_storage: Optional[bool] = None


class SNMPConfig(BaseModel):
    enabled: Optional[bool] = None
    version: Optional[str] = None
    community_strings_default: Optional[bool] = None


class InterfaceSecurity(BaseModel):
    unused_ports_disabled: Optional[bool] = None
    port_security_enabled: Optional[bool] = None


class NormalizedParameter(BaseModel):
    """One AI- or parser-derived (raw_line -> normalized value) mapping,
    kept for full evidentiary traceability."""
    model_config = {"protected_namespaces": ()}

    raw_command: str
    normalized_parameter: str
    value: Any
    confidence: float = 1.0
    source: str = Field(description="'parser' (deterministic) or 'ai' (RAG/LLM)")
    retrieved_knowledge: Optional[List[str]] = None
    model_version: Optional[str] = None
    human_validated: bool = False
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class SecurityBaselineModel(BaseModel):
    device: DeviceInfo
    management: ManagementConfig = Field(default_factory=ManagementConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    aaa: AAAConfig = Field(default_factory=AAAConfig)
    password_policy: PasswordPolicy = Field(default_factory=PasswordPolicy)
    snmp: SNMPConfig = Field(default_factory=SNMPConfig)
    interfaces: InterfaceSecurity = Field(default_factory=InterfaceSecurity)

    # Fully extensible bucket for anything not yet modeled explicitly.
    extra_parameters: Dict[str, Any] = Field(default_factory=dict)

    # Full evidence trail: every raw line -> normalized parameter mapping
    # that contributed to this baseline.
    provenance: List[NormalizedParameter] = Field(default_factory=list)

    raw_config_hash: Optional[str] = None
    normalized_at: datetime = Field(default_factory=datetime.utcnow)

    def flatten(self) -> Dict[str, Any]:
        """Flatten to dotted-path dict, e.g. 'management.ssh.version' -> 2,
        for the rule engine / OPA input document."""
        out: Dict[str, Any] = {}

        def _walk(prefix: str, obj: Any):
            if isinstance(obj, BaseModel):
                for k, v in obj.model_dump().items():
                    _walk(f"{prefix}.{k}" if prefix else k, v)
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    _walk(f"{prefix}.{k}" if prefix else k, v)
            else:
                out[prefix] = obj

        data = self.model_dump(exclude={"provenance"})
        for section, value in data.items():
            _walk(section, value)
        return out
