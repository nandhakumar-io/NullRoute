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

from pydantic import BaseModel, Field, ValidationError

__all__ = [
    "DeviceInfo", "SSHConfig", "TelnetConfig", "HTTPConfig", "ManagementConfig",
    "LoggingConfig", "AAAConfig", "PasswordPolicy", "SNMPConfig",
    "InterfaceSecurity", "NormalizedParameter", "SecurityBaselineModel",
    "RadiusServer", "TacacsServer", "SyslogServerEntry", "NTPConfig",
    "InterfaceEntry", "VLANEntry", "ACLEntry", "FirewallPolicyEntry",
    "StaticRoute", "OSPFConfig", "BGPConfig", "RoutingConfig", "CryptoConfig",
    "ValidationError",
]


class DeviceInfo(BaseModel):
    vendor: str
    model: Optional[str] = None
    os: Optional[str] = None
    version: Optional[str] = None
    hostname: Optional[str] = None
    serial_number: Optional[str] = None


class SSHConfig(BaseModel):
    # Enforce the declared types (int/bool/etc.) on every assignment, not
    # just on construction. Without this, a plain `setattr(...)` from the
    # AI/RAG normalizer (ai/normalize.py) or the deterministic parser's
    # `_set_dotted` helper can silently store a mistyped value (e.g. the
    # string "v2" into a field declared `Optional[int]`), which then fails
    # an `eq 2` OPA comparison even though the device is actually correct.
    model_config = {"validate_assignment": True}

    enabled: Optional[bool] = None
    version: Optional[int] = None
    idle_timeout: Optional[int] = None
    key_exchange_algorithms: Optional[List[str]] = None
    port: Optional[int] = None


class TelnetConfig(BaseModel):
    model_config = {"validate_assignment": True}

    enabled: Optional[bool] = None


class HTTPConfig(BaseModel):
    model_config = {"validate_assignment": True}

    enabled: Optional[bool] = None
    https_only: Optional[bool] = None
    port: Optional[int] = None


class ManagementConfig(BaseModel):
    model_config = {"validate_assignment": True}

    ssh: SSHConfig = Field(default_factory=SSHConfig)
    telnet: TelnetConfig = Field(default_factory=TelnetConfig)
    http: HTTPConfig = Field(default_factory=HTTPConfig)
    console_timeout: Optional[int] = None
    banner_configured: Optional[bool] = None


class RadiusServer(BaseModel):
    model_config = {"validate_assignment": True}

    address: Optional[str] = None
    auth_port: Optional[int] = None
    acct_port: Optional[int] = None


class TacacsServer(BaseModel):
    model_config = {"validate_assignment": True}

    address: Optional[str] = None
    port: Optional[int] = None


class SyslogServerEntry(BaseModel):
    model_config = {"validate_assignment": True}

    address: Optional[str] = None
    severity: Optional[str] = None


class NTPConfig(BaseModel):
    model_config = {"validate_assignment": True}

    servers: List[str] = Field(default_factory=list)


class LoggingConfig(BaseModel):
    model_config = {"validate_assignment": True}

    enabled: Optional[bool] = None
    remote_syslog: Optional[bool] = None
    syslog_servers: Optional[List[str]] = None
    log_level: Optional[str] = None
    ntp_synced: Optional[bool] = None
    # Added for context-aware normalization: full syslog server detail
    # (address + minimum severity) and the NTP server list, kept alongside
    # the pre-existing boolean/scalar fields above (which OPA already
    # evaluates and which are left untouched) rather than replacing them.
    syslog_servers_detail: List[SyslogServerEntry] = Field(default_factory=list)
    ntp: NTPConfig = Field(default_factory=NTPConfig)


class AAAConfig(BaseModel):
    model_config = {"validate_assignment": True}

    enabled: Optional[bool] = None
    authentication_method: Optional[str] = None
    accounting_enabled: Optional[bool] = None
    local_fallback: Optional[bool] = None
    # Added: authorization (distinct from authentication/accounting) plus
    # the actual RADIUS/TACACS+ server definitions referenced by
    # `authentication_method` (e.g. "group radius local") -- previously
    # this relationship (method name -> concrete server addresses) was
    # lost entirely because normalization only ever saw one line at a time.
    authorization_method: Optional[str] = None
    radius_servers: List[RadiusServer] = Field(default_factory=list)
    tacacs_servers: List[TacacsServer] = Field(default_factory=list)


class PasswordPolicy(BaseModel):
    model_config = {"validate_assignment": True}

    min_length: Optional[int] = None
    complexity_required: Optional[bool] = None
    max_age_days: Optional[int] = None
    encrypted_storage: Optional[bool] = None


class SNMPConfig(BaseModel):
    model_config = {"validate_assignment": True}

    enabled: Optional[bool] = None
    version: Optional[str] = None
    community_strings_default: Optional[bool] = None
    # Added: the actual configured community strings / trap destinations,
    # not just the "is it public/private" boolean OPA checks.
    community_strings: List[str] = Field(default_factory=list)
    trap_servers: List[str] = Field(default_factory=list)


class InterfaceEntry(BaseModel):
    model_config = {"validate_assignment": True}

    name: Optional[str] = None
    description: Optional[str] = None
    ip_address: Optional[str] = None
    vlan: Optional[int] = None
    admin_state: Optional[str] = None  # up | down
    port_security: Optional[bool] = None


class VLANEntry(BaseModel):
    model_config = {"validate_assignment": True}

    id: Optional[int] = None
    name: Optional[str] = None


class ACLEntry(BaseModel):
    model_config = {"validate_assignment": True}

    name: Optional[str] = None
    applied_interface: Optional[str] = None
    direction: Optional[str] = None  # in | out


class FirewallPolicyEntry(BaseModel):
    model_config = {"validate_assignment": True}

    name: Optional[str] = None
    source_zone: Optional[str] = None
    destination_zone: Optional[str] = None
    action: Optional[str] = None  # allow | deny


class StaticRoute(BaseModel):
    model_config = {"validate_assignment": True}

    destination: Optional[str] = None
    next_hop: Optional[str] = None


class OSPFConfig(BaseModel):
    model_config = {"validate_assignment": True}

    enabled: Optional[bool] = None
    process_id: Optional[int] = None


class BGPConfig(BaseModel):
    model_config = {"validate_assignment": True}

    enabled: Optional[bool] = None
    as_number: Optional[int] = None


class RoutingConfig(BaseModel):
    model_config = {"validate_assignment": True}

    ospf: OSPFConfig = Field(default_factory=OSPFConfig)
    bgp: BGPConfig = Field(default_factory=BGPConfig)
    static_routes: List[StaticRoute] = Field(default_factory=list)


class CryptoConfig(BaseModel):
    model_config = {"validate_assignment": True}

    tls_min_version: Optional[str] = None
    certificates: List[str] = Field(default_factory=list)


class InterfaceSecurity(BaseModel):
    model_config = {"validate_assignment": True}

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

    # Added vendor-neutral structures (see problem statement item 4) for
    # facts the deterministic parsers + block-aware AI normalizer can now
    # extract: individual interfaces, VLANs, ACLs, firewall/security
    # policies, routing (OSPF/BGP/static), and crypto/TLS. Kept as
    # separate top-level sections rather than folded into `interfaces`
    # (already used for the CIS unused-ports/port-security booleans OPA
    # evaluates) so no existing OPA control's dotted path changes.
    interfaces_detail: List[InterfaceEntry] = Field(default_factory=list)
    vlans: List[VLANEntry] = Field(default_factory=list)
    acls: List[ACLEntry] = Field(default_factory=list)
    firewall_policies: List[FirewallPolicyEntry] = Field(default_factory=list)
    routing: RoutingConfig = Field(default_factory=RoutingConfig)
    crypto: CryptoConfig = Field(default_factory=CryptoConfig)

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