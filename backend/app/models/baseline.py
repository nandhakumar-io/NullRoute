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
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


class DeviceInfo(BaseModel):
    vendor: str
    model: Optional[str] = None
    os: Optional[str] = None
    version: Optional[str] = None
    hostname: Optional[str] = None
    serial_number: Optional[str] = None


class SSHConfig(BaseModel):
    enabled: Union[bool, str, None] = None
    version: Optional[int] = None
    idle_timeout: Optional[int] = None
    key_exchange_algorithms: Optional[List[str]] = None
    port: Optional[int] = None


class TelnetConfig(BaseModel):
    enabled: Union[bool, str, None] = None


class HTTPConfig(BaseModel):
    enabled: Union[bool, str, None] = None
    https_only: Union[bool, str, None] = None
    port: Optional[int] = None


class ManagementConfig(BaseModel):
    ssh: SSHConfig = Field(default_factory=SSHConfig)
    telnet: TelnetConfig = Field(default_factory=TelnetConfig)
    http: HTTPConfig = Field(default_factory=HTTPConfig)
    console_timeout: Optional[int] = None
    banner_configured: Union[bool, str, None] = None


class RadiusServer(BaseModel):
    address: str
    auth_port: Optional[int] = None
    acct_port: Optional[int] = None
    key: Optional[str] = None


class TACACSServer(BaseModel):
    address: str
    port: Optional[int] = None
    key: Optional[str] = None


class VLAN(BaseModel):
    id: Any
    name: Optional[str] = None
    description: Optional[str] = None


class ACLRule(BaseModel):
    name: str
    direction: Optional[str] = None
    action: Optional[str] = None


class FirewallPolicy(BaseModel):
    """Vendor-neutral representation of a zone/rulebase firewall policy
    (FortiOS `config firewall policy`, PAN-OS `set rulebase security rules`,
    Cisco zone-based `class-map`/`policy-map`, etc). Deliberately separate
    from ACLRule: an ACL is an ordered permit/deny match list bound to an
    interface, a firewall policy is a stateful zone/app/service rule — the
    two must not be collapsed into one shape or compliance controls that
    apply to only one of them (e.g. "default deny between zones") cannot be
    evaluated correctly."""
    name: str
    action: Optional[str] = None  # allow/deny/drop
    source_zone: Optional[str] = None
    destination_zone: Optional[str] = None
    source: Optional[List[str]] = None
    destination: Optional[List[str]] = None
    service: Optional[List[str]] = None
    application: Optional[List[str]] = None
    logging_enabled: Union[bool, str, None] = None
    enabled: Union[bool, str, None] = None


class CryptoConfig(BaseModel):
    """TLS/SSH/certificate posture — kept distinct from management.ssh so
    cipher/protocol-strength controls can be evaluated independently of
    whether the management protocol itself is merely enabled."""
    min_tls_version: Optional[str] = None
    weak_ciphers_disabled: Union[bool, str, None] = None
    ssh_key_exchange_algorithms: Optional[List[str]] = None
    certificate_expiry_checked: Union[bool, str, None] = None
    self_signed_cert_in_use: Union[bool, str, None] = None


class ServicesConfig(BaseModel):
    """Generic enabled/disabled service inventory for services that don't
    warrant their own typed section (ftp, tftp, finger, cdp/lldp, http proxy,
    etc). Management-plane protocols with dedicated compliance controls
    (ssh/telnet/http) stay in ManagementConfig — this is the catch-all so
    vendor-specific service toggles don't get dropped into extra_parameters
    where the rule engine can't reliably find them."""
    enabled_services: List[str] = Field(default_factory=list)
    disabled_services: List[str] = Field(default_factory=list)


class SyslogServer(BaseModel):
    address: str
    severity: Optional[str] = None
    facility: Optional[str] = None


class NTPConfig(BaseModel):
    enabled: Union[bool, str, None] = None
    servers: List[str] = Field(default_factory=list)


class RoutingOSPF(BaseModel):
    enabled: Union[bool, str, None] = None
    process_id: Optional[int] = None


class RoutingConfig(BaseModel):
    ospf: RoutingOSPF = Field(default_factory=RoutingOSPF)


class LoggingConfig(BaseModel):
    enabled: Union[bool, str, None] = None
    remote_syslog: Union[bool, str, None] = None
    syslog_servers: Optional[List[str]] = None
    syslog_servers_detail: List[SyslogServer] = Field(default_factory=list)
    log_level: Optional[str] = None
    ntp_synced: Union[bool, str, None] = None
    ntp: NTPConfig = Field(default_factory=NTPConfig)


class AAAConfig(BaseModel):
    enabled: Union[bool, str, None] = None
    authentication_method: Optional[str] = None
    accounting_enabled: Union[bool, str, None] = None
    local_fallback: Union[bool, str, None] = None
    radius_servers: List[RadiusServer] = Field(default_factory=list)
    tacacs_servers: List[TACACSServer] = Field(default_factory=list)


class PasswordPolicy(BaseModel):
    min_length: Optional[int] = None
    complexity_required: Union[bool, str, None] = None
    max_age_days: Optional[int] = None
    encrypted_storage: Union[bool, str, None] = None


class SNMPConfig(BaseModel):
    enabled: Union[bool, str, None] = None
    version: Optional[str] = None
    community_strings_default: Union[bool, str, None] = None
    community_strings: List[str] = Field(default_factory=list)


class InterfaceSecurity(BaseModel):
    unused_ports_disabled: Union[bool, str, None] = None
    port_security_enabled: Union[bool, str, None] = None


class SecurityGroup(BaseModel):
    name: Optional[str] = None
    allow_ssh: Union[bool, str, None] = None
    allow_http: Union[bool, str, None] = None
    allow_all_egress: Union[bool, str, None] = None
    restrict_default_vpc: Union[bool, str, None] = None

class IAMRole(BaseModel):
    name: str = "default"
    privilege_escalation: Union[bool, str, None] = None
    cross_account_access: Union[bool, str, None] = None

class CloudVPC(BaseModel):
    id: Optional[str] = None
    flow_logs_enabled: Union[bool, str, None] = None
    default_security_group_closed: Union[bool, str, None] = None
    security_groups: List[SecurityGroup] = Field(default_factory=list)
    iam_roles: List[IAMRole] = Field(default_factory=list)

class KubernetesNetworkPolicy(BaseModel):
    name: Optional[str] = None
    namespace: Optional[str] = None
    default_deny_all_ingress: Union[bool, str, None] = None
    default_deny_all_egress: Union[bool, str, None] = None
    istio_mtls_strict: Union[bool, str, None] = None


class NormalizedParameter(BaseModel):
    """One AI- or parser-derived (raw_line -> normalized value) mapping,
    kept for full evidentiary traceability."""
    model_config = {"protected_namespaces": ()}

    raw_command: str
    normalized_parameter: str
    value: Any
    confidence: float = 1.0
    source: str = Field(description="'parser' (deterministic) or 'ai' (RAG/LLM)")
    vendor: Optional[str] = None
    line_number: Optional[int] = None
    parser_version: Optional[str] = None
    retrieved_knowledge: Optional[List[str]] = None
    model_version: Optional[str] = Field(
        default=None,
        description="AI model version/tag when source='ai'. Distinct from parser_version.",
    )
    human_validated: bool = False
    ai_provenance: Optional[Dict[str, Any]] = Field(
        default=None,
        description=(
            "Only for source='ai': how the interpretation was produced -- route "
            "(cache_hit / approved_mapping / llm / review_required), classifier "
            "(intent, confidence, backend, model_version), embedding (nearest "
            "intent, similarity), retrieval evidence, LLM model + prompt "
            "fingerprint. Absent on parser facts and on facts persisted before "
            "this field existed."
        ),
    )
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class SecurityBaselineModel(BaseModel):
    device: DeviceInfo
    management: ManagementConfig = Field(default_factory=ManagementConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    aaa: AAAConfig = Field(default_factory=AAAConfig)
    password_policy: PasswordPolicy = Field(default_factory=PasswordPolicy)
    snmp: SNMPConfig = Field(default_factory=SNMPConfig)
    interfaces: InterfaceSecurity = Field(default_factory=InterfaceSecurity)
    routing: RoutingConfig = Field(default_factory=RoutingConfig)
    vlans: List[VLAN] = Field(default_factory=list)
    acls: List[ACLRule] = Field(default_factory=list)
    firewall_policies: List[FirewallPolicy] = Field(default_factory=list)
    crypto: CryptoConfig = Field(default_factory=CryptoConfig)
    services: ServicesConfig = Field(default_factory=ServicesConfig)

    cloud_constructs: CloudVPC = Field(default_factory=CloudVPC)
    kube_constructs: KubernetesNetworkPolicy = Field(default_factory=KubernetesNetworkPolicy)

    # Fully extensible bucket for anything not yet modeled explicitly.
    extra_parameters: Dict[str, Any] = Field(default_factory=dict)

    # Full evidence trail: every raw line -> normalized parameter mapping
    # that contributed to this baseline.
    provenance: List[NormalizedParameter] = Field(default_factory=list)

    # Unresolved input carried forward for Part 2/3 and human review. Each
    # entry documents WHY something couldn't be normalized (low-confidence
    # vendor detection, a block no parser/AI path could interpret, an AI
    # pipeline stage that was unavailable, etc). Never silently dropped —
    # see services/pipeline.py and ai/normalize.py.
    unknown_evidence: List[Dict[str, Any]] = Field(default_factory=list)

    raw_config_hash: Optional[str] = None
    normalized_at: datetime = Field(default_factory=datetime.utcnow)

    def flatten(self) -> Dict[str, Any]:
        """Flatten to dotted-path dict, e.g. 'management.ssh.version' -> 2,
        for the rule engine / OPA input document."""
        out: Dict[str, Any] = {}

        def _walk(prefix: str, obj: Any):
            if isinstance(obj, BaseModel):
                for k, v in obj.model_dump().items():
                    if isinstance(v, list):
                        out[f"{prefix}.{k}"] = v
                    else:
                        _walk(f"{prefix}.{k}" if prefix else k, v)
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, list):
                        out[f"{prefix}.{k}"] = v
                    else:
                        _walk(f"{prefix}.{k}" if prefix else k, v)
            elif isinstance(obj, list):
                out[prefix] = obj
            elif prefix:
                out[prefix] = obj

        data = self.model_dump(exclude={"provenance"})
        for section, value in data.items():
            _walk(section, value)
        return out