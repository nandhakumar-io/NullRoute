"""OpenBao credential service (Phase 6).

OpenBao is a Vault-API-compatible open-source secrets manager. This module
is the ONLY place in the codebase permitted to read/write secret material.
Everywhere else in the system (PostgreSQL, MinIO, NATS, logs, evidence,
reports, Fabric) must only ever see a `credential_ref` string -- never the
secret itself (RULE 6).

Configuration (env vars):
    OPENBAO_ENABLED        default "true"
    OPENBAO_ADDR           default "http://openbao:8200"
    OPENBAO_TOKEN          auth token (dev/demo only -- production should use
                            AppRole/Kubernetes auth; token auth is supported
                            here because it's what the bundled docker-compose
                            OpenBao container uses for the demo)
    OPENBAO_MOUNT          KV v2 mount, default "secret"
    OPENBAO_PATH_PREFIX    default "netsec-auditor/devices"

Design:
    - Secrets are addressed by `credential_ref`, a generated opaque path
      component (e.g. "dev-<uuid4>"), never the device hostname/IP, so a
      leaked ref alone doesn't identify the device.
    - Secret material is only ever held in memory for the duration of a
      single collection/deployment call (Phase 7/15) -- callers must not
      cache the return value of get_device_credentials() beyond that scope.
    - Every operation is tenant-scoped: the caller must pass tenant_id and
      it becomes part of the secret path, so OpenBao ACL policies (bound to
      the same path convention) can enforce tenant isolation at the vault
      layer too, not just in application code.
"""
from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx

OPENBAO_ENABLED = os.getenv("OPENBAO_ENABLED", "true").lower() == "true"
OPENBAO_ADDR = os.getenv("OPENBAO_ADDR", "http://openbao:8200")
OPENBAO_TOKEN = os.getenv("OPENBAO_TOKEN", "")
OPENBAO_MOUNT = os.getenv("OPENBAO_MOUNT", "secret")
OPENBAO_PATH_PREFIX = os.getenv("OPENBAO_PATH_PREFIX", "netsec-auditor/devices")


class OpenBaoError(RuntimeError):
    """Raised on any OpenBao communication/config failure. Callers (collectors,
    deployment service) must treat this as a hard stop -- never fall back to
    a default/empty credential."""


@dataclass
class DeviceCredentials:
    """In-memory-only holder for decrypted secret material. Must never be
    logged, serialized into an API response, put on NATS, written to
    evidence, or persisted to disk. Collectors/deployment code must let this
    object go out of scope as soon as the SSH/NETCONF/RESTCONF/SNMP session
    is established."""
    credential_type: str
    secret: Dict[str, Any]


def _client() -> httpx.Client:
    if not OPENBAO_TOKEN:
        raise OpenBaoError("OPENBAO_TOKEN is not configured")
    return httpx.Client(
        base_url=OPENBAO_ADDR,
        headers={"X-Vault-Token": OPENBAO_TOKEN},
        timeout=10.0,
    )


def _kv_path(tenant_id: str, credential_ref: str) -> str:
    return f"{OPENBAO_PATH_PREFIX}/{tenant_id}/{credential_ref}"


def generate_credential_ref() -> str:
    """Opaque, non-identifying reference stored in PostgreSQL
    (DeviceCredentialRef.credential_ref)."""
    return f"dev-{uuid.uuid4()}"


def store_device_credentials(
    tenant_id: str,
    credential_ref: str,
    credential_type: str,
    secret: Dict[str, Any],
) -> None:
    """Write secret material to OpenBao KV v2. Called once at credential
    onboarding/rotation time; `secret` must never be logged by the caller."""
    if not OPENBAO_ENABLED:
        raise OpenBaoError("OpenBao integration is disabled (OPENBAO_ENABLED=false)")
    path = _kv_path(tenant_id, credential_ref)
    with _client() as c:
        resp = c.post(
            f"/v1/{OPENBAO_MOUNT}/data/{path}",
            json={"data": {"credential_type": credential_type, **secret}},
        )
        if resp.status_code >= 300:
            raise OpenBaoError(f"OpenBao store failed ({resp.status_code}): {resp.text[:200]}")


def get_device_credentials(tenant_id: str, credential_ref: str) -> DeviceCredentials:
    """Read secret material. Return value must only be held for the
    duration of a single collection/deployment call (see module docstring)."""
    if not OPENBAO_ENABLED:
        raise OpenBaoError("OpenBao integration is disabled (OPENBAO_ENABLED=false)")
    path = _kv_path(tenant_id, credential_ref)
    with _client() as c:
        resp = c.get(f"/v1/{OPENBAO_MOUNT}/data/{path}")
        if resp.status_code == 404:
            raise OpenBaoError(f"No credentials found for ref {credential_ref}")
        if resp.status_code >= 300:
            raise OpenBaoError(f"OpenBao read failed ({resp.status_code}): {resp.text[:200]}")
        data = resp.json().get("data", {}).get("data", {})
    credential_type = data.pop("credential_type", "unknown")
    return DeviceCredentials(credential_type=credential_type, secret=data)


def rotate_device_credentials(
    tenant_id: str,
    credential_ref: str,
    credential_type: str,
    new_secret: Dict[str, Any],
) -> None:
    """Overwrite with new secret material (KV v2 creates a new version;
    prior versions remain in OpenBao's own history per its retention
    policy, not ours -- we never keep a copy)."""
    store_device_credentials(tenant_id, credential_ref, credential_type, new_secret)


def delete_device_credentials(tenant_id: str, credential_ref: str) -> None:
    """Permanently destroy all versions of this secret in OpenBao."""
    if not OPENBAO_ENABLED:
        raise OpenBaoError("OpenBao integration is disabled (OPENBAO_ENABLED=false)")
    path = _kv_path(tenant_id, credential_ref)
    with _client() as c:
        resp = c.delete(f"/v1/{OPENBAO_MOUNT}/metadata/{path}")
        if resp.status_code >= 300 and resp.status_code != 404:
            raise OpenBaoError(f"OpenBao delete failed ({resp.status_code}): {resp.text[:200]}")


def health() -> Dict[str, Any]:
    """Best-effort health probe for GET /api/ai/... style health endpoints
    elsewhere -- never raises, always returns a status dict."""
    if not OPENBAO_ENABLED:
        return {"status": "disabled"}
    if not OPENBAO_TOKEN:
        return {"status": "misconfigured", "reason": "OPENBAO_TOKEN not set"}
    try:
        with httpx.Client(base_url=OPENBAO_ADDR, timeout=5.0) as c:
            resp = c.get("/v1/sys/health")
            if resp.status_code in (200, 429, 472, 473):
                return {"status": "available", "http_status": resp.status_code}
            return {"status": "unavailable", "http_status": resp.status_code}
    except Exception as e:  # noqa: BLE001
        return {"status": "unavailable", "error": str(e)}


def redact_secret_values(text: str, secret: Dict[str, Any]) -> str:
    """Defense-in-depth for RULE 6 (secrets never leak into logs, error
    messages, evidence, alerts, or reports). Collectors/deployers/verifiers
    build `error=f"...: {e}"` strings from third-party library exceptions
    (netmiko, ncclient, pyats/unicon, httpx, pysnmp) whose exact wording is
    outside our control -- some versions of these libraries are known to
    echo connection parameters, including cleartext credentials, into
    exception messages. Rather than trust every third-party exception
    string to never contain a secret, scrub any value from `secret` that
    actually appears verbatim in the text before that text is ever stored
    on a model, logged, or returned in an API response. Values that are
    empty, None, or too short to be meaningfully secret (<4 chars, e.g. a
    port number) are left alone -- redacting short substrings would mangle
    unrelated text and isn't needed for security.
    """
    if not text or not secret:
        return text
    redacted = text
    for key, value in secret.items():
        if not isinstance(value, str) or len(value) < 4:
            continue
        if value and value in redacted:
            redacted = redacted.replace(value, f"[REDACTED:{key}]")
    return redacted
