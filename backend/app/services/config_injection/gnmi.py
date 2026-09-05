"""gNMI/OpenConfig injector (spec sections 22-28).

Feature-flagged (GNMI_ENABLED / OPENCONFIG_ENABLED) and optional-dependency
(pygnmi), following the exact discipline used everywhere else in this
codebase: never crash, never fabricate success, never silently fall back
to another transport, and never touch the network with a request that
fails static schema validation.

Safety sequence per Set (section 25):
  1. credentials resolved by the caller (deployment_service.py via
     OpenBao) -- this module only holds them for the duration of the call
  2. static schema validation (openconfig.validate_path/validate_value)
     -- BEFORE any network call
  3. Capabilities() -- verify the target actually advertises the
     requested model
  4. construct and send the validated SetRequest
  5. return a request_hash of exactly what was sent, never credentials
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import List

from app.models.db import Device
from app.services.config_injection import openconfig
from app.services.config_injection.base import BaseInjector
from app.services.config_injection.result import (
    GNMI_DISABLED, GNMI_FAILED, GNMI_OK, GNMI_SCHEMA_MISMATCH,
    GNMI_UNAVAILABLE, GnmiResult, GnmiUpdate,
)
from app.services.openbao_service import DeviceCredentials, redact_secret_values

try:
    from pygnmi.client import gNMIclient
    PYGNMI_AVAILABLE = True
except ImportError:  # pragma: no cover
    PYGNMI_AVAILABLE = False
    gNMIclient = None


def _gnmi_enabled() -> bool:
    return os.environ.get("GNMI_ENABLED", "false").strip().lower() == "true"


class GnmiInjector(BaseInjector):
    transport = "gnmi"

    def _client(self, device: Device, credentials: DeviceCredentials):
        secret = credentials.secret
        management_address = getattr(device, "management_address", None) or device.hostname
        port = int(os.environ.get("GNMI_PORT", secret.get("gnmi_port", 6030)))
        timeout = int(os.environ.get("GNMI_TIMEOUT", 20))
        tls_enabled = os.environ.get("GNMI_TLS_ENABLED", "true").strip().lower() == "true"
        kwargs = dict(
            target=(management_address, port),
            username=secret.get("username"),
            password=secret.get("password"),
            timeout=timeout,
            insecure=not tls_enabled,
        )
        ca_cert = os.environ.get("GNMI_CA_CERT")
        if tls_enabled and ca_cert:
            kwargs["path_cert"] = ca_cert
        return gNMIclient(**kwargs)

    def capabilities(self, device: Device, credentials: DeviceCredentials) -> GnmiResult:
        if not _gnmi_enabled():
            return GnmiResult(success=False, status=GNMI_DISABLED, error="GNMI_ENABLED is not set to true")
        if not PYGNMI_AVAILABLE:
            return GnmiResult(success=False, status=GNMI_UNAVAILABLE, error="pygnmi is not installed")
        try:
            with self._client(device, credentials) as client:
                caps = client.capabilities()
            return GnmiResult(success=True, status=GNMI_OK, data=caps)
        except Exception as e:  # noqa: BLE001 -- must degrade, never crash the caller
            return GnmiResult(success=False, status=GNMI_UNAVAILABLE,
                               error=redact_secret_values(str(e), credentials.secret))

    def set(self, device: Device, credentials: DeviceCredentials, updates: List[GnmiUpdate]) -> GnmiResult:
        if not _gnmi_enabled():
            return GnmiResult(success=False, status=GNMI_DISABLED, error="GNMI_ENABLED is not set to true")
        if not PYGNMI_AVAILABLE:
            return GnmiResult(success=False, status=GNMI_UNAVAILABLE, error="pygnmi is not installed")
        if not updates:
            return GnmiResult(success=False, status=GNMI_SCHEMA_MISMATCH, error="no updates supplied")

        # Step 2: static schema validation BEFORE touching the network.
        try:
            for u in updates:
                openconfig.validate_path(u.model, u.path)
                if u.operation != "delete":
                    openconfig.validate_value(u.path, u.value)
        except openconfig.SchemaMismatch as e:
            return GnmiResult(success=False, status=GNMI_SCHEMA_MISMATCH, error=str(e))

        operation = updates[0].operation
        model = updates[0].model
        if any(u.operation != operation or u.model != model for u in updates):
            return GnmiResult(success=False, status=GNMI_SCHEMA_MISMATCH, error="all updates in one Set must share the same model and operation")

        try:
            with self._client(device, credentials) as client:
                # Step 3: verify the live target advertises this model --
                # our own static allow-list is necessary but not sufficient.
                caps = client.capabilities()
                supported = {m.get("name") for m in caps.get("supported_models", [])} if isinstance(caps, dict) else set()
                if supported and model not in supported:
                    return GnmiResult(success=False, status=GNMI_SCHEMA_MISMATCH, error=f"target Capabilities did not advertise model '{model}'")

                # Step 4: construct and send the validated SetRequest.
                kw = {"update": None, "replace": None, "delete": None}
                if operation == "update":
                    kw["update"] = [(u.path, u.value) for u in updates]
                elif operation == "replace":
                    kw["replace"] = [(u.path, u.value) for u in updates]
                elif operation == "delete":
                    kw["delete"] = [u.path for u in updates]
                else:
                    return GnmiResult(success=False, status=GNMI_SCHEMA_MISMATCH, error=f"unsupported operation '{operation}'")

                response = client.set(**kw)

            request_hash = hashlib.sha256(
                json.dumps([u.__dict__ for u in updates], sort_keys=True, default=str).encode("utf-8")
            ).hexdigest()
            return GnmiResult(success=True, status=GNMI_OK, request_hash=request_hash, data=response)
        except TimeoutError as e:
            return GnmiResult(success=False, status=GNMI_FAILED,
                               error=redact_secret_values(f"timed out: {e}", credentials.secret))
        except Exception as e:  # noqa: BLE001 -- must degrade, never crash the caller
            return GnmiResult(success=False, status=GNMI_FAILED,
                               error=redact_secret_values(str(e), credentials.secret))
