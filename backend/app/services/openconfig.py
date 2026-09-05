"""OpenConfig safety checks (spec section 25): before any gNMI Set,
verify the requested model is one this deployment supports, the path
looks like a real OpenConfig path for that model, and the value's type
is sane for the path. This is intentionally a lightweight allow-list,
NOT a full YANG schema validator -- OPENCONFIG_MODEL_PATH lets an
operator point at a real YANG model directory for stricter validation
later; until then this catches the obvious unsafe-request classes
(wrong model, malformed path, wrong value type) without pretending to
be a complete schema engine.

OpenConfig models are vendor-neutral YANG models covering configuration
and operational state; gNMI provides Capabilities/Get/Set/Subscribe.
"""
from __future__ import annotations

from typing import Any, Dict

# Supported OpenConfig modules for this deployment, and the path prefix
# each one's paths must start with. Extending this list is the intended
# way to add support for another OpenConfig module -- do not silently
# accept an unlisted model.
SUPPORTED_MODELS: Dict[str, str] = {
    "openconfig-interfaces": "/interfaces",
    "openconfig-system": "/system",
    "openconfig-acl": "/acl",
    "openconfig-network-instance": "/network-instances",
}

# Coarse per-prefix expected value type, for the handful of leaves this
# deployment actually writes. Anything not listed here just gets a
# type-is-JSON-serializable check rather than a hard reject, since the
# allow-list can't enumerate every leaf of every module up front.
_EXPECTED_TYPES = {
    "/interfaces": (bool, str, int),
    "/system": (str, int, bool),
    "/acl": (str, int, bool, list, dict),
    "/network-instances": (str, int, bool, list, dict),
}


class SchemaMismatch(ValueError):
    pass


def validate_model(model: str) -> None:
    if model not in SUPPORTED_MODELS:
        raise SchemaMismatch(
            f"Unsupported OpenConfig model '{model}'; supported models are {sorted(SUPPORTED_MODELS)}"
        )


def validate_path(model: str, path: str) -> None:
    validate_model(model)
    prefix = SUPPORTED_MODELS[model]
    if not path.startswith(prefix):
        raise SchemaMismatch(
            f"Path '{path}' does not belong to model '{model}' (expected prefix '{prefix}')"
        )
    if ".." in path or path.count("/") < 1:
        raise SchemaMismatch(f"Path '{path}' is not a well-formed gNMI path")


def validate_value(model: str, path: str, value: Any, operation: str) -> None:
    if operation == "delete":
        return  # delete carries no value
    prefix = SUPPORTED_MODELS.get(model)
    expected = _EXPECTED_TYPES.get(prefix, (str, int, bool, list, dict))
    if not isinstance(value, expected):
        raise SchemaMismatch(
            f"Value for path '{path}' has type {type(value).__name__}, expected one of "
            f"{[t.__name__ for t in expected]}"
        )


def validate_capabilities_support(model: str, supported_models: list) -> None:
    """Cross-check the requested model against the device's own
    Capabilities() response (section 25 step 3-4)."""
    names = {m.get("name") if isinstance(m, dict) else str(m) for m in supported_models}
    if model not in names:
        raise SchemaMismatch(
            f"Device Capabilities() did not report support for model '{model}' "
            f"(reported: {sorted(n for n in names if n)})"
        )