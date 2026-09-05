"""Static OpenConfig schema validation (spec section 25 steps 5-6).

This is deliberately conservative: it checks that a path's root container
belongs to a model we recognize, not full YANG type-checking (that would
require bundling the entire OpenConfig model tree). Real type validation
against the target's actual schema still happens via a live Capabilities
check in config_injection/gnmi.py before any Set is issued -- this module
only rejects requests that are structurally wrong before they ever reach
the network.
"""
from __future__ import annotations

from typing import Any, Dict


class SchemaMismatch(Exception):
    """Raised for any OpenConfig model/path/value validation failure."""


# root container each supported model is rooted under
_MODEL_ROOTS: Dict[str, str] = {
    "openconfig-interfaces": "/interfaces",
    "openconfig-system": "/system",
    "openconfig-acl": "/acl",
    "openconfig-network-instance": "/network-instances",
}


def known_models() -> Dict[str, str]:
    return dict(_MODEL_ROOTS)


def validate_model(model: str) -> None:
    if model not in _MODEL_ROOTS:
        raise SchemaMismatch(f"unrecognized OpenConfig model '{model}'; supported models are {sorted(_MODEL_ROOTS)}")


def validate_path(model: str, path: str) -> None:
    validate_model(model)
    root = _MODEL_ROOTS[model]
    if not isinstance(path, str) or not path.startswith(root):
        raise SchemaMismatch(f"path '{path}' does not belong to model '{model}' (expected prefix '{root}')")


def validate_value(path: str, value: Any) -> None:
    """A leaf's value must be a scalar (str/bool/int/float) or None
    (used for delete). A dict/list at a leaf path is a structural error
    -- most likely the caller meant to target a container, not a leaf."""
    if isinstance(value, (dict, list)):
        raise SchemaMismatch(f"value for path '{path}' must be a scalar; got {type(value).__name__}")
