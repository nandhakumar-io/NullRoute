"""Config-injection transport registry -- same shape as
services/deployment/registry.py and services/verification/registry.py."""
from __future__ import annotations

from typing import Dict, Optional

from app.services.config_injection.base import BaseInjector
from app.services.config_injection.gnmi import GnmiInjector

_INJECTORS: Dict[str, BaseInjector] = {
    "gnmi": GnmiInjector(),
}


def get_injector(transport: Optional[str] = None) -> Optional[BaseInjector]:
    if transport is None:
        return None
    return _INJECTORS.get(transport)
