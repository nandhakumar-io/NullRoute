"""Verifier registry -- same shape as services/deployment/registry.py."""
from __future__ import annotations

from typing import Dict, Optional

from app.services.verification.base import BaseVerifier
from app.services.verification.pyats_genie import PyatsGenieVerifier

_VERIFIERS: Dict[str, BaseVerifier] = {
    "pyats_genie": PyatsGenieVerifier(),
}


def get_verifier(engine: Optional[str] = None) -> Optional[BaseVerifier]:
    if engine is None:
        return None
    return _VERIFIERS.get(engine)
