"""Base interface for optional standards-based configuration-injection
transports (spec sections 22-28). Today only gNMI/OpenConfig implements
this; the interface exists so a future transport doesn't require
reshaping the ChangeRequest/deployment bridge again.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from app.models.db import Device
from app.services.config_injection.result import GnmiResult, GnmiUpdate
from app.services.openbao_service import DeviceCredentials


class BaseInjector(ABC):
    transport: str = "unknown"

    @abstractmethod
    def capabilities(self, device: Device, credentials: DeviceCredentials) -> GnmiResult:
        raise NotImplementedError

    @abstractmethod
    def set(self, device: Device, credentials: DeviceCredentials, updates: List[GnmiUpdate]) -> GnmiResult:
        raise NotImplementedError
