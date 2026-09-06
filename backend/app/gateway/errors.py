"""Device Gateway error taxonomy (Part 12).

Every failure the gateway can produce -- signature/replay/tenant rejections,
device connectivity problems, or credential resolution failures -- maps to
exactly one of these codes. `GatewayError.message` must never contain a
secret value (password, private key, token, SNMP community); construction
sites are responsible for that, this module only carries the classification.
"""
from __future__ import annotations

from enum import Enum


class GatewayErrorCode(str, Enum):
    DEVICE_UNREACHABLE = "DEVICE_UNREACHABLE"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    PROTOCOL_UNSUPPORTED = "PROTOCOL_UNSUPPORTED"
    COMMAND_TIMEOUT = "COMMAND_TIMEOUT"
    CONFIG_COLLECTION_FAILED = "CONFIG_COLLECTION_FAILED"
    PARSER_FAILED = "PARSER_FAILED"
    INVALID_JOB_SIGNATURE = "INVALID_JOB_SIGNATURE"
    EXPIRED_JOB = "EXPIRED_JOB"
    REPLAYED_JOB = "REPLAYED_JOB"
    TENANT_MISMATCH = "TENANT_MISMATCH"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVAL_INVALID = "APPROVAL_INVALID"
    DEVICE_NOT_FOUND = "DEVICE_NOT_FOUND"
    CREDENTIAL_UNAVAILABLE = "CREDENTIAL_UNAVAILABLE"
    MALFORMED_ENVELOPE = "MALFORMED_ENVELOPE"
    OPERATION_UNSUPPORTED = "OPERATION_UNSUPPORTED"
    REQUESTER_INVALID = "REQUESTER_INVALID"
    CONCURRENCY_LIMIT = "CONCURRENCY_LIMIT"


class GatewayError(Exception):
    """Raised by validator/worker code. `code` is always safe to serialize
    and return to a caller; `message` is a short, secret-free description."""

    def __init__(self, code: GatewayErrorCode, message: str):
        super().__init__(message)
        self.code = code
        self.message = message

    def to_dict(self) -> dict:
        return {"error_code": self.code.value, "error_message": self.message}