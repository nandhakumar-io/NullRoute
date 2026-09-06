import httpx
import pytest
import respx

from app.services import fabric_service
from app.services.fabric_service import FabricNotConfiguredError, FabricUnavailableError

EVIDENCE_URL = f"{fabric_service.FABRIC_GATEWAY_URL}/evidence"


@pytest.mark.asyncio
async def test_anchor_disabled_raises_not_configured(monkeypatch):
    monkeypatch.setattr(fabric_service, "FABRIC_ENABLED", False)
    with pytest.raises(FabricNotConfiguredError):
        await fabric_service.anchor_evidence("ev-1", "deadbeef")


@pytest.mark.asyncio
async def test_health_check_disabled_reports_disabled(monkeypatch):
    monkeypatch.setattr(fabric_service, "FABRIC_ENABLED", False)
    result = await fabric_service.health_check()
    assert result == {"enabled": False, "healthy": False, "status": "DISABLED"}


@pytest.mark.asyncio
@respx.mock
async def test_anchor_evidence_success(monkeypatch):
    monkeypatch.setattr(fabric_service, "FABRIC_ENABLED", True)
    respx.post(EVIDENCE_URL).mock(
        return_value=httpx.Response(
            201, json={"evidenceId": "ev-1", "evidenceHash": "deadbeef", "txId": "tx-123", "docType": "evidenceAnchor"}
        )
    )
    result = await fabric_service.anchor_evidence(
        "ev-1", "deadbeef", scan_id="scan-1", final_decision="BLOCK"
    )
    assert result["status"] == "ANCHORED"
    assert result["transaction_id"] == "tx-123"


@pytest.mark.asyncio
@respx.mock
async def test_anchor_evidence_unavailable_raises_after_retries(monkeypatch):
    monkeypatch.setattr(fabric_service, "FABRIC_ENABLED", True)
    monkeypatch.setattr(fabric_service, "FABRIC_MAX_RETRIES", 2)
    monkeypatch.setattr(fabric_service, "FABRIC_RETRY_BASE_SECONDS", 0.0)
    respx.post(EVIDENCE_URL).mock(side_effect=httpx.ConnectError("connection refused"))
    with pytest.raises(FabricUnavailableError):
        await fabric_service.anchor_evidence("ev-2", "cafebabe")


@pytest.mark.asyncio
@respx.mock
async def test_anchor_evidence_never_reports_success_on_error(monkeypatch):
    """Section 19: a 5xx/garbage gateway response must never surface as a
    successful anchor with a fabricated transaction id."""
    monkeypatch.setattr(fabric_service, "FABRIC_ENABLED", True)
    monkeypatch.setattr(fabric_service, "FABRIC_MAX_RETRIES", 1)
    respx.post(EVIDENCE_URL).mock(return_value=httpx.Response(500, json={"error": "chaincode error"}))
    with pytest.raises(FabricUnavailableError):
        await fabric_service.anchor_evidence("ev-3", "0000")


@pytest.mark.asyncio
@respx.mock
async def test_verify_evidence_match(monkeypatch):
    monkeypatch.setattr(fabric_service, "FABRIC_ENABLED", True)
    respx.post(f"{fabric_service.FABRIC_GATEWAY_URL}/evidence/ev-1/verify").mock(
        return_value=httpx.Response(200, json={"evidenceId": "ev-1", "match": True, "status": "INTEGRITY_VERIFIED"})
    )
    result = await fabric_service.verify_evidence("ev-1", "deadbeef")
    assert result["match"] is True
    assert result["status"] == "INTEGRITY_VERIFIED"


@pytest.mark.asyncio
@respx.mock
async def test_verify_evidence_mismatch():
    fabric_service.FABRIC_ENABLED = True
    try:
        respx.post(f"{fabric_service.FABRIC_GATEWAY_URL}/evidence/ev-1/verify").mock(
            return_value=httpx.Response(
                200, json={"evidenceId": "ev-1", "match": False, "status": "INTEGRITY_FAILURE"}
            )
        )
        result = await fabric_service.verify_evidence("ev-1", "tampered-hash")
        assert result["match"] is False
        assert result["status"] == "INTEGRITY_FAILURE"
    finally:
        fabric_service.FABRIC_ENABLED = False


@pytest.mark.asyncio
async def test_get_evidence_disabled_raises():
    with pytest.raises(FabricNotConfiguredError):
        await fabric_service.get_evidence("ev-1")


@pytest.mark.asyncio
@respx.mock
async def test_get_history_returns_list(monkeypatch):
    monkeypatch.setattr(fabric_service, "FABRIC_ENABLED", True)
    respx.get(f"{fabric_service.FABRIC_GATEWAY_URL}/evidence/ev-1/history").mock(
        return_value=httpx.Response(200, json=[{"evidenceId": "ev-1", "txId": "tx-1"}])
    )
    history = await fabric_service.get_history("ev-1")
    assert isinstance(history, list)
    assert history[0]["txId"] == "tx-1"


@pytest.mark.asyncio
@respx.mock
async def test_anchor_evidence_idempotency_violation_raises(monkeypatch):
    """Section 16: Idempotent anchor but DIFFERENT hash must be rejected."""
    monkeypatch.setattr(fabric_service, "FABRIC_ENABLED", True)
    monkeypatch.setattr(fabric_service, "FABRIC_MAX_RETRIES", 1)
    respx.post(EVIDENCE_URL).mock(
        return_value=httpx.Response(500, json={"error": "idempotency violation: evidenceId ev-1 already exists with different hash deadbeef"})
    )
    with pytest.raises(FabricUnavailableError, match="idempotency violation"):
        await fabric_service.anchor_evidence("ev-1", "cafebabe")
