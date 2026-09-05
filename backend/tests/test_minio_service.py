import pytest

from app.services import minio_service


def test_object_key_naming_convention():
    key = minio_service.object_key("tenant-a", "dev-1", "scan-1", "raw.cfg")
    assert key == "tenants/tenant-a/devices/dev-1/scans/scan-1/raw.cfg"


def test_put_object_degrades_gracefully_when_disabled(monkeypatch):
    monkeypatch.setattr(minio_service, "MINIO_ENABLED", False)
    result = minio_service.put_object("tenants/t/devices/d/scans/s/raw.cfg", b"hello")
    assert result is None  # best-effort: never raises, never blocks the caller


def test_get_object_raises_when_disabled(monkeypatch):
    monkeypatch.setattr(minio_service, "MINIO_ENABLED", False)
    with pytest.raises(minio_service.ObjectStoreError):
        minio_service.get_object("tenants/t/devices/d/scans/s/raw.cfg")


def test_health_reports_disabled(monkeypatch):
    monkeypatch.setattr(minio_service, "MINIO_ENABLED", False)
    assert minio_service.health() == {"status": "disabled"}


def test_health_reports_misconfigured_when_enabled_without_credentials(monkeypatch):
    monkeypatch.setattr(minio_service, "MINIO_ENABLED", True)
    monkeypatch.setattr(minio_service, "MINIO_LIB_AVAILABLE", True)
    monkeypatch.setattr(minio_service, "MINIO_ACCESS_KEY", "")
    monkeypatch.setattr(minio_service, "MINIO_SECRET_KEY", "")
    monkeypatch.setattr(minio_service, "_client", None)
    assert minio_service.health() == {"status": "misconfigured"}


def test_put_object_uses_real_client_when_available(monkeypatch):
    calls = {}

    class FakeClient:
        def bucket_exists(self, bucket):
            return True

        def put_object(self, bucket, key, stream, length):
            calls["bucket"] = bucket
            calls["key"] = key
            calls["data"] = stream.read()
            calls["length"] = length

    monkeypatch.setattr(minio_service, "MINIO_ENABLED", True)
    monkeypatch.setattr(minio_service, "_get_client", lambda: FakeClient())
    monkeypatch.setattr(minio_service, "_bucket_ready", False)

    result = minio_service.put_object("tenants/t/devices/d/scans/s/raw.cfg", b"hostname r1\n")
    assert result is not None
    assert result.object_key == "tenants/t/devices/d/scans/s/raw.cfg"
    assert result.sha256 == __import__("hashlib").sha256(b"hostname r1\n").hexdigest()
    assert calls["data"] == b"hostname r1\n"


def test_put_object_returns_none_on_backend_error(monkeypatch):
    class FailingClient:
        def bucket_exists(self, bucket):
            raise RuntimeError("connection refused")

    monkeypatch.setattr(minio_service, "MINIO_ENABLED", True)
    monkeypatch.setattr(minio_service, "_get_client", lambda: FailingClient())
    monkeypatch.setattr(minio_service, "_bucket_ready", False)

    result = minio_service.put_object("tenants/t/devices/d/scans/s/raw.cfg", b"data")
    assert result is None  # degrades gracefully, does not raise