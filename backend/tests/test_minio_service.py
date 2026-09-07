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


class _FakeClient:
    """Stands in for minio.Minio. bucket_has_object_lock controls whether
    `get_object_lock_config` succeeds (locked bucket) or raises the same
    S3Error MinIO returns for a bucket with no lock config -- mirrors the
    two real states _ensure_bucket has to distinguish."""

    def __init__(self, bucket_exists=True, bucket_has_object_lock=True):
        self._bucket_exists = bucket_exists
        self._bucket_has_object_lock = bucket_has_object_lock
        self.put_calls = []
        self.retention_calls = []
        self.made_bucket_with_lock = None

    def bucket_exists(self, bucket):
        return self._bucket_exists

    def make_bucket(self, bucket, object_lock=False):
        self._bucket_exists = True
        self.made_bucket_with_lock = object_lock
        self._bucket_has_object_lock = object_lock

    def get_object_lock_config(self, bucket):
        if not self._bucket_has_object_lock:
            from minio.error import S3Error

            raise S3Error(
                response=None, code="ObjectLockConfigurationNotFoundError", message="not configured",
                resource="resource", request_id="request-id", host_id="host-id",
            )
        return object()

    def put_object(self, bucket, key, stream, length, content_type="application/octet-stream"):
        self.put_calls.append({"bucket": bucket, "key": key, "data": stream.read(), "length": length,
                                "content_type": content_type})

    def set_object_retention(self, bucket, key, config=None, version_id=None):
        self.retention_calls.append({"bucket": bucket, "key": key, "config": config})


def test_put_object_uses_real_client_when_available(monkeypatch):
    client = _FakeClient()

    monkeypatch.setattr(minio_service, "MINIO_ENABLED", True)
    monkeypatch.setattr(minio_service, "_get_client", lambda: client)
    monkeypatch.setattr(minio_service, "_bucket_ready", False)
    monkeypatch.setattr(minio_service, "_bucket_object_lock_status", None)

    result = minio_service.put_object("tenants/t/devices/d/scans/s/raw.cfg", b"hostname r1\n")
    assert result is not None
    assert result.object_key == "tenants/t/devices/d/scans/s/raw.cfg"
    assert result.sha256 == __import__("hashlib").sha256(b"hostname r1\n").hexdigest()
    assert client.put_calls[0]["data"] == b"hostname r1\n"
    # Not requested as immutable -> no retention call, even though the
    # bucket has object lock available.
    assert client.retention_calls == []


def test_put_object_returns_none_on_backend_error(monkeypatch):
    class FailingClient:
        def bucket_exists(self, bucket):
            raise RuntimeError("connection refused")

    monkeypatch.setattr(minio_service, "MINIO_ENABLED", True)
    monkeypatch.setattr(minio_service, "_get_client", lambda: FailingClient())
    monkeypatch.setattr(minio_service, "_bucket_ready", False)
    monkeypatch.setattr(minio_service, "_bucket_object_lock_status", None)

    result = minio_service.put_object("tenants/t/devices/d/scans/s/raw.cfg", b"data")
    assert result is None  # degrades gracefully, does not raise


def test_immutable_put_applies_retention_when_bucket_supports_object_lock(monkeypatch):
    client = _FakeClient(bucket_exists=False)  # forces make_bucket(object_lock=True) path

    monkeypatch.setattr(minio_service, "MINIO_ENABLED", True)
    monkeypatch.setattr(minio_service, "MINIO_OBJECT_LOCK_ENABLED", True)
    monkeypatch.setattr(minio_service, "_get_client", lambda: client)
    monkeypatch.setattr(minio_service, "_bucket_ready", False)
    monkeypatch.setattr(minio_service, "_bucket_object_lock_status", None)

    result = minio_service.put_object(
        "tenants/t/devices/d/scans/s/evidence.json", b"{}", content_type="application/json", immutable=True,
    )
    assert result is not None
    assert client.made_bucket_with_lock is True
    assert len(client.retention_calls) == 1
    assert client.retention_calls[0]["key"] == "tenants/t/devices/d/scans/s/evidence.json"


def test_immutable_put_downgrades_gracefully_when_bucket_lacks_object_lock(monkeypatch):
    """A bucket created before this feature existed can't retroactively get
    Object Lock -- immutable=True must not raise or fail the write, just
    skip the retention call (the gap is surfaced via health(), not here)."""
    client = _FakeClient(bucket_exists=True, bucket_has_object_lock=False)

    monkeypatch.setattr(minio_service, "MINIO_ENABLED", True)
    monkeypatch.setattr(minio_service, "MINIO_OBJECT_LOCK_ENABLED", True)
    monkeypatch.setattr(minio_service, "_get_client", lambda: client)
    monkeypatch.setattr(minio_service, "_bucket_ready", False)
    monkeypatch.setattr(minio_service, "_bucket_object_lock_status", None)

    result = minio_service.put_object(
        "tenants/t/devices/d/scans/s/evidence.json", b"{}", immutable=True,
    )
    assert result is not None  # write still succeeds
    assert client.retention_calls == []  # but no retention applied


def test_health_reports_object_lock_warning_when_bucket_unlocked(monkeypatch):
    client = _FakeClient(bucket_exists=True, bucket_has_object_lock=False)

    monkeypatch.setattr(minio_service, "MINIO_ENABLED", True)
    monkeypatch.setattr(minio_service, "MINIO_LIB_AVAILABLE", True)
    monkeypatch.setattr(minio_service, "MINIO_ACCESS_KEY", "k")
    monkeypatch.setattr(minio_service, "MINIO_SECRET_KEY", "s")
    monkeypatch.setattr(minio_service, "MINIO_OBJECT_LOCK_ENABLED", True)
    monkeypatch.setattr(minio_service, "_get_client", lambda: client)
    monkeypatch.setattr(minio_service, "_bucket_ready", False)
    monkeypatch.setattr(minio_service, "_bucket_object_lock_status", None)

    result = minio_service.health()
    assert result["status"] == "available"
    assert result["object_lock"] is False
    assert "cannot be enabled retroactively" in result["object_lock_warning"]