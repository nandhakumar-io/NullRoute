import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("OPA_URL", "http://opa.test")
os.environ.setdefault("OPA_FAIL_MODE", "block")
os.environ.setdefault("FABRIC_GATEWAY_URL", "http://fabric-gateway.test")
os.environ.setdefault("FABRIC_MAX_RETRIES", "2")
os.environ.setdefault("FABRIC_RETRY_BASE_SECONDS", "0.01")
os.environ.setdefault("JOB_SIGNING_SECRET", "test-signing-secret")
os.environ.setdefault("GATEWAY_MOCK_CONNECTOR", "true")
os.environ.setdefault("JOB_TTL_SECONDS", "120")

# KNOWN ISSUE (not fixed here -- see chat writeup): app/db.py builds its
# SQLAlchemy engine once at import time from os.environ["DATABASE_URL"].
# Several test files (test_change_requests.py, test_alert_service.py, ...)
# set DATABASE_URL per-test via monkeypatch and re-`from app.main import
# app`, expecting an isolated database each time. Because Python caches
# modules, only the first test in the whole pytest *session* actually gets
# its own engine; later tests in other files can silently share it,
# producing order-dependent failures when the full suite runs together
# (compare: tests pass file-by-file, some fail only in `pytest tests/`).
# A blanket sys.modules purge was tried and reverted -- it breaks the many
# tests that monkeypatch module objects (e.g. app.auth.jwt) captured at
# collection time, since a fresh import creates a new object the patch no
# longer applies to. The real fix is to stop caching the engine at import
# time (e.g. build it lazily from a function, or key a small cache by
# DATABASE_URL) so app/db.py itself is test-isolation-safe; that's a
# app/db.py change, not a conftest one, and is out of scope for this pass.