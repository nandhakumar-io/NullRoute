import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("OPA_URL", "http://opa.test")
os.environ.setdefault("OPA_FAIL_MODE", "block")
os.environ.setdefault("FABRIC_GATEWAY_URL", "http://fabric-gateway.test")
os.environ.setdefault("FABRIC_MAX_RETRIES", "2")
os.environ.setdefault("FABRIC_RETRY_BASE_SECONDS", "0.01")
# Background workers (scheduler, training, metrics-poller, vuln-sync,
# evidence-verification, network-scan) now start in-process by default (see
# app/main.py's RUN_EMBEDDED_WORKERS) so a bare `uvicorn`/run.sh is fully
# functional locally. Tests spin up the app via TestClient too, and each
# worker's loop fires an immediate DB poll on startup -- against the test
# DB/transaction, concurrently with whatever a test is asserting. Keep them
# off here; tests that specifically exercise a worker call its `run_once()`/
# `main()` directly and don't need the embedded scheduler at all.
os.environ.setdefault("RUN_EMBEDDED_WORKERS", "false")