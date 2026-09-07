import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("OPA_URL", "http://opa.test")
os.environ.setdefault("OPA_FAIL_MODE", "block")
os.environ.setdefault("FABRIC_GATEWAY_URL", "http://fabric-gateway.test")
os.environ.setdefault("FABRIC_MAX_RETRIES", "2")
os.environ.setdefault("FABRIC_RETRY_BASE_SECONDS", "0.01")
