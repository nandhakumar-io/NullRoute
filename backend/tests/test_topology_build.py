"""POST /api/topology/build: the config-upload topology-build path.

Regression coverage for the reported bug: uploading configs from the
Topology page triggered the full compliance-scan pipeline
(scan_runner.start_scan_task) instead of building an actual topology, and
every uploaded file was collapsed onto one shared "Ad-Hoc Config Uploads"
device (via routers/scans.py's _adhoc_device), so a multi-file upload could
never show a real multi-node network.

This endpoint must instead: create one Device per file, run only the
deterministic/LLM-fallback structural parse (services/topology_service.py),
and never call scan_runner at all.
"""
import pytest
from fastapi.testclient import TestClient

from app.auth import dependencies as deps_mod
from app.auth import jwt as jwt_mod

CISCO_CFG = b"""
hostname CORE-SW-01
!
interface GigabitEthernet1/0/1
 description Uplink
 ip address 10.10.10.1 255.255.255.252
!
vlan 100
 name USERS
!
ip route 0.0.0.0 0.0.0.0 10.10.10.2
!
"""

JUNOS_CFG = b"""
set system host-name EDGE-RTR-01
set interfaces ge-0/0/0 unit 0 family inet address 10.20.20.1/30
set vlans VLAN20 vlan-id 20
set routing-options static route 0.0.0.0/0 next-hop 10.20.20.2
"""


@pytest.fixture(autouse=True)
def _demo_auth(monkeypatch):
    monkeypatch.setattr(jwt_mod, "AUTH_ENABLED", False)
    monkeypatch.setattr(deps_mod, "AUTH_ENABLED", False)
    yield


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("MINIO_ENABLED", "false")
    # Ollama unreachable on purpose -- the LLM fallback must degrade to "no
    # facts added" rather than block or fail the build.
    monkeypatch.setenv("OLLAMA_HOST", "http://127.0.0.1:1")
    monkeypatch.setenv("AI_LLM_TIMEOUT_SECONDS", "1")
    from app.main import app
    from app.services import scan_runner

    calls = {"start_scan_task": 0}

    def fake_start_scan_task(*a, **kw):
        calls["start_scan_task"] += 1

    monkeypatch.setattr(scan_runner, "start_scan_task", fake_start_scan_task)

    with TestClient(app) as client:
        yield client, calls


def test_build_creates_one_device_per_file_and_never_scans(env):
    client, calls = env
    files = [
        ("files", ("core-sw-01.cfg", CISCO_CFG, "text/plain")),
        ("files", ("edge-rtr-01.cfg", JUNOS_CFG, "text/plain")),
    ]
    r = client.post("/api/topology/build", files=files, data={"group_name": "Test Block"})
    assert r.status_code == 200, r.text
    body = r.json()

    assert len(body["devices"]) == 2
    device_ids = {d["device_id"] for d in body["devices"]}
    assert len(device_ids) == 2, "each uploaded file must get its own device, not a shared ad-hoc one"

    cisco = next(d for d in body["devices"] if d["filename"] == "core-sw-01.cfg")
    assert cisco["hostname"] == "CORE-SW-01"
    assert cisco["interfaces"] >= 1
    assert cisco["vlans"] == 1
    assert cisco["routes"] == 1

    junos = next(d for d in body["devices"] if d["filename"] == "edge-rtr-01.cfg")
    assert junos["hostname"] == "EDGE-RTR-01"
    assert junos["interfaces"] >= 1
    assert junos["vlans"] == 1
    assert junos["routes"] == 1

    assert body["group_id"] is not None
    assert body["group_name"] == "Test Block"

    # The core assertion: building topology must never run the compliance
    # scan pipeline.
    assert calls["start_scan_task"] == 0

    # And the persisted rows are real, queryable via the existing topology
    # endpoints -- not just present in the build response.
    ifaces = client.get(f"/api/devices/{cisco['device_id']}/interfaces").json()
    assert any(i["name"] == "GigabitEthernet1/0/1" and i["ip_address"] == "10.10.10.1" for i in ifaces)


def test_build_isolates_a_bad_file(env):
    client, calls = env
    files = [
        ("files", ("good.cfg", CISCO_CFG, "text/plain")),
        ("files", ("bad.bin", b"\xff\xfe\x00\x01" * 10, "application/octet-stream")),
    ]
    r = client.post("/api/topology/build", files=files)
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["devices"]) == 2
    good = next(d for d in body["devices"] if d["filename"] == "good.cfg")
    assert good["error"] is None
    assert good["interfaces"] >= 1