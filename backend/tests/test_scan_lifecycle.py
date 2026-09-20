"""Scan lifecycle: force-stop, delete (single + bulk), bulk upload, orphans.

Regression coverage for:
  - "Stop" left scans in STOP_REQUESTED / "Stopping..." forever when there was
    no live pipeline task (reload, already ended, queued), so they kept
    reappearing in the running list and re-stopping returned 409.
  - DELETE /api/scans/{id} and POST /api/scans/bulk-delete didn't exist even
    though the frontend called them.
  - Bulk upload spawned one unbounded pipeline per file.

The real pipeline needs OPA/Batfish/etc., so scan_runner.run_pipeline /
continue_resume are replaced with controllable fakes; everything else (routes,
DB, task registry, cancellation) is the real code.
"""
import asyncio
import time
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.auth import dependencies as deps_mod
from app.auth import jwt as jwt_mod


@pytest.fixture(autouse=True)
def _demo_auth(monkeypatch):
    monkeypatch.setattr(jwt_mod, "AUTH_ENABLED", False)
    monkeypatch.setattr(deps_mod, "AUTH_ENABLED", False)
    yield


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("SCAN_PIPELINE_CONCURRENCY", "2")
    monkeypatch.setenv("SCAN_STOP_GRACE_SECONDS", "2")
    from app.main import app
    from app.services import scan_runner

    state = {"running": 0, "max_running": 0, "started": [], "finished": [], "block": True}

    async def fake_run_pipeline(db, scan, raw_text, framework="ALL", resume_stage=None):
        state["running"] += 1
        state["max_running"] = max(state["max_running"], state["running"])
        state["started"].append(scan.id)
        try:
            scan.status = "normalized"
            db.commit()
            # Long enough that only cancellation can end it early.
            await asyncio.sleep(30 if state["block"] else 0.15)
            scan.status, scan.control_state, scan.final_decision = "completed", "RUNNING", "PASS"
            db.commit()
            state["finished"].append(scan.id)
        finally:
            state["running"] -= 1
        return scan

    async def fake_continue_resume(db, scan):
        return await fake_run_pipeline(db, scan, "", resume_stage="x")

    monkeypatch.setattr(scan_runner, "run_pipeline", fake_run_pipeline)
    monkeypatch.setattr(scan_runner, "continue_resume", fake_continue_resume)

    with TestClient(app) as client:
        yield client, state, scan_runner


def _db():
    from app.db import SessionLocal
    return SessionLocal()


def _mk_scan(status="completed", control_state="RUNNING", **kw):
    """Insert a device + scan directly (no pipeline) and return the scan id."""
    from app.models.db import Device, Scan
    from app.routers.devices import get_or_create_demo_tenant

    db = _db()
    try:
        tenant = get_or_create_demo_tenant(db)
        dev = Device(tenant_id=tenant.id, hostname="sw-" + status)
        db.add(dev)
        db.commit()
        scan = Scan(tenant_id=tenant.id, device_id=dev.id, framework="ALL", status=status,
                    control_state=control_state, **kw)
        db.add(scan)
        db.commit()
        return scan.id
    finally:
        db.close()


def _get(scan_id):
    from app.models.db import Scan
    db = _db()
    try:
        s = db.get(Scan, scan_id)
        return None if s is None else (s.status, s.control_state)
    finally:
        db.close()


def _wait(pred, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.05)
    return False


CFG = b"hostname sw1\nenable secret 5 abc\n"


# ------------------------------------------------------------------ stop ---

def test_force_stop_is_immediate_and_removes_task(env):
    client, state, runner = env
    scan = client.post("/api/scans/upload", files={"file": ("a.cfg", CFG)}).json()
    assert _wait(lambda: scan["id"] in state["started"])
    assert runner.has_live_task(scan["id"])

    t0 = time.time()
    r = client.post(f"/api/scans/{scan['id']}/stop", params={"immediate": True})
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["status"], body["control_state"]) == ("stopped", "STOPPED")
    assert body["stopped_at"]
    assert time.time() - t0 < 2.5  # not waiting on the 30s pipeline
    assert _wait(lambda: not runner.has_live_task(scan["id"]))
    assert state["running"] == 0
    assert scan["id"] not in [s["id"] for s in client.get("/api/scans/running").json()]


def test_stop_is_idempotent_and_finished_is_409(env):
    client, state, _ = env
    scan = client.post("/api/scans/upload", files={"file": ("a.cfg", CFG)}).json()
    assert _wait(lambda: scan["id"] in state["started"])
    assert client.post(f"/api/scans/{scan['id']}/stop", params={"immediate": True}).status_code == 200
    # The screenshot bug: second click -> "nothing to stop" error toast.
    again = client.post(f"/api/scans/{scan['id']}/stop", params={"immediate": True})
    assert again.status_code == 200 and again.json()["control_state"] == "STOPPED"

    done = _mk_scan("completed")
    assert client.post(f"/api/scans/{done}/stop", params={"immediate": True}).status_code == 409
    assert _get(done) == ("completed", "RUNNING")  # untouched, NOT left in STOP_REQUESTED


def test_stop_orphan_without_task_finalizes_immediately(env):
    """A scan stuck in STOP_REQUESTED with no pipeline (the '14 pending' state)."""
    client, _, _ = env
    orphan = _mk_scan("normalized", "STOP_REQUESTED")
    r = client.post(f"/api/scans/{orphan}/stop", params={"immediate": True})
    assert r.status_code == 200
    assert _get(orphan) == ("stopped", "STOPPED")


def test_non_immediate_stop_without_task_also_finalizes(env):
    client, _, _ = env
    orphan = _mk_scan("opa_evaluating", "RUNNING")
    assert client.post(f"/api/scans/{orphan}/stop").status_code == 200
    assert _get(orphan) == ("stopped", "STOPPED")


def test_stop_paused_scan(env):
    client, _, _ = env
    paused = _mk_scan("paused", "PAUSED")
    assert client.post(f"/api/scans/{paused}/stop", params={"immediate": True}).status_code == 200
    assert _get(paused) == ("stopped", "STOPPED")


def test_running_list_repairs_stale_stop_requests(env):
    """Even if nothing calls stop again, a stuck STOP_REQUESTED must not
    linger in the running list (count going down then back up)."""
    client, _, _ = env
    from app.models.db import Scan
    stuck = _mk_scan("normalized", "STOP_REQUESTED")
    fresh = _mk_scan("normalized", "STOP_REQUESTED")
    db = _db()
    try:  # `stuck` has been in that state for a while; `fresh` just got requested
        db.query(Scan).filter(Scan.id == stuck).update({"updated_at": datetime.utcnow() - timedelta(minutes=5)})
        db.commit()
    finally:
        db.close()
    ids = [s["id"] for s in client.get("/api/scans/running").json()]
    assert stuck not in ids
    assert _get(stuck) == ("stopped", "STOPPED")
    assert fresh in ids  # within the grace window it is left for the live pipeline


def test_startup_reconcile_marks_lost_pipelines_resumable(env):
    _, _, runner = env
    running = _mk_scan("opa_evaluating", "RUNNING")
    stopping = _mk_scan("normalized", "STOP_REQUESTED")
    pausing = _mk_scan("normalized", "PAUSE_REQUESTED")
    paused = _mk_scan("paused", "PAUSED")
    done = _mk_scan("completed", "RUNNING")
    db = _db()
    try:
        assert runner.reconcile_stale(db, startup=True) == 3
    finally:
        db.close()
    assert _get(running) == ("stopped", "STOPPED")
    assert _get(stopping) == ("stopped", "STOPPED")
    assert _get(pausing) == ("paused", "PAUSED")
    assert _get(paused) == ("paused", "PAUSED")
    assert _get(done) == ("completed", "RUNNING")


def test_pause_without_live_task_pauses_directly(env):
    client, _, _ = env
    orphan = _mk_scan("normalized", "RUNNING")
    assert client.post(f"/api/scans/{orphan}/pause").status_code == 200
    assert _get(orphan) == ("paused", "PAUSED")
    done = _mk_scan("completed", "RUNNING")
    assert client.post(f"/api/scans/{done}/pause").status_code == 409


def test_resume_runs_in_background_and_returns_immediately(env):
    client, state, runner = env
    state["block"] = True
    sid = _mk_scan("stopped", "STOPPED", raw_config_path="k", pipeline_stage="start")
    t0 = time.time()
    r = client.post(f"/api/scans/{sid}/resume")
    assert r.status_code == 200, r.text
    assert time.time() - t0 < 2  # did not wait for the (30s) pipeline
    assert r.json()["status"] == "resuming"
    assert _wait(lambda: sid in state["started"])
    # ...and because it is a registered task, it can be force-stopped again.
    assert client.post(f"/api/scans/{sid}/stop", params={"immediate": True}).status_code == 200
    assert _get(sid) == ("stopped", "STOPPED")


def test_resume_without_archived_config_is_400(env):
    client, _, _ = env
    sid = _mk_scan("stopped", "STOPPED")
    assert client.post(f"/api/scans/{sid}/resume").status_code == 400


# ----------------------------------------------------------- bulk stop -----

def test_bulk_stop_stops_running_and_queued(env):
    client, state, runner = env
    files = [("files", (f"c{i}.cfg", CFG)) for i in range(5)]
    scans = client.post("/api/scans/bulk-upload", files=files).json()
    ids = [s["id"] for s in scans]
    assert _wait(lambda: len(state["started"]) == 2)  # concurrency limit = 2, 3 queued
    done = _mk_scan("completed")

    r = client.post("/api/scans/bulk-stop", json={"scan_ids": ids + [done, "nope"], "immediate": True})
    assert r.status_code == 200, r.text
    body = r.json()
    assert sorted(body["stopped"]) == sorted(ids)
    assert {s["id"] for s in body["skipped"]} == {done, "nope"}
    for i in ids:
        assert _get(i) == ("stopped", "STOPPED")
    assert _wait(lambda: not any(runner.has_live_task(i) for i in ids))
    assert state["running"] == 0
    # queued ones never started
    assert len(state["started"]) == 2
    assert client.get("/api/scans/running").json() == []


# --------------------------------------------------------- bulk upload -----

def test_bulk_upload_is_bounded_and_isolates_bad_files(env):
    client, state, runner = env
    state["block"] = False
    files = [("files", (f"router{i}.cfg", CFG)) for i in range(6)]
    files.append(("files", ("empty.cfg", b"   \n")))
    files.append(("files", ("blob.bin", b"\x00\x01\x02binary")))
    t0 = time.time()
    r = client.post("/api/scans/bulk-upload", files=files, data={"framework": "ALL"})
    assert r.status_code == 200, r.text
    assert time.time() - t0 < 3  # returns without waiting on pipelines
    scans = r.json()
    assert len(scans) == 8
    good = [s for s in scans if s["status"] != "failed"]
    bad = [s for s in scans if s["status"] == "failed"]
    assert [s["source_filename"] for s in good] == [f"router{i}.cfg" for i in range(6)]
    assert {s["source_filename"] for s in bad} == {"empty.cfg", "blob.bin"}
    assert all(s["error"] for s in bad)
    assert all(s["status"] == "queued" for s in good)

    assert _wait(lambda: len(state["finished"]) == 6, timeout=10)
    assert state["max_running"] <= 2  # SCAN_PIPELINE_CONCURRENCY
    assert state["max_running"] == 2  # ...and it actually used the concurrency
    for s in good:
        assert _get(s["id"]) == ("completed", "RUNNING")


def test_bulk_upload_rejects_oversized_batches(env, monkeypatch):
    client, _, _ = env
    from app.routers import scans as scans_router
    monkeypatch.setattr(scans_router, "MAX_BULK_FILES", 3)
    files = [("files", (f"c{i}.cfg", CFG)) for i in range(4)]
    assert client.post("/api/scans/bulk-upload", files=files).status_code == 413
    assert client.get("/api/scans").json() == []  # nothing half-created


def test_upload_rejects_empty_file(env):
    client, _, _ = env
    assert client.post("/api/scans/upload", files={"file": ("e.cfg", b"")}).status_code == 400


def test_stop_then_delete_queued_scan(env):
    client, state, runner = env
    files = [("files", (f"c{i}.cfg", CFG)) for i in range(4)]
    ids = [s["id"] for s in client.post("/api/scans/bulk-upload", files=files).json()]
    assert _wait(lambda: len(state["started"]) == 2)
    queued = [i for i in ids if i not in state["started"]][0]
    r = client.delete(f"/api/scans/{queued}", params={"force": True})
    assert r.status_code == 200
    assert _get(queued) is None
    assert _wait(lambda: not runner.has_live_task(queued))
    assert queued not in state["started"]  # never ran


# --------------------------------------------------------------- delete ----

def _seed_children(scan_id):
    """Findings + analyses (deleted with the scan) and evidence + topology +
    alerts (kept, detached)."""
    from app.models.db import (Alert, EvidenceRecord, Finding, NetworkInterface, OPAAnalysis, RagDocument, Scan)
    db = _db()
    try:
        scan = db.get(Scan, scan_id)
        f = Finding(scan_id=scan_id, framework="ALL", control_id="C1", title="t", severity="HIGH", result="FAIL")
        db.add(f)
        db.flush()
        db.add(OPAAnalysis(scan_id=scan_id, policy_version="1", decision="BLOCK", decision_id="d", source="opa", result_json={}))
        db.add(RagDocument(tenant_id=scan.tenant_id, source_type="finding", source_id=f.id, title="x", content="y"))
        db.add(EvidenceRecord(evidence_id="ev-" + scan_id, scan_id=scan_id, evidence_json={}, evidence_hash="h"))
        db.add(NetworkInterface(device_id=scan.device_id, tenant_id=scan.tenant_id, scan_id=scan_id, name="Gi0/1"))
        db.commit()
        return f.id
    finally:
        db.close()


def test_delete_scan_removes_children_but_keeps_evidence_and_topology(env):
    client, _, _ = env
    from app.models.db import EvidenceRecord, Finding, NetworkInterface, OPAAnalysis, RagDocument
    sid = _mk_scan("blocked")
    fid = _seed_children(sid)

    r = client.delete(f"/api/scans/{sid}")
    assert r.status_code == 200, r.text
    assert r.json() == {"deleted": sid}
    assert client.get(f"/api/scans/{sid}").status_code == 404

    db = _db()
    try:
        assert db.query(Finding).filter(Finding.scan_id == sid).count() == 0
        assert db.query(OPAAnalysis).filter(OPAAnalysis.scan_id == sid).count() == 0
        assert db.query(RagDocument).filter(RagDocument.source_id == fid).count() == 0
        ev = db.query(EvidenceRecord).filter(EvidenceRecord.evidence_id == "ev-" + sid).one()
        assert ev.scan_id is None  # kept, detached
        assert db.query(NetworkInterface).filter(NetworkInterface.name == "Gi0/1").one().scan_id is None
    finally:
        db.close()


def test_delete_missing_scan_is_404(env):
    client, _, _ = env
    assert client.delete("/api/scans/nope").status_code == 404


def test_delete_running_scan_needs_force(env):
    client, state, runner = env
    scan = client.post("/api/scans/upload", files={"file": ("a.cfg", CFG)}).json()
    assert _wait(lambda: scan["id"] in state["started"])
    r = client.delete(f"/api/scans/{scan['id']}")
    assert r.status_code == 409 and "still running" in r.json()["detail"]
    assert _get(scan["id"]) is not None

    r = client.delete(f"/api/scans/{scan['id']}", params={"force": True})
    assert r.status_code == 200, r.text
    assert _get(scan["id"]) is None
    assert _wait(lambda: not runner.has_live_task(scan["id"]))
    assert state["running"] == 0


def test_delete_golden_baseline_needs_force(env):
    client, _, _ = env
    from app.models.db import BaselineApproval, Scan
    sid = _mk_scan("completed")
    db = _db()
    try:
        s = db.get(Scan, sid)
        db.add(BaselineApproval(tenant_id=s.tenant_id, device_id=s.device_id, scan_id=sid, approved_by="me"))
        db.commit()
    finally:
        db.close()
    r = client.delete(f"/api/scans/{sid}")
    assert r.status_code == 409 and "golden baseline" in r.json()["detail"]  # frontend keys off this text
    assert client.delete(f"/api/scans/{sid}", params={"force": True}).status_code == 200
    assert _get(sid) is None


def test_bulk_delete_partial_success(env):
    client, state, runner = env
    a = _mk_scan("completed")
    b = _mk_scan("blocked")
    _seed_children(b)
    running = client.post("/api/scans/upload", files={"file": ("a.cfg", CFG)}).json()["id"]
    assert _wait(lambda: running in state["started"])

    r = client.post("/api/scans/bulk-delete", json={"scan_ids": [a, b, running, "ghost"]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert sorted(body["deleted"]) == sorted([a, b])
    failed = {f["id"]: f["detail"] for f in body["failed"]}
    assert set(failed) == {running, "ghost"}
    assert "still running" in failed[running]
    assert _get(a) is None and _get(b) is None and _get(running) is not None

    r = client.post("/api/scans/bulk-delete", json={"scan_ids": [running], "force": True})
    assert r.json()["deleted"] == [running] and r.json()["failed"] == []
    assert _get(running) is None
    assert _wait(lambda: not runner.has_live_task(running))


def test_bulk_delete_validates_payload(env):
    client, _, _ = env
    assert client.post("/api/scans/bulk-delete", json={"scan_ids": []}).status_code == 422


def test_delete_many_is_chunked(env):
    """> SQLite's 999 bound-variable limit in one call."""
    client, _, _ = env
    from app.models.db import Device, Scan
    from app.routers.devices import get_or_create_demo_tenant
    db = _db()
    try:
        t = get_or_create_demo_tenant(db)
        d = Device(tenant_id=t.id, hostname="bulk")
        db.add(d)
        db.commit()
        ids = []
        for _ in range(450):
            s = Scan(tenant_id=t.id, device_id=d.id, framework="ALL", status="completed")
            db.add(s)
            db.flush()
            ids.append(s.id)
        db.commit()
    finally:
        db.close()
    # API cap is 500 per call; still exercises the chunking helper (400/chunk).
    r = client.post("/api/scans/bulk-delete", json={"scan_ids": ids})
    assert r.status_code == 200 and len(r.json()["deleted"]) == 450


def test_list_scans_device_filter_and_source_filename(env):
    client, state, _ = env
    state["block"] = False
    s = client.post("/api/scans/upload", files={"file": ("core-sw.cfg", CFG)}).json()
    assert s["source_filename"] == "core-sw.cfg"
    other = _mk_scan("completed")
    all_ids = [x["id"] for x in client.get("/api/scans").json()]
    assert {s["id"], other} <= set(all_ids)
    only = client.get("/api/scans", params={"device_id": s["device_id"]}).json()
    assert other not in [x["id"] for x in only]
