"""Admin auto-validate, dataset draft/finalize, atomic job claim / retry /
cancel, transformers arg drift, intent coverage, and PRODUCTION model loading."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.auth import dependencies as deps_mod
from app.auth import jwt as jwt_mod
from app.models.db import (
    Base, CommandMapping, DatasetItem, DatasetVersion, ModelRegistryEntry, Tenant, TrainingExample, TrainingJob,
)
from app.services import dataset_service, hitl_service, model_registry_service, training_service, vector_search


@pytest.fixture
def db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/t.db", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    s = sessionmaker(bind=engine)()
    t = Tenant(name="T1")
    s.add(t)
    s.commit()
    s.tenant_id = t.id
    yield s
    s.close()


def _user(name="alice", roles=("admin",)):
    return type("U", (), {"username": name, "roles": list(roles)})()


def _mapping(db, cmd="ip ssh version 1", param="ssh_management.version"):
    m = CommandMapping(tenant_id=db.tenant_id, vendor="cisco_ios", raw_command_pattern=cmd,
                       normalized_parameter=param, example_value="1", confidence=0.5, status="pending")
    db.add(m)
    db.commit()
    return m


@pytest.fixture(autouse=True)
def _no_embedder(monkeypatch):
    monkeypatch.setattr(vector_search, "embed_text", lambda t: None)


# ------------------------------------------------------------ HITL gate --
def test_admin_approve_and_correct_auto_validate(db):
    m = _mapping(db)
    hitl_service.approve_mapping(db, m, {}, None, _user())
    ex = db.query(TrainingExample).one()
    assert ex.validation_status == "VALIDATED"
    assert ex.intent == "ssh_management" and ex.normalized_facts["facts"]  # not an empty row / UNKNOWN

    m2 = _mapping(db, "ntp server 1.1.1.1", "ntp_config.server")
    hitl_service.correct_mapping(db, m2, {"facts": [{"parameter": "ntp_config.server", "value": "1.1.1.1"}]}, "fix", _user())
    assert db.query(TrainingExample).filter_by(human_action="CORRECTED").one().validation_status == "VALIDATED"


def test_analyst_review_stays_pending(db):
    m = _mapping(db)
    hitl_service.approve_mapping(db, m, {}, None, _user("bob", ["security_analyst"]))
    assert db.query(TrainingExample).one().validation_status == "PENDING"


def test_auto_validate_can_be_turned_off(db, monkeypatch):
    monkeypatch.setenv("HITL_ADMIN_AUTO_VALIDATE", "false")
    hitl_service.approve_mapping(db, _mapping(db), {}, None, _user())
    assert db.query(TrainingExample).one().validation_status == "PENDING"


def test_reject_is_never_validated(db):
    hitl_service.reject_mapping(db, _mapping(db), "bad", _user())
    assert db.query(TrainingExample).one().validation_status == "EXCLUDED"


def test_secrets_redacted_before_embedding(db, monkeypatch):
    seen = []
    monkeypatch.setattr(vector_search, "embed_text", lambda t: seen.append(t))
    hitl_service.approve_mapping(db, _mapping(db, "snmp-server community hunter2 RO", "snmp_config.community"), {}, None, _user())
    assert seen and "hunter2" not in seen[0]


# ------------------------------------------------------------- datasets --
def _validated(db, n):
    ids = []
    for i in range(n):
        ex = TrainingExample(tenant_id=db.tenant_id, raw_config_hash=f"h{i}", raw_config_redacted=f"cmd {i}",
                             vendor="cisco_ios", intent="ntp_config", normalized_facts={"facts": []},
                             human_action="APPROVED", created_by="a", validation_status="VALIDATED",
                             created_at=datetime.utcnow() + timedelta(seconds=i))
        db.add(ex)
        db.flush()
        ids.append(ex.id)
    db.commit()
    return ids


def test_draft_edit_finalize_clone_lifecycle(db):
    u = _user()
    ids = _validated(db, 3)
    pending = TrainingExample(tenant_id=db.tenant_id, raw_config_hash="p", raw_config_redacted="x", intent="ntp_config",
                              normalized_facts={}, human_action="APPROVED", created_by="a")
    db.add(pending)
    db.commit()

    dv = dataset_service.create_draft(db, db.tenant_id, u, "d1")
    assert dv.status == "DRAFT"
    with pytest.raises(ValueError):
        dataset_service.finalize(db, db.tenant_id, dv.id, u)  # empty

    dataset_service.add_examples(db, db.tenant_id, dv.id, ids + [pending.id], u)
    dv = dataset_service.get_dataset(db, db.tenant_id, dv.id)
    assert dv.example_count == 3  # non-VALIDATED example not addable

    dataset_service.remove_example(db, db.tenant_id, dv.id, ids[0], u)
    assert dataset_service.get_dataset(db, db.tenant_id, dv.id).example_count == 2

    fin = dataset_service.finalize(db, db.tenant_id, dv.id, u)
    assert fin.status == "FINALIZED" and fin.is_immutable and fin.dataset_hash and fin.finalized_at
    with pytest.raises(ValueError):
        dataset_service.add_examples(db, db.tenant_id, fin.id, [ids[0]], u)
    with pytest.raises(ValueError):
        dataset_service.delete_draft(db, db.tenant_id, fin.id, u)

    clone = dataset_service.clone(db, db.tenant_id, fin.id, u, "d2")
    assert clone.status == "DRAFT" and clone.parent_version == fin.id and clone.example_count == 2
    dataset_service.add_examples(db, db.tenant_id, clone.id, [ids[0]], u)
    # finalized parent is untouched
    assert dataset_service.get_dataset(db, db.tenant_id, fin.id).example_count == 2
    assert db.query(DatasetItem).filter_by(dataset_version_id=fin.id).count() == 2


def test_finalize_dedup_keeps_newest(db):
    u = _user()
    old = TrainingExample(tenant_id=db.tenant_id, raw_config_hash="same", raw_config_redacted="c", intent="ntp_config",
                          normalized_facts={}, human_action="APPROVED", created_by="a", validation_status="VALIDATED",
                          created_at=datetime.utcnow() - timedelta(days=1))
    new = TrainingExample(tenant_id=db.tenant_id, raw_config_hash="same", raw_config_redacted="c", intent="acl_config",
                          normalized_facts={}, human_action="CORRECTED", created_by="a", validation_status="VALIDATED",
                          created_at=datetime.utcnow())
    db.add_all([old, new])
    db.commit()
    dv = dataset_service.create_draft(db, db.tenant_id, u, "dd")
    dataset_service.add_examples(db, db.tenant_id, dv.id, [old.id, new.id], u)
    fin = dataset_service.finalize(db, db.tenant_id, dv.id, u)
    assert fin.example_count == 1 and fin.label_distribution == {"acl_config": 1}


# ------------------------------------------------------- training jobs ----
def _job(db, status="QUEUED"):
    ids = _validated(db, 2)
    u = _user()
    dv = dataset_service.create_draft(db, db.tenant_id, u, f"dj{datetime.utcnow().timestamp()}")
    dataset_service.add_examples(db, db.tenant_id, dv.id, ids, u)
    dv = dataset_service.finalize(db, db.tenant_id, dv.id, u)
    job = training_service.create_training_job(db, db.tenant_id, dv.id, None, u)
    job.status = status
    db.commit()
    return job


def test_cannot_train_on_draft_or_other_tenant(db):
    dv = dataset_service.create_draft(db, db.tenant_id, _user(), "drafty")
    with pytest.raises(ValueError):
        training_service.create_training_job(db, db.tenant_id, dv.id, None, _user())
    fin = _job(db).dataset_version_id
    with pytest.raises(ValueError):
        training_service.create_training_job(db, "other-tenant", fin, None, _user())


def test_claim_is_atomic(db):
    job = _job(db)
    assert training_service.claim_job(db, job.id) is True
    assert training_service.claim_job(db, job.id) is False
    db.refresh(job)
    assert job.status == "RUNNING" and job.started_at is not None


def test_run_skips_already_claimed(db, monkeypatch):
    job = _job(db, "RUNNING")
    monkeypatch.setattr(training_service, "_execute_training", lambda *a: pytest.fail("must not run twice"))
    training_service.run_training_job(db, job.id)


def test_failed_job_records_error_and_can_retry(db):
    job = _job(db)
    training_service.run_training_job(db, job.id)  # torch/transformers absent here -> real FAILED, no fake metrics
    db.refresh(job)
    assert job.status == "FAILED" and job.error and not job.metrics
    again = training_service.requeue_job(db, job.id, db.tenant_id)
    assert again.status == "QUEUED" and again.error is None
    with pytest.raises(ValueError):
        training_service.requeue_job(db, job.id, db.tenant_id)  # QUEUED can't be retried


def test_cancel_only_queued(db):
    job = _job(db)
    assert training_service.cancel_job(db, job.id, db.tenant_id).status == "CANCELLED"
    with pytest.raises(ValueError):
        training_service.cancel_job(db, job.id, db.tenant_id)
    with pytest.raises(ValueError):
        training_service.cancel_job(db, job.id, "other-tenant")


def test_stale_running_jobs_recovered(db):
    job = _job(db, "RUNNING")
    job.started_at = datetime.utcnow() - timedelta(hours=5)
    db.commit()
    assert training_service.recover_stale_jobs(db, 180) == 1
    db.refresh(job)
    assert job.status == "FAILED"


def test_training_args_follow_installed_transformers():
    class New:
        def __init__(self, eval_strategy=None, use_cpu=False, output_dir=None): ...

    class Old:
        def __init__(self, evaluation_strategy=None, no_cuda=False, output_dir=None): ...

    k = training_service._training_args_kwargs(New, output_dir="x", _use_gpu=False)
    assert k["eval_strategy"] == "epoch" and k["use_cpu"] is True and "no_cuda" not in k
    k = training_service._training_args_kwargs(Old, output_dir="x", _use_gpu=True)
    assert k["evaluation_strategy"] == "epoch" and k["no_cuda"] is False and "eval_strategy" not in k


def test_intent_coverage():
    c = training_service._intent_coverage(["ntp_config", "ssh_management", "UNKNOWN"])
    assert c["known_intents_total"] == 13 and c["known_intents_covered"] == 2
    assert "acl_config" in c["known_intents_missing"] and 0 < c["intent_coverage"] < 1


# ------------------------------------------------ PRODUCTION model loading --
def _promoted(db, path):
    u = _user()
    e = model_registry_service.create_candidate(db, "clf-v1", "classifier", "d1", "base", path, "h",
                                                {"macro_f1": 0.95, "unknown_f1": 0.96}, "job", u)
    model_registry_service.approve_candidate(db, e.id, u)
    e.status = "PRODUCTION"
    db.commit()
    return e


def test_reload_uses_production_entry_and_reports_failure(db, monkeypatch):
    from app.ai import model_registry as reg
    monkeypatch.delenv("AI_CLASSIFIER_REMOTE_URL", raising=False)
    monkeypatch.setenv("AI_ENABLED", "true")
    e = _promoted(db, "/does/not/exist")
    r = reg.reload_from_registry(db)
    assert r.production_model_id is None and "could not be loaded" in r.production_load_error
    assert r.classifier.backend_name == "keyword-fallback"  # still serving something

    from app.ai import classifier as clf
    seen = {}

    def fake_distilbert(path, version=None):
        seen["path"] = path
        return clf.LoadedClassifier("distilbert", version or path, lambda t: None)
    monkeypatch.setattr(clf, "_try_load_distilbert", fake_distilbert)
    r = reg.reload_from_registry(db)
    assert seen["path"] == "/does/not/exist" and r.production_model_id == e.id
    assert r.production_load_error is None and r.model_version.startswith("clf-v1@")
    reg.reset_registry_for_tests()


def test_production_beats_remote_url(monkeypatch):
    from app.ai import classifier as clf
    monkeypatch.setenv("AI_CLASSIFIER_REMOTE_URL", "http://remote.invalid")
    monkeypatch.setattr(clf, "_try_load_distilbert", lambda p, v=None: clf.LoadedClassifier("distilbert", v or p, lambda t: None))
    assert clf.load_classifier(production_path="/x", production_version="v").backend_name == "distilbert"
    assert clf.load_classifier().backend_name == "remote-classifier"


# ------------------------------------------------------------------ API ----
@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(jwt_mod, "AUTH_ENABLED", False)
    monkeypatch.setattr(deps_mod, "AUTH_ENABLED", False)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/api.db")
    monkeypatch.setenv("AI_ENABLED", "false")
    from app.main import app
    with TestClient(app) as c:
        yield c


def test_registry_api_lists_json_with_coverage_and_full_lifecycle(client):
    from app.db import SessionLocal
    d = SessionLocal()
    e = model_registry_service.create_candidate(
        d, "clf-api", "classifier", "d1", "base", "/nope", "h",
        {"macro_f1": 0.95, "unknown_f1": 0.96, **training_service._intent_coverage(["ntp_config"])}, "job", _user())
    mid = e.id
    d.close()

    rows = client.get("/api/ai/registry/models").json()
    row = next(r for r in rows if r["id"] == mid)
    assert row["status"] == "CANDIDATE" and row["known_intents_covered"] == 1 and row["known_intents_total"] == 13

    assert client.post(f"/api/ai/registry/models/{mid}/approve").json()["status"] == "APPROVED"
    assert client.post(f"/api/ai/registry/models/{mid}/promote").json()["status"] == "PRODUCTION"
    assert client.post("/api/ai/registry/models/rollback", json={"target_model_id": mid}).status_code == 400
    assert client.get("/api/ai/registry/models/nope").status_code == 404


def test_jobs_api_run_disabled_and_retry_cancel(client, monkeypatch):
    from app.db import SessionLocal
    from app.auth.dependencies import DEMO_TENANT_NAME
    d = SessionLocal()
    t = d.query(Tenant).filter_by(name=DEMO_TENANT_NAME).first()
    if not t:
        t = Tenant(name=DEMO_TENANT_NAME)
        d.add(t)
        d.commit()
    d.tenant_id = t.id
    job = _job(d)
    jid = job.id
    d.close()

    assert client.post(f"/api/ai/training/jobs/{jid}/run").status_code == 409
    assert client.post(f"/api/ai/training/jobs/{jid}/retry").status_code == 400  # still QUEUED
    r = client.post(f"/api/ai/training/jobs/{jid}/cancel"); assert r.status_code == 200, r.text; assert r.json()["status"] == "CANCELLED"
    assert client.post(f"/api/ai/training/jobs/{jid}/retry").json()["status"] == "QUEUED"
    assert client.get(f"/api/ai/training/jobs/{jid}").json()["id"] == jid
    assert client.get("/api/ai/training/jobs/missing").status_code == 404
    assert any(j["id"] == jid for j in client.get("/api/ai/training/jobs").json())


def test_ai_health_reports_production_fields(client):
    h = client.get("/api/ai/health").json()
    assert "production_model_id" in h and "production_load_error" in h


def test_datasets_api_full_flow(client):
    from app.db import SessionLocal
    from app.auth.dependencies import DEMO_TENANT_NAME
    d = SessionLocal()
    t = d.query(Tenant).filter_by(name=DEMO_TENANT_NAME).first() or Tenant(name=DEMO_TENANT_NAME)
    d.add(t)
    d.commit()
    d.tenant_id = t.id
    ids = _validated(d, 2)
    d.close()

    r = client.post("/api/ai/datasets/draft", json={"version_label": "api-d1"})
    assert r.status_code == 200 and r.json()["status"] == "DRAFT"
    did = r.json()["id"]
    assert client.post("/api/ai/datasets/draft", json={"version_label": "api-d1"}).status_code == 400  # duplicate label
    assert client.post(f"/api/ai/datasets/{did}/finalize").status_code == 400  # empty
    assert client.post(f"/api/ai/datasets/{did}/examples", json={"example_ids": ids}).json()["example_count"] == 2
    assert len(client.get(f"/api/ai/datasets/{did}/examples").json()) == 2
    fin = client.post(f"/api/ai/datasets/{did}/finalize").json()
    assert fin["status"] == "FINALIZED" and fin["dataset_hash"]
    assert client.delete(f"/api/ai/datasets/{did}/examples/{ids[0]}").status_code == 400  # frozen
    c = client.post(f"/api/ai/datasets/{did}/clone", json={"new_label": "api-d2"}).json()
    assert c["status"] == "DRAFT" and c["example_count"] == 2
    assert client.delete(f"/api/ai/datasets/{c['id']}").json() == {"deleted": True}
    assert {x["version"] for x in client.get("/api/ai/datasets").json()} >= {"api-d1"}
    assert client.get(f"/api/ai/datasets/{did}").json()["id"] == did
