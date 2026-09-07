"""
Tests for dataset_service.py — canonical content-addressable hashing and
frozen-test leakage protection.

These run fully offline against SQLite (same pattern as the existing
test_hitl_loop2_training.py tests) and do NOT require GPU, NATS, OPA,
or any other infrastructure.
"""
import hashlib
import json
import os
import pytest
import uuid


@pytest.mark.asyncio
async def test_dataset_hash_is_content_addressable(monkeypatch, tmp_path):
    """Same examples in any insertion order must produce the same dataset hash."""
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    # No reference dataset — leakage protection is a no-op here
    monkeypatch.setenv("AI_REFERENCE_DATASET_PATH", str(tmp_path / "no_such_file.json"))

    from app.db import SessionLocal, Base, engine
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    from app.models.db import Tenant, TrainingExample
    tenant = Tenant(name=f"ht-{uuid.uuid4()}")
    db.add(tenant)
    db.commit()

    def _make_example(db, tenant_id, raw_hash, vendor, intent):
        ex = TrainingExample(
            tenant_id=tenant_id,
            raw_config_hash=raw_hash,
            raw_config_redacted=f"# config for {intent}",
            vendor=vendor,
            intent=intent,
            normalized_facts={"management.ssh.version": 2},
            human_action="APPROVED",
            created_by="test",
            validation_status="VALIDATED",
        )
        db.add(ex)
        db.commit()
        return ex

    ex1 = _make_example(db, tenant.id, "hash_aaa", "Cisco", "AAA_AUTHENTICATION")
    ex2 = _make_example(db, tenant.id, "hash_ssh", "Cisco", "SECURITY_MANAGEMENT")

    from app.services import dataset_service

    mock_user = type("U", (), {"username": "test"})

    dv1 = dataset_service.create_dataset_version(db, tenant.id, mock_user, f"v-{uuid.uuid4()}")
    dv2 = dataset_service.create_dataset_version(db, tenant.id, mock_user, f"v-{uuid.uuid4()}")

    # Both versions snapshot the same examples so should have the same hash
    assert dv1.dataset_hash == dv2.dataset_hash, (
        "Two DatasetVersions built from identical example sets must have the same hash"
    )


@pytest.mark.asyncio
async def test_dataset_hash_changes_when_content_changes(monkeypatch, tmp_path):
    """Changing any field on an example must change the dataset hash."""
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("AI_REFERENCE_DATASET_PATH", str(tmp_path / "no_such_file.json"))

    from app.db import SessionLocal, Base, engine
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    from app.models.db import Tenant, TrainingExample
    tenant = Tenant(name=f"ht2-{uuid.uuid4()}")
    db.add(tenant)
    db.commit()

    ex = TrainingExample(
        tenant_id=tenant.id,
        raw_config_hash="hash_unique_v1",
        raw_config_redacted="ip ssh version 2",
        vendor="Cisco",
        intent="SECURITY_MANAGEMENT",
        normalized_facts={"management.ssh.version": 2},
        human_action="APPROVED",
        created_by="test",
        validation_status="VALIDATED",
    )
    db.add(ex)
    db.commit()

    from app.services import dataset_service
    mock_user = type("U", (), {"username": "test"})

    dv1 = dataset_service.create_dataset_version(db, tenant.id, mock_user, f"v1-{uuid.uuid4()}")
    hash1 = dv1.dataset_hash

    # Mutate the example's intent
    db.refresh(ex)
    ex.intent = "DIFFERENT_INTENT"
    ex.dataset_version = None  # allow re-inclusion
    ex.validation_status = "VALIDATED"
    db.commit()

    dv2 = dataset_service.create_dataset_version(db, tenant.id, mock_user, f"v2-{uuid.uuid4()}")
    hash2 = dv2.dataset_hash

    assert hash1 != hash2, (
        "Changing an example's intent must produce a different dataset hash"
    )


@pytest.mark.asyncio
async def test_frozen_test_leakage_excludes_matching_examples(monkeypatch, tmp_path):
    """An example whose raw_config_hash matches a frozen test benchmark hash
    must be marked EXCLUDED and must NOT appear in the DatasetVersion."""
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")

    # Build a fake reference dataset JSON with one known text
    frozen_text = "aaa authentication login default group radius local"
    frozen_hash = hashlib.sha256(frozen_text.encode()).hexdigest()
    ref_path = tmp_path / "ref_dataset.json"
    ref_path.write_text(json.dumps([{"intent": "AAA", "text": frozen_text}]))
    monkeypatch.setenv("AI_REFERENCE_DATASET_PATH", str(ref_path))

    from app.db import SessionLocal, Base, engine
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    from app.models.db import Tenant, TrainingExample
    tenant = Tenant(name=f"ht3-{uuid.uuid4()}")
    db.add(tenant)
    db.commit()

    # Example whose raw_config_hash MATCHES a frozen-test benchmark entry
    leaking_ex = TrainingExample(
        tenant_id=tenant.id,
        raw_config_hash=frozen_hash,  # will be caught by leakage check
        raw_config_redacted=frozen_text,
        vendor="Cisco",
        intent="AAA_AUTHENTICATION",
        normalized_facts={},
        human_action="APPROVED",
        created_by="test",
        validation_status="VALIDATED",
    )
    db.add(leaking_ex)

    # Example that is safe (not in the frozen set)
    safe_ex = TrainingExample(
        tenant_id=tenant.id,
        raw_config_hash="completely_different_hash_xyz",
        raw_config_redacted="ip ssh version 2",
        vendor="Cisco",
        intent="SECURITY_MANAGEMENT",
        normalized_facts={},
        human_action="APPROVED",
        created_by="test",
        validation_status="VALIDATED",
    )
    db.add(safe_ex)
    db.commit()

    from app.services import dataset_service
    mock_user = type("U", (), {"username": "test"})
    dv = dataset_service.create_dataset_version(db, tenant.id, mock_user, f"v-{uuid.uuid4()}")

    # Only the safe example should be in the dataset
    assert dv.example_count == 1, (
        f"Expected 1 example (leaking one excluded), got {dv.example_count}"
    )

    # The leaking example must have been marked EXCLUDED in the DB
    db.refresh(leaking_ex)
    assert leaking_ex.validation_status == "EXCLUDED", (
        "A leaking example must be marked EXCLUDED so it cannot enter any future training run"
    )


@pytest.mark.asyncio
async def test_frozen_test_leakage_graceful_when_file_missing(monkeypatch, tmp_path):
    """If ai_reference_dataset.json is missing, dataset creation must still
    succeed (leakage protection is skipped with a warning, not an error)."""
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("AI_REFERENCE_DATASET_PATH", str(tmp_path / "does_not_exist.json"))

    from app.db import SessionLocal, Base, engine
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    from app.models.db import Tenant, TrainingExample
    tenant = Tenant(name=f"ht4-{uuid.uuid4()}")
    db.add(tenant)
    db.commit()

    ex = TrainingExample(
        tenant_id=tenant.id,
        raw_config_hash="safe_hash_no_ref",
        raw_config_redacted="ip ssh version 2",
        vendor="Cisco",
        intent="SECURITY_MANAGEMENT",
        normalized_facts={},
        human_action="APPROVED",
        created_by="test",
        validation_status="VALIDATED",
    )
    db.add(ex)
    db.commit()

    from app.services import dataset_service
    mock_user = type("U", (), {"username": "test"})

    # Must not raise
    dv = dataset_service.create_dataset_version(db, tenant.id, mock_user, f"v-{uuid.uuid4()}")
    assert dv.example_count == 1
    assert dv.is_immutable is True
