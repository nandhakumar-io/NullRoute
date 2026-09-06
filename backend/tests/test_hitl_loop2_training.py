import pytest
from app.models.db import TrainingExample, DatasetVersion
from app.services import dataset_service, training_service

@pytest.mark.asyncio
async def test_hitl_loop2_dataset_immutability(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    from app.db import SessionLocal, Base, engine
    Base.metadata.create_all(bind=engine)
    db_session = SessionLocal()

    from app.models.db import Tenant, TrainingExample
    import uuid
    test_tenant = Tenant(name=f"TestTenant_{uuid.uuid4()}")
    db_session.add(test_tenant)
    db_session.commit()
    
    # 1. Create a validated training example
    example = TrainingExample(
        tenant_id=test_tenant.id,
        raw_config_hash="abc",
        raw_config_redacted="interface eth0",
        vendor="arista",
        intent="interfaces",
        normalized_facts={"interfaces.port_security_enabled": True},
        human_action="APPROVED",
        created_by="admin",
        validation_status="VALIDATED"
    )
    db_session.add(example)
    db_session.commit()

    # 2. Compile dataset
    mock_user = type("User", (), {"username": "admin"})
    dataset = dataset_service.create_dataset_version(db_session, test_tenant.id, mock_user, "v1")
    
    # 3. Assert immutability and linkage
    assert dataset.is_immutable
    assert dataset.example_count == 1
    
    db_session.refresh(example)
    assert example.dataset_version == dataset.version

@pytest.mark.asyncio
async def test_hitl_loop2_job_lifecycle(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test2.db")
    from app.db import SessionLocal, Base, engine
    Base.metadata.create_all(bind=engine)
    db_session = SessionLocal()

    from app.models.db import Tenant, DatasetVersion
    test_tenant = Tenant(name="TestTenant2")
    db_session.add(test_tenant)
    db_session.commit()

    dataset = DatasetVersion(
        version="v2",
        created_by="admin",
        dataset_hash="hash456"
    )
    db_session.add(dataset)
    db_session.commit()

    mock_user = type("User", (), {"username": "admin"})
    job = training_service.create_training_job(
        db_session, test_tenant.id, dataset.id, "base_v2", mock_user
    )

    assert job.status == "QUEUED"
    assert job.dataset_version_id == dataset.id

