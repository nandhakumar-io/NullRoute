import pytest
from app.models.db import ModelRegistryEntry
from app.services import model_registry_service

def test_hitl_e2e_model_promotion(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test3.db")
    from app.db import SessionLocal, Base, engine
    Base.metadata.create_all(bind=engine)
    db_session = SessionLocal()
    
    mock_user = type("User", (), {"username": "admin"})
    
    # 1. Register candidate model
    entry = model_registry_service.create_candidate(
        db_session,
        model_name="test_classifier_v1",
        model_type="classifier",
        dataset_version="v1",
        base_model_version="base",
        artifact_path="/tmp/model",
        model_hash="hash123",
        metrics={"macro_f1": 0.95, "unknown_f1": 0.96},
        training_job_id="job123",
        user=mock_user,
    )
    assert entry.status == "CANDIDATE"

    # 2. Approve model
    approved = model_registry_service.approve_candidate(db_session, entry.id, mock_user)
    assert approved.status == "APPROVED"

    # 3. Promote model to production
    # Before promotion, there shouldn't be any PRODUCTION models
    prods = db_session.query(ModelRegistryEntry).filter_by(status="PRODUCTION").all()
    assert len(prods) == 0

    promoted = model_registry_service.promote_to_production(db_session, entry.id, mock_user)
    # To test rollback, we must rollback to an ARCHIVED model.
    entry.status = "ARCHIVED"
    db_session.commit()
    
    # 4. Rollback model
    rolled_back = model_registry_service.rollback(db_session, entry.id, mock_user)
    assert rolled_back.status == "PRODUCTION"
    prods_after = db_session.query(ModelRegistryEntry).filter_by(status="PRODUCTION").all()
    assert len(prods_after) == 1
    assert prods_after[0].id == entry.id
