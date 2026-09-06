"""
Dataset Service - Loop 2 (Offline Training Orchestration)
"""
import json
import hashlib
from typing import Any, Dict, Optional
from datetime import datetime
from sqlalchemy.orm import Session

from app.models.db import TrainingExample, DatasetVersion


def _compute_hash(examples):
    hasher = hashlib.sha256()
    for ex in examples:
        # Include fields important for the dataset version reproducible state
        hasher.update(ex.id.encode('utf-8'))
        hasher.update(ex.raw_config_hash.encode('utf-8'))
        hasher.update(str(ex.human_action).encode('utf-8'))
    return hasher.hexdigest()

def prevent_frozen_test_leakage(example: TrainingExample, frozen_test_hashes: set) -> None:
    if example.raw_config_hash in frozen_test_hashes:
        example.validation_status = "EXCLUDED"


def create_dataset_version(db: Session, tenant_id: Optional[str], user: Any, version_label: str) -> DatasetVersion:
    # Example logic: collect all VALIDATED examples that aren't already part of this version
    # The spec dictates immutability, frozen set leakage prevention, etc.
    
    # 1. Load frozen set hashes to prevent leakage
    # We could simulate this by loading the AI_REFERENCE_DATASET JSON and hashing it.
    frozen_test_hashes = set()  
    
    q = db.query(TrainingExample).filter(TrainingExample.validation_status == "VALIDATED")
    if tenant_id:
        q = q.filter((TrainingExample.tenant_id == tenant_id) | (TrainingExample.tenant_id.is_(None)))
    examples = q.order_by(TrainingExample.created_at).all()
    
    # Exclude frozen leakage and deduplicate
    seen_hashes = set()
    clean_examples = []
    
    for ex in examples:
        prevent_frozen_test_leakage(ex, frozen_test_hashes)
        if ex.validation_status == "EXCLUDED":
            continue
        if ex.raw_config_hash in seen_hashes:
            continue
        seen_hashes.add(ex.raw_config_hash)
        clean_examples.append(ex)

    # 2. Build distributions
    vendor_dist = {}
    label_dist = {}
    source_dist = {}
    for ex in clean_examples:
        vendor = ex.vendor or "unknown"
        vendor_dist[vendor] = vendor_dist.get(vendor, 0) + 1
        
        intent = ex.intent or "unknown"
        label_dist[intent] = label_dist.get(intent, 0) + 1
        
        src = ex.source_mapping_id or "unknown"
        source_dist[src] = source_dist.get(src, 0) + 1
        
        # update ex.dataset_version assignment
        ex.dataset_version = version_label

    dataset_hash = _compute_hash(clean_examples)
    
    dv = DatasetVersion(
        version=version_label,
        tenant_id=tenant_id,
        created_by=user.username if hasattr(user, "username") and user.username else "admin",
        created_at=datetime.utcnow(),
        example_count=len(clean_examples),
        label_distribution=label_dist,
        vendor_distribution=vendor_dist,
        source_distribution=source_dist,
        validation_status="VALIDATED",
        training_status="PENDING",
        dataset_hash=dataset_hash,
        is_immutable=True
    )
    
    db.add(dv)
    db.commit()
    db.refresh(dv)
    return dv


def get_dataset(db: Session, tenant_id: Optional[str], version_id: str) -> Optional[DatasetVersion]:
    q = db.query(DatasetVersion).filter(DatasetVersion.version == version_id)
    if tenant_id:
        q = q.filter((DatasetVersion.tenant_id == tenant_id) | (DatasetVersion.tenant_id.is_(None)))
    return q.first()
