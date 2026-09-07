"""
Dataset Service - Loop 2 (Offline Training Orchestration)

Dataset content hashing uses a fully canonical JSON serialization of every
field that defines the example's identity. This makes the hash reproducible
from content alone (re-computing it on any machine with the same examples
produces the same hash) and sensitive to any change in the example data.

Frozen-test leakage prevention: before building a training dataset we load
the authoritative evaluation benchmark (`ai_reference_dataset.json`, the
same file the DistilBERT evaluator uses) and compute SHA-256 of each
entry's text. Any TrainingExample whose raw_config_hash collides with a
frozen-test hash is marked EXCLUDED — it must never appear in training.
This prevents training-set contamination of the benchmark and preserves
the validity of all reported evaluation metrics (macro_f1, unknown_f1).
"""
import json
import hashlib
import logging
import os
from typing import Any, Dict, Optional, Set
from datetime import datetime
from sqlalchemy.orm import Session

from app.models.db import TrainingExample, DatasetVersion

logger = logging.getLogger(__name__)

# Path to the frozen evaluation benchmark.  Resolvable from the repo root
# at runtime (container mounts /app/backend, where ai_reference_dataset.json
# is placed by the Dockerfile COPY step) or via env override for tests.
_REFERENCE_DATASET_PATH = os.getenv(
    "AI_REFERENCE_DATASET_PATH",
    os.path.join(os.path.dirname(__file__), "..", "..", "ai_reference_dataset.json"),
)


def _load_frozen_test_hashes() -> Set[str]:
    """Return SHA-256 hashes for every text sample in the frozen evaluation
    benchmark.  These hashes are compared against TrainingExample.raw_config_hash
    to detect and exclude any example that leaked from the evaluation set into
    the training pool.

    Failure modes that must not abort dataset creation:
    - Missing or unreadable reference dataset  → log warning, return empty set
    - Malformed JSON                            → log warning, return empty set
    Any of these means we skip leakage protection (not silently pretend it
    worked), but we still build the dataset rather than blocking the whole flow.
    """
    path = os.path.normpath(_REFERENCE_DATASET_PATH)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            entries = json.load(fh)
        hashes: Set[str] = set()
        for entry in entries:
            text = entry.get("text", "")
            if text:
                hashes.add(hashlib.sha256(text.encode("utf-8")).hexdigest())
        logger.info(
            "Loaded %d frozen test hashes from %s", len(hashes), path
        )
        return hashes
    except FileNotFoundError:
        logger.warning(
            "ai_reference_dataset.json not found at %s — "
            "frozen-test leakage protection disabled for this run.",
            path,
        )
        return set()
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Failed to load reference dataset from %s: %s — "
            "frozen-test leakage protection disabled for this run.",
            path, exc,
        )
        return set()


def _canonical_example_dict(ex: TrainingExample) -> dict:
    """Return a deterministic, fully-specified dict of the fields that define
    the identity of a training example.  Used for content-addressable hashing
    so the dataset_hash is reproducible from the data, not just from row IDs."""
    return {
        "id": ex.id,
        "raw_config_hash": ex.raw_config_hash,
        "raw_config_redacted": ex.raw_config_redacted or "",
        "vendor": ex.vendor or "",
        "intent": ex.intent or "",
        "normalized_facts": ex.normalized_facts if isinstance(ex.normalized_facts, dict) else {},
        "human_action": ex.human_action or "",
        "correction_reason": ex.correction_reason or "",
    }


def _compute_hash(examples: list) -> str:
    """Canonical, content-addressable SHA-256 hash of the entire example set.

    Uses a deterministic JSON serialization (sort_keys=True, no extra
    whitespace) of every field that defines the example's identity — not
    just the row ID and a single hash column.  Feeding the same examples in
    any order produces the same hash; changing ANY field in ANY example
    changes the hash.

    The outer serialization wraps the sorted-by-id list in a stable envelope
    so that insertion order in the DB cannot affect reproducibility.
    """
    sorted_examples = sorted(
        [_canonical_example_dict(ex) for ex in examples],
        key=lambda d: d["id"],
    )
    canonical_json = json.dumps(sorted_examples, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def prevent_frozen_test_leakage(example: TrainingExample, frozen_test_hashes: Set[str]) -> None:
    """Mark `example` as EXCLUDED if its raw_config_hash matches any hash in
    the frozen evaluation benchmark.  This is a write to the ORM object only
    — the caller is responsible for committing the session so that the
    exclusion is persisted before the dataset snapshot is taken."""
    if example.raw_config_hash in frozen_test_hashes:
        example.validation_status = "EXCLUDED"
        logger.debug(
            "TrainingExample %s excluded: raw_config_hash %s matches frozen test set",
            example.id, example.raw_config_hash,
        )


def create_dataset_version(
    db: Session,
    tenant_id: Optional[str],
    user: Any,
    version_label: str,
) -> DatasetVersion:
    """Snapshot all VALIDATED, non-leaking, non-duplicate training examples
    for `tenant_id` (plus global/tenant-null examples) into an immutable
    DatasetVersion row.

    Steps:
      1. Load frozen test hashes from the benchmark file.
      2. Query VALIDATED examples (tenant-scoped + global).
      3. Mark any that collide with the frozen test set as EXCLUDED.
      4. Deduplicate by raw_config_hash.
      5. Compute canonical content-addressable dataset_hash.
      6. Persist DatasetVersion with label distributions and mark immutable.
    """
    # 1. Frozen-test leakage protection ----------------------------------------
    frozen_test_hashes = _load_frozen_test_hashes()

    # 2. Load candidate examples -----------------------------------------------
    q = db.query(TrainingExample).filter(TrainingExample.validation_status == "VALIDATED")
    if tenant_id:
        q = q.filter(
            (TrainingExample.tenant_id == tenant_id) | (TrainingExample.tenant_id.is_(None))
        )
    examples = q.order_by(TrainingExample.created_at).all()

    # 3 + 4. Leakage exclusion + deduplication ---------------------------------
    seen_hashes: Set[str] = set()
    clean_examples = []
    excluded_count = 0

    for ex in examples:
        # Mutates ex.validation_status if it matches the frozen set
        prevent_frozen_test_leakage(ex, frozen_test_hashes)
        if ex.validation_status == "EXCLUDED":
            excluded_count += 1
            continue
        if ex.raw_config_hash in seen_hashes:
            continue
        seen_hashes.add(ex.raw_config_hash)
        clean_examples.append(ex)

    if excluded_count:
        logger.info(
            "Dataset %s: excluded %d example(s) matching the frozen test set",
            version_label, excluded_count,
        )
        # Persist the EXCLUDED status updates so they survive after this call
        db.flush()

    # 5. Build distributions + assign version label ----------------------------
    vendor_dist: Dict[str, int] = {}
    label_dist: Dict[str, int] = {}
    source_dist: Dict[str, int] = {}

    for ex in clean_examples:
        vendor = ex.vendor or "unknown"
        vendor_dist[vendor] = vendor_dist.get(vendor, 0) + 1

        intent = ex.intent or "unknown"
        label_dist[intent] = label_dist.get(intent, 0) + 1

        src = ex.source_mapping_id or "unknown"
        source_dist[src] = source_dist.get(src, 0) + 1

        ex.dataset_version = version_label

    # 6. Canonical content-addressable dataset hash ----------------------------
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
        is_immutable=True,
    )

    db.add(dv)
    db.commit()
    db.refresh(dv)
    return dv


def get_dataset(db: Session, tenant_id: Optional[str], version_id: str) -> Optional[DatasetVersion]:
    q = db.query(DatasetVersion).filter(DatasetVersion.version == version_id)
    if tenant_id:
        q = q.filter(
            (DatasetVersion.tenant_id == tenant_id) | (DatasetVersion.tenant_id.is_(None))
        )
    return q.first()
