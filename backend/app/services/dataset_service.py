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

from app.models.db import TrainingExample, DatasetVersion, DatasetItem

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


def _ensure_label_free(db: Session, label: str) -> None:
    if not label or not label.strip():
        raise ValueError("Dataset version label is required")
    if db.query(DatasetVersion).filter(DatasetVersion.version == label).first():
        raise ValueError(f"A dataset version labelled {label!r} already exists")


def create_draft(
    db: Session,
    tenant_id: Optional[str],
    user: Any,
    version_label: str,
) -> DatasetVersion:
    """Create an empty, mutable DRAFT dataset version. Examples are added to
    it afterwards via add_examples(); nothing is snapshotted yet."""
    _ensure_label_free(db, version_label)
    dv = DatasetVersion(
        version=version_label,
        tenant_id=tenant_id,
        created_by=user.username if hasattr(user, "username") and user.username else "admin",
        created_at=datetime.utcnow(),
        example_count=0,
        label_distribution={},
        vendor_distribution={},
        source_distribution={},
        validation_status="DRAFT",
        training_status=None,
        dataset_hash="",
        is_immutable=False,
        status="DRAFT",
    )
    db.add(dv)
    db.commit()
    db.refresh(dv)
    return dv


def _require_draft(db: Session, tenant_id: Optional[str], version_id: str) -> DatasetVersion:
    dv = get_dataset(db, tenant_id, version_id)
    if not dv:
        raise ValueError(f"Dataset {version_id} not found")
    if dv.status != "DRAFT":
        raise ValueError(f"Dataset {version_id} is {dv.status}, not DRAFT — only drafts can be edited")
    return dv


def _recompute_draft_distributions(db: Session, dv: DatasetVersion) -> None:
    """Recompute the cached counts/distributions shown on a DRAFT from its
    current DatasetItem membership. Cheap live preview; the authoritative
    numbers are recomputed again (with leakage/dedup applied) at finalize."""
    examples = (
        db.query(TrainingExample)
        .join(DatasetItem, DatasetItem.training_example_id == TrainingExample.id)
        .filter(DatasetItem.dataset_version_id == dv.id)
        .all()
    )
    vendor_dist: Dict[str, int] = {}
    label_dist: Dict[str, int] = {}
    source_dist: Dict[str, int] = {}
    for ex in examples:
        vendor_dist[ex.vendor or "unknown"] = vendor_dist.get(ex.vendor or "unknown", 0) + 1
        label_dist[ex.intent or "unknown"] = label_dist.get(ex.intent or "unknown", 0) + 1
        src = ex.source_mapping_id or "unknown"
        source_dist[src] = source_dist.get(src, 0) + 1
    dv.example_count = len(examples)
    dv.vendor_distribution = vendor_dist
    dv.label_distribution = label_dist
    dv.source_distribution = source_dist


def add_examples(
    db: Session,
    tenant_id: Optional[str],
    version_id: str,
    example_ids: list,
    user: Any,
) -> DatasetVersion:
    """Add VALIDATED training examples to a DRAFT dataset. Silently skips
    ids that are already members (idempotent) or that aren't VALIDATED
    (rejected/pending examples must never be addable — the caller gets back
    which ids were actually added via the returned dataset's example_count
    delta, or can re-fetch to see current membership)."""
    dv = _require_draft(db, tenant_id, version_id)

    existing_ids = {
        row[0] for row in db.query(DatasetItem.training_example_id)
        .filter(DatasetItem.dataset_version_id == dv.id).all()
    }

    q = db.query(TrainingExample).filter(
        TrainingExample.id.in_(example_ids),
        TrainingExample.validation_status == "VALIDATED",
    )
    if tenant_id:
        q = q.filter((TrainingExample.tenant_id == tenant_id) | (TrainingExample.tenant_id.is_(None)))

    for ex in q.all():
        if ex.id in existing_ids:
            continue
        db.add(DatasetItem(dataset_version_id=dv.id, training_example_id=ex.id))
        existing_ids.add(ex.id)

    db.flush()
    _recompute_draft_distributions(db, dv)
    db.commit()
    db.refresh(dv)
    return dv


def remove_example(
    db: Session,
    tenant_id: Optional[str],
    version_id: str,
    example_id: str,
    user: Any,
) -> DatasetVersion:
    dv = _require_draft(db, tenant_id, version_id)
    db.query(DatasetItem).filter(
        DatasetItem.dataset_version_id == dv.id,
        DatasetItem.training_example_id == example_id,
    ).delete()
    db.flush()
    _recompute_draft_distributions(db, dv)
    db.commit()
    db.refresh(dv)
    return dv


def delete_draft(db: Session, tenant_id: Optional[str], version_id: str, user: Any) -> None:
    dv = _require_draft(db, tenant_id, version_id)
    db.query(DatasetItem).filter(DatasetItem.dataset_version_id == dv.id).delete()
    db.delete(dv)
    db.commit()


def finalize(
    db: Session,
    tenant_id: Optional[str],
    version_id: str,
    user: Any,
    allow_empty: bool = False,
) -> DatasetVersion:
    """Freeze a DRAFT into an immutable, reproducible snapshot.

    1. Load the draft's current member examples (via DatasetItem, not the
       old dataset_version string column — this is what makes the result
       reproducible: an unrelated later draft can never change what this
       finalized version contains).
    2. Apply frozen-test leakage exclusion.
    3. Deduplicate by raw_config_hash, keeping the MOST RECENT example per
       hash (a later correction should win over an earlier wrong approval —
       fixes the old "dedupe keeps the oldest row" bug).
    4. Refuse to finalize an empty dataset.
    5. Compute the canonical content-addressable hash and lock the version.
    """
    dv = _require_draft(db, tenant_id, version_id)

    frozen_test_hashes = _load_frozen_test_hashes()

    examples = (
        db.query(TrainingExample)
        .join(DatasetItem, DatasetItem.training_example_id == TrainingExample.id)
        .filter(DatasetItem.dataset_version_id == dv.id)
        .order_by(TrainingExample.created_at.desc())  # newest first
        .all()
    )

    seen_hashes: Set[str] = set()
    clean_examples = []
    excluded_count = 0

    for ex in examples:
        prevent_frozen_test_leakage(ex, frozen_test_hashes)
        if ex.validation_status == "EXCLUDED":
            excluded_count += 1
            # Drop it from this draft's membership too, so a re-finalize or
            # a future clone doesn't keep offering a leaked example.
            db.query(DatasetItem).filter(
                DatasetItem.dataset_version_id == dv.id,
                DatasetItem.training_example_id == ex.id,
            ).delete()
            continue
        if ex.raw_config_hash in seen_hashes:
            # Already kept a newer example with this hash — drop this
            # (older) duplicate's membership row too.
            db.query(DatasetItem).filter(
                DatasetItem.dataset_version_id == dv.id,
                DatasetItem.training_example_id == ex.id,
            ).delete()
            continue
        seen_hashes.add(ex.raw_config_hash)
        clean_examples.append(ex)

    if not clean_examples and not allow_empty:
        raise ValueError("Cannot finalize an empty dataset — add at least one VALIDATED example first")

    if excluded_count:
        logger.info(
            "Dataset %s: excluded %d example(s) matching the frozen test set",
            dv.version, excluded_count,
        )

    vendor_dist: Dict[str, int] = {}
    label_dist: Dict[str, int] = {}
    source_dist: Dict[str, int] = {}
    for ex in clean_examples:
        vendor_dist[ex.vendor or "unknown"] = vendor_dist.get(ex.vendor or "unknown", 0) + 1
        label_dist[ex.intent or "unknown"] = label_dist.get(ex.intent or "unknown", 0) + 1
        src = ex.source_mapping_id or "unknown"
        source_dist[src] = source_dist.get(src, 0) + 1

    dv.example_count = len(clean_examples)
    dv.vendor_distribution = vendor_dist
    dv.label_distribution = label_dist
    dv.source_distribution = source_dist
    dv.dataset_hash = _compute_hash(clean_examples)
    dv.validation_status = "VALIDATED"
    dv.training_status = "PENDING"
    dv.status = "FINALIZED"
    dv.is_immutable = True
    dv.finalized_at = datetime.utcnow()

    db.commit()
    db.refresh(dv)
    return dv


def clone(
    db: Session,
    tenant_id: Optional[str],
    source_version_id: str,
    user: Any,
    new_label: str,
) -> DatasetVersion:
    """Start a new DRAFT from a finalized version's membership, so admins can
    edit further without touching the immutable source (which trained models
    still reference via ModelRegistryEntry.dataset_version)."""
    source = get_dataset(db, tenant_id, source_version_id)
    if not source:
        raise ValueError(f"Dataset {source_version_id} not found")

    _ensure_label_free(db, new_label)
    dv = DatasetVersion(
        version=new_label,
        tenant_id=tenant_id,
        created_by=user.username if hasattr(user, "username") and user.username else "admin",
        created_at=datetime.utcnow(),
        example_count=0,
        label_distribution={},
        vendor_distribution={},
        source_distribution={},
        validation_status="DRAFT",
        training_status=None,
        dataset_hash="",
        is_immutable=False,
        status="DRAFT",
        parent_version=source.id,
    )
    db.add(dv)
    db.flush()

    member_ids = [
        row[0] for row in db.query(DatasetItem.training_example_id)
        .filter(DatasetItem.dataset_version_id == source.id).all()
    ]
    for ex_id in member_ids:
        db.add(DatasetItem(dataset_version_id=dv.id, training_example_id=ex_id))

    db.flush()
    _recompute_draft_distributions(db, dv)
    db.commit()
    db.refresh(dv)
    return dv


def list_draft_examples(db: Session, tenant_id: Optional[str], version_id: str):
    dv = get_dataset(db, tenant_id, version_id)
    if not dv:
        raise ValueError(f"Dataset {version_id} not found")
    return (
        db.query(TrainingExample)
        .join(DatasetItem, DatasetItem.training_example_id == TrainingExample.id)
        .filter(DatasetItem.dataset_version_id == dv.id)
        .all()
    )


def create_dataset_version(
    db: Session,
    tenant_id: Optional[str],
    user: Any,
    version_label: str,
) -> DatasetVersion:
    """Back-compat one-shot helper: create a draft from every currently
    VALIDATED example and immediately finalize it. Prefer create_draft() +
    add_examples() + finalize() for the editable flow."""
    dv = create_draft(db, tenant_id, user, version_label)

    q = db.query(TrainingExample).filter(TrainingExample.validation_status == "VALIDATED")
    if tenant_id:
        q = q.filter((TrainingExample.tenant_id == tenant_id) | (TrainingExample.tenant_id.is_(None)))
    example_ids = [ex.id for ex in q.all()]

    add_examples(db, tenant_id, dv.id, example_ids, user)
    return finalize(db, tenant_id, dv.id, user, allow_empty=True)


def get_dataset(db: Session, tenant_id: Optional[str], version_id: str) -> Optional[DatasetVersion]:
    """Look up by primary-key id (jobs and the registry reference datasets by
    id). Falls back to matching by the human-readable `version` label for
    backward compatibility with older callers/links."""
    q = db.query(DatasetVersion).filter(DatasetVersion.id == version_id)
    if tenant_id:
        q = q.filter((DatasetVersion.tenant_id == tenant_id) | (DatasetVersion.tenant_id.is_(None)))
    dv = q.first()
    if dv:
        return dv
    q = db.query(DatasetVersion).filter(DatasetVersion.version == version_id)
    if tenant_id:
        q = q.filter((DatasetVersion.tenant_id == tenant_id) | (DatasetVersion.tenant_id.is_(None)))
    return q.first()