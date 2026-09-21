"""
Training Service - Loop 2 (Offline Model Fine-Tuning)

Implements REAL DistilBERT intent-classification fine-tuning on the examples
collected by the HITL workflow.  The spec explicitly states:

  "If training dependencies are unavailable, report FAILED/UNAVAILABLE
   rather than generating placeholder metrics."

So this module:
  - Loads the DatasetVersion's VALIDATED examples from PostreSQL.
  - Splits 80/20 train/validation, stratified by intent where possible.
  - Fine-tunes `distilbert-base-uncased` (or the configured base model) using
    HuggingFace Transformers + PyTorch on CPU/GPU.
  - Evaluates on the held-out validation split and records REAL metrics.
  - Saves the fine-tuned model to /tmp/training_artifacts/<job_id>/.
  - Creates a ModelRegistryEntry via model_registry_service.create_candidate().
  - Sets job.status = COMPLETED / FAILED and never fabricates metrics.

CPU training is deliberate: DistilBERT fine-tuning on a few hundred intent-
classification examples takes <5 min on modern server CPU and <30 s with a
GPU.  The intent-classification dataset here is small (a few hundred labelled
commands) so this is entirely feasible without a dedicated GPU during demos.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import datetime
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.db import DatasetVersion, DatasetItem, ModelRegistryEntry, TrainingExample, TrainingJob

logger = logging.getLogger(__name__)

# Where fine-tuned model artifacts are stored locally for the demo.
# In a real deployment this would be MinIO; for the demo we use /tmp which
# is writable inside the container.
ARTIFACT_BASE_DIR = os.getenv("TRAINING_ARTIFACT_DIR", "/tmp/training_artifacts")

# The DistilBERT base model name.  In the container there is no internet
# access to huggingface.co during training — we point at the local model
# cache or use a pre-pulled snapshot. The env var lets operators override
# the checkpoint path to a locally cached one.
BASE_MODEL = os.getenv("TRAINING_BASE_MODEL", "distilbert-base-uncased")


# ---------------------------------------------------------------------------
# Job creation (CREATE — does NOT run training)
# ---------------------------------------------------------------------------

def create_training_job(
    db: Session,
    tenant_id: Optional[str],
    dataset_version_id: str,
    base_model_version: Optional[str],
    user: Any,
) -> TrainingJob:
    """Create a TrainingJob row in QUEUED status.

    Training is NOT run here — a background worker picks up QUEUED rows and
    calls run_training_job().  This separation keeps the API request fast and
    lets training run asynchronously without blocking an HTTP handler.
    """
    dv = db.query(DatasetVersion).filter(DatasetVersion.id == dataset_version_id).first()
    if not dv:
        raise ValueError(f"DatasetVersion {dataset_version_id} not found")
    if tenant_id and dv.tenant_id and dv.tenant_id != tenant_id:
        raise ValueError(f"DatasetVersion {dataset_version_id} not found")
    if dv.status != "FINALIZED":
        raise ValueError(f"DatasetVersion {dataset_version_id} is {dv.status}, not FINALIZED — finalize it before training")

    job = TrainingJob(
        tenant_id=tenant_id,
        dataset_version_id=dataset_version_id,
        base_model_version=base_model_version or BASE_MODEL,
        status="QUEUED",
        created_by=user.username if hasattr(user, "username") and user.username else "admin",
    )

    db.add(job)
    db.commit()
    db.refresh(job)

    # Wake the training worker immediately via NATS -- best effort, and only
    # when we are inside a running event loop. Never block here waiting on a
    # broker (run_until_complete against an unreachable NATS used to stall
    # this call for minutes); the worker also polls, so a skipped publish
    # just means the job starts on the next poll.
    try:
        import asyncio
        from app import events

        loop = asyncio.get_running_loop()
        loop.create_task(
            events.publish("training.job.queued", {
                "job_id": job.id,
                "dataset_version_id": dataset_version_id,
                "tenant_id": tenant_id,
            })
        )
    except RuntimeError:
        logger.debug("training.job.queued NATS publish skipped (no running event loop)")
    except Exception:  # noqa: BLE001 - job row was already committed
        logger.debug("training.job.queued NATS publish failed", exc_info=True)

    return job


# ---------------------------------------------------------------------------
# Job execution (called by the training worker synchronously)
# ---------------------------------------------------------------------------

def claim_job(db: Session, job_id: str) -> bool:
    """Atomically move a job QUEUED -> RUNNING. Returns True only for the one
    caller whose UPDATE actually changed the row, so the NATS callback and the
    poll loop (or two worker containers) can never both run the same job."""
    from sqlalchemy import update

    res = db.execute(
        update(TrainingJob)
        .where(TrainingJob.id == job_id, TrainingJob.status == "QUEUED")
        .values(status="RUNNING", started_at=datetime.utcnow(), error=None)
    )
    db.commit()
    return (res.rowcount or 0) == 1


def requeue_job(db: Session, job_id: str, tenant_id: Optional[str] = None) -> TrainingJob:
    """FAILED/CANCELLED -> QUEUED (the "retry" the worker docs always mentioned)."""
    job = _get_job(db, job_id, tenant_id)
    if job.status not in ("FAILED", "CANCELLED"):
        raise ValueError(f"Job is {job.status}; only FAILED or CANCELLED jobs can be retried")
    job.status = "QUEUED"
    job.error = None
    job.started_at = None
    job.completed_at = None
    db.commit()
    db.refresh(job)
    return job


def cancel_job(db: Session, job_id: str, tenant_id: Optional[str] = None) -> TrainingJob:
    """Only a QUEUED job can be cancelled; a RUNNING fine-tune can't be
    interrupted safely from here."""
    job = _get_job(db, job_id, tenant_id)
    if job.status != "QUEUED":
        raise ValueError(f"Job is {job.status}; only QUEUED jobs can be cancelled")
    job.status = "CANCELLED"
    job.completed_at = datetime.utcnow()
    db.commit()
    db.refresh(job)
    return job


def _get_job(db: Session, job_id: str, tenant_id: Optional[str]) -> TrainingJob:
    q = db.query(TrainingJob).filter(TrainingJob.id == job_id)
    if tenant_id:
        q = q.filter((TrainingJob.tenant_id == tenant_id) | (TrainingJob.tenant_id.is_(None)))
    job = q.first()
    if not job:
        raise ValueError(f"TrainingJob {job_id} not found")
    return job


def recover_stale_jobs(db: Session, stale_minutes: Optional[int] = None) -> int:
    """A worker that dies mid-fine-tune leaves its job RUNNING forever. Mark
    those FAILED (retryable) once they exceed TRAINING_JOB_STALE_MINUTES."""
    from datetime import timedelta

    minutes = stale_minutes if stale_minutes is not None else int(os.getenv("TRAINING_JOB_STALE_MINUTES", "180"))
    cutoff = datetime.utcnow() - timedelta(minutes=minutes)
    stale = db.query(TrainingJob).filter(TrainingJob.status == "RUNNING", TrainingJob.started_at < cutoff).all()
    for job in stale:
        job.status = "FAILED"
        job.error = f"Worker stopped responding (no completion after {minutes} min); retry to run it again."
        job.completed_at = datetime.utcnow()
    if stale:
        db.commit()
    return len(stale)


def run_training_job(db: Session, job_id: str) -> None:
    """Fine-tune DistilBERT on the examples in the job's DatasetVersion.

    Claims the job atomically first (QUEUED -> RUNNING); if another worker
    already claimed it, this is a no-op. Sets job.status to COMPLETED (with
    real metrics) or FAILED (with error text). Never generates placeholder
    metrics on failure.

    This function is synchronous and CPU-safe.  The training worker runs it
    in a thread pool so it doesn't block the event loop.
    """
    job = db.query(TrainingJob).filter(TrainingJob.id == job_id).first()
    if not job:
        logger.error("TrainingJob %s not found", job_id)
        return
    if job.status == "CANCELLED":
        logger.info("TrainingJob %s is CANCELLED, skipping", job_id)
        return
    if not claim_job(db, job_id):
        logger.info("TrainingJob %s was already claimed by another runner, skipping", job_id)
        return
    db.refresh(job)

    try:
        _execute_training(db, job)
    except Exception as exc:  # noqa: BLE001
        logger.exception("TrainingJob %s failed: %s", job_id, exc)
        db.rollback()
        job = db.query(TrainingJob).filter(TrainingJob.id == job_id).first()
        job.status = "FAILED"
        job.error = f"{type(exc).__name__}: {exc}"
        job.completed_at = datetime.utcnow()
        db.commit()


def _execute_training(db: Session, job: TrainingJob) -> None:
    """Core fine-tuning path.  Raises on any failure so the caller can mark
    the job FAILED with the real exception message."""

    # ------------------------------------------------------------------
    # 1. Import heavy dependencies early to get a clear error when they
    #    are missing (spec: report FAILED/UNAVAILABLE, never placeholder).
    # ------------------------------------------------------------------
    try:
        import torch
        from transformers import (
            DistilBertForSequenceClassification,
            DistilBertTokenizerFast,
            Trainer,
            TrainingArguments,
        )
        from torch.utils.data import Dataset as TorchDataset
    except ImportError as exc:
        raise RuntimeError(
            f"Training dependencies unavailable — install torch and transformers: {exc}"
        ) from exc

    # ------------------------------------------------------------------
    # 2. Load training examples from the DatasetVersion
    # ------------------------------------------------------------------
    dv = db.query(DatasetVersion).filter(DatasetVersion.id == job.dataset_version_id).first()
    if not dv:
        raise ValueError(f"DatasetVersion {job.dataset_version_id} not found")

    examples = (
        db.query(TrainingExample)
        .join(DatasetItem, DatasetItem.training_example_id == TrainingExample.id)
        .filter(
            DatasetItem.dataset_version_id == dv.id,
            TrainingExample.validation_status != "EXCLUDED",
            TrainingExample.human_action.in_(["APPROVED", "CORRECTED"]),
        )
        .all()
    )

    if len(examples) < 2:
        raise ValueError(
            f"DatasetVersion {dv.version} has only {len(examples)} usable example(s) — "
            "need at least 2 to train (1 train, 1 validation)."
        )

    # ------------------------------------------------------------------
    # 3. Build label encoder (intent → int)
    # ------------------------------------------------------------------
    intents = sorted(set(ex.intent or "UNKNOWN" for ex in examples))
    label2id = {intent: idx for idx, intent in enumerate(intents)}
    id2label = {idx: intent for intent, idx in label2id.items()}
    num_labels = len(intents)

    # ------------------------------------------------------------------
    # 4. Train / validation split (80 / 20, stratified where possible)
    # ------------------------------------------------------------------
    train_examples, val_examples = _stratified_split(examples, label2id, train_ratio=0.80)
    if not val_examples:
        # Pathological case: all examples have the same intent — put 1 in val
        train_examples, val_examples = examples[:-1], examples[-1:]

    logger.info(
        "TrainingJob %s: %d train / %d val examples, %d intents",
        job.id, len(train_examples), len(val_examples), num_labels,
    )

    # ------------------------------------------------------------------
    # 5. Tokenise
    # ------------------------------------------------------------------
    tokenizer = DistilBertTokenizerFast.from_pretrained(
        job.base_model_version or BASE_MODEL, local_files_only=False,
    )

    class _IntentDataset(TorchDataset):
        def __init__(self, exs):
            texts = [ex.raw_config_redacted or "" for ex in exs]
            labels = [label2id.get(ex.intent or "UNKNOWN", 0) for ex in exs]
            enc = tokenizer(texts, truncation=True, padding=True, max_length=128)
            self.input_ids = enc["input_ids"]
            self.attention_mask = enc["attention_mask"]
            self.labels = labels

        def __len__(self):
            return len(self.labels)

        def __getitem__(self, idx):
            return {
                "input_ids": torch.tensor(self.input_ids[idx]),
                "attention_mask": torch.tensor(self.attention_mask[idx]),
                "labels": torch.tensor(self.labels[idx]),
            }

    train_dataset = _IntentDataset(train_examples)
    val_dataset = _IntentDataset(val_examples)

    # ------------------------------------------------------------------
    # 6. Model
    # ------------------------------------------------------------------
    model = DistilBertForSequenceClassification.from_pretrained(
        job.base_model_version or BASE_MODEL,
        num_labels=num_labels,
        id2label=id2label,
        label2id=label2id,
        local_files_only=False,
    )

    # ------------------------------------------------------------------
    # 7. Training arguments (conservative for demo CPU training)
    # ------------------------------------------------------------------
    artifact_dir = os.path.join(ARTIFACT_BASE_DIR, job.id)
    os.makedirs(artifact_dir, exist_ok=True)

    use_gpu = torch.cuda.is_available()
    training_args = TrainingArguments(**_training_args_kwargs(
        TrainingArguments,
        output_dir=artifact_dir,
        num_train_epochs=5 if len(train_examples) >= 10 else 10,
        per_device_train_batch_size=min(8, len(train_examples)),
        per_device_eval_batch_size=min(8, len(val_examples)),
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        logging_steps=10,
        report_to=[],  # disable W&B / tensorboard
        disable_tqdm=True,
        _use_gpu=use_gpu,
    ))

    # ------------------------------------------------------------------
    # 8. Train
    # ------------------------------------------------------------------
    t0 = time.perf_counter()
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
    )
    trainer.train()
    train_duration_ms = (time.perf_counter() - t0) * 1000.0

    # ------------------------------------------------------------------
    # 9. Evaluate on val split and compute REAL metrics
    # ------------------------------------------------------------------
    metrics = _compute_real_metrics(
        trainer=trainer,
        val_dataset=val_dataset,
        val_examples=val_examples,
        label2id=label2id,
        id2label=id2label,
        train_duration_ms=train_duration_ms,
    )

    metrics.update(_intent_coverage(intents))

    # ------------------------------------------------------------------
    # 10. Save model + tokenizer artifacts
    # ------------------------------------------------------------------
    model_dir = os.path.join(artifact_dir, "model")
    os.makedirs(model_dir, exist_ok=True)
    trainer.save_model(model_dir)
    tokenizer.save_pretrained(model_dir)

    # Write metadata alongside the model
    meta = {
        "job_id": job.id,
        "dataset_version": dv.version,
        "base_model": job.base_model_version or BASE_MODEL,
        "num_labels": num_labels,
        "label2id": label2id,
        "id2label": id2label,
        "metrics": metrics,
        "trained_at": datetime.utcnow().isoformat(),
    }
    with open(os.path.join(model_dir, "training_meta.json"), "w") as fh:
        json.dump(meta, fh, indent=2)

    # ------------------------------------------------------------------
    # 11. Hash the saved model for provenance
    # ------------------------------------------------------------------
    model_hash = _hash_model_dir(model_dir)

    # ------------------------------------------------------------------
    # 12. Register as a CANDIDATE in the model registry
    # ------------------------------------------------------------------
    from app.services import model_registry_service

    # Build a mock user object for the audit log
    mock_user = type("_SystemUser", (), {
        "username": "system:training-worker",
        "id": None,
        "sub": "system",
    })()

    model_registry_service.create_candidate(
        db=db,
        model_name=f"intent-classifier-{dv.version}",
        model_type="classifier",
        dataset_version=dv.version,
        base_model_version=job.base_model_version or BASE_MODEL,
        artifact_path=model_dir,
        model_hash=model_hash,
        metrics=metrics,
        training_job_id=job.id,
        user=mock_user,
    )

    # ------------------------------------------------------------------
    # 13. Mark job COMPLETED with real metrics
    # ------------------------------------------------------------------
    job.status = "COMPLETED"
    job.completed_at = datetime.utcnow()
    job.metrics = metrics
    job.artifact_path = model_dir
    db.commit()

    logger.info(
        "TrainingJob %s COMPLETED — macro_f1=%.4f, unknown_f1=%.4f, latency_ms=%.0f",
        job.id,
        metrics.get("macro_f1", 0.0),
        metrics.get("unknown_f1", 0.0),
        train_duration_ms,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _training_args_kwargs(args_cls, *, _use_gpu: bool, **kw) -> dict:
    """transformers renamed evaluation_strategy -> eval_strategy and no_cuda ->
    use_cpu across releases (the old names are removed in newer ones). Pick
    whichever the installed TrainingArguments actually accepts."""
    import inspect

    params = set(inspect.signature(args_cls.__init__).parameters)
    kw["eval_strategy" if "eval_strategy" in params else "evaluation_strategy"] = "epoch"
    if "use_cpu" in params:
        kw["use_cpu"] = not _use_gpu
    elif "no_cuda" in params:
        kw["no_cuda"] = not _use_gpu
    return kw


def _intent_coverage(trained_intents) -> dict:
    """How much of the 13-intent taxonomy a model trained only on HITL data
    actually knows. Shown on the Models tab; promotion is deliberately not
    gated on it (see routers/model_registry.py)."""
    from app.ai.classifier import KNOWN_INTENTS

    trained = sorted(set(trained_intents))
    covered = [i for i in KNOWN_INTENTS if i in trained]
    return {
        "intents_trained": trained,
        "known_intents_total": len(KNOWN_INTENTS),
        "known_intents_covered": len(covered),
        "known_intents_missing": [i for i in KNOWN_INTENTS if i not in trained],
        "intent_coverage": round(len(covered) / len(KNOWN_INTENTS), 4) if KNOWN_INTENTS else 0.0,
    }


def _stratified_split(examples, label2id, train_ratio=0.80):
    """Roughly stratified 80/20 split by intent label."""
    from collections import defaultdict
    buckets = defaultdict(list)
    for ex in examples:
        buckets[label2id.get(ex.intent or "UNKNOWN", 0)].append(ex)

    train, val = [], []
    for label_examples in buckets.values():
        n_train = max(1, round(len(label_examples) * train_ratio))
        train.extend(label_examples[:n_train])
        val.extend(label_examples[n_train:])
    return train, val


def _compute_real_metrics(
    trainer,
    val_dataset,
    val_examples,
    label2id,
    id2label,
    train_duration_ms,
) -> dict:
    """Run inference on the validation set and return real per-class and
    aggregate metrics.  Never fabricates values."""
    import numpy as np

    predictions_output = trainer.predict(val_dataset)
    raw_logits = predictions_output.predictions  # shape (n, num_labels)
    pred_ids = np.argmax(raw_logits, axis=1).tolist()
    true_ids = [label2id.get(ex.intent or "UNKNOWN", 0) for ex in val_examples]

    num_labels = len(label2id)
    tp = [0] * num_labels
    fp = [0] * num_labels
    fn = [0] * num_labels

    for pred, true in zip(pred_ids, true_ids):
        if pred == true:
            tp[true] += 1
        else:
            fp[pred] += 1
            fn[true] += 1

    per_class_f1 = []
    per_class_precision = []
    per_class_recall = []
    for i in range(num_labels):
        prec = tp[i] / (tp[i] + fp[i]) if (tp[i] + fp[i]) > 0 else 0.0
        rec = tp[i] / (tp[i] + fn[i]) if (tp[i] + fn[i]) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        per_class_f1.append(f1)
        per_class_precision.append(prec)
        per_class_recall.append(rec)

    correct = sum(1 for p, t in zip(pred_ids, true_ids) if p == t)
    accuracy = correct / len(true_ids) if true_ids else 0.0
    macro_f1 = float(np.mean(per_class_f1))
    macro_precision = float(np.mean(per_class_precision))
    macro_recall = float(np.mean(per_class_recall))

    # Weighted F1
    support = [0] * num_labels
    for t in true_ids:
        support[t] += 1
    total = sum(support) or 1
    weighted_f1 = float(sum(f1 * s / total for f1, s in zip(per_class_f1, support)))

    # UNKNOWN intent F1 (key safety metric for the classifier)
    unknown_label_id = label2id.get("UNKNOWN", label2id.get("unknown", None))
    unknown_f1 = per_class_f1[unknown_label_id] if unknown_label_id is not None else 0.0

    return {
        "accuracy": round(accuracy, 4),
        "macro_f1": round(macro_f1, 4),
        "macro_precision": round(macro_precision, 4),
        "macro_recall": round(macro_recall, 4),
        "weighted_f1": round(weighted_f1, 4),
        "unknown_f1": round(unknown_f1, 4),
        "latency_ms": round(train_duration_ms, 1),
        "val_examples": len(val_examples),
        "num_labels": len(label2id),
        "per_class_f1": {id2label[i]: round(per_class_f1[i], 4) for i in range(len(label2id))},
    }


def _hash_model_dir(model_dir: str) -> str:
    """SHA-256 over all files in the model directory, sorted by relative path,
    to produce a stable provenance hash for the ModelRegistryEntry."""
    hasher = hashlib.sha256()
    for root, _, files in os.walk(model_dir):
        for fname in sorted(files):
            rel = os.path.relpath(os.path.join(root, fname), model_dir)
            hasher.update(rel.encode())
            with open(os.path.join(root, fname), "rb") as fh:
                while chunk := fh.read(65536):
                    hasher.update(chunk)
    return hasher.hexdigest()