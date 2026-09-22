"""Ordered pipeline-stage tracking for deployments and rollbacks.

The auditor's question after a failed change is "where exactly did it stop?":
was the device unreachable, did authentication fail, was the pre-change hash
stale, did the commit get rejected, or did it land and then fail verification /
post-validation?  A single `status` + free-text `error` cannot answer that
reliably, so every deployment / rollback persists an ordered list of stage
records and each service flips them as it goes.

A stage record is a plain JSON object:

    {
      "key":         "connect",
      "label":       "Device connection",
      "status":      "pending" | "running" | "passed" | "warning" | "failed" | "skipped",
      "started_at":  ISO-8601 | None,
      "finished_at": ISO-8601 | None,
      "detail":      str | None,      # what happened, human readable
      "error":       str | None,      # why it failed (already credential-redacted upstream)
      "kind":        str | None,      # machine-readable failure class, e.g. "connection"
    }

The tracker commits after every transition, so a UI polling the deployment
list sees stages move `pending -> running -> passed` live.

It never raises: stage bookkeeping must not be able to mask the real outcome of
a deployment.  A failed DB write is logged and swallowed.
"""
from __future__ import annotations

import copy
import logging
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sqlalchemy.orm import Session

logger = logging.getLogger("stage_tracker")

PENDING, RUNNING, PASSED, WARNING, FAILED, SKIPPED = (
    "pending", "running", "passed", "warning", "failed", "skipped",
)

# (key, label) -- order is the order they execute in.
DEPLOY_STAGES: List[Tuple[str, str]] = [
    ("credentials", "Credentials"),
    ("connect", "Device connection"),
    ("precheck", "Pre-change hash check"),
    ("plan", "Command plan"),
    ("commit", "Push & commit"),
    ("verify", "Post-change verification"),
    ("postval", "Post-validation (OPA · Batfish · Risk)"),
]

ROLLBACK_STAGES: List[Tuple[str, str]] = [
    ("archive", "Load pre-change config"),
    ("credentials", "Credentials"),
    ("plan", "Revert plan"),
    ("push", "Push revert"),
    ("verify", "Re-collect & hash check"),
    ("postval", "Post-validation (OPA · Batfish · Risk)"),
]


def _now() -> str:
    return datetime.utcnow().isoformat()


def blank_stages(spec: Iterable[Tuple[str, str]]) -> List[Dict[str, Any]]:
    return [
        {"key": k, "label": label, "status": PENDING, "started_at": None,
         "finished_at": None, "duration_ms": None, "detail": None, "error": None, "kind": None}
        for k, label in spec
    ]


class StageTracker:
    """Mutates `record.stages` (a JSON column) and commits on each transition."""

    def __init__(self, db: Session, record: Any, spec: Iterable[Tuple[str, str]]):
        self.db = db
        self.record = record
        self._spec = list(spec)
        if not getattr(record, "stages", None):
            self._save(blank_stages(self._spec))

    # -- internals ---------------------------------------------------------
    def _stages(self) -> List[Dict[str, Any]]:
        # Deep copy: SQLAlchemy only notices a JSON column change when the
        # attribute is *reassigned*, not when the list is mutated in place.
        return copy.deepcopy(self.record.stages or blank_stages(self._spec))

    def _save(self, stages: List[Dict[str, Any]]) -> None:
        try:
            self.record.stages = stages
            self.db.commit()
        except Exception:  # noqa: BLE001 -- bookkeeping must never mask the real outcome
            logger.warning("Could not persist stage update", exc_info=True)
            try:
                self.db.rollback()
            except Exception:  # noqa: BLE001
                pass

    def _update(self, key: str, **fields: Any) -> None:
        stages = self._stages()
        for s in stages:
            if s["key"] == key:
                # Auto-compute duration_ms when finishing (a finished_at is in fields
                # but started_at was already recorded from the start() call).
                if "finished_at" in fields and fields["finished_at"] and s.get("started_at"):
                    try:
                        from datetime import datetime as _dt
                        t0 = _dt.fromisoformat(s["started_at"])
                        t1 = _dt.fromisoformat(fields["finished_at"])
                        fields["duration_ms"] = round((t1 - t0).total_seconds() * 1000)
                    except Exception:  # noqa: BLE001
                        pass
                s.update(fields)
                break
        else:  # unknown key: ignore rather than crash a deployment
            logger.warning("Unknown stage key %r", key)
            return
        self._save(stages)

    # -- public API --------------------------------------------------------
    def start(self, key: str, detail: Optional[str] = None) -> None:
        self._update(key, status=RUNNING, started_at=_now(), finished_at=None, detail=detail, error=None, kind=None)

    def ok(self, key: str, detail: Optional[str] = None, status: str = PASSED) -> None:
        stages = self._stages()
        started = next((s["started_at"] for s in stages if s["key"] == key), None)
        self._update(key, status=status, started_at=started or _now(), finished_at=_now(),
                     detail=detail if detail is not None else next((s["detail"] for s in stages if s["key"] == key), None))

    def warn(self, key: str, detail: Optional[str] = None) -> None:
        self.ok(key, detail, status=WARNING)

    def fail(self, key: str, error: str, kind: Optional[str] = None, detail: Optional[str] = None,
             skip_rest: bool = True) -> None:
        """Mark a stage failed. `skip_rest=False` is for stages whose failure
        does not stop the pipeline (e.g. a hash mismatch still proceeds to
        post-validation so the auditor gets evidence of what is on the device)."""
        stages = self._stages()
        started = next((s["started_at"] for s in stages if s["key"] == key), None)
        self._update(key, status=FAILED, started_at=started or _now(), finished_at=_now(),
                     error=error, kind=kind, detail=detail)
        if skip_rest:
            self.skip_pending("Not reached: an earlier stage failed.")

    def skip(self, key: str, detail: Optional[str] = None) -> None:
        self._update(key, status=SKIPPED, finished_at=_now(), detail=detail)

    def skip_pending(self, reason: str) -> None:
        stages = self._stages()
        changed = False
        for s in stages:
            if s["status"] == PENDING:
                s.update(status=SKIPPED, detail=reason)
                changed = True
        if changed:
            self._save(stages)

    def fail_running(self, error: str, kind: str = "internal") -> None:
        """Used by the crash handler: mark whichever stage was in flight failed
        (or the first pending one if none was running)."""
        stages = self._stages()
        target = next((s["key"] for s in stages if s["status"] == RUNNING), None) \
            or next((s["key"] for s in stages if s["status"] == PENDING), None)
        if target:
            self.fail(target, error, kind=kind)


def classify_push_error(error: Optional[str]) -> str:
    """Bucket a deployer error string into a failure class the UI can badge.

    The deployers return free-text errors (`Authentication failed: ...`,
    `Connection timed out: ...`, `Deployment push failed: ...`).  Splitting them
    here lets the auditor distinguish "we never reached the device" from "the
    device rejected our commit" without every deployer having to grow a new
    error taxonomy.
    """
    e = (error or "").lower()
    if any(t in e for t in ("authentication", "auth fail", "permission denied", "invalid credentials", "unauthorized")):
        return "authentication"
    if any(t in e for t in ("timed out", "timeout", "connection refused", "no route", "unreachable",
                            "connection reset", "tcp connection", "name or service not known",
                            "network is unreachable", "could not connect", "unavailable")):
        return "connection"
    if any(t in e for t in ("not installed", "no ssh deployment profile", "unsupported", "disabled", "no management address")):
        return "unsupported"
    if any(t in e for t in ("invalid", "rejected", "% ", "error:", "syntax", "incomplete command", "ambiguous")):
        return "commit_rejected"
    return "commit_failed"


KIND_LABELS: Dict[str, str] = {
    "connection": "Device unreachable",
    "authentication": "Authentication failed",
    "unsupported": "Transport unsupported / unavailable",
    "commit_rejected": "Device rejected the commit",
    "commit_failed": "Commit failed",
    "stale_hash": "Config changed since validation",
    "no_plan": "No safe command set",
    "verification_mismatch": "Config differs from approved proposal",
    "verification_unavailable": "Could not re-collect config",
    "credentials": "Credentials unavailable",
    "internal": "Unexpected internal error",
}
