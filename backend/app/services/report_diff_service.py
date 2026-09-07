"""Report diffing -- "what changed since last audit" (Reporting/Evidence
feedback item).

This is deliberately a different axis from `drift_service.py` /
`security_baseline_drift.py`: those compare raw config lines / normalized
baseline parameters between two scans. This module compares the
*compliance verdicts* (Finding rows) two scans produced -- i.e. what a
security reviewer sees change in the report itself, not the underlying
config. A control can flip PASS->FAIL with no baseline-drift signal at
all if e.g. an OPA policy version changed, and conversely a raw config
diff can be noisy with cosmetic changes that never touch a control the
compliance engine tracks. Both views are useful; this one is scoped to
the report.

Findings are matched across scans by (framework, control_id) -- the
compliance engine's own stable identifier for "the same control" --
never by row id, title text, or ordinal position, since findings are
regenerated (new ids) on every scan.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.db import Finding, Scan

_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _key(f: Finding) -> Tuple[str, str]:
    return (f.framework or "", f.control_id or f.id)


def _finding_dict(f: Finding) -> dict:
    return {
        "control_id": f.control_id,
        "framework": f.framework,
        "title": f.title,
        "severity": f.severity,
        "result": f.result,
        "expected_value": f.expected_value,
        "actual_value": f.actual_value,
        "parameter": f.parameter,
    }


def find_previous_scan(db: Session, scan: Scan, tenant_id: str) -> Optional[Scan]:
    """Most recent completed scan for the same device, before `scan`,
    scoped to the tenant (never cross-tenant, matching the Phase 5 rule
    used everywhere else in this file's siblings)."""
    return (
        db.query(Scan)
        .filter(
            Scan.device_id == scan.device_id,
            Scan.tenant_id == tenant_id,
            Scan.id != scan.id,
            Scan.status == "completed",
            Scan.created_at < scan.created_at,
        )
        .order_by(Scan.created_at.desc())
        .first()
    )


@dataclass
class ReportDiff:
    baseline_scan_id: Optional[str]
    current_scan_id: str
    baseline_created_at: Optional[str]
    current_created_at: Optional[str]
    baseline_score: Optional[float]
    current_score: Optional[float]
    score_delta: Optional[float]
    newly_failing: List[dict] = field(default_factory=list)   # PASS/absent -> FAIL
    resolved: List[dict] = field(default_factory=list)         # FAIL -> PASS
    still_failing: List[dict] = field(default_factory=list)    # FAIL -> FAIL, unchanged
    severity_changed: List[dict] = field(default_factory=list)  # FAIL -> FAIL, severity moved
    unchanged_count: int = 0

    def to_dict(self) -> dict:
        return {
            "baseline_scan_id": self.baseline_scan_id,
            "current_scan_id": self.current_scan_id,
            "baseline_created_at": self.baseline_created_at,
            "current_created_at": self.current_created_at,
            "baseline_score": self.baseline_score,
            "current_score": self.current_score,
            "score_delta": self.score_delta,
            "summary": {
                "newly_failing": len(self.newly_failing),
                "resolved": len(self.resolved),
                "still_failing": len(self.still_failing),
                "severity_changed": len(self.severity_changed),
                "unchanged": self.unchanged_count,
            },
            "newly_failing": self.newly_failing,
            "resolved": self.resolved,
            "still_failing": self.still_failing,
            "severity_changed": self.severity_changed,
        }


def build_report_diff(db: Session, current: Scan, baseline: Optional[Scan]) -> ReportDiff:
    current_findings = db.query(Finding).filter(Finding.scan_id == current.id).all()
    current_by_key: Dict[Tuple[str, str], Finding] = {_key(f): f for f in current_findings}

    if baseline is None:
        # No prior scan to diff against: every current failure is "new"
        # relative to an empty baseline, which is the correct framing for
        # a device's first-ever audit rather than an error.
        diff = ReportDiff(
            baseline_scan_id=None,
            current_scan_id=current.id,
            baseline_created_at=None,
            current_created_at=current.created_at.isoformat() if current.created_at else None,
            baseline_score=None,
            current_score=current.compliance_score,
            score_delta=None,
        )
        diff.newly_failing = [_finding_dict(f) for f in current_findings if f.result == "FAIL"]
        diff.unchanged_count = 0
        return diff

    baseline_findings = db.query(Finding).filter(Finding.scan_id == baseline.id).all()
    baseline_by_key: Dict[Tuple[str, str], Finding] = {_key(f): f for f in baseline_findings}

    diff = ReportDiff(
        baseline_scan_id=baseline.id,
        current_scan_id=current.id,
        baseline_created_at=baseline.created_at.isoformat() if baseline.created_at else None,
        current_created_at=current.created_at.isoformat() if current.created_at else None,
        baseline_score=baseline.compliance_score,
        current_score=current.compliance_score,
        score_delta=(
            round(current.compliance_score - baseline.compliance_score, 2)
            if current.compliance_score is not None and baseline.compliance_score is not None
            else None
        ),
    )

    all_keys = set(current_by_key) | set(baseline_by_key)
    for k in all_keys:
        cur = current_by_key.get(k)
        base = baseline_by_key.get(k)

        cur_fail = bool(cur and cur.result == "FAIL")
        base_fail = bool(base and base.result == "FAIL")

        if cur_fail and not base_fail:
            diff.newly_failing.append(_finding_dict(cur))
        elif base_fail and not cur_fail:
            # Control existed as a failure before and is no longer failing
            # (passed, or the control/finding simply doesn't recur this
            # scan -- either way it's not a live problem anymore).
            diff.resolved.append(_finding_dict(base))
        elif cur_fail and base_fail:
            cur_rank = _SEVERITY_RANK.get((cur.severity or "").upper(), -1)
            base_rank = _SEVERITY_RANK.get((base.severity or "").upper(), -1)
            if cur_rank != base_rank:
                entry = _finding_dict(cur)
                entry["previous_severity"] = base.severity
                diff.severity_changed.append(entry)
            else:
                diff.still_failing.append(_finding_dict(cur))
        else:
            diff.unchanged_count += 1

    return diff
