"""
Configuration drift detection (Phase 11).

Every collection/upload produces a raw_config_hash on the Scan row. This
module compares that hash against the device's immediately-preceding scan's
hash. On a mismatch it computes a line-level diff, applies a keyword
heuristic to flag "security-impacting" changes and their likely affected
control IDs, and writes an immutable DriftEvent row.

This module NEVER renders a compliance verdict. "security_impacting" is a
triage signal only, used by the pipeline to decide whether a drifted
configuration is worth a full OPA/Batfish re-evaluation versus a purely
cosmetic change (e.g. a banner or comment edit) -- the verdict itself always
comes from OPA (see services/opa_service.py), never from this heuristic.
"""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import List, Optional

from sqlalchemy.orm import Session

from app.models.db import DriftEvent, Scan

# Keyword -> (affected control ids, is security-impacting) heuristic. This is
# intentionally conservative and additive: it only ever flags MORE changes
# for review, never suppresses a genuine diff. Extend as new controls are
# added to policies/controls.py.
_SECURITY_KEYWORDS: List[tuple] = [
    (re.compile(r"\btelnet\b", re.I), ["CIS-TELNET-001"]),
    (re.compile(r"\bssh\b", re.I), ["CIS-SSH-001"]),
    (re.compile(r"\bhttp\b(?!s)", re.I), ["CIS-HTTP-001"]),
    (re.compile(r"\bhttps\b", re.I), ["CIS-HTTP-002"]),
    (re.compile(r"password|secret|enable secret|enable password", re.I), ["CIS-PASSWORD-001"]),
    (re.compile(r"access-list|acl\b|ip access-group|filter-list", re.I), ["ACL-EFFECTIVENESS-001"]),
    (re.compile(r"\bvlan\b", re.I), ["SEGMENTATION-USER-SERVER-001"]),
    (re.compile(r"\bvty\b|line vty", re.I), ["CIS-SSH-001"]),
    (re.compile(r"snmp", re.I), ["CIS-SNMP-001"]),
    (re.compile(r"aaa\b|radius|tacacs", re.I), ["CIS-AAA-001"]),
    (re.compile(r"\bntp\b", re.I), []),
    (re.compile(r"logging|syslog", re.I), []),
    (re.compile(r"no shutdown|^\s*shutdown\s*$", re.I), []),
    (re.compile(r"management|mgmt", re.I), ["MGMT-ISOLATION-GUEST-001"]),
]


@dataclass
class DriftAnalysis:
    changed: bool
    added_lines: List[str] = field(default_factory=list)
    removed_lines: List[str] = field(default_factory=list)
    changed_sections: List[str] = field(default_factory=list)
    security_impacting: bool = False
    affected_controls: List[str] = field(default_factory=list)


def diff_configs(previous_text: Optional[str], current_text: str) -> DriftAnalysis:
    """Pure line-level diff + heuristic triage. `previous_text` is None for a
    device's very first observed configuration -- treated as "no drift"
    (nothing to compare against), not as an added-everything drift."""
    if previous_text is None:
        return DriftAnalysis(changed=False)

    prev_lines = previous_text.splitlines()
    cur_lines = current_text.splitlines()
    if prev_lines == cur_lines:
        return DriftAnalysis(changed=False)

    sm = difflib.SequenceMatcher(a=prev_lines, b=cur_lines)
    added: List[str] = []
    removed: List[str] = []
    changed_sections: List[str] = []
    affected: set = set()
    security_impacting = False

    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        removed_chunk = prev_lines[i1:i2]
        added_chunk = cur_lines[j1:j2]
        removed.extend(removed_chunk)
        added.extend(added_chunk)
        section_label = f"{tag}:{i1}-{i2}->{j1}-{j2}"
        changed_sections.append(section_label)
        for line in removed_chunk + added_chunk:
            for pattern, control_ids in _SECURITY_KEYWORDS:
                if pattern.search(line):
                    security_impacting = True
                    affected.update(control_ids)

    return DriftAnalysis(
        changed=True,
        added_lines=added,
        removed_lines=removed,
        changed_sections=changed_sections,
        security_impacting=security_impacting,
        affected_controls=sorted(affected),
    )


def get_previous_scan(db: Session, device_id: str, exclude_scan_id: str) -> Optional[Scan]:
    return (
        db.query(Scan)
        .filter(Scan.device_id == device_id, Scan.id != exclude_scan_id, Scan.raw_config_hash.isnot(None))
        .order_by(Scan.created_at.desc())
        .first()
    )


def record_drift(
    db: Session,
    tenant_id: str,
    device_id: str,
    current_scan: Scan,
    previous_text: Optional[str],
    current_text: str,
) -> Optional[DriftEvent]:
    """Compares `current_scan` against the device's prior scan (by hash) and,
    if changed, persists an immutable DriftEvent. Returns None when there is
    no prior scan to compare against or the hashes match (no drift)."""
    previous_scan = get_previous_scan(db, device_id, exclude_scan_id=current_scan.id)
    previous_hash = previous_scan.raw_config_hash if previous_scan else None

    if previous_hash == current_scan.raw_config_hash:
        return None  # identical config (including "no prior scan" -> both None only if hash None, guarded below)
    if previous_scan is None:
        return None  # first-ever observed configuration for this device: nothing to diff against

    analysis = diff_configs(previous_text, current_text)
    if not analysis.changed:
        return None

    event = DriftEvent(
        tenant_id=tenant_id,
        device_id=device_id,
        previous_scan_id=previous_scan.id,
        current_scan_id=current_scan.id,
        previous_config_hash=previous_hash,
        current_config_hash=current_scan.raw_config_hash,
        added_lines=analysis.added_lines[:500],
        removed_lines=analysis.removed_lines[:500],
        changed_sections=analysis.changed_sections[:200],
        security_impacting=analysis.security_impacting,
        affected_controls=analysis.affected_controls,
        pipeline_rerun_triggered=True,  # the pipeline always continues to OPA/Batfish for THIS scan regardless
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def record_hash_only_drift(
    db: Session,
    tenant_id: str,
    device_id: str,
    current_scan: Scan,
    previous_scan: Scan,
) -> Optional[DriftEvent]:
    """Used when the raw config hash changed but the previous scan's raw
    text could not be recovered from object storage (e.g. a MinIO outage at
    collection time). Records that drift occurred without fabricating a
    line-level diff against an empty string, which would otherwise flag
    every line of the current config as "added" -- a false full-rewrite
    drift event. Conservatively marked security_impacting=True since the
    actual change can't be inspected."""
    event = DriftEvent(
        tenant_id=tenant_id,
        device_id=device_id,
        previous_scan_id=previous_scan.id,
        current_scan_id=current_scan.id,
        previous_config_hash=previous_scan.raw_config_hash,
        current_config_hash=current_scan.raw_config_hash,
        added_lines=[],
        removed_lines=[],
        changed_sections=["hash-only: previous raw config unrecoverable, diff not computed"],
        security_impacting=True,
        affected_controls=[],
        pipeline_rerun_triggered=True,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def to_dict(event: DriftEvent) -> dict:
    return {
        "id": event.id,
        "tenant_id": event.tenant_id,
        "device_id": event.device_id,
        "previous_scan_id": event.previous_scan_id,
        "current_scan_id": event.current_scan_id,
        "previous_config_hash": event.previous_config_hash,
        "current_config_hash": event.current_config_hash,
        "added_lines": event.added_lines or [],
        "removed_lines": event.removed_lines or [],
        "changed_sections": event.changed_sections or [],
        "security_impacting": event.security_impacting,
        "affected_controls": event.affected_controls or [],
        "pipeline_rerun_triggered": event.pipeline_rerun_triggered,
        "created_at": event.created_at.isoformat() if event.created_at else None,
    }