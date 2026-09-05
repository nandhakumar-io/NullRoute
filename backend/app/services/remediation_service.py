"""Phase 14 -- AI remediation suggestions.

Per RULE 3 ("AI can interpret, classify, detect unknowns, explain and
suggest remediation, but AI cannot directly decide compliance") and RULE
10 ("do not fabricate ... results"), this module deliberately does NOT
generate synthetic vendor CLI lines with an LLM -- guessing exact
configuration syntax and presenting it as a "suggestion" risks being
wrong in a way a human reviewer might miss, and there is no trained
generative model in this codebase's AI stack (classifier.py/embeddings.py
are intent classifiers, not code generators).

Instead, `suggest_remediation_for_scan()` assembles a deterministic,
human-readable suggestion from data that already exists and is already
trusted: each FAILing Finding's own `remediation` guidance text (the same
text shown in Scan Detail and PDF/JSON/CSV reports), grouped and
vendor-annotated. This is the "AI remediation suggestion" step in the
Phase 14 workflow -- explicitly a starting point for a human to turn into
concrete `proposed_config` text, never a ready-to-deploy artifact and
never a compliance verdict.
"""
from __future__ import annotations

from typing import Any, Dict, List

from sqlalchemy.orm import Session

from app.models.db import Device, Finding, Scan


def suggest_remediation_for_scan(db: Session, scan: Scan) -> Dict[str, Any]:
    """Returns per-finding remediation guidance for every FAIL finding on
    `scan`, plus a plain-language summary. Never touches OPA/Batfish/risk
    -- those already ran during the scan; this only re-presents their
    output for a human building a ChangeRequest."""
    device = db.query(Device).filter(Device.id == scan.device_id).first()
    vendor = (device.vendor if device else None) or "Unknown"

    fails: List[Finding] = (
        db.query(Finding)
        .filter(Finding.scan_id == scan.id, Finding.result == "FAIL")
        .order_by(Finding.severity)
        .all()
    )

    suggestions = [
        {
            "control_id": f.control_id,
            "title": f.title,
            "severity": f.severity,
            "framework": f.framework,
            "parameter": f.parameter,
            "expected_value": f.expected_value,
            "actual_value": f.actual_value,
            "guidance": f.remediation,
        }
        for f in fails
    ]

    return {
        "scan_id": scan.id,
        "device_id": scan.device_id,
        "vendor": vendor,
        "finding_count": len(suggestions),
        "suggestions": suggestions,
        "note": (
            "Deterministic guidance assembled from existing OPA finding "
            "remediation text -- not generated configuration and not a "
            "compliance decision. A human must translate this into the "
            "proposed_config for a Change Request; AI never writes or "
            "deploys configuration directly."
        ),
    }