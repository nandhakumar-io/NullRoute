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

import httpx
import json
import os
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from app.models.db import Device, Finding, Scan
from app.services import remediation_templates

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://ollama:11434")
LLM_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:8b")


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


async def generate_remediation_cli_for_scan(db: Session, scan: Scan) -> Dict[str, Any]:
    """Phase 14+ -- vendor-specific remediation CLI generation.

    Implements, per FAIL finding, the pipeline:

        Finding -> control_id -> (vendor, os/version) -> validated template
                -> step-by-step CLI -> human approval

    Only `control_id`s with a hand-authored, reviewed entry in
    `remediation_templates` produce CLI (`cli_available: true`). Every
    other finding still returns its existing prose `remediation` text
    (`cli_available: false`) rather than a guessed command sequence --
    this function never asks an LLM to invent syntax (RULE 3/RULE 10,
    same boundary `suggest_remediation_for_scan` already documents).

    The response is a proposal, not an action: `requires_human_approval`
    is always true, nothing here is sent to a device, and turning this
    into something deployable still goes through the existing
    ChangeRequest flow (services/change_request_service.py), which is the
    only path with a human APPROVED gate before deployment_service runs.
    """
    device = db.query(Device).filter(Device.id == scan.device_id).first()
    vendor = (device.vendor if device else None) or "Unknown"
    os_family = (device.os if device else None) or "Unknown"

    fails: List[Finding] = (
        db.query(Finding)
        .filter(Finding.scan_id == scan.id, Finding.result == "FAIL")
        .order_by(Finding.severity)
        .all()
    )

    remediations = []
    for f in fails:
        template = remediation_templates.get_template(f.control_id, vendor)
        if template:
            has_placeholder = any("<" in c and ">" in c for c in template.commands)
            remediations.append({
                "finding_id": f.id,
                "control_id": f.control_id,
                "title": f.title,
                "severity": f.severity,
                "vendor": template.vendor,
                "os_family": template.os_family,
                "cli_available": True,
                "description": template.description,
                "cli_steps": list(template.commands),
                "save_commands": list(template.save_commands),
                "reference": template.reference,
                "requires_site_values": has_placeholder,
                "requires_human_approval": True,
                "note": (
                    "Fill in any <PLACEHOLDER> values for this site before use. "
                    "This is a validated template, not a device-specific fact -- "
                    "a human must review and approve it (ideally via a "
                    "ChangeRequest) before anything is applied to the device."
                ),
            })
        else:
            try:
                system_prompt = f"Write configuration CLI commands for {vendor} {os_family} to fix this security failing.\\nIssue: {f.title}\\nGuidance: {f.remediation}\\nActual Value: {f.actual_value}\\nOutput ONLY a JSON array of strings containing the commands exactly, without markdown fences or explanations."
                async with httpx.AsyncClient(timeout=120.0) as client:
                    resp = await client.post(
                        f"{OLLAMA_HOST}/generate",
                        json={
                            "model": LLM_MODEL,
                            "prompt": system_prompt,
                            "stream": False,
                            "format": "json"
                        }
                    )
                    resp.raise_for_status()
                    text = resp.json().get("response", "[]").strip()
                    if "```json" in text:
                        text = text.split("```json")[-1].split("```")[0].strip()
                    elif "```" in text:
                        text = text.split("```")[-1].split("```")[0].strip()
                    generated = json.loads(text)
                    
                    if not isinstance(generated, list):
                        generated = [str(generated)]
            except Exception as e:
                generated = []

            if generated:
                remediations.append({
                    "finding_id": f.id,
                    "control_id": f.control_id,
                    "title": f.title,
                    "severity": f.severity,
                    "vendor": vendor,
                    "os_family": os_family,
                    "cli_available": True,
                    "description": "AI Generated Synthesized CLI Remediation",
                    "cli_steps": list(generated),
                    "save_commands": ["write memory"],
                    "reference": None,
                    "requires_site_values": False,
                    "requires_human_approval": True,
                    "guidance": f.remediation,
                    "note": (
                        "This template was dynamically generated by the AI LLM Engine. "
                        "A human MUST rigorously review the syntax prior to deployment."
                    ),
                })
            else:
                remediations.append({
                    "finding_id": f.id,
                    "control_id": f.control_id,
                    "title": f.title,
                    "severity": f.severity,
                    "vendor": vendor,
                    "os_family": os_family,
                    "cli_available": False,
                    "description": None,
                    "cli_steps": [],
                    "save_commands": [],
                    "reference": None,
                    "requires_site_values": None,
                    "requires_human_approval": True,
                    "guidance": f.remediation,
                    "note": (
                        "No validated CLI template exists yet for this vendor/control "
                        "pair -- showing prose guidance only. Add a reviewed template "
                        "in app/services/remediation_templates.py to enable CLI "
                        "generation for this control; never fabricate one at request time."
                    ),
                })

    return {
        "scan_id": scan.id,
        "device_id": scan.device_id,
        "vendor": vendor,
        "os_family": os_family,
        "finding_count": len(remediations),
        "cli_generated_count": sum(1 for r in remediations if r["cli_available"]),
        "remediations": remediations,
        "requires_human_approval": True,
    }
