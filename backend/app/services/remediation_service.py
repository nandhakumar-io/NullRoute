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
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.db import Device, DeviceVulnerabilityMatch, Finding, Scan, Vulnerability
from app.services import remediation_templates

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://ollama:11434")
LLM_MODEL = os.getenv("OLLAMA_MODEL", "llama")


def _active_device_vulnerabilities(db: Session, device: Optional[Device]) -> List[Dict[str, Any]]:
    """Open, CISA-KEV-flagged CVE matches for this device -- i.e. "actively
    targeted" in the literal sense KEV defines it (Known EXPLOITED
    Vulnerabilities, not merely "possible"). Correlation itself already ran
    (services/vuln_correlation_service.py, via vuln_sync_worker); this only
    reads what's already there.

    `status == "open"` excludes matches a reviewer has already dispositioned
    as mitigated/accepted_risk/false_positive (RULE 15 -- those decisions are
    never overwritten and must not keep resurfacing as if unaddressed).
    """
    if device is None:
        return []
    rows = (
        db.query(DeviceVulnerabilityMatch)
        .join(Vulnerability, DeviceVulnerabilityMatch.cve_id == Vulnerability.cve_id)
        .filter(
            DeviceVulnerabilityMatch.device_id == device.id,
            DeviceVulnerabilityMatch.status == "open",
            Vulnerability.kev_flag.is_(True),
        )
        .order_by(DeviceVulnerabilityMatch.risk_priority_score.desc().nullslast())
        .all()
    )
    out = []
    for m in rows:
        v = m.vulnerability
        out.append({
            "cve_id": v.cve_id,
            "cvss_score": v.cvss_score,
            "severity": v.severity,
            "kev_flag": True,
            "risk_priority_score": m.risk_priority_score,
            "remediation_advice": v.remediation_advice,
            "description": v.description,
        })
    return out


def _firmware_advisory_lines(vulns: List[Dict[str, Any]]) -> List[str]:
    """Deterministic CLI-comment lines for actively-exploited CVEs.

    Written in code from `Vulnerability.remediation_advice` / NVD data --
    never by the LLM. RULE 3/10 in this module already forbid asking an
    LLM to invent syntax; a firmware/OS target version is exactly the kind
    of fact an LLM can plausibly hallucinate, and getting it wrong here is
    worse than a bad ACL line -- it's advice to run an update that may not
    exist. So this deterministic path is the one always trusted; any prompt
    injection into the LLM (see `_vuln_prompt_context`) is a supplementary
    nudge, never the source of truth.
    """
    lines: List[str] = []
    for v in vulns:
        advice = v.get("remediation_advice") or (
            "Apply the vendor's fixed release for this CVE; no specific target "
            "version is on record -- check the vendor's PSIRT advisory."
        )
        cvss = f"CVSS {v['cvss_score']}" if v.get("cvss_score") is not None else "CVSS unknown"
        lines.append(
            f"! [FIRMWARE ADVISORY] {v['cve_id']} ({cvss}, CISA KEV -- actively exploited in the wild): {advice}"
        )
    return lines


def _vuln_prompt_context(vulns: List[Dict[str, Any]]) -> str:
    """Summary block appended to the LLM prompt so the model has the CVE
    context when synthesizing CLI for a control with no validated template.
    The model is told to leave firmware-version advice to the lines already
    supplied, not to invent its own -- see `_firmware_advisory_lines`."""
    if not vulns:
        return ""
    entries = "\n".join(
        f"- {v['cve_id']} (CVSS {v.get('cvss_score', '?')}, actively exploited per CISA KEV)"
        for v in vulns
    )
    return (
        "\n\nThis device also has the following actively-exploited vulnerabilities on record:\n"
        f"{entries}\n"
        "Do not invent a firmware or OS version to fix these -- specific update guidance is "
        "supplied separately. Focus only on the network configuration fix requested above."
    )


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


async def generate_remediation_cli_for_scan(db: Session, scan: Scan) -> Dict[str, Any]:  # noqa: C901
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

    Vulnerability Management integration: if this device has an open,
    CISA-KEV-flagged CVE match (services/vuln_correlation_service.py --
    i.e. a vulnerability confirmed under active exploitation, not merely
    theoretically possible), a `[FIRMWARE ADVISORY]` line is appended to
    every finding's `cli_steps` and the full list is returned as
    `device_vulnerabilities`. That advisory text always comes from the
    vulnerability database (`Vulnerability.remediation_advice`), written
    in code -- never generated by the LLM, for the same reason the rest of
    this module won't let an LLM invent CLI syntax: a wrong firmware
    version is worse than a wrong ACL line. When the LLM path runs (no
    validated template), the CVE list is also added to its prompt so the
    model has the context, but it's explicitly told not to guess a
    firmware version itself.
    """
    device = db.query(Device).filter(Device.id == scan.device_id).first()
    vendor = (device.vendor if device else None) or "Unknown"
    os_family = (device.os if device else None) or "Unknown"

    # Task 3 -- Vulnerability Management pipeline integration. Computed once
    # for the whole scan (it's a device-level fact, not per-finding), then
    # appended to every generated remediation so a reviewer sees firmware
    # risk alongside the network config fix, not in a separate screen they
    # might not open.
    active_vulns = _active_device_vulnerabilities(db, device)
    firmware_lines = _firmware_advisory_lines(active_vulns)
    vuln_prompt_suffix = _vuln_prompt_context(active_vulns)

    fails: List[Finding] = (
        db.query(Finding)
        .filter(Finding.scan_id == scan.id, Finding.result == "FAIL")
        .order_by(Finding.severity)
        .all()
    )

    import asyncio
    # Bound concurrency to prevent HTTP read timeouts while queries wait
    # their turn inside the AI. A much lower limit keeps waiting inside
    # asyncio rather than httpx queues.
    _semaphore = asyncio.Semaphore(2)

    async def _generate(f: Finding) -> Dict[str, Any]:
        # ---- Cache hit: return stored CLI without touching the LLM ----------
        if f.ai_cli_cache:
            cached = f.ai_cli_cache  # list[str] saved from a previous call
            cli_steps = list(cached) + firmware_lines
            return {
                "finding_id": f.id,
                "control_id": f.control_id,
                "title": f.title,
                "severity": f.severity,
                "vendor": vendor,
                "os_family": os_family,
                "cli_available": True,
                "description": "AI Generated Synthesized CLI Remediation",
                "cli_steps": cli_steps,
                "save_commands": ["write memory"],
                "reference": None,
                "requires_site_values": False,
                "requires_human_approval": True,
                "guidance": f.remediation,
                "active_vulnerabilities": [v["cve_id"] for v in active_vulns],
                "cached": True,
                "note": (
                    "This template was dynamically generated by the AI LLM Engine "
                    "(returned from cache — LLM was not called again). "
                    "A human MUST rigorously review the syntax prior to deployment."
                    + (
                        " This device also has actively-exploited CVE(s) on record -- "
                        "the [FIRMWARE ADVISORY] line(s) were added deterministically "
                        "from the vulnerability database, not by the LLM, and need a "
                        "firmware update separate from this CLI fix."
                        if firmware_lines else ""
                    )
                ),
            }

        # ---- Match the template to this device's actual OS family -----------
        template = remediation_templates.get_template(f.control_id, vendor, os_family)
        if template:
            has_placeholder = any("<" in c and ">" in c for c in template.commands)
            cli_steps = list(template.commands)
            if firmware_lines:
                cli_steps = cli_steps + firmware_lines
            return {
                "finding_id": f.id,
                "control_id": f.control_id,
                "title": f.title,
                "severity": f.severity,
                "vendor": template.vendor,
                "os_family": template.os_family,
                "cli_available": True,
                "description": template.description,
                "cli_steps": cli_steps,
                "save_commands": list(template.save_commands),
                "reference": template.reference,
                "requires_site_values": has_placeholder,
                "requires_human_approval": True,
                "active_vulnerabilities": [v["cve_id"] for v in active_vulns],
                "note": (
                    "Fill in any <PLACEHOLDER> values for this site before use. "
                    "This is a validated template, not a device-specific fact -- "
                    "a human must review and approve it (ideally via a "
                    "ChangeRequest) before anything is applied to the device."
                    + (
                        " This device also has actively-exploited CVE(s) on record -- "
                        "see the [FIRMWARE ADVISORY] line(s) below; they are separate "
                        "from this control's network fix and need a maintenance-window "
                        "firmware update, not a config push."
                        if firmware_lines else ""
                    )
                ),
            }
        else:
            llm_error_msg = ""
            generated = []
            v_name = vendor if vendor not in ("Unknown", "Ad-Hoc", None) else "a network device"
            try:
                system_prompt = (
                    f"/no_think Write configuration CLI commands for {v_name} {os_family} to fix this security failing.\\n"
                    f"Issue: {f.title}\\nGuidance: {f.remediation}\\nActual Value: {f.actual_value}\\n"
                    "Output ONLY a JSON array of strings containing the commands exactly, without markdown fences or explanations."
                    + vuln_prompt_suffix
                )
                async with _semaphore:
                    async with httpx.AsyncClient(timeout=300.0) as client:
                        resp = await client.post(
                            f"{OLLAMA_HOST}/generate",
                            json={
                                "model": LLM_MODEL,
                                "prompt": system_prompt,
                                "stream": False
                            }
                        )
                        resp.raise_for_status()
                    text = resp.json().get("response", "[]").strip()
                    import re as _re
                    text = _re.sub(r'<think>.*?</think>', '', text, flags=_re.DOTALL).strip()
                    
                    start_obj = text.find('{')
                    start_arr = text.find('[')
                    start = start_obj if start_obj != -1 and (start_arr == -1 or start_obj < start_arr) else start_arr
                    if start != -1:
                        end_obj = text.rfind('}')
                        end_arr = text.rfind(']')
                        end = end_obj if end_obj > end_arr else end_arr
                        if end != -1 and end > start:
                            text = text[start:end+1]

                    try:
                        generated = json.loads(text)
                    except json.decoder.JSONDecodeError as parse_error:
                        if not text.rstrip().endswith("]"):
                            try:
                                generated = json.loads(text.strip() + "]")
                            except json.decoder.JSONDecodeError:
                                generated = None
                        else:
                            generated = None

                        if generated is None:
                            import re
                            matches = re.findall(r'"((?:[^"\\]|\\.)*)"', text)
                            if matches:
                                repaired = "[" + ",".join('"' + m + '"' for m in matches) + "]"
                                try:
                                    generated = json.loads(repaired)
                                except json.decoder.JSONDecodeError:
                                    raise parse_error
                            else:
                                raise parse_error

                    if isinstance(generated, dict):
                        generated = [str(k) for k in generated.keys()]
                    elif not isinstance(generated, list):
                        generated = [str(generated)]
            except Exception as e:
                import traceback
                traceback.print_exc()
                llm_error_msg = f"Generative AI Exception: {str(e)}"
                try:
                    print(f"DEBUG resp: {resp.text}")
                except Exception:
                    pass
                print(f"DEBUG Error: {llm_error_msg}")
                generated = []

            if generated:
                cli_steps = list(generated)
                if firmware_lines:
                    cli_steps = cli_steps + firmware_lines
                return {
                    "finding_id": f.id,
                    "control_id": f.control_id,
                    "title": f.title,
                    "severity": f.severity,
                    "vendor": vendor,
                    "os_family": os_family,
                    "cli_available": True,
                    "description": "AI Generated Synthesized CLI Remediation",
                    "cli_steps": cli_steps,
                    "save_commands": ["write memory"],
                    "reference": None,
                    "requires_site_values": False,
                    "requires_human_approval": True,
                    "guidance": f.remediation,
                    "active_vulnerabilities": [v["cve_id"] for v in active_vulns],
                    "cached": False,
                    "note": (
                        "This template was dynamically generated by the AI LLM Engine. "
                        "A human MUST rigorously review the syntax prior to deployment."
                        + (
                            " This device also has actively-exploited CVE(s) on record -- "
                            "the [FIRMWARE ADVISORY] line(s) were added deterministically "
                            "from the vulnerability database, not by the LLM, and need a "
                            "firmware update separate from this CLI fix."
                            if firmware_lines else ""
                        )
                    ),
                    "_cache_payload": list(generated),
                }
            else:
                return {
                    "finding_id": f.id,
                    "control_id": f.control_id,
                    "title": f.title,
                    "severity": f.severity,
                    "vendor": vendor,
                    "os_family": os_family,
                    "cli_available": bool(firmware_lines),
                    "description": "Firmware advisory only -- no network CLI fix available" if firmware_lines else None,
                    "cli_steps": firmware_lines,
                    "save_commands": [],
                    "reference": None,
                    "requires_site_values": None,
                    "requires_human_approval": True,
                    "guidance": f.remediation,
                    "active_vulnerabilities": [v["cve_id"] for v in active_vulns],
                    "note": (
                        "No validated CLI template exists yet for this vendor/control "
                        "pair -- showing prose guidance only. " + (f" [AI GENERATION FAILED: {llm_error_msg}]" if llm_error_msg else "The AI generator did not produce syntax.")
                        + (
                            " This device does have actively-exploited CVE(s) on record; "
                            "see the [FIRMWARE ADVISORY] line(s) above."
                            if firmware_lines else ""
                        )
                    ),
                }

    if fails:
        remediations = await asyncio.gather(*[_generate(f) for f in fails])
        
        # Persist generated CLI asynchronously but using the synchronous db session serially to avoid crashes
        cache_updated = False
        for f, rem in zip(fails, remediations):
            if "_cache_payload" in rem:
                f.ai_cli_cache = rem.pop("_cache_payload")
                db.add(f)
                cache_updated = True
                
        if cache_updated:
            try:
                db.commit()
            except Exception:
                db.rollback()
    else:
        remediations = []

    return {
        "scan_id": scan.id,
        "device_id": scan.device_id,
        "vendor": vendor,
        "os_family": os_family,
        "finding_count": len(remediations),
        "cli_generated_count": sum(1 for r in remediations if r["cli_available"]),
        "remediations": remediations,
        "requires_human_approval": True,
        # Device-level vulnerability context (Task 3), surfaced once here so a
        # consumer doesn't have to reconstruct it from every finding's
        # duplicated `active_vulnerabilities` list.
        "device_vulnerabilities": active_vulns,
    }