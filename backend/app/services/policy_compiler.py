"""Rego policy compiler — turns one UnifiedControl + its VendorConfigPatterns
into a generated Rego policy file and reloads it into the running OPA.

This module does NOT touch the deterministic evaluation engine
(app/services/opa_service.py) or the hand-authored bundle under policies/.
It only ever writes into {OPA_POLICY_DIR}/generated/ and pushes that one
file to OPA via the existing policy-management REST API
(GET/PUT {OPA_URL}/v1/policies/{id}) — the same reload path OPA already
exposes, not a new evaluation engine (RULE 2 / RULE 14 in opa_service.py
still hold: OPA remains the sole decision-maker at evaluation time).

Naming: {OPA_POLICY_DIR}/generated/{control_id}_{vendor}.rego
one file per (control, vendor) pair, containing a Rego rule per
ConfigConcept/VendorConfigPattern combination for that vendor.
"""
from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy.orm import Session

from app.services import control_service

OPA_URL = os.getenv("OPA_URL", "http://opa:8181")
OPA_TIMEOUT = float(os.getenv("OPA_TIMEOUT", "5.0"))
OPA_POLICY_DIR = os.getenv("OPA_POLICY_DIR", "policies/")

_SAFE_SEGMENT = re.compile(r"[^a-zA-Z0-9_]")


class PolicyCompilationError(Exception):
    """Raised when a control can't be compiled (no approved control, no
    patterns for the requested vendor, or OPA rejects/can't be reached for
    the reload). Callers (routers/controls.py) turn this into a 400."""


def _safe_segment(value: str) -> str:
    """Sanitize a string for use in a package name / file name segment."""
    return _SAFE_SEGMENT.sub("_", value).strip("_") or "x"


def _rego_string_literal(value: str) -> str:
    """Escape a value for embedding as a Rego string literal."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def generated_dir() -> str:
    path = os.path.join(OPA_POLICY_DIR, "generated")
    os.makedirs(path, exist_ok=True)
    return path


def _policy_id(control_id: str, vendor: str) -> str:
    return f"{_safe_segment(control_id)}_{_safe_segment(vendor)}"


def _package_name(control_id: str, vendor: str) -> str:
    return f"compliance.generated.{_safe_segment(control_id)}_{_safe_segment(vendor)}"


def render_rego(
    control: Any,
    vendor: str,
    concepts: List[Any],
    patterns_by_concept: Dict[str, List[Any]],
    framework_mappings: List[Any],
) -> str:
    """Build the Rego source for one (control, vendor) pair.

    Each ConfigConcept becomes one `concept_<name>_present` rule that is
    true when any of that concept's vendor-specific regex patterns matches
    a line in `input.config_lines` (a list of raw config lines the caller
    supplies at evaluation time — the same shape the rest of the bundle
    expects). The control-level `violation` fires when a concept it cares
    about is required but absent; this file only *detects* concept
    presence, it does not itself decide the pass/fail semantics beyond
    that, since specific expected values still live in the vendor's
    baseline model, not the regex layer.
    """
    control_id = control.id
    frameworks_tag = ",".join(
        f"{m.framework}:{m.external_id}" for m in framework_mappings if m.control_id == control_id
    ) or "none"

    lines: List[str] = []
    lines.append(f"# METADATA: control_id={control_id} frameworks={frameworks_tag}")
    lines.append(f"# generated_at={datetime.utcnow().isoformat()}Z vendor={vendor}")
    lines.append(f"# source: UnifiedControl {control_id!r} — {control.name}")
    lines.append(f"package {_package_name(control_id, vendor)}")
    lines.append("")
    lines.append("import future.keywords.in")
    lines.append("")
    lines.append(f'control_id := "{_rego_string_literal(control_id)}"')
    lines.append("")

    concept_rule_names: List[str] = []
    for concept in concepts:
        vendor_patterns = [p for p in patterns_by_concept.get(concept.id, []) if p.vendor == vendor]
        if not vendor_patterns:
            continue
        rule_name = f"concept_{_safe_segment(concept.concept_name)}_present"
        concept_rule_names.append(rule_name)
        lines.append(f"# concept: {concept.concept_name}")
        for pattern in vendor_patterns:
            lines.append(f"{rule_name} {{")
            lines.append("    some line in input.config_lines")
            lines.append(f'    regex.match(`{pattern.pattern}`, line)')
            lines.append("}")
        lines.append("")

    # Compile-time list of which concept rules exist for this vendor — baked
    # in as a literal array since Rego has no notion of "the set of rule
    # names defined in this package" at eval time.
    joined_names = ", ".join(f'"{n}"' for n in concept_rule_names)
    lines.append("summary := {")
    lines.append('    "control_id": control_id,')
    lines.append(f'    "vendor": "{_rego_string_literal(vendor)}",')
    lines.append(f'    "concepts_evaluated": [{joined_names}],')
    lines.append("}")

    return "\n".join(lines).rstrip() + "\n"


def write_policy_file(control: Any, vendor: str, source: str) -> str:
    """Write the generated Rego to {OPA_POLICY_DIR}/generated/{id}_{vendor}.rego
    and return the absolute path written."""
    path = os.path.join(generated_dir(), f"{_policy_id(control.id, vendor)}.rego")
    with open(path, "w") as f:
        f.write(source)
    return path


async def _reload_policy(policy_id: str, source: str) -> Dict[str, Any]:
    """Push the generated file into the running OPA via the existing
    policy-management REST API: GET /v1/policies (list, sanity check the
    server is reachable) then PUT /v1/policies/{id} (create/replace). This
    reuses OPA's own reload path — it is not a new evaluation engine."""
    async with httpx.AsyncClient(timeout=OPA_TIMEOUT) as client:
        try:
            await client.get(f"{OPA_URL}/v1/policies")
        except httpx.HTTPError as exc:
            raise PolicyCompilationError(f"OPA unreachable while listing policies: {exc}") from exc

        try:
            resp = await client.put(
                f"{OPA_URL}/v1/policies/{policy_id}",
                content=source.encode("utf-8"),
                headers={"Content-Type": "text/plain"},
            )
        except httpx.HTTPError as exc:
            raise PolicyCompilationError(f"OPA unreachable while loading policy {policy_id}: {exc}") from exc

    if resp.status_code >= 300:
        raise PolicyCompilationError(
            f"OPA rejected generated policy {policy_id} ({resp.status_code}): {resp.text[:500]}"
        )
    return {"opa_status_code": resp.status_code, "policy_id": policy_id}


async def compile_and_reload(
    db: Session, tenant_id: str, control_id: str, vendor: Optional[str] = None
) -> Dict[str, Any]:
    """Compile one UnifiedControl (all its VendorConfigPatterns, or just one
    vendor if `vendor` is given) into Rego, write it under
    {OPA_POLICY_DIR}/generated/, and PUT it into OPA. Returns a summary dict
    with the file paths written and the OPA reload results. Raises
    PolicyCompilationError on any failure (missing/unapproved control, no
    patterns to compile, or an OPA-side error) — never partially succeeds
    silently."""
    control = control_service.get_control(db, tenant_id, control_id)
    if not control:
        raise PolicyCompilationError(f"Control {control_id} not found")
    if control.status != "approved":
        raise PolicyCompilationError(
            f"Control {control_id} is '{control.status}', not 'approved' — approve it via "
            "the review workflow before compiling to a policy"
        )

    concepts = control_service.list_concepts(db, control_id)
    patterns = control_service.list_patterns(db, control_id)
    if not patterns:
        raise PolicyCompilationError(f"Control {control_id} has no VendorConfigPatterns to compile")

    vendors = [vendor] if vendor else sorted({p.vendor for p in patterns})

    patterns_by_concept: Dict[str, List[Any]] = {}
    for p in patterns:
        patterns_by_concept.setdefault(p.concept_id, []).append(p)

    framework_mappings = list(getattr(control, "framework_mappings", []) or [])

    results: List[Dict[str, Any]] = []
    for v in vendors:
        has_pattern_for_vendor = any(p.vendor == v for p in patterns)
        if not has_pattern_for_vendor:
            continue
        source = render_rego(control, v, concepts, patterns_by_concept, framework_mappings)
        path = write_policy_file(control, v, source)
        policy_id = _policy_id(control.id, v)
        reload_result = await _reload_policy(policy_id, source)
        results.append({"vendor": v, "path": path, "policy_id": policy_id, **reload_result})

    if not results:
        raise PolicyCompilationError(
            f"No matching vendor patterns found for control {control_id}"
            + (f" and vendor {vendor}" if vendor else "")
        )

    return {"control_id": control_id, "compiled": results}
