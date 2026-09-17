"""
Parity check between the two control catalogs that MUST stay in lockstep:

  - backend/app/policies/controls.py   (Python `CONTROLS` list)
  - policies/common/controls.rego      (OPA `controls` object)

OPA is the sole authoritative decision engine (see services/compliance.py's
module docstring) — the Python catalog is not used to compute a live
decision. But because it is hand-maintained in parallel (as a fixture for
tests, and as the input to remediation-text lookups), a control added,
renamed, or re-severitized in one file and not the other is a silent
correctness bug: OPA would enforce one rule while every other part of the
system (dashboards, remediation text, the reviewer's understanding of "what
is even in the catalog") reflects a different one.

This module is deliberately narrow: it parses the exact literal-dict shape
`policies/common/controls.rego` is written in today with a regex, and raises
loudly (never silently returns an empty/partial catalog) if that shape ever
changes, rather than guessing. If the Rego file is rewritten to compute the
catalog dynamically, this parser must be revisited — that failure mode is
covered by test_control_catalog_parity.py::test_rego_catalog_parses_non_vacuously.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

from app.policies.controls import CONTROLS

REPO_ROOT = Path(__file__).resolve().parents[3]
REGO_CONTROLS_PATH = REPO_ROOT / "policies" / "common" / "controls.rego"

# Matches one `"CONTROL-ID": { ...fields... },` block in the Rego literal.
_BLOCK_RE = re.compile(
    r'"(?P<id>[A-Z0-9\-]+)"\s*:\s*\{(?P<body>.*?)\n\t\},', re.DOTALL
)
_FIELD_RE = re.compile(
    r'"(?P<key>\w+)"\s*:\s*(?P<value>"(?:[^"\\]|\\.)*"|true|false|-?\d+(?:\.\d+)?)'
)


class CatalogParityError(Exception):
    """Raised when the two control catalogs cannot be meaningfully compared,
    or when they diverge. Distinct from a normal assertion failure so a test
    can tell "the parser broke" apart from "the catalogs actually differ"."""


def _coerce(raw: str) -> Any:
    if raw == "true":
        return True
    if raw == "false":
        return False
    if raw.startswith('"'):
        return raw[1:-1]
    if re.fullmatch(r"-?\d+", raw):
        return int(raw)
    return float(raw)


def parse_rego_catalog(path: Path = REGO_CONTROLS_PATH) -> Dict[str, Dict[str, Any]]:
    """Parse policies/common/controls.rego's `controls` object into
    {control_id: {field: value}}. Raises CatalogParityError if the file is
    missing, unreadable, or yields zero controls (almost certainly means the
    regex no longer matches the file's actual shape, not that the catalog is
    really empty)."""
    if not path.exists():
        raise CatalogParityError(f"Rego control catalog not found at {path}")
    text = path.read_text(encoding="utf-8")

    catalog: Dict[str, Dict[str, Any]] = {}
    for block in _BLOCK_RE.finditer(text):
        control_id = block.group("id")
        fields: Dict[str, Any] = {}
        for field_match in _FIELD_RE.finditer(block.group("body")):
            fields[field_match.group("key")] = _coerce(field_match.group("value"))
        catalog[control_id] = fields

    if not catalog:
        raise CatalogParityError(
            f"Parsed zero controls from {path} — the file's shape likely "
            "changed and this regex-based parser needs updating, NOT a sign "
            "the catalog is actually empty."
        )
    return catalog


@dataclass
class ParityReport:
    missing_in_rego: List[str]
    missing_in_python: List[str]
    duplicate_ids_in_python: List[str]
    field_mismatches: Dict[str, Dict[str, tuple]]  # control_id -> {field: (py, rego)}

    @property
    def ok(self) -> bool:
        return not (
            self.missing_in_rego
            or self.missing_in_python
            or self.duplicate_ids_in_python
            or self.field_mismatches
        )

    def describe(self) -> str:
        lines = []
        if self.missing_in_rego:
            lines.append(f"In Python but not Rego: {sorted(self.missing_in_rego)}")
        if self.missing_in_python:
            lines.append(f"In Rego but not Python: {sorted(self.missing_in_python)}")
        if self.duplicate_ids_in_python:
            lines.append(f"Duplicate control_ids in Python catalog: {sorted(self.duplicate_ids_in_python)}")
        for cid, diffs in self.field_mismatches.items():
            for field, (py_val, rego_val) in diffs.items():
                lines.append(f"{cid}.{field}: python={py_val!r} rego={rego_val!r}")
        return "\n".join(lines) or "catalogs match"


# Fields present on the dataclass Control that map directly onto Rego field
# names. `remediation_template` intentionally maps to `remediation` — the
# {vendor} placeholder is resolved later in compliance.py and is not itself
# a source of divergence worth flagging.
_PY_TO_REGO_FIELD = {
    "framework": "framework",
    "title": "title",
    "parameter": "parameter",
    "operator": "operator",
    "expected": "expected",
    "severity": "severity",
    "remediation_template": "remediation",
    "domain": "domain",
}


def compare_catalogs(
    python_controls: List = CONTROLS, rego_catalog: Dict[str, Dict[str, Any]] = None
) -> ParityReport:
    if rego_catalog is None:
        rego_catalog = parse_rego_catalog()

    py_ids: Dict[str, List] = {}
    duplicate_ids: List[str] = []
    for c in python_controls:
        if c.control_id in py_ids:
            duplicate_ids.append(c.control_id)
        py_ids.setdefault(c.control_id, []).append(c)

    py_id_set = set(py_ids.keys())
    rego_id_set = set(rego_catalog.keys())

    missing_in_rego = sorted(py_id_set - rego_id_set)
    missing_in_python = sorted(rego_id_set - py_id_set)

    field_mismatches: Dict[str, Dict[str, tuple]] = {}
    for control_id in sorted(py_id_set & rego_id_set):
        control = py_ids[control_id][0]
        rego_fields = rego_catalog[control_id]
        diffs = {}
        for py_field, rego_field in _PY_TO_REGO_FIELD.items():
            py_val = getattr(control, py_field)
            rego_val = rego_fields.get(rego_field)
            if py_val != rego_val:
                diffs[py_field] = (py_val, rego_val)
        if diffs:
            field_mismatches[control_id] = diffs

    return ParityReport(
        missing_in_rego=missing_in_rego,
        missing_in_python=missing_in_python,
        duplicate_ids_in_python=duplicate_ids,
        field_mismatches=field_mismatches,
    )