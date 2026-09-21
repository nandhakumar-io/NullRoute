"""Inventory/topology extraction (Phase 9).

Deterministic extraction of interfaces, VLANs, VRFs, and static routes from
raw configuration text, powering the inventory/topology views only -- this
data doesn't feed OPA/Batfish/risk (see services/parsers.py for the
SecurityBaselineModel used there).

Was previously its own narrow regex extractor (Cisco/Arista/Juniper/Fortinet
only, no ACLs, no unknown-line tracking). Now delegates to
services/structure_parser.py, the single deterministic structural parser
covering IOS/EOS/AOS-CX, Huawei VRP, Junos, FortiOS, PAN-OS, RouterOS,
SONiC, and Check Point Gaia -- and, unlike the old extractor, tracks which
lines it could NOT explain so the LLM fallback (topology_llm_fallback.py)
only ever looks at genuinely unrecognized lines, never re-guesses at
something the deterministic parser already understood.

RULE 10 (never fabricate): a vendor family structure_parser doesn't
recognize returns an empty TopologyExtraction, exactly as before -- never
guessed or padded with placeholder rows. Every value returned is literally
present in the raw config.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

# Re-exported so existing importers of these names (routers, tests) keep
# working unchanged; structure_parser.py is now the single implementation.
from app.services.structure_parser import (  # noqa: F401
    ExtractedAcl, ExtractedInterface, ExtractedProtocol, ExtractedRoute,
    ExtractedVlan, ExtractedVrf, StructureResult, parse_structure,
)


@dataclass
class TopologyExtraction:
    interfaces: List[ExtractedInterface] = field(default_factory=list)
    vlans: List[ExtractedVlan] = field(default_factory=list)
    vrfs: List[ExtractedVrf] = field(default_factory=list)
    routes: List[ExtractedRoute] = field(default_factory=list)


@dataclass
class TopologyExtractionWithGaps(TopologyExtraction):
    """Same as TopologyExtraction, plus what the deterministic parser could
    NOT explain, so a caller can optionally run the LLM fallback on exactly
    those lines and nothing else."""
    lines: List[str] = field(default_factory=list)
    unknown_indices: List[int] = field(default_factory=list)
    family: Optional[str] = None


def extract_topology(vendor: Optional[str], raw_text: str) -> TopologyExtraction:
    """Deterministic-only extraction (no LLM fallback). Kept as the simple
    entry point for callers (e.g. topology_batfish_service.py) that just
    want vlan/interface names and don't need the unknown-line gap list."""
    result = parse_structure(vendor, raw_text or "")
    return TopologyExtraction(
        interfaces=result.interfaces, vlans=result.vlans,
        vrfs=result.vrfs, routes=result.routes,
    )


def extract_topology_with_gaps(vendor: Optional[str], raw_text: str) -> TopologyExtractionWithGaps:
    """Same extraction, plus the raw lines and the indices of lines the
    deterministic parser did not explain (not `consumed`, `recognized`, or
    `noise`) -- the exact input topology_llm_fallback.interpret_unknown_lines
    expects."""
    raw_text = raw_text or ""
    result = parse_structure(vendor, raw_text)
    lines = raw_text.splitlines()
    unknown = [i for i in range(len(lines)) if lines[i].strip() and i not in result.explained]
    return TopologyExtractionWithGaps(
        interfaces=result.interfaces, vlans=result.vlans, vrfs=result.vrfs, routes=result.routes,
        lines=lines, unknown_indices=unknown, family=result.family,
    )