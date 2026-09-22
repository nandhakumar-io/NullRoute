"""LLM fallback for the *structural* topology parser (services/structure_parser.py).

structure_parser.py is deterministic: any line it doesn't recognize for a
known vendor family, or any line from a vendor it has no family mapping for
at all, is left in the caller's "unknown" set rather than guessed at (see
that module's RULE 10 contract). This module is the single place those
unknown lines go: each is handed to the local Ollama model (same instance
and pattern as ai/normalize.py's security-parameter interpreter) and asked
whether it encodes an interface/VLAN/VRF/route fact.

Contract, mirroring structure_parser.py and ai/normalize.py:
  * never applied unless confidence >= AI_CONFIDENCE_THRESHOLD;
  * every accepted fact is tagged source="llm" downstream (topology_service
    stores it distinctly from source="config"/"batfish") so the UI can show
    which facts were deterministic vs. inferred by the model;
  * Ollama unreachable / bad JSON / anything else -> that line is simply
    left unexplained. This module never fabricates a fact offline; unlike
    ai/normalize.py's security-parameter path there is no safe offline
    heuristic for "is this an interface IP or a VLAN ID", so degrading to a
    guess here would be worse than leaving the line unexplained.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional

import httpx

from app.services.structure_parser import (
    ExtractedInterface, ExtractedRoute, ExtractedVlan, ExtractedVrf,
)

logger = logging.getLogger("topology_llm_fallback")

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://ollama:11434")
LLM_MODEL = os.getenv("OLLAMA_MODEL", "llama")
CONFIDENCE_THRESHOLD = float(os.getenv("AI_CONFIDENCE_THRESHOLD", "0.75"))
LLM_TIMEOUT = float(os.getenv("AI_LLM_TIMEOUT_SECONDS", "60.0"))
# Hard cap per build request so an upload of a huge, mostly-unrecognized
# config can't turn into hundreds of sequential LLM calls; anything beyond
# this is left unexplained rather than silently truncating the config.
MAX_LINES_PER_CALL = int(os.getenv("TOPOLOGY_LLM_FALLBACK_MAX_LINES", "40"))

SYSTEM_PROMPT = """You are a network configuration structure interpreter.
You will be given several raw configuration lines from a network device
that a deterministic parser did NOT recognize. For each line, decide
whether it defines one of: an interface's IP/VLAN/VRF/admin-state, a VLAN
ID/name, a VRF name, or a static route. If a line is not one of those
things (e.g. it's an ACL entry, a routing-protocol statement, or something
unrelated), omit it from the output entirely -- do not guess.

Respond with JSON only, no prose, no markdown fences, in this exact shape:
{"facts": [
  {"line_index": 0, "kind": "interface", "confidence": 0.9,
   "name": "GigabitEthernet0/1", "ip_address": "10.0.0.1",
   "subnet_mask": "255.255.255.0", "vlan": null, "vrf": null, "admin_state": null},
  {"line_index": 2, "kind": "vlan", "confidence": 0.85, "vlan_id": "10", "name": "SALES"},
  {"line_index": 5, "kind": "vrf", "confidence": 0.8, "name": "MGMT"},
  {"line_index": 7, "kind": "route", "confidence": 0.9,
   "destination": "0.0.0.0", "mask": "0.0.0.0", "next_hop": "10.0.0.254", "vrf": null}
]}
Only include a fact if you are reasonably confident; omit anything you are
guessing at rather than inventing a low-confidence entry."""


@dataclass
class LlmTopologyFacts:
    interfaces: List[ExtractedInterface] = field(default_factory=list)
    vlans: List[ExtractedVlan] = field(default_factory=list)
    vrfs: List[ExtractedVrf] = field(default_factory=list)
    routes: List[ExtractedRoute] = field(default_factory=list)
    explained_indices: set = field(default_factory=set)


async def interpret_unknown_lines(
    vendor: Optional[str], lines: List[str], unknown_indices: List[int]
) -> LlmTopologyFacts:
    """`lines` is the full raw_text.splitlines(); `unknown_indices` are the
    0-based indices structure_parser.py couldn't explain. Returns only the
    facts accepted at >= CONFIDENCE_THRESHOLD."""
    out = LlmTopologyFacts()
    if not unknown_indices:
        return out

    batch = unknown_indices[:MAX_LINES_PER_CALL]
    numbered = "\n".join(f"{i}: {lines[i]}" for i in batch if lines[i].strip())
    if not numbered:
        return out

    user_prompt = f"Vendor: {vendor or 'unknown'}\n\nUnrecognized lines:\n{numbered}\n\nRespond with JSON only."

    try:
        async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as client:
            resp = await client.post(
                f"{OLLAMA_HOST}/generate",
                json={
                    "model": LLM_MODEL,
                    "system": SYSTEM_PROMPT,
                    "prompt": user_prompt,
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0.1},
                },
            )
            resp.raise_for_status()
            
            text = resp.json().get("response", "{}")
            import re
            # Remove reasoning content if present (common in Qwen/Llama variations)
            text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL).strip()
            
            # Robust JSON extraction to bypass markdown fences
            start_obj = text.find('{')
            if start_obj != -1:
                end_obj = text.rfind('}')
                if end_obj != -1 and end_obj >= start_obj:
                    text = text[start_obj:end_obj+1]
                    
            parsed = json.loads(text)
    except Exception as e:  # noqa: BLE001 -- offline/unreachable Ollama, bad JSON, etc.
        logger.info("topology LLM fallback unavailable/failed: %r", e)
        return out

    valid_indices = set(batch)
    for item in parsed.get("facts", []) or []:
        try:
            idx = int(item.get("line_index"))
            confidence = float(item.get("confidence", 0))
        except (TypeError, ValueError):
            continue
        if idx not in valid_indices or confidence < CONFIDENCE_THRESHOLD:
            continue
        kind = item.get("kind")
        if kind == "interface" and item.get("name"):
            out.interfaces.append(ExtractedInterface(
                name=str(item["name"]), ip_address=item.get("ip_address"),
                subnet_mask=item.get("subnet_mask"), vlan=item.get("vlan"),
                admin_state=item.get("admin_state"), vrf=item.get("vrf"),
            ))
        elif kind == "vlan" and item.get("vlan_id"):
            out.vlans.append(ExtractedVlan(vlan_id=str(item["vlan_id"]), name=item.get("name")))
        elif kind == "vrf" and item.get("name"):
            out.vrfs.append(ExtractedVrf(name=str(item["name"]), route_distinguisher=item.get("route_distinguisher")))
        elif kind == "route" and item.get("destination"):
            out.routes.append(ExtractedRoute(
                destination=str(item["destination"]), mask=item.get("mask"),
                next_hop=item.get("next_hop"), vrf=item.get("vrf"),
            ))
        else:
            continue
        out.explained_indices.add(idx)

    return out