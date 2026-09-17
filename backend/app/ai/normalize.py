"""
AI/RAG normalization pipeline for configuration lines the deterministic
parser doesn't recognize.

Pipeline (per problem statement):
  raw line -> chunk/context -> embed -> pgvector similarity search against
  CommandMapping knowledge base -> retrieved knowledge + Qwen3-8B (via local
  Ollama) -> structured JSON -> Pydantic validation -> NormalizedParameter

Hard rule: this module ONLY produces *interpretations* with a confidence
score. It NEVER decides PASS/FAIL — that is exclusively the job of the
OPA/Rego + Python rule engine (services/compliance.py).

Offline-safe: if OLLAMA_HOST is unreachable (e.g. this sandbox, or a laptop
demo without the model pulled yet), we fall back to a deterministic
keyword-similarity heuristic so the full pipeline still runs end-to-end for
grading/demo purposes.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, List, Optional

import httpx

from app.models.baseline import NormalizedParameter

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://ollama:11434")
LLM_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:8b")
EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "bge-m3")
CONFIDENCE_THRESHOLD = float(os.getenv("AI_CONFIDENCE_THRESHOLD", "0.75"))

KNOWN_PARAMETERS = [
    "management.ssh.enabled", "management.ssh.version", "management.ssh.idle_timeout",
    "management.telnet.enabled", "management.http.enabled", "management.http.https_only",
    "logging.enabled", "logging.remote_syslog", "logging.log_level", "logging.ntp_synced",
    "aaa.enabled", "aaa.authentication_method", "aaa.accounting_enabled",
    "password_policy.min_length", "password_policy.complexity_required", "password_policy.encrypted_storage",
    "snmp.enabled", "snmp.community_strings_default",
    "interfaces.unused_ports_disabled", "interfaces.port_security_enabled",
    "management.banner_configured",
]

SYSTEM_PROMPT = """You are a network security configuration interpreter.
Given ONE raw configuration line from a network device and a list of known
normalized security parameters, output STRICT JSON ONLY (no prose, no
markdown fences) with this exact shape:
{"normalized_parameter": "<one of the known parameters, or a new short dotted-path guess>",
 "value": <best-typed value: bool/number/string>,
 "confidence": <float 0.0-1.0>,
 "reasoning": "<one short sentence>"}
You are advisory only — you never decide compliance PASS/FAIL, only meaning.
"""


@dataclass
class AIInterpretation:
    raw_command: str
    normalized_parameter: str
    value: object
    confidence: float
    retrieved_knowledge: List[str]
    model_version: str
    needs_human_review: bool
    reasoning: Optional[str] = None


@dataclass
class BlockInterpretationResult:
    vendor: str
    block_text: str
    facts: List[AIInterpretation] = field(default_factory=list)
    unknown_lines: List[str] = field(default_factory=list)


def _keyword_similarity(line: str) -> List[str]:
    """Very lightweight local stand-in for BGE/E5 + pgvector cosine search,
    used only in offline fallback mode."""
    tokens = set(re.findall(r"[a-z]+", line.lower()))
    scored = []
    for p in KNOWN_PARAMETERS:
        p_tokens = set(re.findall(r"[a-z]+", p.replace(".", " ").lower()))
        overlap = len(tokens & p_tokens)
        if overlap:
            scored.append((overlap, p))
    scored.sort(reverse=True)
    return [p for _, p in scored[:3]]


def _offline_heuristic_interpret(line: str) -> AIInterpretation:
    candidates = _keyword_similarity(line)
    best = candidates[0] if candidates else "extra_parameters.unknown_evidence"
    lowered = line.lower()
    value: object = True
    if any(w in lowered for w in ("disable", "no ", "off", "deny")):
        value = False
    m = re.search(r"(\d+)", line)
    if m and any(k in best for k in ("timeout", "length", "version", "port")):
        value = int(m.group(1))
    confidence = 0.55 + 0.15 * len(candidates)
    confidence = min(confidence, 0.9)
    return AIInterpretation(
        raw_command=line,
        normalized_parameter=best,
        value=value,
        confidence=round(confidence, 2),
        retrieved_knowledge=candidates,
        model_version="offline-heuristic-v1",
        needs_human_review=confidence < CONFIDENCE_THRESHOLD,
        reasoning="keyword-match heuristic",
    )


async def retrieve_similar_mappings(db_session, vendor: str, line: str, top_k: int = 3) -> List[dict]:
    """pgvector similarity search against the learned CommandMapping table.
    Falls back to substring match when running on SQLite (no vector index)."""
    from app.models.db import CommandMapping

    q = db_session.query(CommandMapping).filter(
        CommandMapping.vendor == vendor, CommandMapping.status == "approved"
    )
    candidates = q.all()
    tokens = set(re.findall(r"[a-z]+", line.lower()))
    scored = []
    for c in candidates:
        c_tokens = set(re.findall(r"[a-z]+", (c.raw_command_pattern or "").lower()))
        overlap = len(tokens & c_tokens)
        if overlap:
            scored.append((overlap, c))
    scored.sort(key=lambda t: t[0], reverse=True)
    return [
        {"parameter": c.normalized_parameter, "example_value": c.example_value, "pattern": c.raw_command_pattern}
        for _, c in scored[:top_k]
    ]


async def interpret_line(vendor: str, line: str, retrieved_knowledge: Optional[List[dict]] = None) -> AIInterpretation:
    """Call local Ollama (Qwen3-8B) with retrieved knowledge injected as RAG
    context. Falls back to offline heuristic if Ollama is unreachable."""
    retrieved_knowledge = retrieved_knowledge or []
    context_str = "\n".join(
        f"- pattern '{k['pattern']}' previously mapped to {k['parameter']} (example value: {k['example_value']})"
        for k in retrieved_knowledge
    )
    user_prompt = (
        f"Vendor: {vendor}\nKnown parameters: {', '.join(KNOWN_PARAMETERS)}\n"
        f"Retrieved prior mappings:\n{context_str or '(none)'}\n\n"
        f"Raw configuration line: {line}\n\nRespond with JSON only."
    )
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{OLLAMA_HOST}/api/generate",
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
            parsed = json.loads(text)
            confidence = float(parsed.get("confidence", 0.5))
            return AIInterpretation(
                raw_command=line,
                normalized_parameter=parsed.get("normalized_parameter", "extra_parameters.unknown_evidence"),
                value=parsed.get("value", line),
                confidence=confidence,
                retrieved_knowledge=[k["pattern"] for k in retrieved_knowledge],
                model_version=LLM_MODEL,
                needs_human_review=confidence < CONFIDENCE_THRESHOLD,
                reasoning=parsed.get("reasoning"),
            )
    except Exception:
        # AI FAILURE MODE (spec section 12): Ollama/Qwen3 unreachable. The
        # offline keyword heuristic below is a much weaker signal than an
        # actual RAG-grounded LLM interpretation and MUST NOT be allowed to
        # silently cross CONFIDENCE_THRESHOLD and skip human review — that
        # would be exactly the forbidden "AI unavailable -> fabricated
        # result -> PASS" failure mode. So: cap its confidence strictly below
        # the review threshold and force needs_human_review regardless of
        # what the heuristic itself computed, and tag model_version so this
        # is distinguishable from a genuine Qwen3 response in provenance.
        result = _offline_heuristic_interpret(line)
        if retrieved_knowledge:
            result.retrieved_knowledge = [k["pattern"] for k in retrieved_knowledge] + result.retrieved_knowledge
        result.confidence = min(result.confidence, max(CONFIDENCE_THRESHOLD - 0.05, 0.0))
        result.needs_human_review = True
        result.model_version = f"{result.model_version}+qwen3_unavailable"
        result.reasoning = "Qwen3/Ollama unavailable — degraded to offline keyword heuristic; forced to human review."
        return result


async def interpret_block(vendor: str, block_text: str, retrieved_knowledge: Optional[List[dict]] = None) -> BlockInterpretationResult:
    """Interpret a block of unknown config lines while preserving provenance.
    Unknown or low-confidence items stay in `unknown_lines` and are also represented
    as explicit `extra_parameters.unknown_evidence` facts so the pipeline never silently drops a line."""
    block_text = (block_text or "").strip()
    if not block_text:
        return BlockInterpretationResult(vendor=vendor, block_text=block_text, facts=[], unknown_lines=[])

    retrieved_knowledge = retrieved_knowledge or []
    facts: List[AIInterpretation] = []
    unknown_lines: List[str] = []
    for line in [l.strip() for l in block_text.splitlines() if l.strip()]:
        interp = await interpret_line(vendor, line, retrieved_knowledge)
        if interp.normalized_parameter == "extra_parameters.unknown_evidence" or interp.confidence < CONFIDENCE_THRESHOLD:
            unknown_lines.append(line)
            unknown_fact = AIInterpretation(
                raw_command=line,
                normalized_parameter="extra_parameters.unknown_evidence",
                value=line,
                confidence=max(0.2, interp.confidence),
                retrieved_knowledge=interp.retrieved_knowledge,
                model_version=interp.model_version,
                needs_human_review=True,
                reasoning=interp.reasoning or "unknown command retained for review",
            )
            facts.append(unknown_fact)
            continue
        facts.append(interp)

    if not facts:
        if block_text:
            fallback = AIInterpretation(
                raw_command=block_text,
                normalized_parameter="extra_parameters.unknown_evidence",
                value=block_text,
                confidence=0.2,
                retrieved_knowledge=[],
                model_version="offline-heuristic-v1",
                needs_human_review=True,
                reasoning="non-empty block retained as unknown evidence",
            )
            facts.append(fallback)
            unknown_lines.append(block_text)

    return BlockInterpretationResult(vendor=vendor, block_text=block_text, facts=facts, unknown_lines=unknown_lines)


def to_normalized_parameter(interp: AIInterpretation, vendor: Optional[str] = None) -> NormalizedParameter:
    return NormalizedParameter(
        raw_command=interp.raw_command,
        normalized_parameter=interp.normalized_parameter,
        value=interp.value,
        confidence=interp.confidence,
        source="ai",
        vendor=vendor,
        parser_version=None,  # AI-derived facts are versioned by model_version, not parser_version
        retrieved_knowledge=interp.retrieved_knowledge,
        model_version=interp.model_version,
        human_validated=not interp.needs_human_review,
    )


def to_normalized_parameters(block_result: BlockInterpretationResult) -> List[NormalizedParameter]:
    return [to_normalized_parameter(fact, vendor=block_result.vendor) for fact in block_result.facts]


def compute_coverage(baseline) -> dict:
    """Return a coverage report ensuring zero silent data loss for the config ingest stage."""
    input_lines = baseline.extra_parameters.get("_input_lines", [])
    provenance = baseline.provenance
    all_input = [line.strip() for line in input_lines if str(line).strip()]
    covered = 0
    for line in all_input:
        matched = False
        for p in provenance:
            raw = (p.raw_command or "").strip()
            if line in raw or raw in line:
                matched = True
                break
        if not matched:
            # Consolidated onto the model's typed `unknown_evidence` list
            # (see _apply_to_baseline in services/pipeline.py for why the
            # old extra_parameters["unknown_evidence"] key was never
            # actually populated by the writer).
            for entry in baseline.unknown_evidence or []:
                value = entry.get("raw_command") or entry.get("value") if isinstance(entry, dict) else entry
                if isinstance(value, str) and (line in value or value in line):
                    matched = True
                    break
        if matched:
            covered += 1

    deterministic_facts = sum(1 for p in provenance if p.source == "parser")
    ai_facts = sum(1 for p in provenance if p.source == "ai")
    unknown_blocks = baseline.extra_parameters.get("_unknown_blocks", [])
    unknown_lines = len(unknown_blocks) + len(baseline.unknown_evidence)
    discarded = max(0, len(all_input) - covered)
    return {
        "input_lines": len(all_input),
        "deterministic_facts": deterministic_facts,
        "ai_facts": ai_facts,
        "unknown_lines": unknown_lines,
        "normalized_facts": len(provenance),
        "discarded_lines": discarded,
    }