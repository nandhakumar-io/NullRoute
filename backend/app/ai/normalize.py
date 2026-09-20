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
LLM_MODEL = os.getenv("OLLAMA_MODEL", "llama")
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
{"interpretations": [
  {"normalized_parameter": "<one of the known parameters, or a new short dotted-path guess>",
   "value": <best-typed value: bool/number/string>,
   "confidence": <float 0.0-1.0>,
   "reasoning": "<one short sentence>"}
]}
You are advisory only — you never decide compliance PASS/FAIL, only meaning.

CRITICAL RULES:
1. Do NOT assign high confidence (>= 0.75) if the line is just a fragment (like `name admin`, `members MGMT`, `name 0`). Classify fragments as `extra_parameters.unknown_evidence` unless you are absolutely certain.
2. If the line lacks enough context to be a complete security configuration, your confidence MUST be below 0.7.
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


def _offline_heuristic_interpret(line: str) -> List[AIInterpretation]:
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
    return [AIInterpretation(
        raw_command=line,
        normalized_parameter=best,
        value=value,
        confidence=round(confidence, 2),
        retrieved_knowledge=candidates,
        model_version="offline-heuristic-v1",
        needs_human_review=confidence < CONFIDENCE_THRESHOLD,
        reasoning="keyword-match heuristic",
    )]


async def retrieve_similar_mappings(db_session, vendor: str, line: str, top_k: int = 3, tenant_id: Optional[str] = None) -> List[dict]:
    """Retrieval half of the HITL training loop: when a human approves or
    corrects an AI interpretation, hitl_service._persist_training_example()
    + vector_search.store_embedding() embed that (raw_command_pattern ->
    embedding) into CommandMapping.embedding. This is where that embedding
    actually gets *used* again -- real pgvector/cosine semantic search
    (services/vector_search.find_similar_mappings) over approved mappings,
    so the next unknown/similarly-worded config line retrieves it as
    few-shot context for interpret_line() below.

    Previously this re-implemented a much weaker plain-Python token-overlap
    search from scratch and never touched the embedding column at all --
    every human correction was stored but silently never fed back into
    future interpretations, so the "training loop" only closed on paper.
    vector_search itself still degrades gracefully (real cosine over stored
    vectors, then token overlap) when running on SQLite or with no embedder
    loaded, so this call is always safe.

    `tenant_id` scopes retrieval to that tenant's own corrections plus
    tenant-agnostic seeded mappings (tenant_id IS NULL) -- pass it whenever
    the caller has it (see services/pipeline.py) so one tenant's corrections
    never leak into another's interpretations."""
    from app.services import vector_search

    results = vector_search.find_similar_mappings(
        db_session, tenant_id=tenant_id, query_text=line, vendor=vendor, status="approved", top_k=top_k,
    )
    return [
        {"parameter": r["normalized_parameter"], "example_value": r["example_value"], "pattern": r["raw_command_pattern"]}
        for r in results
    ]


async def interpret_line(vendor: str, line: str, retrieved_knowledge: Optional[List[dict]] = None) -> List[AIInterpretation]:
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
        # Previously timeout=300.0 with up to 4 attempts meant a single unknown
        # line could block the whole normalize request for up to ~20 minutes
        # against a local, often single-GPU, Ollama instance -- upstream
        # (cloudflared/gateway) then hits its own timeout and drops the
        # request client-side while Ollama keeps grinding through a queue it
        # can't clear, throwing 500s under the pile-up. Fail fast per attempt
        # instead and let the existing offline heuristic fallback below do
        # its job; both are env-overridable for slower hardware.
        llm_timeout = float(os.getenv("AI_LLM_TIMEOUT_SECONDS", "20.0"))
        max_attempts = int(os.getenv("AI_LLM_MAX_ATTEMPTS", "2"))
        async with httpx.AsyncClient(timeout=llm_timeout) as client:
            import asyncio
            for attempt in range(max_attempts):
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
                if resp.status_code == 500 and attempt < max_attempts - 1:
                    await asyncio.sleep(0.75 * (attempt + 1))
                    continue
                resp.raise_for_status()
                break
            text = resp.json().get("response", "{}")
            parsed = json.loads(text)
            
            interpretations_data = parsed.get("interpretations", [parsed])
            interps = []
            for item in interpretations_data:
                confidence = float(item.get("confidence", 0.5))
                interps.append(AIInterpretation(
                    raw_command=line,
                    normalized_parameter=item.get("normalized_parameter", "extra_parameters.unknown_evidence"),
                    value=item.get("value", line),
                    confidence=confidence,
                    retrieved_knowledge=[k["pattern"] for k in retrieved_knowledge],
                    model_version=LLM_MODEL,
                    needs_human_review=confidence < CONFIDENCE_THRESHOLD,
                    reasoning=item.get("reasoning"),
                ))
            
            return interps if interps else _offline_heuristic_interpret(line)
    except Exception as e:
        import traceback
        print(f"DEBUG EXCEPTION for '{line}': {type(e).__name__} - {repr(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"DEBUG HTTP RESPONSE TEXT: {e.response.text}")
        print(traceback.format_exc())
        results = _offline_heuristic_interpret(line)
        for result in results:
            if retrieved_knowledge:
                result.retrieved_knowledge = [k["pattern"] for k in retrieved_knowledge] + result.retrieved_knowledge
            result.confidence = min(result.confidence, max(CONFIDENCE_THRESHOLD - 0.05, 0.0))
            result.needs_human_review = True
            result.model_version = f"{result.model_version}+{LLM_MODEL}_unavailable"
            result.reasoning = f"{LLM_MODEL}/Ollama unavailable — degraded to offline keyword heuristic; forced to human review."
        return results


async def interpret_block(vendor: str, block_text: str, retrieved_knowledge: Optional[List[dict]] = None) -> BlockInterpretationResult:
    """Interpret a block of unknown config lines concurrently while preserving provenance."""
    import asyncio
    block_text = (block_text or "").strip()
    if not block_text:
        return BlockInterpretationResult(vendor=vendor, block_text=block_text, facts=[], unknown_lines=[])

    retrieved_knowledge = retrieved_knowledge or []
    lines = [l.strip() for l in block_text.splitlines() if l.strip()]
    # A single local Ollama instance is usually one GPU worker: firing 10
    # generate() calls at it concurrently was what produced the 500s under
    # load (queued requests timing out server-side) rather than actually
    # speeding anything up. Lower default concurrency, still overridable.
    sem = asyncio.Semaphore(int(os.getenv("AI_LLM_CONCURRENCY", "3")))
    
    async def process_line(line):
        async with sem:
            return line, await interpret_line(vendor, line, retrieved_knowledge)
            
    results_ordered = await asyncio.gather(*(process_line(line) for line in lines))
    
    facts: List[AIInterpretation] = []
    unknown_lines: List[str] = []
    
    for line, interps in results_ordered:
        has_confident_match = False
        for interp in interps:
            if interp.normalized_parameter != "extra_parameters.unknown_evidence" and interp.confidence >= CONFIDENCE_THRESHOLD:
                has_confident_match = True
                facts.append(interp)
                
        if not has_confident_match:
            unknown_lines.append(line)
            first = interps[0] if interps else None
            unknown_fact = AIInterpretation(
                raw_command=line,
                normalized_parameter="extra_parameters.unknown_evidence",
                value=line,
                confidence=max(0.2, getattr(first, 'confidence', 0.2)),
                retrieved_knowledge=getattr(first, 'retrieved_knowledge', []),
                model_version=getattr(first, 'model_version', "offline-heuristic-v1"),
                needs_human_review=True,
                reasoning=getattr(first, 'reasoning', "Fallback categorization")
            )
            facts.append(unknown_fact)

    return BlockInterpretationResult(vendor=vendor, block_text=block_text, facts=facts, unknown_lines=unknown_lines)

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