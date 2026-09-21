"""
Staged, batched, de-duplicated AI normalization of the lines the deterministic
parser did not recognise.

This is the *scheduling* layer over the existing models -- it adds no new
model, queue or service. It replaces the pipeline's old per-line loop

    for each unknown line:  DistilBERT -> MiniLM -> (embed again) -> RAG -> LLM

with

    unknown lines
      -> de-duplicate identical (tenant, vendor, line) inputs
      -> per chunk:
           DistilBERT + MiniLM as true batches (versioned cache first)   [AIAnalysis, advisory]
           RAG retrieval from the SAME MiniLM vector (no second embed)
           route each unique input:
               interpretation-cache hit            -> reuse validated result
               exact human-approved mapping        -> reuse (opt-in, see settings)
               otherwise                           -> LLM with retrieved context
           LLM uncertain / degraded / invalid      -> review_required (never a fact)
      -> map each unique result back to every original occurrence

What this module deliberately does NOT do:

* It never decides PASS/FAIL. Everything it returns is an *interpretation*;
  OPA stays the only compliance authority and nothing here reads a compliance
  verdict or feeds a confidence into one.
* It never lowers a quality gate. The LLM confidence gate (AI_CONFIDENCE_THRESHOLD,
  applied inside normalize.interpret_line) is unchanged; uncertain results keep
  needs_human_review=True and continue to the existing Human Review queue.
* DistilBERT's coarse *intent* label cannot stand in for the LLM: it names one
  of 13 intent classes, not a normalized parameter + typed value, so there is
  nothing to "continue to normalization" with. DistilBERT/MiniLM output stays
  what it was -- the advisory AIAnalysis row -- and is now also attached to
  each AI fact's provenance. Skipping the LLM is therefore only allowed on
  validated evidence (cache of a validated interpretation, or an exact
  human-approved mapping), never on classifier confidence alone.
"""
from __future__ import annotations

import asyncio
import copy
import json
import logging
import os
import re
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence, Tuple

from app.ai import inference_cache
from app.ai import normalize as normalize_mod
from app.ai import service as ai_service
from app.ai import settings as ai_settings
from app.ai.model_registry import AIRegistry, get_registry
from app.ai.normalize import AIInterpretation
from app.ai.schemas import AIAnalysisResult

logger = logging.getLogger("ai.staged")

UNKNOWN_EVIDENCE = "extra_parameters.unknown_evidence"

ROUTE_CACHE_HIT = "cache_hit"
ROUTE_APPROVED_MAPPING = "approved_mapping"
ROUTE_LLM = "llm"
ROUTE_REVIEW = "review_required"
ROUTE_SKIPPED_BLANK = "skipped_blank"

# Embedder backends whose vectors the RAG retrieval may consume (mirrors the
# check in vector_search.embed_text).
_RAG_BACKENDS = ("minilm", "minilm-remote", "remote-minilm")

InterpretFn = Callable[[str, str, List[dict]], Awaitable[List[AIInterpretation]]]
RetrieveFn = Callable[..., List[dict]]
CheckpointFn = Callable[[], Awaitable[None]]


@dataclass(frozen=True)
class InferenceItem:
    """One unknown line to interpret, with the context the models actually
    consume. `vendor` and `line` reach the LLM prompt; `tenant_id` scopes RAG
    retrieval; `device_id` is carried for logging/audit only."""
    line: str
    vendor: str
    tenant_id: Optional[str] = None
    device_id: Optional[str] = None


@dataclass
class OccurrenceResult:
    """Result for ONE original occurrence (input order is preserved)."""
    index: int
    item: InferenceItem
    analysis: AIAnalysisResult
    interpretations: List[AIInterpretation]
    route: str
    cache_hit: bool
    provenance: Dict[str, Any]


@dataclass
class StageStats:
    total_lines: int = 0
    unique_inputs: int = 0
    duplicates_eliminated: int = 0
    chunks: int = 0
    interpretation_cache_hits: int = 0
    interpretation_cache_misses: int = 0
    approved_mapping_reuses: int = 0
    llm_calls: int = 0
    classifier_batches: int = 0
    classifier_texts_computed: int = 0
    classifier_cache_hits: int = 0
    embedder_batches: int = 0
    embedder_texts_computed: int = 0
    embedder_cache_hits: int = 0
    human_review_lines: int = 0
    duration_ms: float = 0.0
    classifier_device: str = "n/a"
    embedder_device: str = "n/a"

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _llm_concurrency() -> int:
    # Same knob (and default) the pipeline already used for LLM fan-out.
    try:
        return max(1, int(os.getenv("AI_LLM_CONCURRENCY", "3")))
    except ValueError:
        return 3


def retrieval_fingerprint(retrieved: Sequence[dict]) -> str:
    """Digest of exactly the retrieved knowledge the LLM prompt is built from
    (pattern / parameter / example value, in prompt order)."""
    return inference_cache.make_key([
        [k.get("pattern"), k.get("parameter"), str(k.get("example_value"))] for k in retrieved
    ])


def _norm_ws(s: Any) -> str:
    return " ".join(str(s or "").split())


def _coerce_example_value(raw: Any) -> Any:
    """CommandMapping.example_value is stored as text; recover the typed value
    the interpretation model uses (bool / int / float / str)."""
    if isinstance(raw, (bool, int, float)):
        return raw
    text = str(raw if raw is not None else "").strip()
    if text.lower() in ("true", "false"):
        return text.lower() == "true"
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if re.fullmatch(r"-?\d+\.\d+", text):
        return float(text)
    return text


def approved_mapping_interpretation(line: str, retrieved: Sequence[dict]) -> Optional[Tuple[AIInterpretation, dict]]:
    """A validated interpretation from an EXACT human-approved mapping, or None.

    `retrieved` only ever contains status='approved', vendor- and tenant-scoped
    rows (vector_search.find_similar_mappings). Requires: same pattern (modulo
    whitespace), all exact matches agree on the parameter and value, a usable
    mapping confidence. Anything else -- no match, conflicting matches, missing
    evidence -- returns None so the line goes to the LLM.
    """
    exact = [k for k in retrieved if _norm_ws(k.get("pattern")) == _norm_ws(line)]
    if not exact:
        return None
    if len({(k.get("parameter"), str(k.get("example_value"))) for k in exact}) != 1:
        return None  # conflicting approved mappings -> not "strong", let the LLM see them
    k = exact[0]
    param = k.get("parameter")
    if not isinstance(param, str) or not param.strip():
        return None
    if k.get("example_value") in (None, ""):
        return None
    try:
        conf = normalize_mod.parse_llm_confidence(k.get("mapping_confidence"))
    except (TypeError, ValueError):
        return None
    interp = AIInterpretation(
        raw_command=line,
        normalized_parameter=param,
        value=_coerce_example_value(k.get("example_value")),
        confidence=conf,
        retrieved_knowledge=[x["pattern"] for x in retrieved],
        model_version=f"approved-mapping:{k.get('mapping_id')}",
        needs_human_review=conf < normalize_mod.CONFIDENCE_THRESHOLD,
        reasoning="Exact match to a human-approved CommandMapping; LLM not consulted.",
    )
    return interp, k


def _revalidate(interps: Sequence[AIInterpretation]) -> bool:
    """Gate applied to every cached interpretation before reuse: cached output
    must satisfy the same structural + confidence rules as fresh output."""
    if not interps:
        return False
    for i in interps:
        if not isinstance(i.normalized_parameter, str) or not i.normalized_parameter.strip():
            return False
        try:
            conf = normalize_mod.parse_llm_confidence(i.confidence)
        except (TypeError, ValueError):
            return False
        if i.needs_human_review or conf < normalize_mod.CONFIDENCE_THRESHOLD:
            return False
    return True


def _cacheable(interps: Sequence[AIInterpretation]) -> bool:
    """Only successful, validated, confident, non-degraded LLM output is cached."""
    if not _revalidate(interps):
        return False
    if any("_unavailable" in (i.model_version or "") for i in interps):
        return False
    return any(i.normalized_parameter != UNKNOWN_EVIDENCE for i in interps)


def _interp_to_dict(i: AIInterpretation) -> Dict[str, Any]:
    return asdict(i)


def _interp_from_dict(d: Dict[str, Any]) -> AIInterpretation:
    return AIInterpretation(**d)


def _base_provenance(registry: AIRegistry, analysis: AIAnalysisResult, retrieved: Sequence[dict], stage_route: str) -> Dict[str, Any]:
    clf, emb = registry.classifier, registry.embedder
    return {
        "route": stage_route,
        "classifier": {
            "backend": getattr(clf, "backend_name", None),
            "model_version": getattr(clf, "model_version", None),
            "intent": analysis.intent,
            "confidence": analysis.classifier_confidence,
            "decision": analysis.decision,
            "requires_review": analysis.requires_review,
        },
        "embedding": {
            "backend": getattr(emb, "backend_name", None),
            "model_version": getattr(emb, "model_version", None),
            "nearest_intent": analysis.nearest_intent,
            "similarity": analysis.semantic_similarity,
        },
        "retrieval": {
            "count": len(retrieved),
            "mapping_ids": [k.get("mapping_id") for k in retrieved if k.get("mapping_id")],
            "patterns_fingerprint": retrieval_fingerprint(retrieved)[:16],
            "best_similarity": max((k.get("similarity") or 0.0) for k in retrieved) if retrieved else None,
        },
        "registry_model_version": registry.model_version,
    }


# --------------------------------------------------------------------------
# main entry point
# --------------------------------------------------------------------------

async def normalize_unknown_lines(
    items: Sequence[InferenceItem],
    *,
    db: Any,
    interpret_fn: InterpretFn,
    checkpoint: Optional[CheckpointFn] = None,
    registry: Optional[AIRegistry] = None,
    retrieve_fn: Optional[RetrieveFn] = None,
) -> Tuple[List[OccurrenceResult], StageStats]:
    """Interpret `items` and return one OccurrenceResult per item, in input order.

    interpret_fn(vendor, line, retrieved) is the LLM stage (normalize.interpret_line;
    injected so the pipeline's existing patch point keeps working).
    checkpoint() is awaited between chunks so pause/stop requests still land
    within one chunk. Exceptions from interpret_fn propagate, as before.
    """
    registry = registry or get_registry()
    retrieve_fn = retrieve_fn or normalize_mod.retrieve_similar_mappings_for_vector
    stats = StageStats(total_lines=len(items))
    started = time.perf_counter()
    if not items:
        return [], stats

    clf, emb = registry.classifier, registry.embedder
    if registry.enabled:
        stats.classifier_device = getattr(clf, "device", "n/a")
        stats.embedder_device = getattr(emb, "device", "n/a")

    # 1. De-duplicate on what the models actually see (+ tenant, which scopes
    #    retrieval). Same key => same inputs => one inference, fanned back out.
    groups: "OrderedDict[Tuple[Optional[str], str, str], List[int]]" = OrderedDict()
    for idx, item in enumerate(items):
        groups.setdefault((item.tenant_id, item.vendor, item.line), []).append(idx)
    stats.unique_inputs = len(groups)
    stats.duplicates_eliminated = len(items) - len(groups)

    cache = inference_cache.get_cache()
    prompt_fp = normalize_mod.prompt_fingerprint()
    clf_ver = getattr(clf, "model_version", "n/a")
    emb_ver = getattr(emb, "model_version", "n/a")
    llm_meta = {"model": normalize_mod.LLM_MODEL, "prompt_fingerprint": prompt_fp}

    resolved: Dict[Tuple[Optional[str], str, str], Tuple[List[AIInterpretation], str, bool, Dict[str, Any], AIAnalysisResult]] = {}

    keys = list(groups.keys())
    chunk_size = ai_settings.normalize_chunk_size()
    sem = asyncio.Semaphore(_llm_concurrency())

    for chunk_start in range(0, len(keys), chunk_size):
        chunk = keys[chunk_start: chunk_start + chunk_size]
        stats.chunks += 1

        # 2. DistilBERT + MiniLM, batched, off the event loop.
        lines = [k[2] for k in chunk]
        analyses, astats = await asyncio.to_thread(ai_service.analyze_commands_detailed, lines, registry)
        stats.classifier_batches += astats.classifier_batch_calls
        stats.classifier_texts_computed += astats.classifier_computed
        stats.classifier_cache_hits += astats.classifier_cache_hits
        stats.embedder_batches += astats.embedder_batch_calls
        stats.embedder_texts_computed += astats.embedder_computed
        stats.embedder_cache_hits += astats.embedder_cache_hits
        by_line = {ln: a for ln, a in zip(lines, analyses)}  # identical lines share one analysis

        # 3. Retrieval (reusing the batch vector) + routing.
        pending: List[Tuple[Tuple[Optional[str], str, str], List[dict], Optional[str]]] = []
        for key in chunk:
            tenant_id, vendor, line = key
            analysis = by_line[line]
            if not line.strip():
                resolved[key] = ([], ROUTE_SKIPPED_BLANK, False, _base_provenance(registry, analysis.result, [], ROUTE_SKIPPED_BLANK), analysis.result)
                continue

            rag_vec = analysis.vector if getattr(emb, "backend_name", None) in _RAG_BACKENDS else None
            retrieved = retrieve_fn(db, vendor, line, rag_vec, tenant_id=tenant_id)

            ckey = inference_cache.interpretation_key(
                tenant_id=tenant_id, vendor=vendor, line=line,
                llm_model=normalize_mod.LLM_MODEL, prompt_fingerprint=prompt_fp,
                parser_version=_parser_version(), classifier_version=str(clf_ver),
                embedder_version=str(emb_ver), registry_version=registry.model_version,
                retrieval_fingerprint=retrieval_fingerprint(retrieved),
            )
            if cache is not None:
                hit = cache.get(inference_cache.NS_INTERPRETATION, ckey)
                if hit is not inference_cache.MISS:
                    interps = [_interp_from_dict(d) for d in hit["interpretations"]]
                    if _revalidate(interps):
                        stats.interpretation_cache_hits += 1
                        prov = _base_provenance(registry, analysis.result, retrieved, ROUTE_CACHE_HIT)
                        prov["llm"] = hit.get("llm", llm_meta)
                        resolved[key] = (interps, ROUTE_CACHE_HIT, True, prov, analysis.result)
                        continue
                stats.interpretation_cache_misses += 1

            if ai_settings.retrieval_shortcut_enabled():
                reused = approved_mapping_interpretation(line, retrieved)
                if reused is not None:
                    interp, mapping = reused
                    stats.approved_mapping_reuses += 1
                    prov = _base_provenance(registry, analysis.result, retrieved, ROUTE_APPROVED_MAPPING)
                    prov["approved_mapping_id"] = mapping.get("mapping_id")
                    route = ROUTE_REVIEW if interp.needs_human_review else ROUTE_APPROVED_MAPPING
                    resolved[key] = ([interp], route, False, prov, analysis.result)
                    continue

            pending.append((key, retrieved, ckey))

        # 4. LLM only for what nothing above could resolve (bounded concurrency,
        #    order-preserving gather).
        async def _call(key: Tuple[Optional[str], str, str], retrieved: List[dict]) -> List[AIInterpretation]:
            async with sem:
                return await interpret_fn(key[1], key[2], retrieved)

        if pending:
            stats.llm_calls += len(pending)
            outs = await asyncio.gather(*[_call(k, r) for k, r, _ in pending])
            for (key, retrieved, ckey), interps in zip(pending, outs):
                analysis = by_line[key[2]]
                needs_review = any(i.needs_human_review for i in interps) or not interps
                route = ROUTE_REVIEW if needs_review else ROUTE_LLM
                prov = _base_provenance(registry, analysis.result, retrieved, route)
                prov["llm"] = llm_meta
                if cache is not None and ckey is not None and _cacheable(interps):
                    cache.put(inference_cache.NS_INTERPRETATION, ckey, {
                        "interpretations": [_interp_to_dict(i) for i in interps], "llm": llm_meta,
                    })
                resolved[key] = (interps, route, False, prov, analysis.result)

        # Pause/stop checkpoint between chunks (never after the last one).
        if checkpoint is not None and chunk_start + chunk_size < len(keys):
            await checkpoint()

    # 5. Fan results back out to every original occurrence, in input order.
    results: List[OccurrenceResult] = []
    for idx, item in enumerate(items):
        interps, route, cache_hit, prov, analysis_result = resolved[(item.tenant_id, item.vendor, item.line)]
        occ_interps = copy.deepcopy(interps)
        if any(i.needs_human_review for i in occ_interps):
            stats.human_review_lines += 1
        results.append(OccurrenceResult(
            index=idx, item=item, analysis=analysis_result.model_copy(),
            interpretations=occ_interps, route=route, cache_hit=cache_hit,
            provenance=copy.deepcopy(prov),
        ))

    stats.duration_ms = round((time.perf_counter() - started) * 1000.0, 3)
    _emit(stats)
    return results, stats


def _parser_version() -> str:
    try:
        from app.services.parsers import PARSER_VERSION
        return PARSER_VERSION
    except Exception:  # noqa: BLE001
        return "parser-unknown"


def _emit(stats: StageStats) -> None:
    """Counts and timings only -- never line text, values or credentials."""
    logger.info("ai.staged_normalization %s", json.dumps(stats.as_dict(), sort_keys=True))
    try:
        from app.services import observability as obs
        obs.record_ai_inference_duration_ms(stats.duration_ms)
        reg = obs.registry
        reg.inc_counter("ai_pipeline_lines_total", stats.total_lines)
        reg.inc_counter("ai_pipeline_unique_inputs_total", stats.unique_inputs)
        reg.inc_counter("ai_pipeline_duplicates_eliminated_total", stats.duplicates_eliminated)
        reg.inc_counter("ai_pipeline_interpretation_cache_hits_total", stats.interpretation_cache_hits)
        reg.inc_counter("ai_pipeline_llm_calls_total", stats.llm_calls)
        reg.inc_counter("ai_pipeline_human_review_lines_total", stats.human_review_lines)
    except Exception:  # noqa: BLE001 - metrics must never fail a scan
        pass