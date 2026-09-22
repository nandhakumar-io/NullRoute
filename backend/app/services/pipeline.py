"""
Orchestrates the full ingestion -> normalization -> compliance pipeline for
one uploaded configuration, emitting the architecture's event-bus subjects
at each stage.

Pause / stop / resume
----------------------
An operator can pause or stop a running scan's pipeline at any stage
boundary via the API (POST /api/scans/{id}/pause | /stop | /resume,
routers/scans.py), and resume it later from where it left off rather than
re-running the whole thing.

  STAGE_ORDER = start -> normalize -> opa -> batfish -> finalize -> done

`_checkpoint()` is called at each of those boundaries (never mid-write --
always right after a commit). It re-reads `scan.control_state` from the DB
(another request may have changed it while this coroutine was awaiting
something) and, if PAUSE_REQUESTED/STOP_REQUESTED, persists just enough
state to resume and unwinds via PipelinePaused/PipelineStopped -- neither
of which is treated as a pipeline failure.

Only the "normalize" stage (per-line AI/RAG interpretation) is slow enough
to be worth resuming *without* redoing -- so it's also checkpointed
mid-stage, every BATCH_SIZE lines, so a stop on a large config doesn't have
to wait for every remaining line to finish. OPA/Batfish/risk/correlation
are all fast deterministic/rule-based passes over the persisted baseline,
so resuming from any stage at or after "opa" simply reloads
`scan.baseline_json` and re-runs them -- cheaper and far simpler than
reconstructing their in-memory result objects, and produces the exact same
output since they're deterministic given the same baseline.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import time
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm import Session

from app import events
from app.ai import service as ai_service  # noqa: F401 (kept importable; staged.py drives it now)
from app.ai import staged as ai_staged
from app.ai.normalize import (interpret_line, retrieve_similar_mappings,  # noqa: F401 (retrieve_similar_mappings kept importable here)
                               to_normalized_parameter)
from app.models.baseline import SecurityBaselineModel
from app.models.db import AIAnalysis, BatfishAnalysis, Device, Finding, OPAAnalysis, Scan
from app.services import batfish_service, evidence_service, fabric_service, minio_service, opa_service, risk_engine
from app.services.change_validation_service import correlate
from app.services.compliance import compute_score, evaluate_baseline_via_opa, opa_decision_to_findings
from app.services.parsers import parse_config
from app.services.vendor_detect import detect_vendor
from app.services import rag_service

# Stage boundaries a pause/stop request can land on, in pipeline order.
# Exposed for the API/UI layer (routers/scans.py, schemas.py) so a paused
# scan can show a human label for where it stopped.
STAGE_ORDER = ["start", "normalize", "opa", "batfish", "finalize", "done"]
STAGE_LABELS = {
    "start": "Vendor detection & deterministic parsing",
    "normalize": "AI/RAG normalization of unknown lines",
    "opa": "OPA policy evaluation",
    "batfish": "Batfish behavioral analysis",
    "finalize": "Risk scoring, correlation & evidence anchoring",
    "done": "Complete",
}
# Stages from which resuming can skip straight to OPA by reloading the
# already-persisted baseline instead of re-parsing/re-normalizing.
_RESUMABLE_FROM_BASELINE = {"opa", "batfish", "finalize"}
# (AI normalize checkpoint granularity now lives in app/ai/settings.py: AI_NORMALIZE_CHUNK_SIZE, default 40)


class PipelinePaused(Exception):
    """Raised internally to unwind run_pipeline cleanly when an operator
    pauses a scan mid-flight. Always caught inside run_pipeline itself --
    never propagates to the caller as an error."""

    def __init__(self, stage: str):
        self.stage = stage
        super().__init__(f"Pipeline paused at stage '{stage}'")


class PipelineStopped(Exception):
    """Same as PipelinePaused but for a full stop. A stopped scan is still
    resumable via resume_pipeline() from its last checkpointed stage --
    "stop" here means "stop running now", not "discard progress"; a human
    who wants to discard it entirely just starts a fresh scan."""

    def __init__(self, stage: str):
        self.stage = stage
        super().__init__(f"Pipeline stopped at stage '{stage}'")


async def _checkpoint(db: Session, scan: Scan, stage: str) -> None:
    """Safe stage-boundary check. Re-reads control_state from the DB (a
    concurrent pause/stop request may have updated it) and, if a pause or
    stop was requested, persists the checkpoint and raises to unwind.

    Also records stage timing: each call marks the *start* of `stage` and
    finalises the timing of the stage that was previously running (i.e. the
    stage name stored in scan.pipeline_stage before this call updates it).
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    now_ms = time.monotonic_ns() // 1_000_000  # monotonic for elapsed, iso for display

    try:
        db.refresh(scan)
    except InvalidRequestError:
        raise PipelineStopped(stage)

    timings = dict(scan.stage_timings or {})

    def _suspend_current_stage():
        current = scan.pipeline_stage
        if current and current in timings:
            entry = dict(timings[current])
            started_ms = entry.pop("_started_ms", None)
            if started_ms is not None:
                entry["duration_ms"] = (entry.get("duration_ms") or 0) + (now_ms - started_ms)
            timings[current] = entry
            scan.stage_timings = timings

    if scan.control_state == "STOPPED":
        raise PipelineStopped(stage)
    if scan.control_state == "STOP_REQUESTED":
        _suspend_current_stage()
        scan.status = "stopped"
        scan.control_state = "STOPPED"
        scan.pipeline_stage = stage
        scan.stopped_at = datetime.utcnow()
        db.commit()
        await events.publish("pipeline.stopped", {"scan_id": scan.id, "stage": stage})
        raise PipelineStopped(stage)
    if scan.control_state == "PAUSE_REQUESTED":
        _suspend_current_stage()
        scan.status = "paused"
        scan.control_state = "PAUSED"
        scan.pipeline_stage = stage
        scan.paused_at = datetime.utcnow()
        db.commit()
        await events.publish("pipeline.paused", {"scan_id": scan.id, "stage": stage})
        raise PipelinePaused(stage)

    # --- timing ---
    prev_stage = scan.pipeline_stage

    # Finalise the previous stage's timing entry if it was started
    if prev_stage and prev_stage != stage and prev_stage in timings:
        entry = dict(timings[prev_stage])
        if entry.get("started_at") and not entry.get("completed_at"):
            entry["completed_at"] = now_iso
            started_ms = entry.pop("_started_ms", None)
            if started_ms is not None:
                entry["duration_ms"] = (entry.get("duration_ms") or 0) + (now_ms - started_ms)
        timings[prev_stage] = entry

    # Start timing the new stage (only if not already started, so a resume
    # entering mid-stage doesn't reset the clock on the current stage)
    if stage not in timings:
        timings[stage] = {
            "started_at": now_iso,
            "_started_ms": now_ms,
            "completed_at": None,
            "duration_ms": 0,
        }
    elif not timings[stage].get("completed_at") and timings[stage].get("_started_ms") is None:
        # Resuming a previously suspended stage
        timings[stage]["_started_ms"] = now_ms

    scan.stage_timings = timings
    scan.pipeline_stage = stage
    if stage == "done":
        timings["done"]["completed_at"] = now_iso
        scan.stage_timings = timings
    db.commit()


def validate_resumable(scan: Scan) -> None:
    """Raise ValueError unless `scan` can be resumed right now. Split out of
    resume_pipeline() so the API can reject a bad resume *synchronously*
    (HTTP 400) before handing the actual work to a background task."""
    if scan.control_state not in ("PAUSED", "STOPPED"):
        raise ValueError(f"Scan {scan.id} is not paused or stopped (control_state={scan.control_state})")
    if not scan.raw_config_path:
        raise ValueError(f"Scan {scan.id} has no archived raw configuration to resume from")
    if (scan.pipeline_stage or "start") in _RESUMABLE_FROM_BASELINE and not scan.baseline_json:
        raise ValueError(f"Scan {scan.id} has no persisted baseline to resume from (never completed normalization)")


def mark_resuming(db: Session, scan: Scan) -> str:
    """Flip a validated PAUSED/STOPPED scan back to RUNNING and return the
    stage to re-enter at. Committed immediately so the UI (and a second
    concurrent resume click) sees it before any work starts."""
    resume_stage = scan.pipeline_stage or "start"
    scan.control_state = "RUNNING"
    scan.status = "resuming"
    scan.error = None
    scan.resumed_at = datetime.utcnow()
    db.commit()
    return resume_stage


async def continue_resume(db: Session, scan: Scan) -> Scan:
    """Second half of a resume: scan is already flagged RUNNING/"resuming"
    (mark_resuming). Reloads the archived raw config from MinIO -- the
    pipeline never keeps the full config text in the DB row itself -- and
    re-enters run_pipeline() at the right point."""
    resume_stage = scan.pipeline_stage or "start"
    # MinIO client is synchronous; keep it off the event loop.
    raw_bytes = await asyncio.to_thread(minio_service.get_object, scan.raw_config_path)
    raw_text = raw_bytes.decode("utf-8", errors="replace")
    await events.publish("pipeline.resumed", {"scan_id": scan.id, "stage": resume_stage})
    return await run_pipeline(db, scan, raw_text, framework=scan.framework or "ALL", resume_stage=resume_stage)


async def resume_pipeline(db: Session, scan: Scan) -> Scan:
    """Resume a PAUSED or STOPPED scan from its last checkpointed stage and
    wait for it to finish. (The HTTP API instead splits this into
    validate_resumable -> mark_resuming -> a background continue_resume so
    the request doesn't block and the run stays stoppable.)"""
    validate_resumable(scan)
    mark_resuming(db, scan)
    return await continue_resume(db, scan)


async def run_pipeline(
    db: Session, scan: Scan, raw_text: str, framework: str = "ALL", resume_stage: Optional[str] = None, batfish_checks: Optional[str] = None
) -> Scan:
    skip_normalize = resume_stage in _RESUMABLE_FROM_BASELINE
    try:
        await _checkpoint(db, scan, "start")

        if not skip_normalize:
            # 1. Vendor/OS detection ------------------------------------------------
            guess = await asyncio.to_thread(detect_vendor, raw_text)
            device: Device = db.query(Device).get(scan.device_id)
            # Only let a confident, in-scope guess set device identity. A
            # review_required guess (low confidence OR an unsupported vendor) must
            # never silently become a trusted vendor — it is recorded on the scan
            # for visibility/audit but does NOT populate device.vendor/os, and it
            # forces the config down the unknown-block/AI path in step 2 below
            # rather than a vendor-specific deterministic parser.
            if not guess.review_required and guess.vendor != "Unknown":
                device.vendor = device.vendor or guess.vendor
                device.os = device.os or guess.os
            scan.vendor_detection_confidence = guess.confidence
            scan.vendor_detection_method = guess.detection_method
            scan.vendor_detection_evidence = guess.evidence
            scan.vendor_review_required = guess.review_required
            db.commit()

            scan.raw_config_hash = hashlib.sha256(raw_text.encode()).hexdigest()

            # Archive the raw config to MinIO and record its object key on the
            # scan. This is what makes a Scan a "snapshot" for the Config
            # Backups page (routers/backups.py::list_device_snapshots only
            # lists Scan rows with raw_config_path set) and what
            # backup_destination_service.auto_export_after_scan needs to push
            # to remote destinations, AND what resume_pipeline() above reloads
            # the raw text from when resuming a paused/stopped scan later.
            # Best-effort: an object-store outage must not fail the scan
            # itself, matching every other put_object call site in this app.
            try:
                object_key = minio_service.object_key(scan.tenant_id, scan.device_id, scan.id, "raw_config.txt")
                stored = await asyncio.to_thread(
                    minio_service.put_object, object_key, raw_text.encode("utf-8"), content_type="text/plain",
                )
                # put_object() returns None (never raises) on any storage
                # failure; only record the key when the bytes really landed,
                # otherwise resume/backup would point at an object that
                # doesn't exist.
                if stored is not None:
                    scan.raw_config_path = object_key
            except Exception:  # noqa: BLE001
                pass

            scan.status = "parsed"
            db.commit()
            await events.publish("config.uploaded", {"scan_id": scan.id, "device_id": scan.device_id})

            # 2. Deterministic parsing ----------------------------------------------
            # A review_required guess never reaches parse_config with a vendor
            # name — "Unknown" routes the whole config through block-preservation
            # + the AI/RAG unknown pipeline (step 3) instead of guessing which
            # vendor parser to (mis)apply.
            effective_vendor = "Unknown" if guess.review_required else (device.vendor or guess.vendor)
            baseline: SecurityBaselineModel = await asyncio.to_thread(parse_config, effective_vendor, raw_text)
            if guess.review_required:
                baseline.unknown_evidence.append({
                    "reason": "vendor_detection_review_required",
                    "guessed_vendor": guess.vendor,
                    "platform": guess.platform,
                    "confidence": guess.confidence,
                    "detection_method": guess.detection_method,
                    "evidence": guess.evidence,
                })
            baseline.device.hostname = baseline.device.hostname or device.hostname
            baseline.device.model = device.model
            baseline.device.version = device.version
            baseline.device.serial_number = device.serial_number
            baseline.raw_config_hash = scan.raw_config_hash
            await events.publish("config.parsed", {"scan_id": scan.id, "matched_params": len(baseline.provenance)})

            # 2.5 Merge structural topology (VLANs, etc) into the compliance baseline.
            # parsers.py does not have a 100% structural parser (like junos hierarchy flattening), 
            # so we use topology_extractor's robust pipeline to cover the gaps.
            from app.services.topology_extractor import extract_topology_with_gaps
            gapped = await asyncio.to_thread(extract_topology_with_gaps, effective_vendor, raw_text)
            
            vlan_ids = {str(v.id) for v in baseline.vlans}
            for v in gapped.vlans:
                if str(v.vlan_id) not in vlan_ids:
                    from app.models.baseline import VLAN, NormalizedParameter
                    try:
                        baseline.vlans.append(VLAN(id=int(v.vlan_id), name=v.name))
                        baseline.provenance.append(NormalizedParameter(
                            raw_command=gapped.lines[v.line - 1] if v.line else "unknown topology mapping",
                            normalized_parameter="vlans",
                            value=v.name or str(v.vlan_id),
                            confidence=1.0,
                            source="parser",
                            vendor=effective_vendor,
                            human_validated=True
                        ))
                    except ValueError:
                        pass
                    vlan_ids.add(str(v.vlan_id))
            
            # Map structural ACLs into the compliance baseline if missing
            from app.models.baseline import ACLRule
            acl_names = {a.name for a in baseline.acls}
            for a in getattr(gapped, "acls", []):
                if a.name not in acl_names:
                    baseline.acls.append(ACLRule(name=a.name))
                    baseline.provenance.append(NormalizedParameter(
                        raw_command=gapped.lines[a.line - 1] if getattr(a, "line", None) else "unknown topology mapping",
                        normalized_parameter="acls",
                        value=a.name,
                        confidence=1.0,
                        source="parser",
                        vendor=effective_vendor,
                        human_validated=True
                    ))
                    acl_names.add(a.name)


            from app.services.topology_llm_fallback import interpret_unknown_lines
            if gapped.unknown_indices:
                llm_facts = await interpret_unknown_lines(effective_vendor, gapped.lines, gapped.unknown_indices)
                for v in llm_facts.vlans:
                    if str(v.vlan_id) not in vlan_ids:
                        from app.models.baseline import VLAN, NormalizedParameter
                        try:
                            baseline.vlans.append(VLAN(id=int(v.vlan_id), name=v.name))
                            baseline.provenance.append(NormalizedParameter(
                                raw_command=gapped.lines[v.line - 1] if v.line else "unknown topology ai mapping",
                                normalized_parameter="vlans",
                                value=v.name or str(v.vlan_id),
                                confidence=0.8,
                                source="ai",
                                model_version="topology_llm_fallback",
                                vendor=effective_vendor,
                                human_validated=False
                            ))
                        except ValueError:
                            pass
                        vlan_ids.add(str(v.vlan_id))

            await _checkpoint(db, scan, "normalize")

            # 3. AI/RAG normalization of unknown lines -------------------------------
            unknown_lines = baseline.extra_parameters.pop("_unknown_lines", [])
            if unknown_lines:
                await events.publish("ai.mapping.required", {"scan_id": scan.id, "count": len(unknown_lines)})
            # A resumed/restarted normalize stage re-does the whole stage, so
            # clear any AIAnalysis rows an earlier interrupted attempt left
            # behind instead of inserting a second copy of every one.
            db.query(AIAnalysis).filter(AIAnalysis.scan_id == scan.id).delete()
            db.commit()

            # Staged, batched, de-duplicated AI normalization (app/ai/staged.py):
            #   DistilBERT + MiniLM as true batches (versioned cache first) ->
            #   RAG retrieval from the same MiniLM vector -> LLM only for what
            #   the cache / validated evidence could not resolve -> uncertain
            #   results stay needs_human_review (existing HITL queue).
            # Every unknown line is still normalized and AIAnalysis-recorded
            # (bounded concurrency, never a coverage cap); duplicates are
            # computed once and fanned back out to each occurrence.
            # `interpret_line` is passed by name at call time so the existing
            # patch point (app.services.pipeline.interpret_line) keeps working.
            interp_vendor = device.vendor or guess.vendor
            inference_items = [
                ai_staged.InferenceItem(line=l, vendor=interp_vendor, tenant_id=scan.tenant_id, device_id=device.id)
                for l in unknown_lines
            ]

            async def _normalize_checkpoint():
                # Honour a pause/stop request between chunks instead of only
                # after every unknown line has been sent through the models.
                await _checkpoint(db, scan, "normalize")

            occurrences, ai_stats = await ai_staged.normalize_unknown_lines(
                inference_items, db=db, interpret_fn=interpret_line, checkpoint=_normalize_checkpoint,
            )
            __import__("logging").getLogger("pipeline").info(
                "ai.normalize_summary scan=%s input_lines=%s deterministic_facts=%s unknown_lines=%s stats=%s",
                scan.id, len(baseline.extra_parameters.get("_input_lines", [])),
                sum(1 for p in baseline.provenance if p.source == "parser"), len(unknown_lines),
                ai_stats.as_dict(),
            )

            for occ in occurrences:
                ai_result = occ.analysis
                db.add(AIAnalysis(
                    scan_id=scan.id,
                    device_id=device.id,
                    tenant_id=scan.tenant_id,
                    raw_command=occ.item.line,
                    raw_command_hash=hashlib.sha256(occ.item.line.encode()).hexdigest(),
                    intent=ai_result.intent,
                    classifier_confidence=ai_result.classifier_confidence,
                    semantic_similarity=ai_result.semantic_similarity,
                    nearest_intent=ai_result.nearest_intent,
                    nearest_vendor=ai_result.nearest_vendor,
                    models_agree=ai_result.models_agree,
                    decision=ai_result.decision,
                    requires_review=ai_result.requires_review,
                    reason=ai_result.reason,
                    model_version=ai_result.model_version,
                    inference_latency_ms=ai_result.inference_latency_ms,
                ))

            for occ in occurrences:
                for interp in occ.interpretations:
                    norm_param = to_normalized_parameter(interp, vendor=interp_vendor, ai_provenance=occ.provenance)
                    baseline.provenance.append(norm_param)
                    if interp.needs_human_review:
                        _queue_for_training(db, interp_vendor, interp)
                    else:
                        _apply_to_baseline(baseline, norm_param)
            db.commit()
            if unknown_lines:
                await events.publish("ai.mapping.completed", {"scan_id": scan.id})

            scan.status = "normalized"
            scan.baseline_json = baseline.model_dump(mode="json")
            db.commit()
            guess_vendor = guess.vendor
        else:
            # Resuming at/after "opa": the baseline was already fully
            # normalized and persisted in an earlier run of this pipeline --
            # reload it rather than re-parsing/re-normalizing from scratch.
            device = db.query(Device).get(scan.device_id)
            if not scan.baseline_json:
                raise ValueError(f"Scan {scan.id} has no persisted baseline to resume from (never completed normalization)")
            baseline = SecurityBaselineModel(**scan.baseline_json)
            guess_vendor = device.vendor

        await _checkpoint(db, scan, "opa")

        # 4. OPA policy evaluation (the ONLY authoritative PASS/FAIL engine;
        #    never the LLM, never a silent Python fallback — see
        #    services/compliance.py and services/opa_service.py) ------------
        scan.status = "opa_evaluating"
        db.commit()
        await events.publish("compliance.scan.started", {"scan_id": scan.id, "framework": framework})
        opa_decision = await evaluate_baseline_via_opa(scan.id, baseline, framework, db=db, tenant_id=scan.tenant_id)
        db.add(OPAAnalysis(
            scan_id=scan.id, policy_version=opa_decision.policy_version,
            decision=opa_decision.decision, decision_id=opa_decision.decision_id,
            source=opa_decision.source, result_json=opa_decision.to_dict(),
        ))
        scan.opa_decision = opa_decision.decision
        scan.opa_policy_version = opa_decision.policy_version
        scan.opa_decision_id = opa_decision.decision_id
        db.commit()
        await events.publish("compliance.opa.completed", {"scan_id": scan.id, "decision": opa_decision.decision})

        # A resumed run re-evaluates OPA against the same persisted baseline
        # (deterministic -> same findings), so clear any Finding rows from
        # the earlier partial run before inserting fresh ones, same as
        # routers/scans.py::rerun_scan does.
        if skip_normalize:
            db.query(Finding).filter(Finding.scan_id == scan.id).delete()
            db.commit()

        findings = opa_decision_to_findings(opa_decision, baseline)
        for f in findings:
            f.pop("line_number", None)
            db.add(Finding(scan_id=scan.id, **f))
        db.commit()
        for f in findings:
            await events.publish("finding.created", {"scan_id": scan.id, "control_id": f["control_id"], "result": f["result"]})

        score = compute_score(findings)

        await _checkpoint(db, scan, "batfish")

        # 5. Batfish behavioral analysis — the network-behavior engine
        #    (RULE 3). Runs on the candidate configuration's own snapshot;
        #    unsupported vendors/features and coordinator outages surface as
        #    explicit BATFISH_UNSUPPORTED/BATFISH_UNAVAILABLE, never as
        #    BATFISH_PASS (RULE 13). --------------------------------------
        scan.status = "batfish_evaluating"
        db.commit()
        loop = asyncio.get_running_loop()
        bf_result = await loop.run_in_executor(
            None,
            lambda: batfish_service.analyze_security_behavior(
                scan_id=scan.id,
                vendor=device.vendor or guess_vendor or "",
                hostname=baseline.device.hostname or device.hostname or "device",
                raw_config=raw_text,
                selected_checks=batfish_checks.split(",") if batfish_checks else None,
            )
        )
        batfish_status = bf_result.status
        db.add(BatfishAnalysis(
            scan_id=scan.id, network_name=bf_result.network_name, snapshot_name=bf_result.snapshot_name,
            status=bf_result.status, critical_violation=bf_result.critical_violation,
            init_issues=bf_result.init_issues, result_json=bf_result.to_dict(),
        ))
        batfish_findings = bf_result.findings()
        for bf_f in batfish_findings:
            if bf_f["result"] in ("FAIL",):
                db.add(Finding(
                    scan_id=scan.id, framework=framework, control_id=bf_f["control_id"],
                    title=bf_f["title"], severity=bf_f["severity"], result="FAIL",
                    parameter=f"{bf_f['source_zone']}->{bf_f['destination_zone']}",
                    evidence_line=bf_f.get("detail"), remediation="Correct ACL/segmentation to block this path.",
                    # Same denormalized vendor field OPA findings carry --
                    # without it Batfish findings were silently excluded
                    # from vendor_scores and the cross-vendor matrix too.
                    vendor=device.vendor or guess_vendor or None,
                ))
        db.commit()
        await events.publish("compliance.batfish.completed", {"scan_id": scan.id, "status": batfish_status})

        await _checkpoint(db, scan, "finalize")

        # 6. Deterministic risk score --------------------------------------
        unknown_count = len(baseline.provenance and [p for p in baseline.provenance if p.source == "ai" and p.confidence < 0.75])
        risk = risk_engine.calculate_risk(
            opa_decision.findings, batfish_findings=batfish_findings, unknown_syntax_count=unknown_count,
        )
        scan.risk_score = risk.risk_score
        scan.risk_level = risk.risk_level
        db.commit()

        # 7. Correlation -> final decision ----------------------------------
        compliance_decision = correlate(
            syntax_ok=True, opa_decision=opa_decision, risk=risk, batfish_status=batfish_status,
            batfish_critical_violation=bf_result.critical_violation,
        )
        scan.final_decision = compliance_decision.decision
        scan.final_reason = compliance_decision.reason
        scan.batfish_status = batfish_status
        db.commit()
        await events.publish("compliance.correlation.completed", {"scan_id": scan.id, "decision": compliance_decision.decision})

        # 8. Evidence package -> canonicalize -> SHA-256 -> store off-chain -
        evidence = evidence_service.build_evidence(
            scan_id=scan.id, device_id=device.id, tenant_id=scan.tenant_id,
            event_type="scan.completed", actor="system:pipeline", vendor=baseline.device.vendor or "Unknown",
            config_hash=scan.raw_config_hash, baseline_hash=hashlib.sha256(
                evidence_service.canonicalize_evidence(scan.baseline_json).encode()
            ).hexdigest(),
            opa_result=opa_decision.to_dict(), batfish_result=bf_result.to_dict(),
            risk_result=risk.to_dict(), final_decision=compliance_decision.decision, framework=framework,
            control_ids=[f["control_id"] for f in findings], finding_ids=[],
        )
        canonical = evidence_service.canonicalize_evidence(evidence)
        evidence_hash = evidence_service.hash_evidence(canonical)
        record = evidence_service.store_evidence(db, evidence, evidence_hash)
        scan.evidence_id = record.evidence_id
        await events.publish("evidence.anchor.requested", {"scan_id": scan.id, "evidence_id": record.evidence_id})

        # 8b. Fabric anchor — best-effort, never blocks the scan result -----
        # If FABRIC_ENABLED=false the evidence stays fully valid off-chain
        # (fabric_status="NOT_ANCHORED"). If Fabric is enabled but the
        # gateway is unreachable, the record is marked FABRIC_UNAVAILABLE —
        # never falsely reported as anchored (section 19, RULE 15).
        if fabric_service.FABRIC_ENABLED:
            try:
                anchor = await fabric_service.anchor_evidence(
                    record.evidence_id,
                    evidence_hash,
                    scan_id=scan.id,
                    device_id=device.id,
                    tenant_id=scan.tenant_id,
                    event_type=evidence["event_type"],
                    config_hash=evidence["config_hash"],
                    baseline_hash=evidence["baseline_hash"],
                    opa_decision=opa_decision.decision,
                    batfish_decision=bf_result.status,
                    final_decision=compliance_decision.decision,
                    policy_version=opa_decision.policy_version,
                    batfish_snapshot=bf_result.snapshot_name or "",
                    model_version=evidence.get("model_version") or "",
                    timestamp=evidence["timestamp"],
                    actor="system:pipeline",
                )
                record.fabric_status = "ANCHORED"
                record.fabric_tx_id = anchor.get("transaction_id")
                record.fabric_block_number = anchor.get("block_number")
                db.commit()
                await events.publish(
                    "evidence.anchor.completed",
                    {"scan_id": scan.id, "evidence_id": record.evidence_id, "tx_id": record.fabric_tx_id},
                )
            except fabric_service.FabricUnavailableError as e:
                record.fabric_status = "FABRIC_UNAVAILABLE"
                db.commit()
                await events.publish(
                    "evidence.anchor.failed",
                    {"scan_id": scan.id, "evidence_id": record.evidence_id, "reason": str(e)},
                )
                if fabric_service.FABRIC_REQUIRED_FOR_CRITICAL_CHANGES and compliance_decision.decision == "BLOCK":
                    # Critical evidence must be anchored — surface this to the
                    # scan itself rather than silently completing.
                    scan.status = "review"
                    scan.final_reason = (scan.final_reason or "") + " | FABRIC_UNAVAILABLE for critical evidence"
                    db.commit()

        # 9. Final scan status ------------------------------------------
        previous_score = device.last_compliance_score  # before this scan overwrites it
        scan.compliance_score = score
        scan.status = {"PASS": "completed", "REVIEW": "review", "BLOCK": "blocked"}[compliance_decision.decision]
        scan.updated_at = datetime.utcnow()
        device.last_scan_at = datetime.utcnow()
        device.last_compliance_score = score
        db.commit()

        # Compliance-score thresholds -> COMPLIANCE_SCORE_LOW alerts.
        # Best-effort (the service swallows its own errors).
        try:
            from app.services import alert_service
            await alert_service.evaluate_compliance_thresholds(db, scan)
        except Exception:  # noqa: BLE001
            __import__("logging").getLogger("pipeline").exception("compliance threshold alerting failed for scan %s", scan.id)
        await events.publish("compliance.scan.completed", {"scan_id": scan.id, "score": score, "decision": compliance_decision.decision})

        # Topology page data (interfaces / VLAN membership / VRFs / routes /
        # L3 adjacency): Batfish-modelled from this config, regex fallback.
        # Best-effort -- must never fail a completed scan.
        try:
            from app.services import topology_batfish_service
            await topology_batfish_service.refresh_topology(
                db, tenant_id=scan.tenant_id, devices_with_raw=[(device, raw_text)],
                scan_ids={device.id: scan.id}, key=f"dev-{device.id}",
            )
        except Exception:  # noqa: BLE001
            __import__("logging").getLogger("pipeline").exception("topology refresh failed for scan %s", scan.id)
            try:
                db.rollback()
            except Exception:  # noqa: BLE001
                pass

        # Keep the "Ask NetSecAuditor" RAG corpus current: incrementally
        # upsert this scan's device + failing findings rather than waiting
        # on a manual /api/rag/reindex click. Best-effort -- indexing
        # trouble must never fail a completed scan.
        try:
            rag_service.index_scan_results(db, scan.tenant_id, scan, device)
        except Exception:
            logger = __import__("logging").getLogger("pipeline")
            logger.exception("rag incremental index failed for scan %s", scan.id)

        scan.control_state = "RUNNING"
        await _checkpoint(db, scan, "done")

    except (PipelinePaused, PipelineStopped):
        # Already persisted (status/control_state/pipeline_stage/timestamp)
        # inside _checkpoint() -- not a failure, just an early, resumable
        # exit. Nothing further to do here.
        return scan
    except Exception as e:  # keep the demo resilient; surface the error on the scan
        # A DB error leaves the session needing a rollback before it can
        # commit anything, including this failure record.
        db.rollback()
        scan.status = "failed"
        scan.error = str(e)
        db.commit()
        raise
    return scan


def _apply_to_baseline(baseline: SecurityBaselineModel, norm_param) -> None:
    # Special-cased: this is the sentinel normalized_parameter used by
    # ai/normalize.py for facts it could not confidently map to a typed
    # field. It must accumulate on the model's dedicated `unknown_evidence`
    # list (spec section 9/14) rather than being routed through the dotted
    # setattr walk below, which would previously land in
    # extra_parameters["extra_parameters.unknown_evidence"] as a single
    # value that got silently overwritten by the next unknown line (data
    # loss) and was never the same key compute_coverage() actually read
    # back (a pre-existing key mismatch: writer used
    # "extra_parameters.unknown_evidence", reader used "unknown_evidence").
    if norm_param.normalized_parameter == "extra_parameters.unknown_evidence":
        baseline.unknown_evidence.append({
            "raw_command": norm_param.raw_command,
            "value": norm_param.value,
            "confidence": norm_param.confidence,
            "model_version": norm_param.model_version,
            "vendor": norm_param.vendor,
        })
        return

    parts = norm_param.normalized_parameter.split(".")
    obj = baseline
    try:
        for p in parts[:-1]:
            obj = getattr(obj, p)
        setattr(obj, parts[-1], norm_param.value)
    except (AttributeError, ValueError):
        # Strip a leading 'extra_parameters.' so the AI/LLM normalization
        # path lands values at the same clean keys the deterministic parser
        # now uses (services/parsers.py::_set_dotted) -- e.g. 'domain_name',
        # not the doubled-up 'extra_parameters.domain_name' this previously
        # produced, which is exactly the key-mismatch bug already called out
        # above for the 'unknown_evidence' sentinel.
        param = norm_param.normalized_parameter
        key = param[len("extra_parameters."):] if param.startswith("extra_parameters.") else param
        baseline.extra_parameters[key] = norm_param.value


def _queue_for_training(db: Session, vendor: str, interp) -> None:
    from app.models.db import CommandMapping
    existing = (
        db.query(CommandMapping)
        .filter(CommandMapping.vendor == vendor, CommandMapping.raw_command_pattern == interp.raw_command)
        .first()
    )
    if existing:
        return
    db.add(CommandMapping(
        vendor=vendor,
        raw_command_pattern=interp.raw_command,
        normalized_parameter=interp.normalized_parameter,
        example_value=str(interp.value),
        ai_suggested_meaning=f"AI-suggested mapping to '{interp.normalized_parameter}' with value {interp.value!r}",
        confidence=interp.confidence,
        status="pending",
        model_version=interp.model_version,
    ))
    db.commit()