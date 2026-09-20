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

import hashlib
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app import events
from app.ai import service as ai_service
from app.ai.normalize import (interpret_line, retrieve_similar_mappings,
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
_NORMALIZE_BATCH_SIZE = 40  # checkpoint frequency inside the AI loop


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
    stop was requested, persists the checkpoint and raises to unwind."""
    db.refresh(scan)
    if scan.control_state == "STOP_REQUESTED":
        scan.status = "stopped"
        scan.control_state = "STOPPED"
        scan.pipeline_stage = stage
        scan.stopped_at = datetime.utcnow()
        db.commit()
        await events.publish("pipeline.stopped", {"scan_id": scan.id, "stage": stage})
        raise PipelineStopped(stage)
    if scan.control_state == "PAUSE_REQUESTED":
        scan.status = "paused"
        scan.control_state = "PAUSED"
        scan.pipeline_stage = stage
        scan.paused_at = datetime.utcnow()
        db.commit()
        await events.publish("pipeline.paused", {"scan_id": scan.id, "stage": stage})
        raise PipelinePaused(stage)
    scan.pipeline_stage = stage
    db.commit()


async def resume_pipeline(db: Session, scan: Scan) -> Scan:
    """Resume a PAUSED or STOPPED scan from its last checkpointed stage.
    Reloads the archived raw config from MinIO (raw_config_path) -- the
    pipeline never keeps the full config text in the DB row itself -- and
    re-enters run_pipeline() at the right point."""
    if scan.control_state not in ("PAUSED", "STOPPED"):
        raise ValueError(f"Scan {scan.id} is not paused or stopped (control_state={scan.control_state})")
    if not scan.raw_config_path:
        raise ValueError(f"Scan {scan.id} has no archived raw configuration to resume from")

    raw_text = minio_service.get_object(scan.raw_config_path).decode("utf-8", errors="replace")
    resume_stage = scan.pipeline_stage or "start"

    scan.control_state = "RUNNING"
    scan.status = "resuming"
    scan.resumed_at = datetime.utcnow()
    db.commit()
    await events.publish("pipeline.resumed", {"scan_id": scan.id, "stage": resume_stage})

    return await run_pipeline(db, scan, raw_text, framework=scan.framework or "ALL", resume_stage=resume_stage)


async def run_pipeline(
    db: Session, scan: Scan, raw_text: str, framework: str = "ALL", resume_stage: Optional[str] = None,
) -> Scan:
    skip_normalize = resume_stage in _RESUMABLE_FROM_BASELINE
    try:
        await _checkpoint(db, scan, "start")

        if not skip_normalize:
            # 1. Vendor/OS detection ------------------------------------------------
            guess = detect_vendor(raw_text)
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
                minio_service.put_object(object_key, raw_text.encode("utf-8"), content_type="text/plain")
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
            baseline: SecurityBaselineModel = parse_config(effective_vendor, raw_text)
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

            await _checkpoint(db, scan, "normalize")

            # 3. AI/RAG normalization of unknown lines -------------------------------
            unknown_lines = baseline.extra_parameters.pop("_unknown_lines", [])
            if unknown_lines:
                await events.publish("ai.mapping.required", {"scan_id": scan.id, "count": len(unknown_lines)})
            for line in unknown_lines:
                # 3a. Trained-AI intent classification (DistilBERT + MiniLM hybrid
                #     decision engine) — purely an interpretation signal, persisted
                #     for review; it never sets compliance PASS/FAIL and never
                #     overrides the Ollama/RAG normalization result below.
                ai_result = ai_service.analyze_command(line)
                db.add(AIAnalysis(
                    scan_id=scan.id,
                    device_id=device.id,
                    tenant_id=scan.tenant_id,
                    raw_command_hash=hashlib.sha256(line.encode()).hexdigest(),
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

            import asyncio
            # Bound *concurrency*, not coverage: every unknown line must still be
            # normalized (and therefore eligible for remediation) no matter how
            # large the uploaded config is. The old `unknown_lines[:60]` slice
            # silently dropped everything past the first 60 unknown lines from
            # both normalization and downstream remediation on large configs --
            # a semaphore-limited gather keeps demo/production latency in check
            # without ever skipping lines.
            _CONCURRENCY = 20
            semaphore = asyncio.Semaphore(_CONCURRENCY)

            async def _process_line(line: str):
                async with semaphore:
                    retrieved = await retrieve_similar_mappings(db, device.vendor or guess.vendor, line, tenant_id=scan.tenant_id)
                    interp_vendor = device.vendor or guess.vendor
                    interps = await interpret_line(interp_vendor, line, retrieved)
                    return interp_vendor, interps

            # Processed in batches, with a checkpoint after each one, so a
            # pause/stop request on a large config takes effect within one
            # batch instead of only after every unknown line has been sent
            # through the AI normalizer.
            lines_to_process = [l for l in unknown_lines if l.strip()]
            results = []
            for batch_start in range(0, len(lines_to_process), _NORMALIZE_BATCH_SIZE):
                batch = lines_to_process[batch_start: batch_start + _NORMALIZE_BATCH_SIZE]
                batch_results = await asyncio.gather(*[_process_line(line) for line in batch])
                results.extend(batch_results)
                if batch_start + _NORMALIZE_BATCH_SIZE < len(lines_to_process):
                    await _checkpoint(db, scan, "normalize")

            for interp_vendor, interps in results:
                for interp in interps:
                    norm_param = to_normalized_parameter(interp, vendor=interp_vendor)
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
        import asyncio
        loop = asyncio.get_running_loop()
        bf_result = await loop.run_in_executor(
            None,
            lambda: batfish_service.analyze_security_behavior(
                scan_id=scan.id,
                vendor=device.vendor or guess_vendor or "",
                hostname=baseline.device.hostname or device.hostname or "device",
                raw_config=raw_text,
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
        scan.compliance_score = score
        scan.status = {"PASS": "completed", "REVIEW": "review", "BLOCK": "blocked"}[compliance_decision.decision]
        scan.updated_at = datetime.utcnow()
        device.last_scan_at = datetime.utcnow()
        device.last_compliance_score = score
        db.commit()
        await events.publish("compliance.scan.completed", {"scan_id": scan.id, "score": score, "decision": compliance_decision.decision})

        # User-configured "alert me when the score drops below X" thresholds.
        # Best-effort inside evaluate_compliance_thresholds -- never fails a scan.
        from app.services import alert_service
        await alert_service.evaluate_compliance_thresholds(db, scan)

        # Keep the "Ask NetSecAuditor" RAG corpus current: incrementally
        # upsert this scan's device + failing findings rather than waiting
        # on a manual /api/rag/reindex click. Best-effort -- indexing
        # trouble must never fail a completed scan.
        try:
            rag_service.index_scan_results(db, scan.tenant_id, scan, device)
        except Exception:
            logger = __import__("logging").getLogger("pipeline")
            logger.exception("rag incremental index failed for scan %s", scan.id)

        scan.pipeline_stage = "done"
        scan.control_state = "RUNNING"
        db.commit()

    except (PipelinePaused, PipelineStopped):
        # Already persisted (status/control_state/pipeline_stage/timestamp)
        # inside _checkpoint() -- not a failure, just an early, resumable
        # exit. Nothing further to do here.
        return scan
    except Exception as e:  # keep the demo resilient; surface the error on the scan
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
        baseline.extra_parameters[norm_param.normalized_parameter] = norm_param.value


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