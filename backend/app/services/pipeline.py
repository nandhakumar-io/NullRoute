"""
Orchestrates the full ingestion -> normalization -> compliance pipeline for
one uploaded configuration, emitting the architecture's event-bus subjects
at each stage.
"""
from __future__ import annotations

import hashlib
import logging
import time
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app import events
from app.ai import service as ai_service
from app.ai.normalize import (interpret_line, retrieve_similar_mappings,
                               to_normalized_parameter)
from app.models.baseline import SecurityBaselineModel
from app.models.db import AIAnalysis, BatfishAnalysis, Device, Finding, OPAAnalysis, Scan
from app.services import alert_service, batfish_service, drift_service, evidence_service, fabric_service, minio_service, opa_service, risk_engine, topology_service
from app.services.change_validation_service import correlate
from app.services.compliance import compute_score, evaluate_baseline_via_opa, opa_decision_to_findings
from app.services.parsers import parse_config
from app.services.vendor_detect import detect_vendor
from app.services.telemetry import increment_counter, record_histogram, tracer

logger = logging.getLogger("pipeline")


async def run_pipeline(db: Session, scan: Scan, raw_text: str, framework: str = "ALL") -> Scan:
    _pipeline_start = time.perf_counter()
    with tracer.start_as_current_span("pipeline.run") as _span:
        _span.set_attribute("scan_id", scan.id)
        _span.set_attribute("tenant_id", scan.tenant_id)
        result = await _run_pipeline_body(db, scan, raw_text, framework)
        record_histogram("scan_duration_ms", (time.perf_counter() - _pipeline_start) * 1000.0,
                          {"framework": framework, "final_decision": scan.final_decision or "unknown"})
        return result


async def _run_pipeline_body(db: Session, scan: Scan, raw_text: str, framework: str = "ALL") -> Scan:
    try:
        # 1. Vendor/OS detection ------------------------------------------------
        guess = detect_vendor(raw_text)
        device: Device = db.query(Device).get(scan.device_id)
        if guess.vendor != "Unknown":
            device.vendor = device.vendor or guess.vendor
            device.os = device.os or guess.os
        db.commit()

        scan.raw_config_hash = hashlib.sha256(raw_text.encode()).hexdigest()
        # Phase 8: archive the raw configuration bytes in MinIO; PostgreSQL
        # keeps only the object key + hash (RULE 6/12). Best-effort -- a
        # MinIO outage must not fail the scan (see minio_service.put_object).
        raw_key = minio_service.object_key(scan.tenant_id, scan.device_id, scan.id, "raw.cfg")
        put_result = minio_service.put_object(raw_key, raw_text.encode("utf-8"), content_type="text/plain")
        if put_result is not None:
            scan.raw_config_path = put_result.object_key
        scan.status = "parsed"
        db.commit()
        await events.publish("config.uploaded", {"scan_id": scan.id, "device_id": scan.device_id})

        # 1a. Configuration drift (Phase 11) -------------------------------
        # Best-effort, never fails the scan: compares this scan's raw config
        # against the device's immediately-preceding scan (by hash), and
        # persists an immutable DriftEvent describing the diff. Purely a
        # triage/record signal -- the pipeline always continues to OPA below
        # regardless of drift status (RULE 1: only OPA renders a verdict).
        try:
            previous_scan = drift_service.get_previous_scan(db, scan.device_id, exclude_scan_id=scan.id)
            previous_text: Optional[str] = None
            if previous_scan and previous_scan.raw_config_hash != scan.raw_config_hash:
                if previous_scan.raw_config_path:
                    try:
                        previous_text = minio_service.get_object(previous_scan.raw_config_path).decode("utf-8", errors="replace")
                    except Exception:
                        previous_text = ""  # prior text unrecoverable but hash differs: still record the hash change
                else:
                    previous_text = ""
            if previous_scan and previous_text is not None:
                drift_event = drift_service.record_drift(
                    db, tenant_id=scan.tenant_id, device_id=scan.device_id,
                    current_scan=scan, previous_text=previous_text, current_text=raw_text,
                )
                if drift_event is not None:
                    await events.publish("device.drift.detected", {
                        "scan_id": scan.id, "device_id": scan.device_id,
                        "drift_event_id": drift_event.id,
                        "security_impacting": drift_event.security_impacting,
                    })
                    if drift_event.security_impacting:
                        try:
                            await alert_service.alert_drift(
                                db, scan.tenant_id, scan.device_id, scan.id, drift_event.id,
                            )
                        except Exception:  # noqa: BLE001 - alerting must never fail the scan
                            logger.warning("Drift alert dispatch failed for scan %s", scan.id, exc_info=True)
        except Exception:  # noqa: BLE001
            db.rollback()

        # 1b. Inventory/topology extraction (Phase 9) ---------------------------
        # Best-effort, never fails the scan. Replaces this device's previous
        # snapshot rows since these represent CURRENT observed state, not a
        # history (see models/db.py NetworkInterface docstring).
        try:
            topology_service.refresh_device_topology(
                db, tenant_id=scan.tenant_id, device_id=scan.device_id, scan_id=scan.id,
                vendor=device.vendor or guess.vendor, raw_text=raw_text,
            )
        except Exception:  # noqa: BLE001
            db.rollback()

        # 2. Deterministic parsing ----------------------------------------------
        baseline: SecurityBaselineModel = parse_config(device.vendor or guess.vendor, raw_text)
        baseline.device.hostname = baseline.device.hostname or device.hostname
        baseline.device.model = device.model
        baseline.device.version = device.version
        baseline.device.serial_number = device.serial_number
        baseline.raw_config_hash = scan.raw_config_hash
        await events.publish("config.parsed", {"scan_id": scan.id, "matched_params": len(baseline.provenance)})

        # 3. AI/RAG normalization of unknown lines -------------------------------
        unknown_lines = baseline.extra_parameters.pop("_unknown_lines", [])
        if unknown_lines:
            await events.publish("ai.mapping.required", {"scan_id": scan.id, "count": len(unknown_lines)})
        for line in unknown_lines[:60]:  # cap for demo latency
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

            retrieved = await retrieve_similar_mappings(db, scan.tenant_id, device.vendor or guess.vendor, line)
            interp = await interpret_line(device.vendor or guess.vendor, line, retrieved)
            norm_param = to_normalized_parameter(interp)
            baseline.provenance.append(norm_param)
            if interp.needs_human_review:
                _queue_for_training(db, scan.tenant_id, device.vendor or guess.vendor, interp)
            else:
                _apply_to_baseline(baseline, norm_param)
        db.commit()
        if unknown_lines:
            await events.publish("ai.mapping.completed", {"scan_id": scan.id})

        scan.status = "normalized"
        scan.baseline_json = baseline.model_dump(mode="json")
        db.commit()

        # 4. OPA policy evaluation (the ONLY authoritative PASS/FAIL engine;
        #    never the LLM, never a silent Python fallback — see
        #    services/compliance.py and services/opa_service.py) ------------
        scan.status = "opa_evaluating"
        db.commit()
        await events.publish("compliance.scan.started", {"scan_id": scan.id, "framework": framework})
        opa_decision = await evaluate_baseline_via_opa(scan.id, baseline, framework)
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

        findings = opa_decision_to_findings(opa_decision, baseline)
        for f in findings:
            db.add(Finding(scan_id=scan.id, **f))
        db.commit()
        for f in findings:
            await events.publish("finding.created", {"scan_id": scan.id, "control_id": f["control_id"], "result": f["result"]})

        score = compute_score(findings)

        # 5. Batfish behavioral analysis — the network-behavior engine
        #    (RULE 3). Runs on the candidate configuration's own snapshot;
        #    unsupported vendors/features and coordinator outages surface as
        #    explicit BATFISH_UNSUPPORTED/BATFISH_UNAVAILABLE, never as
        #    BATFISH_PASS (RULE 13). --------------------------------------
        scan.status = "batfish_evaluating"
        db.commit()
        bf_result = batfish_service.analyze_security_behavior(
            scan_id=scan.id,
            vendor=device.vendor or guess.vendor or "",
            hostname=baseline.device.hostname or device.hostname or "device",
            raw_config=raw_text,
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
                ))
        db.commit()
        await events.publish("compliance.batfish.completed", {"scan_id": scan.id, "status": batfish_status})

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
                try:
                    await alert_service.alert_fabric_anchor_failure(
                        db, scan.tenant_id, scan.id, record.evidence_id, str(e),
                    )
                except Exception:  # noqa: BLE001 - alerting must never fail the scan
                    logger.warning("Fabric-failure alert dispatch failed for scan %s", scan.id, exc_info=True)
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

        try:
            await alert_service.evaluate_scan_for_alerts(db, scan, findings)
        except Exception:  # noqa: BLE001 - alerting must never fail the scan
            logger.warning("Post-scan alert evaluation failed for scan %s", scan.id, exc_info=True)

    except Exception as e:  # keep the demo resilient; surface the error on the scan
        scan.status = "failed"
        scan.error = str(e)
        db.commit()
        raise
    return scan


def _apply_to_baseline(baseline: SecurityBaselineModel, norm_param) -> None:
    parts = norm_param.normalized_parameter.split(".")
    obj = baseline
    try:
        for p in parts[:-1]:
            obj = getattr(obj, p)
        setattr(obj, parts[-1], norm_param.value)
    except AttributeError:
        baseline.extra_parameters[norm_param.normalized_parameter] = norm_param.value


def _queue_for_training(db: Session, tenant_id: str, vendor: str, interp) -> None:
    from app.models.db import CommandMapping
    existing = (
        db.query(CommandMapping)
        .filter(
            CommandMapping.tenant_id == tenant_id,
            CommandMapping.vendor == vendor,
            CommandMapping.raw_command_pattern == interp.raw_command,
        )
        .first()
    )
    if existing:
        return
    db.add(CommandMapping(
        tenant_id=tenant_id,
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