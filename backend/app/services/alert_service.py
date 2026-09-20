"""Phase 13 -- alert engine.

Every alert in the system is created through `create_alert()`, which
persists the row first (so GET /api/alerts is always the source of truth)
and then best-effort dispatches to whichever destinations are configured
via environment variables. A destination failing to accept the
notification never fails the alert creation itself, and never fails the
caller's pipeline/collection/anchor flow -- alerting is observational, not
part of the compliance decision path.

Destinations (all optional, off by default):
  ALERT_NATS_ENABLED   ("true"/"false", default true if NATS already used)
  ALERT_WEBHOOK_URL     generic JSON POST
  ALERT_NTFY_URL        e.g. https://ntfy.sh/my-topic (plain text POST)
  ALERT_SMTP_HOST / ALERT_SMTP_PORT / ALERT_EMAIL_FROM / ALERT_EMAIL_TO
                        best-effort SMTP email; skipped entirely if
                        ALERT_SMTP_HOST is unset (never fabricate delivery).
"""
from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app import events
from app.models.db import AIAnalysis, Alert, Scan

logger = logging.getLogger("alert_service")

VALID_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL")
ALERT_NTFY_URL = os.getenv("ALERT_NTFY_URL")
ALERT_SMTP_HOST = os.getenv("ALERT_SMTP_HOST")
ALERT_SMTP_PORT = int(os.getenv("ALERT_SMTP_PORT", "587"))
ALERT_EMAIL_FROM = os.getenv("ALERT_EMAIL_FROM", "alerts@compliance-auditor.local")
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO")


def to_dict(a: Alert) -> Dict[str, Any]:
    return {
        "id": a.id, "tenant_id": a.tenant_id, "category": a.category, "severity": a.severity,
        "title": a.title, "detail": a.detail, "scan_id": a.scan_id, "device_id": a.device_id,
        "extra": a.extra, "status": a.status, "acknowledged_by": a.acknowledged_by,
        "acknowledged_at": a.acknowledged_at, "dispatch_results": a.dispatch_results,
        "created_at": a.created_at,
    }


async def _dispatch(alert: Alert) -> Dict[str, Any]:
    results: Dict[str, Any] = {}

    payload = {
        "id": alert.id, "tenant_id": alert.tenant_id, "category": alert.category,
        "severity": alert.severity, "title": alert.title, "detail": alert.detail,
        "scan_id": alert.scan_id, "device_id": alert.device_id,
    }

    try:
        await events.publish("alert.created", payload)
        results["nats"] = "published"
    except Exception as e:  # pragma: no cover - events.publish already swallows most errors
        results["nats"] = f"failed: {e}"

    if ALERT_WEBHOOK_URL:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(ALERT_WEBHOOK_URL, json=payload)
            results["webhook"] = f"status_{resp.status_code}"
        except Exception as e:
            results["webhook"] = f"failed: {e}"
            logger.warning("Alert webhook dispatch failed: %s", e)

    if ALERT_NTFY_URL:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(
                    ALERT_NTFY_URL,
                    content=f"[{alert.severity}] {alert.title}\n{alert.detail or ''}".encode(),
                    headers={"Title": alert.category},
                )
            results["ntfy"] = f"status_{resp.status_code}"
        except Exception as e:
            results["ntfy"] = f"failed: {e}"
            logger.warning("Alert ntfy dispatch failed: %s", e)

    if ALERT_SMTP_HOST and ALERT_EMAIL_TO:
        try:
            import smtplib
            from email.mime.text import MIMEText

            msg = MIMEText(alert.detail or alert.title)
            msg["Subject"] = f"[{alert.severity}] {alert.title}"
            msg["From"] = ALERT_EMAIL_FROM
            msg["To"] = ALERT_EMAIL_TO
            with smtplib.SMTP(ALERT_SMTP_HOST, ALERT_SMTP_PORT, timeout=5) as smtp:
                smtp.send_message(msg)
            results["email"] = "sent"
        except Exception as e:
            results["email"] = f"failed: {e}"
            logger.warning("Alert email dispatch failed: %s", e)
    else:
        results["email"] = "skipped (not configured)"

    return results


async def create_alert(
    db: Session,
    tenant_id: str,
    category: str,
    severity: str,
    title: str,
    detail: Optional[str] = None,
    scan_id: Optional[str] = None,
    device_id: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
    extra_channel_ids: Optional[List[str]] = None,
) -> Alert:
    if severity not in VALID_SEVERITIES:
        severity = "MEDIUM"
    alert = Alert(
        tenant_id=tenant_id, category=category, severity=severity, title=title,
        detail=detail, scan_id=scan_id, device_id=device_id, extra=extra or {},
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)

    legacy_results = await _dispatch(alert)
    try:
        from app.services import alert_channel_service
        channel_results = await alert_channel_service.route_and_dispatch(db, alert, extra_channel_ids)
    except Exception as e:  # noqa: BLE001 - configurable-channel routing must never block alert creation
        logger.warning("Configurable alert-channel routing failed: %s", e)
        channel_results = {}
    alert.dispatch_results = {**legacy_results, **channel_results}
    db.commit()
    db.refresh(alert)
    return alert


def acknowledge_alert(db: Session, alert: Alert, acknowledged_by: str) -> Alert:
    alert.status = "ACKNOWLEDGED"
    alert.acknowledged_by = acknowledged_by
    alert.acknowledged_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)
    return alert


# ---------------------------------------------------------------------------
# Rule evaluation -- called from the pipeline / collection / drift / fabric
# code paths. Each function is independent and best-effort: a failure here
# must never fail the caller's actual work.
# ---------------------------------------------------------------------------

async def evaluate_scan_for_alerts(db: Session, scan: Scan, findings: List[Dict[str, Any]]) -> List[Alert]:
    created: List[Alert] = []

    for f in findings:
        if f.get("severity") == "CRITICAL" and f.get("result") == "FAIL":
            created.append(await create_alert(
                db, scan.tenant_id, "CRITICAL_FINDING", "CRITICAL",
                title=f"Critical finding: {f.get('title') or f.get('control_id')}",
                detail=f.get("evidence_line") or f.get("remediation"),
                scan_id=scan.id, device_id=scan.device_id,
                extra={"control_id": f.get("control_id")},
            ))

    if scan.risk_level in ("HIGH", "CRITICAL"):
        created.append(await create_alert(
            db, scan.tenant_id, "HIGH_RISK", scan.risk_level,
            title=f"Scan risk level {scan.risk_level} (score {scan.risk_score})",
            detail=scan.final_reason, scan_id=scan.id, device_id=scan.device_id,
        ))

    if scan.opa_decision in ("OPA_UNAVAILABLE",) or (scan.opa_decision == "BLOCK"):
        created.append(await create_alert(
            db, scan.tenant_id, "OPA_FAILURE",
            "CRITICAL" if scan.opa_decision == "BLOCK" else "HIGH",
            title=f"OPA decision: {scan.opa_decision}",
            detail=scan.final_reason, scan_id=scan.id, device_id=scan.device_id,
        ))

    if scan.batfish_status == "BATFISH_FAIL":
        created.append(await create_alert(
            db, scan.tenant_id, "BATFISH_VIOLATION", "HIGH",
            title="Batfish behavioral violation detected",
            detail=scan.final_reason, scan_id=scan.id, device_id=scan.device_id,
        ))

    ai_rows = db.query(AIAnalysis).filter(AIAnalysis.scan_id == scan.id).all()
    unknown_count = sum(1 for r in ai_rows if r.decision == "UNKNOWN")
    review_count = sum(1 for r in ai_rows if r.requires_review)
    if unknown_count:
        created.append(await create_alert(
            db, scan.tenant_id, "AI_UNKNOWN_CONFIGURATION", "MEDIUM",
            title=f"{unknown_count} unknown configuration command(s) detected",
            scan_id=scan.id, device_id=scan.device_id,
            extra={"unknown_count": unknown_count},
        ))
    elif review_count:
        created.append(await create_alert(
            db, scan.tenant_id, "AI_LOW_CONFIDENCE", "LOW",
            title=f"{review_count} configuration command(s) flagged for AI review",
            scan_id=scan.id, device_id=scan.device_id,
            extra={"review_count": review_count},
        ))

    return created


async def alert_collection_failure(db: Session, tenant_id: str, device_id: str, error: Optional[str]) -> Alert:
    return await create_alert(
        db, tenant_id, "DEVICE_COLLECTION_FAILURE", "HIGH",
        title="Device configuration collection failed",
        detail=error, device_id=device_id,
    )


async def alert_drift(db: Session, tenant_id: str, device_id: str, scan_id: str, drift_event_id: str) -> Alert:
    return await create_alert(
        db, tenant_id, "CONFIGURATION_DRIFT", "MEDIUM",
        title="Security-impacting configuration drift detected",
        scan_id=scan_id, device_id=device_id, extra={"drift_event_id": drift_event_id},
    )


async def alert_fabric_anchor_failure(db: Session, tenant_id: str, scan_id: str, evidence_id: str, reason: str) -> Alert:
    return await create_alert(
        db, tenant_id, "FABRIC_ANCHOR_FAILURE", "HIGH",
        title="Evidence Fabric anchor failed",
        detail=reason, scan_id=scan_id, extra={"evidence_id": evidence_id},
    )


async def alert_evidence_integrity_failure(db: Session, tenant_id: str, scan_id: str, evidence_id: str, detail: str) -> Alert:
    return await create_alert(
        db, tenant_id, "EVIDENCE_INTEGRITY_FAILURE", "CRITICAL",
        title="Evidence integrity verification failed",
        detail=detail, scan_id=scan_id, extra={"evidence_id": evidence_id},
    )


async def alert_rollback_required(db: Session, tenant_id: str, device_id: str, deployment_id: str, detail: str) -> Alert:
    """Raised the moment a DeploymentRecord lands in DRIFTED (push
    succeeded, post-deploy hash didn't match the approved proposed config)
    -- i.e. the device is running something nobody approved and a human
    needs to decide whether to roll it back (services/rollback_service.py
    never triggers itself, per the same RULE 4/5 human-approval discipline
    deployment_service.py already follows)."""
    return await create_alert(
        db, tenant_id, "ROLLBACK_REQUIRED", "HIGH",
        title="Deployment drifted from approved configuration -- rollback may be required",
        detail=detail, device_id=device_id, extra={"deployment_id": deployment_id},
    )


async def alert_rollback_failed(db: Session, tenant_id: str, device_id: str, rollback_id: str, detail: str) -> Alert:
    """CRITICAL: a rollback attempt did not leave the device in the known-
    good pre-change state (push failed, or push reported success but
    post-rollback verification didn't match). Section 12 of the
    integration brief: never report rollback success without verification,
    and a failed rollback is CRITICAL/manual-intervention, not a retryable
    background condition."""
    return await create_alert(
        db, tenant_id, "ROLLBACK_FAILED", "CRITICAL",
        title="Rollback failed -- device configuration state is unverified, manual intervention required",
        detail=detail, device_id=device_id, extra={"rollback_id": rollback_id},
    )


async def alert_vulnerability_breach(db: Session, tenant_id: str, device_id: str, cve_id: str, score: float, evidence: Dict[str, Any]) -> Alert:
    """Triggered when a new DeviceVulnerabilityMatch is found with high confidence."""
    severity = "CRITICAL" if score >= 9.0 else ("HIGH" if score >= 7.0 else "MEDIUM")
    return await create_alert(
        db, tenant_id, "VULNERABILITY_BREACH", severity,
        title=f"Vulnerability Detected: {cve_id} (Score {score:.1f})",
        detail=f"Device matched vulnerable CPE indicating exposure to {cve_id}.",
        device_id=device_id, extra={"cve_id": cve_id, "risk_score": score, "evidence": evidence},
    )


async def evaluate_compliance_thresholds(db: Session, scan: Scan) -> List[Alert]:
    """Raise COMPLIANCE_SCORE_LOW for every enabled tenant threshold the scan's
    compliance score is below. Best-effort: never raises into the pipeline."""
    created: List[Alert] = []
    try:
        from app.models.alerting import ComplianceAlertThreshold

        score = scan.compliance_score
        if score is None:
            return created
        rows = db.query(ComplianceAlertThreshold).filter(
            ComplianceAlertThreshold.tenant_id == scan.tenant_id,
            ComplianceAlertThreshold.enabled == True,  # noqa: E712
        ).all()
        for t in rows:
            if t.device_id and t.device_id != scan.device_id:
                continue
            if t.framework and (scan.framework or "").upper() not in (t.framework.upper(), "ALL"):
                continue
            if score >= t.threshold:
                continue
            if t.only_on_crossing:
                prev = (
                    db.query(Scan)
                    .filter(Scan.device_id == scan.device_id, Scan.id != scan.id,
                            Scan.compliance_score.isnot(None), Scan.created_at < scan.created_at)
                    .order_by(Scan.created_at.desc()).first()
                )
                if prev is not None and prev.compliance_score < t.threshold:
                    continue
            hostname = getattr(getattr(scan, "device", None), "hostname", None) or scan.device_id
            alert = await create_alert(
                db, scan.tenant_id, "COMPLIANCE_SCORE_LOW", t.severity or "HIGH",
                title=f"Compliance score {score:g}% is below threshold {t.threshold:g}% on {hostname}",
                detail=f"Threshold '{t.name}': scan {scan.id} ({scan.framework}) scored {score:g}%, "
                       f"below the configured minimum of {t.threshold:g}%.",
                scan_id=scan.id, device_id=scan.device_id,
                extra={"threshold_id": t.id, "threshold": t.threshold, "score": score},
                extra_channel_ids=list(t.channel_ids or []),
            )
            t.last_triggered_at = datetime.utcnow()
            t.trigger_count = (t.trigger_count or 0) + 1
            db.commit()
            created.append(alert)
    except Exception:  # noqa: BLE001
        logger.exception("Compliance threshold evaluation failed for scan %s", getattr(scan, "id", None))
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass
    return created
