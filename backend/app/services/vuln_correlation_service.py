"""Vulnerability correlation service — for each device, builds a CPE 2.3
string from vendor/model/version, matches it against every Vulnerability's
`affected_cpe_ranges`, and upserts DeviceVulnerabilityMatch rows.

Risk scoring: risk_priority_score = cvss_score * kev_boost * exposure_factor
  - kev_boost = 1.5 if the CVE is CISA-KEV-flagged, else 1.0
  - exposure_factor = 1.25 if a ConfigConcept tied to the affected
    service/protocol shows that concept's VendorConfigPattern actually
    matches this device's most recent scanned config, else 1.0

Cross-links a DeviceVulnerabilityMatch to a UnifiedControl when the
control's ConfigConcepts overlap with the concepts implicated by the CVE
match (e.g. a CVE in an SNMPv1 daemon links to the control that mandates
disabling SNMPv1 / requiring SNMPv3).

Historical DeviceVulnerabilityMatch rows are never deleted; re-running
correlation updates risk_priority_score/evidence on existing open rows and
only status transitions happen through the reviewer-driven PATCH endpoint,
matching this codebase's RULE 15 (status changes ARE the audit trail).
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.db import (ConfigConcept, Device, DeviceVulnerabilityMatch,
                            Scan, UnifiedControl, VendorConfigPattern,
                            Vulnerability)

logger = logging.getLogger("vuln_correlation_service")

KEV_BOOST = 1.5
EXPOSURE_BOOST = 1.25


def _device_to_cpe(device: Device) -> Optional[str]:
    """Build a best-effort CPE 2.3 string from vendor/model/version.
    Returns None when there isn't enough identifying data to build a
    meaningful CPE (never guesses a vendor -- an unmatched device is
    correctly reported as having zero matches rather than false positives).
    """
    if not device.vendor:
        return None
    vendor = re.sub(r"[^a-z0-9]+", "_", device.vendor.strip().lower())
    product = re.sub(r"[^a-z0-9]+", "_", (device.model or device.os or "*").strip().lower()) or "*"
    version = re.sub(r"[^a-z0-9.]+", "_", (device.version or "*").strip().lower()) or "*"
    return f"cpe:2.3:o:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def _cpe_component(cpe: str, index: int) -> str:
    parts = cpe.split(":")
    return parts[index] if len(parts) > index else "*"


def _cpe_matches(device_cpe: str, candidate: Any) -> bool:
    """Loose match: vendor must match exactly; product matches if either
    side is a wildcard or they're equal/substring; version matches if
    either side is a wildcard, equal, or falls within a NVD version range
    dict. This intentionally favors false positives over false negatives
    for a security correlation feature -- a reviewer confirms/dismisses
    via the status workflow rather than the matcher silently dropping it.
    """
    if isinstance(candidate, str):
        criteria = candidate
        version_start = version_end_excl = version_end_incl = None
    elif isinstance(candidate, dict):
        criteria = candidate.get("criteria", "")
        version_start = candidate.get("versionStartIncluding")
        version_end_excl = candidate.get("versionEndExcluding")
        version_end_incl = candidate.get("versionEndIncluding")
    else:
        return False

    if not criteria:
        return False

    dev_vendor = _cpe_component(device_cpe, 3)
    dev_product = _cpe_component(device_cpe, 4)
    dev_version = _cpe_component(device_cpe, 5)

    cand_vendor = _cpe_component(criteria, 3)
    cand_product = _cpe_component(criteria, 4)
    cand_version = _cpe_component(criteria, 5)

    if cand_vendor not in ("*", dev_vendor):
        return False
    if cand_product not in ("*", dev_product) and cand_product not in dev_product and dev_product not in cand_product:
        return False

    if version_start or version_end_excl or version_end_incl:
        if dev_version in ("*", ""):
            return True  # unknown device version -- can't rule it out, flag for review
        try:
            dv = tuple(int(p) for p in re.findall(r"\d+", dev_version)[:4])
            if version_start:
                vs = tuple(int(p) for p in re.findall(r"\d+", version_start)[:4])
                if dv < vs:
                    return False
            if version_end_excl:
                ve = tuple(int(p) for p in re.findall(r"\d+", version_end_excl)[:4])
                if dv >= ve:
                    return False
            if version_end_incl:
                ve = tuple(int(p) for p in re.findall(r"\d+", version_end_incl)[:4])
                if dv > ve:
                    return False
            return True
        except ValueError:
            return True  # unparsable version -- flag for human review rather than silently skip
    if cand_version in ("*", dev_version):
        return True
    return False


def _device_config_lines(db: Session, device: Device) -> List[str]:
    scan = (
        db.query(Scan)
        .filter(Scan.device_id == device.id, Scan.baseline_json.isnot(None))
        .order_by(Scan.created_at.desc())
        .first()
    )
    if not scan or not scan.baseline_json:
        return []
    extra = (scan.baseline_json or {}).get("extra_parameters") or {}
    return extra.get("_input_lines") or []


def _exposure_factor(db: Session, tenant_id: str, config_lines: List[str], keyword_hint: Optional[str]) -> float:
    """1.25 if any VendorConfigPattern for any ConfigConcept whose name
    matches the CVE's keyword hint (e.g. 'snmp', 'ssh', 'telnet') actually
    matches a line in the device's most recent config; else 1.0 (no
    corroborating evidence the vulnerable service is even enabled).
    """
    if not config_lines or not keyword_hint:
        return 1.0
    concepts = (
        db.query(ConfigConcept)
        .join(UnifiedControl, ConfigConcept.control_id == UnifiedControl.id)
        .filter(UnifiedControl.tenant_id == tenant_id, ConfigConcept.concept_name.ilike(f"%{keyword_hint}%"))
        .all()
    )
    if not concepts:
        return 1.0
    concept_ids = [c.id for c in concepts]
    patterns = db.query(VendorConfigPattern).filter(VendorConfigPattern.concept_id.in_(concept_ids)).all()
    for pattern in patterns:
        try:
            regex = re.compile(pattern.pattern, re.IGNORECASE)
        except re.error:
            continue
        if any(regex.search(line) for line in config_lines):
            return EXPOSURE_BOOST
    return 1.0


def _keyword_hint(vuln: Vulnerability) -> Optional[str]:
    text = (vuln.description or "").lower()
    for kw in ("snmp", "telnet", "ssh", "ftp", "http", "ntp", "syslog", "tftp", "smtp"):
        if kw in text:
            return kw
    return None


def _linked_control_id(db: Session, tenant_id: str, keyword_hint: Optional[str]) -> Optional[str]:
    if not keyword_hint:
        return None
    concept = (
        db.query(ConfigConcept)
        .join(UnifiedControl, ConfigConcept.control_id == UnifiedControl.id)
        .filter(
            UnifiedControl.tenant_id == tenant_id,
            UnifiedControl.status == "approved",
            ConfigConcept.concept_name.ilike(f"%{keyword_hint}%"),
        )
        .first()
    )
    return concept.control_id if concept else None


def correlate_device(db: Session, tenant_id: str, device: Device) -> Dict[str, Any]:
    device_cpe = _device_to_cpe(device)
    if not device_cpe:
        return {"device_id": device.id, "status": "skipped", "reason": "insufficient vendor/model/version data"}

    config_lines = _device_config_lines(db, device)

    vulns = db.query(Vulnerability).filter(Vulnerability.affected_cpe_ranges.isnot(None)).all()
    matched = 0
    for vuln in vulns:
        ranges = vuln.affected_cpe_ranges or []
        if not any(_cpe_matches(device_cpe, c) for c in ranges):
            continue

        keyword_hint = _keyword_hint(vuln)
        exposure_factor = _exposure_factor(db, tenant_id, config_lines, keyword_hint)
        kev_boost = KEV_BOOST if vuln.kev_flag else 1.0
        score = (vuln.cvss_score or 0.0) * kev_boost * exposure_factor
        linked_control_id = _linked_control_id(db, tenant_id, keyword_hint)

        existing = (
            db.query(DeviceVulnerabilityMatch)
            .filter(
                DeviceVulnerabilityMatch.device_id == device.id,
                DeviceVulnerabilityMatch.cve_id == vuln.cve_id,
            )
            .first()
        )
        evidence = {
            "device_cpe": device_cpe,
            "keyword_hint": keyword_hint,
            "exposure_factor": exposure_factor,
            "kev_boost": kev_boost,
        }
        if existing:
            existing.risk_priority_score = score
            existing.evidence = evidence
            if not existing.linked_control_id:
                existing.linked_control_id = linked_control_id
            # status is never overwritten here -- a reviewer's
            # mitigated/accepted_risk/false_positive decision persists
            # across re-correlation runs (RULE 15).
        else:
            db.add(DeviceVulnerabilityMatch(
                tenant_id=tenant_id,
                device_id=device.id,
                cve_id=vuln.cve_id,
                matched_via="cpe",
                risk_priority_score=score,
                status="open",
                evidence=evidence,
                linked_control_id=linked_control_id,
            ))
        matched += 1

    db.commit()
    return {"device_id": device.id, "status": "ok", "matched": matched}


def correlate_all_devices(db: Session) -> Dict[str, Any]:
    """Correlate every enabled device across every tenant. Meant to be
    called from vuln_sync_worker after a sync; one device's failure never
    blocks the rest.
    """
    results = []
    devices = db.query(Device).filter(Device.enabled.is_(True)).all()
    for device in devices:
        try:
            results.append(correlate_device(db, device.tenant_id, device))
        except Exception:  # noqa: BLE001 - one device must never sink the batch
            logger.exception("Correlation failed for device %s", device.id)
            db.rollback()
            results.append({"device_id": device.id, "status": "error"})
    return {"device_count": len(devices), "results": results}