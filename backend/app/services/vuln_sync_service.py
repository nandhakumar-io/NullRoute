"""Vulnerability sync service -- pulls CVE data from NVD, CISA KEV, and
vendor PSIRT feeds and upserts it into the `vulnerabilities` table.

Called from vuln_sync_worker.py on its 24h poll loop, and from
POST /api/vulns/sync for an admin-triggered manual run. Every feed is
independently soft-failing: a down/rate-limited/misconfigured feed never
blocks the others and never crashes the caller (RULE: one failure never
kills the loop, matching every other worker/service pattern in this repo).
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy.orm import Session

from app.models.db import Vulnerability

logger = logging.getLogger("vuln_sync_service")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")
# Without a key: 5 req/30s. With a key: 50 req/30s (NVD's documented tiers).
NVD_RATE_WINDOW_SECONDS = 30.0
NVD_RATE_LIMIT = 50 if NVD_API_KEY else 5
NVD_PAGE_SIZE = int(os.getenv("NVD_PAGE_SIZE", "200"))

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

CISCO_OPENVULN_TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
CISCO_OPENVULN_API_URL = "https://apix.cisco.com/security/advisories/v2/all/severity/critical"
CISCO_CLIENT_ID = os.getenv("CISCO_CLIENT_ID")
CISCO_CLIENT_SECRET = os.getenv("CISCO_CLIENT_SECRET")

JUNIPER_JSA_FEED_URL = os.getenv("JUNIPER_JSA_FEED_URL")
PALOALTO_ADVISORY_FEED_URL = os.getenv("PALOALTO_ADVISORY_FEED_URL")


def _severity_from_cvss(score: Optional[float]) -> str:
    if score is None:
        return "NONE"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def _upsert_vulnerability(db: Session, cve_id: str, fields: Dict[str, Any]) -> None:
    existing = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
    if existing:
        for k, v in fields.items():
            if v is not None:
                setattr(existing, k, v)
        existing.updated_at = datetime.utcnow()
    else:
        db.add(Vulnerability(cve_id=cve_id, **fields))


# ---------------------------------------------------------------------------
# NVD API 2.0
# ---------------------------------------------------------------------------

async def sync_nvd(db: Session, max_pages: Optional[int] = None) -> Dict[str, Any]:
    """Paginated pull of NVD CVE data, upserted by cve_id. Rate-limited to
    NVD_RATE_LIMIT requests per NVD_RATE_WINDOW_SECONDS per NVD's published
    tiers. Soft-fails: returns a result dict with status='error' rather
    than raising, so the worker's other feeds still run.
    """
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    total_upserted = 0
    start_index = 0
    page = 0
    try:
        async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
            while True:
                if max_pages is not None and page >= max_pages:
                    break
                resp = await client.get(
                    NVD_API_URL,
                    params={"resultsPerPage": NVD_PAGE_SIZE, "startIndex": start_index},
                )
                resp.raise_for_status()
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    break

                for item in vulns:
                    cve = item.get("cve", {})
                    cve_id = cve.get("id")
                    if not cve_id:
                        continue
                    metrics = cve.get("metrics", {})
                    cvss_score = None
                    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        entries = metrics.get(key)
                        if entries:
                            cvss_score = entries[0].get("cvssData", {}).get("baseScore")
                            break
                    descriptions = cve.get("descriptions", [])
                    description = next((d["value"] for d in descriptions if d.get("lang") == "en"), None)
                    configurations = cve.get("configurations", [])
                    cpe_ranges: List[Any] = []
                    for config in configurations:
                        for node in config.get("nodes", []):
                            for match in node.get("cpeMatch", []):
                                if match.get("vulnerable"):
                                    cpe_ranges.append({
                                        "criteria": match.get("criteria"),
                                        "versionStartIncluding": match.get("versionStartIncluding"),
                                        "versionEndExcluding": match.get("versionEndExcluding"),
                                        "versionEndIncluding": match.get("versionEndIncluding"),
                                    })

                    _upsert_vulnerability(db, cve_id, {
                        "cvss_score": cvss_score,
                        "severity": _severity_from_cvss(cvss_score),
                        "description": description,
                        "affected_cpe_ranges": cpe_ranges or None,
                        "published_date": _parse_dt(cve.get("published")),
                        "last_modified_date": _parse_dt(cve.get("lastModified")),
                        "source": "nvd",
                    })
                    total_upserted += 1

                db.commit()

                total_results = data.get("totalResults", 0)
                start_index += len(vulns)
                page += 1
                if start_index >= total_results:
                    break
                await asyncio.sleep(NVD_RATE_WINDOW_SECONDS / NVD_RATE_LIMIT)

        return {"status": "ok", "source": "nvd", "upserted": total_upserted, "pages": page}
    except httpx.HTTPError as exc:
        logger.error("NVD sync failed: %s", exc)
        db.rollback()
        return {"status": "error", "source": "nvd", "error": str(exc), "upserted": total_upserted}


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------

async def sync_cisa_kev(db: Session) -> Dict[str, Any]:
    """Pull the CISA Known Exploited Vulnerabilities catalog and flag every
    listed CVE. KEV entries reference CVEs NVD should already have; if NVD
    hasn't synced that CVE yet, a minimal Vulnerability row is created so
    the kev_flag is never lost even if it briefly lacks CVSS/description.
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(CISA_KEV_URL)
            resp.raise_for_status()
            data = resp.json()

        vulns = data.get("vulnerabilities", [])
        flagged = 0
        for item in vulns:
            cve_id = item.get("cveID")
            if not cve_id:
                continue
            existing = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()
            if existing:
                existing.kev_flag = True
                existing.remediation_advice = item.get("requiredAction") or existing.remediation_advice
                existing.updated_at = datetime.utcnow()
            else:
                db.add(Vulnerability(
                    cve_id=cve_id,
                    description=item.get("shortDescription"),
                    kev_flag=True,
                    remediation_advice=item.get("requiredAction"),
                    source="cisa_kev",
                    published_date=_parse_dt(item.get("dateAdded")),
                ))
            flagged += 1
        db.commit()
        return {"status": "ok", "source": "cisa_kev", "flagged": flagged}
    except httpx.HTTPError as exc:
        logger.error("CISA KEV sync failed: %s", exc)
        db.rollback()
        return {"status": "error", "source": "cisa_kev", "error": str(exc)}


# ---------------------------------------------------------------------------
# Vendor PSIRT feeds (soft-fail if credentials/URLs not configured)
# ---------------------------------------------------------------------------

async def sync_cisco_psirt(db: Session) -> Dict[str, Any]:
    if not (CISCO_CLIENT_ID and CISCO_CLIENT_SECRET):
        return {"status": "skipped", "source": "cisco_psirt", "reason": "CISCO_CLIENT_ID/CISCO_CLIENT_SECRET not set"}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            token_resp = await client.post(
                CISCO_OPENVULN_TOKEN_URL,
                data={"grant_type": "client_credentials"},
                auth=(CISCO_CLIENT_ID, CISCO_CLIENT_SECRET),
            )
            token_resp.raise_for_status()
            access_token = token_resp.json().get("access_token")

            adv_resp = await client.get(
                CISCO_OPENVULN_API_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            adv_resp.raise_for_status()
            advisories = adv_resp.json().get("advisories", [])

        upserted = 0
        for adv in advisories:
            for cve_id in adv.get("cves", []) or []:
                _upsert_vulnerability(db, cve_id, {
                    "description": adv.get("summary"),
                    "severity": (adv.get("sir") or "NONE").upper(),
                    "source": "cisco_psirt",
                    "remediation_advice": adv.get("firstPublished") and adv.get("publicationUrl"),
                })
                upserted += 1
        db.commit()
        return {"status": "ok", "source": "cisco_psirt", "upserted": upserted}
    except httpx.HTTPError as exc:
        logger.warning("Cisco openVuln sync failed (soft-fail): %s", exc)
        db.rollback()
        return {"status": "error", "source": "cisco_psirt", "error": str(exc)}


async def sync_generic_vendor_feed(db: Session, source: str, feed_url: Optional[str]) -> Dict[str, Any]:
    """Shared soft-fail puller for vendor feeds that publish a simple JSON
    array of {cve_id, description, severity} (Juniper JSA / Palo Alto).
    Configurable via env var; skipped entirely if not set, matching the
    plan's 'configurable via env vars, soft-fail if unavailable' spec.
    """
    if not feed_url:
        return {"status": "skipped", "source": source, "reason": "feed URL env var not set"}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(feed_url)
            resp.raise_for_status()
            items = resp.json()
        if isinstance(items, dict):
            items = items.get("advisories", items.get("items", []))

        upserted = 0
        for item in items:
            cve_id = item.get("cve_id") or item.get("cveID") or item.get("id")
            if not cve_id:
                continue
            _upsert_vulnerability(db, cve_id, {
                "description": item.get("description") or item.get("summary"),
                "severity": (item.get("severity") or "NONE").upper(),
                "source": source,
            })
            upserted += 1
        db.commit()
        return {"status": "ok", "source": source, "upserted": upserted}
    except httpx.HTTPError as exc:
        logger.warning("%s feed sync failed (soft-fail): %s", source, exc)
        db.rollback()
        return {"status": "error", "source": source, "error": str(exc)}


async def sync_juniper_jsa(db: Session) -> Dict[str, Any]:
    return await sync_generic_vendor_feed(db, "juniper_jsa", JUNIPER_JSA_FEED_URL)


async def sync_paloalto(db: Session) -> Dict[str, Any]:
    return await sync_generic_vendor_feed(db, "paloalto", PALOALTO_ADVISORY_FEED_URL)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

async def sync_all(db: Session, nvd_max_pages: Optional[int] = None) -> Dict[str, Any]:
    """Run every feed in sequence (NVD's rate limit makes concurrent NVD
    pagination counterproductive, and sequential keeps every feed's
    failure isolated and easy to read in the worker log / API response).
    """
    results = []
    results.append(await sync_nvd(db, max_pages=nvd_max_pages))
    results.append(await sync_cisa_kev(db))
    results.append(await sync_cisco_psirt(db))
    results.append(await sync_juniper_jsa(db))
    results.append(await sync_paloalto(db))
    return {"synced_at": datetime.utcnow().isoformat(), "feeds": results}