"""PDF / JSON / CSV compliance report generation."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer, Table,
                                 TableStyle)

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#7f1d1d"),
    "HIGH": colors.HexColor("#b91c1c"),
    "MEDIUM": colors.HexColor("#b45309"),
    "LOW": colors.HexColor("#15803d"),
}


def build_json_report(scan: dict, device: dict, findings: List[dict], evidence: Dict[str, Any] | None = None) -> bytes:
    payload = {
        "report_generated_at": datetime.utcnow().isoformat(),
        "device": device,
        "scan": {k: v for k, v in scan.items() if k not in ("parsed_json", "baseline_json")},
        "compliance_score": scan.get("compliance_score"),
        "findings": findings,
        # Section 31: OPA/Batfish/risk/evidence/Fabric summary, on top of
        # what's already embedded in `scan` (opa_decision, batfish_status,
        # risk_score/level, evidence_id).
        "opa_findings": [f for f in findings if str(f.get("control_id", "")).split("-")[0] in
                         ("CIS", "NIST", "STIG", "ISO27001")],
        "batfish_findings": [f for f in findings if "SEGMENTATION" in str(f.get("control_id", ""))
                              or f.get("parameter", "").find("->") != -1],
        "risk": {"risk_score": scan.get("risk_score"), "risk_level": scan.get("risk_level")},
        "evidence": evidence or {},
    }
    return json.dumps(payload, indent=2, default=str).encode("utf-8")


def build_csv_report(findings: List[dict]) -> bytes:
    buf = io.StringIO()
    fieldnames = ["framework", "control_id", "title", "severity", "parameter",
                  "expected_value", "actual_value", "result", "evidence_line", "remediation"]
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for f in findings:
        writer.writerow({k: f.get(k, "") for k in fieldnames})
    return buf.getvalue().encode("utf-8")


def build_pdf_report(scan: dict, device: dict, findings: List[dict], evidence: Dict[str, Any] | None = None) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=18 * mm, bottomMargin=18 * mm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleX", parent=styles["Title"], textColor=colors.HexColor("#0f172a"))
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], textColor=colors.HexColor("#1e3a8a"))
    normal = styles["Normal"]

    story = []
    story.append(Paragraph("Network Security Compliance Report", title_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", normal))
    story.append(Spacer(1, 12))

    # --- Executive summary (section 31) ---------------------------------
    story.append(Paragraph("Executive Summary", h2))
    fail_count = sum(1 for f in findings if f.get("result") == "FAIL")
    exec_rows = [
        ["Framework", scan.get("framework", "ALL")],
        ["Overall Compliance Score", f"{scan.get('compliance_score', 0)}%"],
        ["Findings (FAIL)", str(fail_count)],
        ["OPA Decision", scan.get("opa_decision") or "-"],
        ["Batfish Status", scan.get("batfish_status") or "-"],
        ["Risk Score / Level", f"{scan.get('risk_score', '-')} / {scan.get('risk_level', '-')}"],
        ["Final Decision", scan.get("final_decision") or "-"],
    ]
    et = Table(exec_rows, colWidths=[160, 290])
    et.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story.append(et)
    story.append(Spacer(1, 14))

    story.append(Paragraph("Device Identification", h2))
    dev_rows = [
        ["Hostname", device.get("hostname", "-")],
        ["Vendor", device.get("vendor", "-")],
        ["Model", device.get("model", "-")],
        ["OS / Version", f"{device.get('os', '-')} {device.get('version', '')}"],
        ["Serial Number", device.get("serial_number", "-")],
    ]
    t = Table(dev_rows, colWidths=[130, 320])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story.append(t)
    story.append(Spacer(1, 14))

    score = scan.get("compliance_score", 0)
    story.append(Paragraph(f"Overall Compliance Score: <b>{score}%</b>", h2))
    story.append(Paragraph(f"Framework: {scan.get('framework', 'ALL')} &nbsp;|&nbsp; Scan ID: {scan.get('id', '-')}", normal))
    story.append(Spacer(1, 14))

    story.append(Paragraph("Findings", h2))
    header = ["Control", "Severity", "Result", "Expected", "Actual"]
    rows = [header]
    for f in findings:
        rows.append([f["control_id"], f["severity"], f["result"], f["expected_value"], f["actual_value"]])
    tbl = Table(rows, colWidths=[90, 60, 60, 90, 90], repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]
    for i, f in enumerate(findings, start=1):
        if f["result"] == "FAIL":
            style_cmds.append(("TEXTCOLOR", (2, i), (2, i), SEVERITY_COLORS.get(f["severity"], colors.red)))
        elif f["result"] == "PASS":
            style_cmds.append(("TEXTCOLOR", (2, i), (2, i), colors.HexColor("#15803d")))
    tbl.setStyle(TableStyle(style_cmds))
    story.append(tbl)
    story.append(Spacer(1, 14))

    story.append(Paragraph("Evidence & Remediation Detail", h2))
    for f in findings:
        if f["result"] != "FAIL":
            continue
        story.append(Paragraph(f"<b>{f['control_id']} — {f['title']}</b> ({f['severity']})", normal))
        story.append(Paragraph(f"Evidence: <font face='Courier'>{f['evidence_line']}</font>", normal))
        story.append(Paragraph(f"Suggested remediation (administrator approval required): {f['remediation']}", normal))
        story.append(Spacer(1, 8))

    # --- Evidence & Fabric anchoring (sections 11, 17, 19, 31) -----------
    story.append(Paragraph("Evidence & Blockchain Anchoring", h2))
    ev = evidence or {}
    evid_rows = [
        ["Evidence ID", scan.get("evidence_id") or "-"],
        ["Evidence SHA-256", ev.get("evidence_hash") or "-"],
        ["Fabric Status", ev.get("fabric_status") or "NOT_ANCHORED"],
        ["Fabric Transaction ID", ev.get("fabric_tx_id") or "-"],
        ["Fabric Block Number", str(ev.get("fabric_block_number") or "-")],
    ]
    evt = Table(evid_rows, colWidths=[160, 290])
    evt.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]))
    story.append(evt)
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Evidence integrity can be independently re-verified at any time via "
        "POST /api/evidence/{evidence_id}/verify (recomputes the SHA-256 over "
        "the stored evidence package and, when Fabric is enabled, compares it "
        "against the on-chain anchor).", normal,
    ))

    doc.build(story)
    return buf.getvalue()


def build_all_reports(scan: dict, device: dict, findings: List[dict], evidence: Dict[str, Any] | None = None) -> Dict[str, bytes]:
    return {
        "json": build_json_report(scan, device, findings, evidence),
        "csv": build_csv_report(findings),
        "pdf": build_pdf_report(scan, device, findings, evidence),
    }
