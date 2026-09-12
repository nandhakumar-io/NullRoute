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


def build_compliance_matrix_section(findings: List[dict], framework_matrix: Dict[str, Dict[str, str]] | None = None) -> List[Dict[str, Any]]:
    """Per-finding table with columns NIST-800-53 / CIS / ISO-27001 /
    DISA-STIG, resolved from `framework_matrix` (see
    control_service.get_framework_matrix). A finding's `control_id` is
    looked up directly against the matrix; findings with no matching
    UnifiedControl (i.e. not yet mapped through the Unified Control
    Library) simply show as "-" for every framework column rather than
    being dropped, so the matrix always covers every finding in the scan.
    """
    framework_matrix = framework_matrix or {}
    frameworks = ("NIST-800-53", "CIS", "ISO-27001", "DISA-STIG")
    rows = []
    for f in findings:
        control_id = f.get("control_id")
        mapping = framework_matrix.get(control_id, {})
        row = {
            "control_id": control_id,
            "title": f.get("title"),
            "result": f.get("result"),
            "severity": f.get("severity"),
        }
        for fw in frameworks:
            row[fw] = mapping.get(fw, "-")
        rows.append(row)
    return rows


def build_vulnerability_panel_section(vuln_matches: List[dict] | None = None) -> List[Dict[str, Any]]:
    """Table of CVE, CVSS, KEV flag, status, linked control (if any) for a
    device's DeviceVulnerabilityMatch rows. Accepts plain dicts (as
    returned by routers/vulnerabilities.py's _match_dict serializer) so
    this module never needs a direct SQLAlchemy import.
    """
    rows = []
    for m in (vuln_matches or []):
        vuln = m.get("vulnerability") or {}
        rows.append({
            "cve_id": m.get("cve_id"),
            "cvss_score": vuln.get("cvss_score"),
            "severity": vuln.get("severity"),
            "kev_flag": vuln.get("kev_flag"),
            "status": m.get("status"),
            "risk_priority_score": m.get("risk_priority_score"),
            "linked_control_id": m.get("linked_control_id"),
        })
    return rows


def build_json_report(
    scan: dict, device: dict, findings: List[dict], evidence: Dict[str, Any] | None = None,
    framework_matrix: Dict[str, Dict[str, str]] | None = None, vuln_matches: List[dict] | None = None,
) -> bytes:
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
        "compliance_matrix": build_compliance_matrix_section(findings, framework_matrix),
        "vulnerability_matches": build_vulnerability_panel_section(vuln_matches),
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


def build_pdf_report(
    scan: dict, device: dict, findings: List[dict], evidence: Dict[str, Any] | None = None,
    framework_matrix: Dict[str, Dict[str, str]] | None = None, vuln_matches: List[dict] | None = None,
) -> bytes:
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

    from xml.sax.saxutils import escape

    story.append(Paragraph("Findings", h2))
    header = [
        Paragraph("<b>Control</b>", normal), 
        Paragraph("<b>Severity</b>", normal), 
        Paragraph("<b>Result</b>", normal), 
        Paragraph("<b>Expected</b>", normal), 
        Paragraph("<b>Actual</b>", normal)
    ]
    rows = [header]
    for f in findings:
        rows.append([
            Paragraph(escape(str(f.get("control_id", ""))), normal),
            Paragraph(escape(str(f.get("severity", ""))), normal),
            Paragraph(f"<b>{escape(str(f.get('result', '')))}</b>", normal),
            Paragraph(escape(str(f.get("expected_value", ""))), normal),
            Paragraph(escape(str(f.get("actual_value", ""))), normal)
        ])
    tbl = Table(rows, colWidths=[90, 55, 55, 120, 120], repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
    ]
    for i, f in enumerate(findings, start=1):
        if f.get("result") == "FAIL":
            style_cmds.append(("TEXTCOLOR", (2, i), (2, i), SEVERITY_COLORS.get(f.get("severity", ""), colors.red)))
        elif f.get("result") == "PASS":
            style_cmds.append(("TEXTCOLOR", (2, i), (2, i), colors.HexColor("#15803d")))
    tbl.setStyle(TableStyle(style_cmds))
    story.append(tbl)
    story.append(Spacer(1, 14))

    # --- Compliance Matrix (multi-framework traceability) ----------------
    matrix_rows = build_compliance_matrix_section(findings, framework_matrix)
    if matrix_rows:
        story.append(Paragraph("Compliance Matrix", h2))
        matrix_header = [Paragraph(f"<b>{h}</b>", normal) for h in
                          ("Control", "NIST-800-53", "CIS", "ISO-27001", "DISA-STIG")]
        matrix_table_rows = [matrix_header]
        for row in matrix_rows:
            matrix_table_rows.append([
                Paragraph(escape(str(row.get("control_id", ""))), normal),
                Paragraph(escape(str(row.get("NIST-800-53", "-"))), normal),
                Paragraph(escape(str(row.get("CIS", "-"))), normal),
                Paragraph(escape(str(row.get("ISO-27001", "-"))), normal),
                Paragraph(escape(str(row.get("DISA-STIG", "-"))), normal),
            ])
        matrix_tbl = Table(matrix_table_rows, colWidths=[100, 95, 95, 95, 95], repeatRows=1)
        matrix_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        story.append(matrix_tbl)
        story.append(Spacer(1, 14))

    # --- Vulnerability Panel (CVE/KEV correlation) ------------------------
    vuln_rows = build_vulnerability_panel_section(vuln_matches)
    if vuln_rows:
        story.append(Paragraph("Vulnerability Panel", h2))
        vuln_header = [Paragraph(f"<b>{h}</b>", normal) for h in
                        ("CVE", "CVSS", "KEV", "Status", "Linked Control")]
        vuln_table_rows = [vuln_header]
        for row in vuln_rows:
            vuln_table_rows.append([
                Paragraph(escape(str(row.get("cve_id", ""))), normal),
                Paragraph(escape(str(row.get("cvss_score", "-"))), normal),
                Paragraph("YES" if row.get("kev_flag") else "no", normal),
                Paragraph(escape(str(row.get("status", ""))), normal),
                Paragraph(escape(str(row.get("linked_control_id") or "-")), normal),
            ])
        vuln_tbl = Table(vuln_table_rows, colWidths=[110, 60, 50, 100, 160], repeatRows=1)
        vuln_style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]
        for i, row in enumerate(vuln_rows, start=1):
            if row.get("kev_flag"):
                vuln_style_cmds.append(("TEXTCOLOR", (2, i), (2, i), colors.HexColor("#b91c1c")))
        vuln_tbl.setStyle(TableStyle(vuln_style_cmds))
        story.append(vuln_tbl)
        story.append(Spacer(1, 14))

    story.append(Paragraph("Evidence & Remediation Detail", h2))
    for f in findings:
        if f.get("result") != "FAIL":
            continue
        story.append(Paragraph(f"<b>{escape(str(f.get('control_id', '')))} — {escape(str(f.get('title', '')))}</b> ({escape(str(f.get('severity', '')))})", normal))
        
        safe_ev = escape(str(f.get('evidence_line', '')))
        safe_rem = escape(str(f.get('remediation', '')))
        story.append(Paragraph(f"Evidence: <font face='Courier'>{safe_ev}</font>", normal))
        story.append(Paragraph(f"Suggested remediation (administrator approval required): {safe_rem}", normal))
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


def build_all_reports(
    scan: dict, device: dict, findings: List[dict], evidence: Dict[str, Any] | None = None,
    framework_matrix: Dict[str, Dict[str, str]] | None = None, vuln_matches: List[dict] | None = None,
) -> Dict[str, bytes]:
    return {
        "json": build_json_report(scan, device, findings, evidence, framework_matrix, vuln_matches),
        "csv": build_csv_report(findings),
        "pdf": build_pdf_report(scan, device, findings, evidence, framework_matrix, vuln_matches),
    }