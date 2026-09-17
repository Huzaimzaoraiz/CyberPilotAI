#!/usr/bin/env python3
"""
Autonomous Cyber-Defense Platform - Reporting & Posture Scoring Engine
Generates publication-grade PDF and structured JSON assessment reports:
- posture_scorer: Calculates organizational risk index and letter grade
- attack_graph_renderer: Serializes attack graph nodes/edges for visual output
- generate_json_report: Complete structured JSON assessment export
- generate_pdf_report: Professional multi-page ReportLab PDF export
- report_exporter: Dual-format wrapper for downstream consumers
"""

import io
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, 
    TableStyle, PageBreak, KeepTogether, HRFlowable
)

logger = logging.getLogger("ReportEngine")


# -----------------------------------------------------------------------------
# 1. posture_scorer
# -----------------------------------------------------------------------------
def posture_scorer(db_snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """
    Computes overall organizational risk score, health index (0-100), and posture grade.
    """
    vulns = db_snapshot.get("vulnerabilities", [])
    assets = db_snapshot.get("assets", [])
    paths = db_snapshot.get("attack_paths", [])
    retests = db_snapshot.get("retests", [])

    total_assets = len(assets)
    total_findings = len(vulns)

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    remediated_count = 0
    active_criticals = 0
    active_highs = 0

    base_penalty = 0.0

    for v in vulns:
        status = str(v.get("status", "")).lower()
        score = float(v.get("criticality_score", 5.0))
        
        # Categorize severity
        if score >= 9.0:
            sev = "CRITICAL"
        elif score >= 7.0:
            sev = "HIGH"
        elif score >= 4.0:
            sev = "MEDIUM"
        else:
            sev = "LOW"
        
        sev_counts[sev] += 1

        if status == "remediated":
            remediated_count += 1
        else:
            # Penalties for active issues
            if sev == "CRITICAL":
                base_penalty += 22.0
                active_criticals += 1
            elif sev == "HIGH":
                base_penalty += 12.0
                active_highs += 1
            elif sev == "MEDIUM":
                base_penalty += 5.0
            else:
                base_penalty += 2.0

    # Path penalty: active attack paths targeting crown jewels deduct points
    path_penalty = min(20.0, len(paths) * 10.0)
    total_deduction = base_penalty + path_penalty

    # Posture score: 100 is completely clean, 0 is fully compromised
    posture_score = max(5, min(100, int(100 - total_deduction)))
    if total_findings == 0:
        posture_score = 98

    # Grade determination
    if posture_score >= 90:
        grade = "A"
    elif posture_score >= 80:
        grade = "B"
    elif posture_score >= 65:
        grade = "C"
    elif posture_score >= 50:
        grade = "D"
    else:
        grade = "F"

    risk_index = round((100 - posture_score) / 10.0, 1)

    return {
        "posture_score": posture_score,
        "posture_grade": grade,
        "risk_index": risk_index,
        "total_assets": total_assets,
        "total_findings": total_findings,
        "active_findings": total_findings - remediated_count,
        "remediated_findings": remediated_count,
        "active_criticals": active_criticals,
        "active_highs": active_highs,
        "severity_counts": sev_counts,
        "attack_paths_identified": len(paths),
        "retests_conducted": len(retests)
    }


# -----------------------------------------------------------------------------
# 2. attack_graph_renderer
# -----------------------------------------------------------------------------
def attack_graph_renderer(graph: Dict[str, Any]) -> Dict[str, Any]:
    """
    Serializes graph nodes and edges for visual rendering and JSON reports.
    """
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    chokepoint = graph.get("chokepoint_vuln_id", "")
    simplified_flow = graph.get("simplified_flow", [])
    
    formatted_nodes = [{"id": n, "label": f"Asset: {n}"} for n in nodes]
    formatted_edges = [{"id": e, "source": nodes[i] if i < len(nodes) else "ingress", "target": nodes[i+1] if i+1 < len(nodes) else "crown_jewel"} for i, e in enumerate(edges)]

    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": formatted_nodes,
        "edges": formatted_edges,
        "break_the_chain_chokepoint": chokepoint,
        "simplified_stages": simplified_flow,
        "cumulative_risk": graph.get("total_risk_score", 0.0),
        "probability": graph.get("path_probability", 1.0)
    }


# -----------------------------------------------------------------------------
# 3. generate_json_report
# -----------------------------------------------------------------------------
def generate_json_report(db_snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """
    Formats full assessment metadata, executive summary, posture score,
    findings table, attack path chokepoints, remediation status, and retest evidence into JSON.
    """
    posture = posture_scorer(db_snapshot)
    session = db_snapshot.get("scan_session", {})
    target = session.get("target") or (db_snapshot.get("assets", [{}])[0].get("asset_identifier", "Target Environment"))

    findings_summary = []
    for f in db_snapshot.get("vulnerabilities", []):
        findings_summary.append({
            "id": f.get("id"),
            "title": f.get("title"),
            "layer": f.get("layer", "Web"),
            "severity_score": f.get("criticality_score"),
            "status": f.get("status"),
            "source": f.get("discovery_source", "tool"),
            "confidence": f.get("confidence_score"),
            "has_leaked_creds": f.get("has_leaked_creds", False),
            "poc_evidence": f.get("proof_of_concept") or "N/A"
        })

    attack_paths_summary = [attack_graph_renderer(p) for p in db_snapshot.get("attack_paths", [])]

    return {
        "assessment_meta": {
            "title": "Autonomous Cyber-Defense Platform Assessment Report",
            "version": "2.0-TechQuest",
            "classification": "CONFIDENTIAL - DEFENSIVE SECURITY AUDIT",
            "target": target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "status": "COMPLETED"
        },
        "executive_summary": {
            "posture_score": posture["posture_score"],
            "posture_grade": posture["posture_grade"],
            "risk_index": posture["risk_index"],
            "overview": (
                f"The autonomous defense platform assessed target '{target}'. "
                f"Discovered {posture['total_findings']} total vulnerability indicators across {posture['total_assets']} assets. "
                f"{posture['remediated_findings']} vulnerabilities were successfully verified as REMEDIATED. "
                f"Current posture grade is evaluated at {posture['posture_grade']} with a risk index of {posture['risk_index']}/10."
            ),
            "critical_concerns": posture["active_criticals"],
            "active_chokepoints": len(attack_paths_summary)
        },
        "posture_metrics": posture,
        "assets_inventory": db_snapshot.get("assets", []),
        "vulnerability_findings": findings_summary,
        "attack_paths": attack_paths_summary,
        "remediations": db_snapshot.get("remediations", []),
        "retest_verifications": db_snapshot.get("retests", [])
    }


# -----------------------------------------------------------------------------
# 4. generate_pdf_report
# -----------------------------------------------------------------------------
def generate_pdf_report(db_snapshot: Dict[str, Any]) -> bytes:
    """
    Uses reportlab to compile a professional, publication-grade PDF report complete
    with executive summary, posture score, vulnerability table, attack chains, and retests.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    posture = posture_scorer(db_snapshot)
    session = db_snapshot.get("scan_session", {})
    target = session.get("target") or (db_snapshot.get("assets", [{}])[0].get("asset_identifier", "Target Organization"))

    styles = getSampleStyleSheet()

    # Custom styling
    primary_color = colors.HexColor("#0F172A")    # Deep Navy
    accent_color = colors.HexColor("#0284C7")     # Ocean Blue
    danger_color = colors.HexColor("#DC2626")     # Crimson
    success_color = colors.HexColor("#16A34A")    # Green
    bg_light = colors.HexColor("#F8FAFC")

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=primary_color,
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=accent_color,
        spaceAfter=15
    )

    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=primary_color,
        spaceBefore=12,
        spaceAfter=8
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
        spaceAfter=6
    )

    badge_style = ParagraphStyle(
        'Badge',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=12,
        alignment=1, # Center
        textColor=colors.white
    )

    story = []

    # Title Banner
    story.append(Paragraph("AUTONOMOUS CYBER-DEFENSE PLATFORM", title_style))
    story.append(Paragraph("Executive & Technical Security Assessment Report", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=accent_color, spaceBefore=2, spaceAfter=12))

    # Meta Info Table
    meta_data = [
        [
            Paragraph("<b>Target Assessment Scope:</b>", body_style),
            Paragraph(f"<b>{target}</b>", body_style),
            Paragraph("<b>Assessment Date:</b>", body_style),
            Paragraph(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), body_style)
        ],
        [
            Paragraph("<b>Platform Version:</b>", body_style),
            Paragraph("2.0 (TechQuest Build)", body_style),
            Paragraph("<b>Classification:</b>", body_style),
            Paragraph("<font color='#DC2626'><b>CONFIDENTIAL AUDIT</b></font>", body_style)
        ]
    ]
    meta_table = Table(meta_data, colWidths=[140, 160, 110, 122])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), bg_light),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # Executive Posture Score Card
    story.append(Paragraph("1. Executive Risk & Security Posture Score", h1_style))
    score_val = posture["posture_score"]
    grade_val = posture["posture_grade"]
    score_bg = success_color if score_val >= 80 else (colors.HexColor("#D97706") if score_val >= 60 else danger_color)

    posture_data = [
        [
            Paragraph(f"<font size=28><b>{grade_val}</b></font><br/><b>POSTURE GRADE</b>", badge_style),
            Paragraph(
                f"<b>Overall Security Posture Score:</b> {score_val} / 100<br/>"
                f"<b>Risk Severity Index:</b> {posture['risk_index']} / 10.0<br/>"
                f"<b>Active Critical Risks:</b> {posture['active_criticals']} | "
                f"<b>Remediated Findings:</b> {posture['remediated_findings']}<br/>"
                f"<i>Non-destructive automated multi-agent security audit executed under explicit scope authorization.</i>",
                body_style
            )
        ]
    ]
    posture_table = Table(posture_data, colWidths=[130, 402])
    posture_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, 0), score_bg),
        ('BACKGROUND', (1, 0), (1, 0), bg_light),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(posture_table)
    story.append(Spacer(1, 14))

    # Findings Table
    story.append(Paragraph("2. Discovered Vulnerabilities & Audit Findings", h1_style))
    vulns = db_snapshot.get("vulnerabilities", [])
    
    findings_rows = [
        [
            Paragraph("<b>Title / Finding</b>", body_style),
            Paragraph("<b>Layer</b>", body_style),
            Paragraph("<b>CVSS</b>", body_style),
            Paragraph("<b>Source</b>", body_style),
            Paragraph("<b>Status</b>", body_style)
        ]
    ]

    if vulns:
        for v in vulns[:15]: # Show up to top 15 in summary table
            status_str = str(v.get("status", "pending")).upper()
            status_color = "#16A34A" if "REMEDIATED" in status_str else ("#DC2626" if "VALIDATED" in status_str else "#64748B")
            findings_rows.append([
                Paragraph(f"<b>{v.get('title', 'Unknown')}</b>", body_style),
                Paragraph(v.get("layer", "Web"), body_style),
                Paragraph(f"{float(v.get('criticality_score', 5.0)):.1f}", body_style),
                Paragraph(v.get("discovery_source", "tool"), body_style),
                Paragraph(f"<font color='{status_color}'><b>{status_str}</b></font>", body_style)
            ])
    else:
        findings_rows.append([
            Paragraph("No active vulnerabilities identified in scope.", body_style),
            Paragraph("-", body_style), Paragraph("-", body_style), Paragraph("-", body_style), Paragraph("-", body_style)
        ])

    findings_table = Table(findings_rows, colWidths=[202, 70, 50, 110, 100])
    findings_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(findings_table)
    story.append(Spacer(1, 14))

    # Attack Path & Chokepoints
    story.append(Paragraph("3. Bayesian Attack Graph & Break-the-Chain Chokepoints", h1_style))
    attack_paths = db_snapshot.get("attack_paths", [])
    if attack_paths:
        for idx, ap in enumerate(attack_paths[:3]):
            chokepoint = ap.get("chokepoint_vuln_id", "None")
            narrative = ap.get("attack_narrative", "Causal exploitation graph identified leading to crown jewel target.")
            path_card = [
                [
                    Paragraph(f"<b>Attack Vector Chain #{idx+1}</b> (Risk Score: {ap.get('total_risk_score', 0):.1f})", body_style)
                ],
                [
                    Paragraph(f"<b>Break-The-Chain Chokepoint:</b> <font color='#DC2626'><b>{chokepoint}</b></font>", body_style)
                ],
                [
                    Paragraph(f"<b>Causal Chain Narrative:</b> {narrative}", body_style)
                ]
            ]
            path_table = Table(path_card, colWidths=[532])
            path_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), bg_light),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(path_table)
            story.append(Spacer(1, 6))
    else:
        story.append(Paragraph("No multi-stage attack paths were observed or reachable.", body_style))

    story.append(Spacer(1, 10))

    # Retest Evidence
    story.append(Paragraph("4. Automated Retest & Remediation Verification", h1_style))
    retests = db_snapshot.get("retests", [])
    if retests:
        retest_rows = [
            [
                Paragraph("<b>Finding ID</b>", body_style),
                Paragraph("<b>Verification Result</b>", body_style),
                Paragraph("<b>Audit Evidence</b>", body_style)
            ]
        ]
        for r in retests[:5]:
            still_vuln = r.get("still_vulnerable", False)
            res_str = "<font color='#DC2626'><b>FAIL - BYPASSED</b></font>" if still_vuln else "<font color='#16A34A'><b>PASS - REMEDIATED</b></font>"
            retest_rows.append([
                Paragraph(r.get("finding_id", "N/A"), body_style),
                Paragraph(res_str, body_style),
                Paragraph(r.get("evidence", "Payload suppressed"), body_style)
            ])
        retest_table = Table(retest_rows, colWidths=[150, 130, 252])
        retest_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(retest_table)
    else:
        story.append(Paragraph("Retesting queue in standby or awaiting remediation application.", body_style))

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#94A3B8"), spaceBefore=10, spaceAfter=8))
    story.append(Paragraph("<i>Autonomous Cyber-Defense Platform • Confidential Automated Audit Report • Non-destructive Verification Only</i>", body_style))

    # Build PDF
    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes


# -----------------------------------------------------------------------------
# 5. report_exporter
# -----------------------------------------------------------------------------
def report_exporter(db_snapshot: Dict[str, Any], format: str = "pdf") -> bytes:
    """
    Unified report export helper returning raw bytes for either 'pdf' or 'json'.
    """
    fmt = format.lower().strip()
    if fmt == "json":
        data = generate_json_report(db_snapshot)
        return json.dumps(data, indent=2).encode("utf-8")
    return generate_pdf_report(db_snapshot)
