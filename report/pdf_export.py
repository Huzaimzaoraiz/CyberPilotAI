import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import io
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, 
    TableStyle, PageBreak, KeepTogether, HRFlowable
)

logger = logging.getLogger('ReportEngine')

from .scorer import posture_scorer

def generate_pdf_report(db_snapshot: Dict[str, Any]) -> bytes:
    """
    Compiles a professional, publication-grade PDF report with ReportLab:
    - Executive Summary & Posture Grade (accounting for validated CVEs & defensive measures)
    - Technical Findings Table
    - Attack Graph & Chaining Section showing exploitation paths & break-the-chain chokepoint
    - Retest Verification Records
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    posture = posture_scorer(db_snapshot)
    session = db_snapshot.get("scan_session", {})
    target = session.get("target") or (db_snapshot.get("assets", [{}])[0].get("asset_identifier", "Target Organization"))

    styles = getSampleStyleSheet()

    # Custom color palette
    primary_color = colors.HexColor("#0F172A")    # Deep Navy
    accent_color = colors.HexColor("#0284C7")     # Ocean Blue
    danger_color = colors.HexColor("#DC2626")     # Crimson
    warning_color = colors.HexColor("#D97706")    # Amber
    success_color = colors.HexColor("#16A34A")    # Emerald Green
    bg_light = colors.HexColor("#F8FAFC")

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=primary_color,
        spaceAfter=4
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=accent_color,
        spaceAfter=12
    )

    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=primary_color,
        spaceBefore=10,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#334155"),
        spaceAfter=4
    )

    body_bold = ParagraphStyle(
        'Body_Bold',
        parent=body_style,
        fontName='Helvetica-Bold'
    )

    badge_style = ParagraphStyle(
        'Badge',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=12,
        alignment=1,
        textColor=colors.white
    )

    story = []

    # Title Banner
    story.append(Paragraph("AUTONOMOUS CYBER-DEFENSE PLATFORM", title_style))
    story.append(Paragraph("Executive & Technical Security Assessment Report", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=accent_color, spaceBefore=2, spaceAfter=10))

    # Meta Info Table
    meta_data = [
        [
            Paragraph("<b>Target Scope:</b>", body_style),
            Paragraph(f"<b>{target}</b>", body_style),
            Paragraph("<b>Assessment Date:</b>", body_style),
            Paragraph(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), body_style)
        ],
        [
            Paragraph("<b>Platform Version:</b>", body_style),
            Paragraph("2.0 (TechQuest Build)", body_style),
            Paragraph("<b>Classification:</b>", body_style),
            Paragraph("<font color='#DC2626'><b>CONFIDENTIAL DEFENSIVE AUDIT</b></font>", body_style)
        ]
    ]
    meta_table = Table(meta_data, colWidths=[110, 190, 110, 130])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), bg_light),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # 1. Executive Posture Score Card
    story.append(Paragraph("1. Executive Risk & Security Posture Score", h1_style))
    score_val = posture["posture_score"]
    grade_val = posture["posture_grade"]
    score_bg = success_color if score_val >= 80 else (warning_color if score_val >= 65 else danger_color)

    defensive_bullets = "<br/>".join([f"• <font color='#16A34A'><b>[Active Defense]</b></font> {m}" for m in posture.get("detected_security_measures", [])])
    if not defensive_bullets:
        defensive_bullets = "• <font color='#DC2626'><b>[Caution]</b></font> Very few / limited defensive security measures detected."

    posture_data = [
        [
            Paragraph(f"<font size=26><b>{grade_val}</b></font><br/><font size=8><b>POSTURE GRADE</b></font>", badge_style),
            Paragraph(
                f"<b>Overall Security Posture Score:</b> {score_val} / 100 &nbsp;|&nbsp; "
                f"<b>Risk Index:</b> {posture['risk_index']} / 10.0<br/>"
                f"<b>Validated Vulnerabilities:</b> {posture['validated_findings_count']} "
                f"(Critical: {posture['active_criticals']}, High: {posture['active_highs']}) &nbsp;|&nbsp; "
                f"<b>Remediated:</b> {posture['remediated_findings']}<br/>"
                f"<b>Verified Defensive Security Controls:</b><br/>{defensive_bullets}",
                body_style
            )
        ]
    ]
    posture_table = Table(posture_data, colWidths=[110, 430])
    posture_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, 0), score_bg),
        ('BACKGROUND', (1, 0), (1, 0), bg_light),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(posture_table)
    story.append(Spacer(1, 10))

    # 2. Findings Table (Highlighting strictly Validated vs Remediated)
    story.append(Paragraph("2. Technical Vulnerability Audit Findings", h1_style))
    vulns = db_snapshot.get("vulnerabilities", [])
    
    findings_rows = [
        [
            Paragraph("<b>Title / Finding</b>", body_bold),
            Paragraph("<b>Layer</b>", body_bold),
            Paragraph("<b>CVSS</b>", body_bold),
            Paragraph("<b>Source</b>", body_bold),
            Paragraph("<b>Validation Status</b>", body_bold)
        ]
    ]

    if vulns:
        for v in vulns:
            title_text = v.get("title") if isinstance(v, dict) else getattr(v, "title", "Unknown")
            layer_text = v.get("layer") if isinstance(v, dict) else getattr(v, "layer", "Web")
            crit_score = v.get("criticality_score") if isinstance(v, dict) else getattr(v, "criticality_score", 5.0)
            disc_source = v.get("discovery_source") if isinstance(v, dict) else getattr(v, "discovery_source", "")

            raw_status = v.get("status") if isinstance(v, dict) else getattr(v, "status", "unvalidated")
            status_val = getattr(raw_status, "value", str(raw_status)).lower().strip()

            if status_val == "remediated":
                status_html = "<font color='#16A34A'><b>REMEDIATED</b></font>"
            elif status_val in ("validated", "done"):
                status_html = "<font color='#DC2626'><b>VALIDATED</b></font>"
            elif status_val == "validating":
                status_html = "<font color='#D97706'><b>VALIDATING</b></font>"
            elif status_val in ("false_positive", "false-positive"):
                status_html = "<font color='#64748B'><b>FALSE POSITIVE</b></font>"
            else:
                status_html = "<font color='#64748B'>UNVALIDATED</font>"

            source_str = "tool" if "tool" in str(disc_source).lower() else "ai_inference"

            findings_rows.append([
                Paragraph(f"<b>{title_text or 'Unknown'}</b>", body_style),
                Paragraph(str(layer_text or 'Web'), body_style),
                Paragraph(f"{float(crit_score or 5.0):.1f}", body_style),
                Paragraph(source_str, body_style),
                Paragraph(status_html, body_style)
            ])
    else:
        findings_rows.append([
            Paragraph("No vulnerability findings recorded for this asset.", body_style),
            Paragraph("-", body_style), Paragraph("-", body_style), Paragraph("-", body_style), Paragraph("-", body_style)
        ])

    findings_table = Table(findings_rows, colWidths=[200, 70, 50, 100, 120])
    findings_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(findings_table)
    story.append(Spacer(1, 10))

    # 3. Probabilistic Attack Graph & Chokepoint Analysis
    story.append(Paragraph("3. Probabilistic Attack Chains & Break-the-Chain Chokepoints", h1_style))
    attack_paths = db_snapshot.get("attack_paths", [])
    if attack_paths:
        for idx, ap in enumerate(attack_paths[:2]):
            chokepoint = ap.get("chokepoint_vuln_id", "None")
            narrative = ap.get("attack_narrative", "Attack graph established leading to target objective.")
            step_details = ap.get("step_details", [])
            
            # Narrative & Chokepoint Block
            chokepoint_card = [
                [
                    Paragraph(f"<b>Attack Vector Corridor #{idx+1}</b> &nbsp;|&nbsp; Cumulative Likelihood: <b>{Math_round_prob(ap.get('path_probability', 0.85))}%</b> &nbsp;|&nbsp; Risk Score: <b>{ap.get('total_risk_score', 0):.1f}</b>", body_bold)
                ],
                [
                    Paragraph(f"<b>Break-The-Chain Chokepoint:</b> <font color='#DC2626'><b>{chokepoint}</b></font> <i>(Remediating this vulnerability breaks the attack sequence)</i>", body_style)
                ],
                [
                    Paragraph(f"<b>Dynamic Attack Narrative:</b> {narrative}", body_style)
                ]
            ]
            c_table = Table(chokepoint_card, colWidths=[540])
            c_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), bg_light),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(c_table)
            story.append(Spacer(1, 6))

            # Step-by-Step Exploitation Path Table
            if step_details:
                step_rows = [
                    [
                        Paragraph("<b>Step</b>", body_bold),
                        Paragraph("<b>From → To Node</b>", body_bold),
                        Paragraph("<b>Exploitation Path / Vector</b>", body_bold),
                        Paragraph("<b>Likelihood</b>", body_bold)
                    ]
                ]
                for s in step_details[:5]:
                    step_rows.append([
                        Paragraph(f"<b>#{s.get('step', 1)}</b>", body_style),
                        Paragraph(f"{s.get('from_node')} → {s.get('to_node')}", body_style),
                        Paragraph(f"<b>{s.get('technique', 'Exploit')}</b>: {s.get('exploitation_path', s.get('reason'))}", body_style),
                        Paragraph(f"{int(s.get('transition_probability', 0.85)*100)}%", body_style)
                    ])
                st_table = Table(step_rows, colWidths=[40, 180, 270, 50])
                st_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
                    ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                    ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ('TOPPADDING', (0, 0), (-1, -1), 3),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ]))
                story.append(st_table)
                story.append(Spacer(1, 8))
    else:
        story.append(Paragraph("No validated multi-stage attack paths reachable. Target perimeter resisted automated exploitation.", body_style))

    story.append(Spacer(1, 6))

    # 4. Automated Retest Evidence
    story.append(Paragraph("4. Automated Retest & Remediation Verification", h1_style))
    retests = db_snapshot.get("retests", [])
    if retests:
        retest_rows = [
            [
                Paragraph("<b>Finding ID</b>", body_bold),
                Paragraph("<b>Verification Result</b>", body_bold),
                Paragraph("<b>Audit Evidence</b>", body_bold)
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
        retest_table = Table(retest_rows, colWidths=[150, 130, 260])
        retest_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(retest_table)
    else:
        story.append(Paragraph("Retesting queue in standby or awaiting post-fix verification.", body_style))

    story.append(Spacer(1, 14))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#94A3B8"), spaceBefore=6, spaceAfter=6))
    story.append(Paragraph("<i>Autonomous Cyber-Defense Platform • Confidential Defensive Assessment • Strict Evidence Separation</i>", body_style))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes


def Math_round_prob(val: float) -> int:
    return int(round((val or 0.85) * 100))


# -----------------------------------------------------------------------------
# 5. report_exporter
# -----------------------------------------------------------------------------
