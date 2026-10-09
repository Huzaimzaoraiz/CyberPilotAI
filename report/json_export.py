import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from .scorer import posture_scorer
from .graph import attack_graph_renderer

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
                f"Autonomous security audit completed for '{target}'. "
                f"Identified {posture['validated_findings_count']} validated vulnerabilities across {posture['total_assets']} assets. "
                f"Verified {posture['security_measures_count']} active defensive security measures. "
                f"Overall security posture evaluated at Grade {posture['posture_grade']} with a health index of {posture['posture_score']}/100."
            ),
            "validated_vulnerabilities": posture["validated_findings_count"],
            "critical_risks": posture["active_criticals"],
            "remediated_findings": posture["remediated_findings"],
            "detected_security_measures": posture["detected_security_measures"]
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
