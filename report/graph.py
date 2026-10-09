import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

def attack_graph_renderer(graph: Dict[str, Any]) -> Dict[str, Any]:
    """
    Serializes graph nodes, edges, and exploitation paths for visual rendering and JSON reports.
    """
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    chokepoint = graph.get("chokepoint_vuln_id", "")
    simplified_flow = graph.get("simplified_flow", [])
    step_details = graph.get("step_details", [])
    grouped_vectors = graph.get("grouped_vectors", [])
    narrative = graph.get("attack_narrative", "")
    
    formatted_nodes = [{"id": n, "label": f"Asset: {n}"} for n in nodes]
    formatted_edges = [
        {
            "id": e, 
            "source": nodes[i] if i < len(nodes) else "ingress", 
            "target": nodes[i+1] if i+1 < len(nodes) else "crown_jewel"
        } 
        for i, e in enumerate(edges)
    ]

    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": formatted_nodes,
        "edges": formatted_edges,
        "break_the_chain_chokepoint": chokepoint,
        "simplified_stages": simplified_flow,
        "step_details": step_details,
        "grouped_vectors": grouped_vectors,
        "attack_narrative": narrative,
        "cumulative_risk": graph.get("total_risk_score", 0.0),
        "probability": graph.get("path_probability", 1.0)
    }


# -----------------------------------------------------------------------------
# 3. generate_json_report
# -----------------------------------------------------------------------------
