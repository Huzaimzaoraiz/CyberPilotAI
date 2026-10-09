import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple
import networkx as nx
from core.models import VulnerabilityRecord, TargetAsset, TaskItem
def graph_builder(validated_findings: List[VulnerabilityRecord], assets: Optional[List[TargetAsset]] = None) -> nx.DiGraph:
    """Constructs a NetworkX directed attack graph from validated findings and assets."""
    G = nx.DiGraph()
    G.add_node("INTERNET", label="Public Internet", node_type="source")
    
    asset_map = {a.id: a for a in (assets or [])}
    for vuln in validated_findings:
        v_id = f"VULN:{vuln.id}"
        G.add_node(v_id, label=vuln.title, vuln=vuln, node_type="vulnerability")
        if vuln.layer in ["Web", "Network", "OSINT"]:
            G.add_edge("INTERNET", v_id, probability=0.9, reason="Direct external exposure")
        if assets:
            a = asset_map.get(vuln.asset_id)
            if a and a.metadata.get("is_crown_jewel"):
                G.add_node(f"JEWEL:{a.id}", label=f"Crown Jewel: {a.asset_identifier}", node_type="target")
                G.add_edge(v_id, f"JEWEL:{a.id}", probability=0.85, reason="Crown jewel compromise")
    return G

def path_ranker(graph: nx.DiGraph) -> List[Dict[str, Any]]:
    """Ranks attack paths by cumulative risk and Bayesian probability."""
    ranked = []
    if "INTERNET" not in graph:
        return ranked
    targets = [n for n in graph.nodes if n.startswith("JEWEL:") or graph.out_degree(n) == 0]
    for target in targets:
        if target == "INTERNET":
            continue
        try:
            for path in nx.all_simple_paths(graph, "INTERNET", target, cutoff=6):
                prob = 1.0
                for u, v in zip(path[:-1], path[1:]):
                    edata = graph.get_edge_data(u, v) or {}
                    prob *= edata.get("probability", 0.85)
                ranked.append({
                    "path": path,
                    "cumulative_probability": round(prob, 4),
                    "steps": len(path) - 1,
                    "target": target
                })
        except Exception:
            pass
    ranked.sort(key=lambda x: x["cumulative_probability"], reverse=True)
    return ranked

