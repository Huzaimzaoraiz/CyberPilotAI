import logging
import math
import networkx as nx
from typing import Dict, Any, List, Tuple, Set, Optional
from core.models import TargetAsset, VulnerabilityRecord, AttackPath, VulnStatus

logger = logging.getLogger("AttackPathAgent")

class MockAttackPathLLM:
    """Deterministic capability-based fallback for evaluating vulnerability chaining."""
    
    async def evaluate_chainability(self, vuln: VulnerabilityRecord, all_assets: List[TargetAsset]) -> Tuple[str, str, bool]:
        if vuln.has_leaked_creds or "metadata" in vuln.title.lower() or "ssrf" in vuln.title.lower():
            public_asset = next((a for a in all_assets if a.id == vuln.asset_id or (a.layer in ["Web", "Network"] and not a.metadata.get("is_crown_jewel"))), None)
            crown_jewel = next((a for a in all_assets if a.metadata.get("is_crown_jewel")), None)
            if public_asset and crown_jewel:
                return public_asset.id, crown_jewel.id, True

        if vuln.layer in ["Network", "Web", "OSINT"]:
            return "INTERNET", vuln.asset_id, True
                
        return "", "", False

    async def evaluate_vuln_transition(self, parent_vuln: VulnerabilityRecord, child_vuln: VulnerabilityRecord) -> Dict[str, Any]:
        """Evaluates causal transition from parent to child vulnerability."""
        if parent_vuln.has_leaked_creds:
            return {
                "is_chainable": True,
                "transition_probability": 0.88,
                "causal_reason": f"Compromised credentials from '{parent_vuln.title}' unlock authenticated access to exploit '{child_vuln.title}'."
            }
        if any(w in parent_vuln.title.lower() for w in ["ssrf", "rce", "command", "proxy", "metadata"]):
            return {
                "is_chainable": True,
                "transition_probability": 0.82,
                "causal_reason": f"Internal network pivot established via '{parent_vuln.title}' bypasses firewalls to expose '{child_vuln.title}'."
            }
        if any(w in parent_vuln.title.lower() for w in ["lfi", "traversal", "23017", "file"]):
            return {
                "is_chainable": True,
                "transition_probability": 0.75,
                "causal_reason": f"Local file disclosure via '{parent_vuln.title}' leaks tokens and secrets required to target '{child_vuln.title}'."
            }
        return {"is_chainable": False, "transition_probability": 0.0, "causal_reason": "No causal link."}


class AttackPathAgent:
    """
    Constructs a Bayesian Vulnerability-to-Vulnerability Attack Graph.
    Traces how an initial vulnerability provides the capabilities (credentials, SSRF, RCE)
    to expose and exploit subsequent vulnerabilities in a causal chain, prioritizing
    paths by maximum exploitation probability.
    """
    def __init__(self, db_client, llm_client):
        self.db = db_client
        self.llm = llm_client
        self.graph = nx.DiGraph()

    async def execute_task(self, payload: Dict[str, Any]):
        logger.info("Recalculating Probabilistic Vulnerability Attack Graph...")
        
        # 1. Fetch current environment state
        assets = await self.db.get_all_assets()
        validated_vulns = await self.db.get_vulnerabilities(status=VulnStatus.VALIDATED)
        
        if not validated_vulns:
            logger.info("No validated vulnerabilities found. Graph is empty.")
            return

        # Map assets by ID for quick lookup
        asset_map: Dict[str, TargetAsset] = {a.id: a for a in assets}
        crown_jewels = [a for a in assets if a.metadata.get("is_crown_jewel")]
        
        # 2. Reset Graph
        self.graph.clear()
        self.graph.add_node("INTERNET", type="ROOT", label="The Public Internet")

        # Add Crown Jewel objective nodes
        for jewel in crown_jewels:
            self.graph.add_node(
                f"JEWEL:{jewel.id}", 
                type="CROWN_JEWEL", 
                asset_id=jewel.id, 
                label=jewel.asset_identifier
            )

        # 3. Add Vulnerability Nodes and evaluate capabilities
        vuln_capabilities: Dict[str, Dict[str, Any]] = {}
        for vuln in validated_vulns:
            vnode = f"VULN:{vuln.id}"
            caps = self._infer_capabilities(vuln)
            vuln_capabilities[vuln.id] = caps
            
            asset = asset_map.get(vuln.asset_id)
            asset_label = asset.asset_identifier if asset else "Target Asset"
            
            self.graph.add_node(
                vnode,
                type="VULNERABILITY",
                vuln_id=vuln.id,
                vuln=vuln,
                asset_id=vuln.asset_id,
                label=f"{vuln.title} on {asset_label}",
                capabilities=caps
            )

        # 4. Connect Ingress Edges: INTERNET -> Perimeter Vulnerabilities
        for vuln in validated_vulns:
            caps = vuln_capabilities[vuln.id]
            asset = asset_map.get(vuln.asset_id)
            is_perimeter = (vuln.layer in ["Network", "Web", "OSINT"]) and (not asset or not asset.metadata.get("is_crown_jewel"))

            if is_perimeter:
                p_ingress = caps["base_probability"]
                weight = -math.log(max(0.01, min(0.99, p_ingress)))
                vnode = f"VULN:{vuln.id}"
                
                asset_name = asset.asset_identifier if asset else "Perimeter"
                self.graph.add_edge(
                    "INTERNET", 
                    vnode, 
                    vuln_id=vuln.id, 
                    weight=weight,
                    probability=p_ingress,
                    from_label="The Public Internet",
                    to_label=asset_name,
                    reason=f"Direct perimeter exploit of {vuln.title} from public internet."
                )
                logger.info(f"Ingress Edge: [INTERNET] -> [{vuln.title[:25]}] (P={p_ingress:.2f})")

        # 5. Connect Vulnerability-to-Vulnerability Edges (V_parent -> V_child)
        # Evaluates if exploiting V_parent unlocks prerequisites for V_child
        for parent_vuln in validated_vulns:
            parent_node = f"VULN:{parent_vuln.id}"
            parent_caps = vuln_capabilities[parent_vuln.id]

            for child_vuln in validated_vulns:
                if parent_vuln.id == child_vuln.id:
                    continue

                child_node = f"VULN:{child_vuln.id}"
                
                # Check causal transition
                can_chain, trans_prob, reason = await self._evaluate_vulnerability_chain(
                    parent_vuln, child_vuln, parent_caps, asset_map
                )

                if can_chain and trans_prob > 0.05:
                    weight = -math.log(max(0.01, min(0.99, trans_prob)))
                    parent_asset = asset_map.get(parent_vuln.asset_id)
                    child_asset = asset_map.get(child_vuln.asset_id)
                    
                    self.graph.add_edge(
                        parent_node, 
                        child_node, 
                        vuln_id=child_vuln.id, 
                        weight=weight,
                        probability=trans_prob,
                        from_label=parent_asset.asset_identifier if parent_asset else "Parent Asset",
                        to_label=child_asset.asset_identifier if child_asset else "Child Asset",
                        reason=reason
                    )
                    logger.info(f"Causal Chain Edge: [{parent_vuln.title[:15]}] -> [{child_vuln.title[:15]}] (P={trans_prob:.2f})")

        # 6. Connect Vulnerabilities to Crown Jewel Target Objectives
        for vuln in validated_vulns:
            caps = vuln_capabilities[vuln.id]
            vnode = f"VULN:{vuln.id}"
            asset = asset_map.get(vuln.asset_id)

            # A vulnerability can pivot to Crown Jewel if it has leaked creds, internal SSRF, or code execution
            can_pivot = caps["has_creds"] or caps["is_internal_pivot"] or caps["is_code_exec"] or caps["is_db_access"]

            if can_pivot:
                for jewel in crown_jewels:
                    jnode = f"JEWEL:{jewel.id}"
                    
                    # Estimate pivot probability to crown jewel based on capability
                    if caps["has_creds"]:
                        pivot_prob = 0.94
                        pivot_reason = f"Compromised credentials from '{vuln.title}' enable direct authenticated login into Crown Jewel DB ({jewel.asset_identifier})."
                    elif caps["is_internal_pivot"]:
                        pivot_prob = 0.88
                        pivot_reason = f"Internal network pivot from '{vuln.title}' allows direct socket tunneling into Crown Jewel DB ({jewel.asset_identifier})."
                    else:
                        pivot_prob = 0.85
                        pivot_reason = f"Remote code execution from '{vuln.title}' allows routing internal database queries into Crown Jewel DB ({jewel.asset_identifier})."

                    weight = -math.log(max(0.01, min(0.99, pivot_prob)))
                    self.graph.add_edge(
                        vnode,
                        jnode,
                        vuln_id=vuln.id,
                        weight=weight,
                        probability=pivot_prob,
                        from_label=asset.asset_identifier if asset else "Perimeter",
                        to_label=jewel.asset_identifier,
                        reason=pivot_reason
                    )
                    logger.info(f"Objective Edge: [{vuln.title[:20]}] -> [Crown Jewel {jewel.asset_identifier}] (P={pivot_prob:.2f})")

        # 7. Find and Rank Attack Paths to Crown Jewels by Maximum Likelihood
        for jewel in crown_jewels:
            jnode = f"JEWEL:{jewel.id}"
            if not nx.has_path(self.graph, "INTERNET", jnode):
                logger.info(f"Crown Jewel ({jewel.asset_identifier}) is unreachable from current graph state.")
                continue

            # Find paths of least resistance (maximum probability) using Dijkstra
            try:
                # Get up to 3 shortest paths
                paths_generator = nx.shortest_simple_paths(self.graph, "INTERNET", jnode, weight="weight")
                found_paths = []
                for _ in range(3):
                    try:
                        p = next(paths_generator)
                        found_paths.append(p)
                    except StopIteration:
                        break

                for rank_idx, path in enumerate(found_paths):
                    await self._build_and_save_path(path, asset_map, rank_idx)

            except Exception as e:
                logger.error(f"Failed calculating attack paths to {jnode}: {e}", exc_info=True)

    def _infer_capabilities(self, vuln: VulnerabilityRecord) -> Dict[str, Any]:
        """Infers offensive capabilities granted by exploiting this vulnerability."""
        title_lower = vuln.title.lower()
        
        has_creds = bool(vuln.has_leaked_creds or "credential" in title_lower or "password" in title_lower or "token" in title_lower)
        is_code_exec = bool("rce" in title_lower or "command" in title_lower or "exec" in title_lower)
        is_internal_pivot = bool("ssrf" in title_lower or "proxy" in title_lower or "metadata" in title_lower or is_code_exec)
        is_info_disc = bool("lfi" in title_lower or "traversal" in title_lower or "23017" in title_lower or "disclosure" in title_lower)
        is_db_access = bool("sql" in title_lower or "injection" in title_lower or "database" in title_lower)
        
        # Base exploitability probability derived from CVSS (0-10) and confidence (0-1)
        base_prob = min(0.95, max(0.20, (vuln.criticality_score / 10.0) * vuln.confidence_score))

        return {
            "has_creds": has_creds,
            "is_code_exec": is_code_exec,
            "is_internal_pivot": is_internal_pivot,
            "is_info_disc": is_info_disc,
            "is_db_access": is_db_access,
            "base_probability": round(base_prob, 2)
        }

    async def _evaluate_vulnerability_chain(
        self, 
        parent_vuln: VulnerabilityRecord, 
        child_vuln: VulnerabilityRecord,
        parent_caps: Dict[str, Any],
        asset_map: Dict[str, TargetAsset]
    ) -> Tuple[bool, float, str]:
        """
        Determines if parent_vuln can lead to child_vuln and calculates transition probability.
        Uses LLM if available, with deterministic capability rules fallback.
        """
        # 1. Ask LLM if client supports evaluate_vuln_transition
        if hasattr(self.llm, "evaluate_vuln_transition"):
            try:
                res = await self.llm.evaluate_vuln_transition(parent_vuln, child_vuln)
                if res.get("is_chainable"):
                    return True, float(res.get("transition_probability", 0.8)), str(res.get("causal_reason", ""))
            except Exception as e:
                logger.warning(f"LLM transition query failed ({e}), falling back to deterministic rules.")

        # 2. Deterministic Rule Matching:
        # Credential leak enables authenticated exploitation of child vulnerability
        if parent_caps["has_creds"]:
            return (
                True, 
                0.90, 
                f"Credentials compromised via '{parent_vuln.title}' satisfy authentication requirements for '{child_vuln.title}'."
            )

        # SSRF or RCE enables internal pivoting to child vulnerability
        if parent_caps["is_internal_pivot"]:
            return (
                True, 
                0.85, 
                f"Internal network pivot established via '{parent_vuln.title}' bypasses firewalls to expose '{child_vuln.title}'."
            )

        # Local file read reveals config files / tokens to exploit child
        if parent_caps["is_info_disc"]:
            return (
                True, 
                0.78, 
                f"Configuration and secret leakage via '{parent_vuln.title}' provides tokens needed to exploit '{child_vuln.title}'."
            )

        return False, 0.0, ""

    async def _build_and_save_path(self, raw_path: List[str], asset_map: Dict[str, TargetAsset], rank_idx: int):
        """Constructs rich step-by-step AttackPath record from graph nodes."""
        step_details = []
        vuln_ids_in_chain = []
        asset_ids_in_chain = []
        cumulative_prob = 1.0

        for u, v in zip(raw_path[:-1], raw_path[1:]):
            edge_data = self.graph.get_edge_data(u, v)
            prob = edge_data.get("probability", 0.9)
            cumulative_prob *= prob
            vuln_id = edge_data.get("vuln_id")
            
            if vuln_id and vuln_id not in vuln_ids_in_chain:
                vuln_ids_in_chain.append(vuln_id)

            vuln_obj = None
            vuln_title = "Exploit Ingress / Pivot"
            if u.startswith("VULN:"):
                node_u_data = self.graph.nodes[u]
                vuln_obj = node_u_data.get("vuln")
                if vuln_obj:
                    vuln_title = vuln_obj.title
            elif v.startswith("VULN:"):
                node_v_data = self.graph.nodes[v]
                vuln_obj = node_v_data.get("vuln")
                if vuln_obj:
                    vuln_title = vuln_obj.title

            step_details.append({
                "step": len(step_details) + 1,
                "from_node": edge_data.get("from_label", u),
                "to_node": edge_data.get("to_label", v),
                "vuln_id": vuln_id,
                "vuln_title": vuln_title,
                "transition_probability": round(prob, 2),
                "reason": edge_data.get("reason", "Causal exploit transition.")
            })

        # Asset IDs traversed (for backward compatibility with UI asset stepper)
        for node in raw_path:
            if node == "INTERNET":
                asset_ids_in_chain.append("INTERNET")
            elif node.startswith("JEWEL:"):
                asset_ids_in_chain.append(node.replace("JEWEL:", ""))
            elif node.startswith("VULN:"):
                node_data = self.graph.nodes[node]
                aid = node_data.get("asset_id")
                if aid and aid not in asset_ids_in_chain:
                    asset_ids_in_chain.append(aid)

        # Chokepoint: The root perimeter vulnerability whose remediation cuts the tree
        chokepoint_vuln_id = vuln_ids_in_chain[0] if vuln_ids_in_chain else ""

        # Total risk score weighted by cumulative probability
        final_prob = round(max(0.1, min(0.99, cumulative_prob)), 2)
        total_risk = round(min(9.9, 6.0 + (final_prob * 3.9)), 1)

        attack_path_record = AttackPath(
            nodes=asset_ids_in_chain,
            edges=vuln_ids_in_chain,
            total_risk_score=total_risk,
            chokepoint_vuln_id=chokepoint_vuln_id,
            path_probability=final_prob,
            step_details=step_details
        )

        await self.db.save_attack_path(attack_path_record)
        logger.warning(
            f"Saved Probabilistic Attack Chain #{rank_idx + 1}: "
            f"Likelihood={final_prob * 100:.1f}%, Risk={total_risk}, Chokepoint={chokepoint_vuln_id[:8]}"
        )

        # Boost priority on the strategic chokepoint so Orchestrator prioritizes remediation
        if chokepoint_vuln_id:
            await self.db.boost_vulnerability_priority(chokepoint_vuln_id, multiplier=1.5)