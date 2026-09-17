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
        # Clear stale attack paths before saving newly computed ones
        await self.db.clear_attack_paths()

        for jewel in crown_jewels:
            jnode = f"JEWEL:{jewel.id}"
            if not nx.has_path(self.graph, "INTERNET", jnode):
                logger.info(f"Crown Jewel ({jewel.asset_identifier}) is unreachable from current graph state.")
                continue

            # Find paths using Dijkstra
            try:
                paths_generator = nx.shortest_simple_paths(self.graph, "INTERNET", jnode, weight="weight")
                found_paths = []
                for _ in range(5):
                    try:
                        p = next(paths_generator)
                        found_paths.append(p)
                    except StopIteration:
                        break

                if found_paths:
                    # Consolidate paths leading to this crown jewel into a unified primary attack path
                    # Grouping same-type attacks together rather than spawning separate attack path boxes
                    await self._build_consolidated_path(found_paths, jewel, asset_map, validated_vulns)

            except Exception as e:
                logger.error(f"Failed calculating attack paths to {jnode}: {e}", exc_info=True)

    def _infer_capabilities(self, vuln: VulnerabilityRecord) -> Dict[str, Any]:
        """Infers offensive capabilities granted by exploiting this vulnerability."""
        title_lower = vuln.title.lower()
        
        has_creds = bool(vuln.has_leaked_creds or any(w in title_lower for w in ["credential", "password", "token", "secret", ".env", "cwe-798", "cwe-200", "auth", "key"]))
        is_code_exec = bool(any(w in title_lower for w in ["rce", "command", "exec", "cwe-78"]))
        is_internal_pivot = bool(any(w in title_lower for w in ["ssrf", "proxy", "metadata", "tunnel", "23017"]) or is_code_exec)
        is_info_disc = bool(any(w in title_lower for w in ["lfi", "traversal", "23017", "disclosure", "dir", "dlr", "swagger", "git", "cwe-200", "cwe-538"]))
        is_db_access = bool(any(w in title_lower for w in ["sql", "injection", "database", "cwe-89"]))
        is_phish = bool(any(w in title_lower for w in ["phish", "dmarc", "spf", "email", "t1566"]))
        is_api = bool(any(w in title_lower for w in ["api", "bola", "idor", "cwe-639", "cwe-306"]))
        
        base_prob = min(0.95, max(0.25, (vuln.criticality_score / 10.0) * vuln.confidence_score))

        return {
            "has_creds": has_creds,
            "is_code_exec": is_code_exec,
            "is_internal_pivot": is_internal_pivot,
            "is_info_disc": is_info_disc,
            "is_db_access": is_db_access,
            "is_phish": is_phish,
            "is_api": is_api,
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
        if hasattr(self.llm, "evaluate_vuln_transition"):
            try:
                res = await self.llm.evaluate_vuln_transition(parent_vuln, child_vuln)
                if res.get("is_chainable"):
                    return True, float(res.get("transition_probability", 0.8)), str(res.get("causal_reason", ""))
            except Exception as e:
                logger.warning(f"LLM transition query failed ({e}), falling back to deterministic rules.")

        if parent_caps["has_creds"]:
            return (
                True, 
                0.90, 
                f"Credentials compromised via '{parent_vuln.title}' satisfy authentication requirements for '{child_vuln.title}'."
            )

        if parent_caps["is_internal_pivot"]:
            return (
                True, 
                0.85, 
                f"Internal network pivot established via '{parent_vuln.title}' bypasses firewalls to expose '{child_vuln.title}'."
            )

        if parent_caps["is_info_disc"] or parent_caps["is_api"]:
            return (
                True, 
                0.78, 
                f"Configuration and secret leakage via '{parent_vuln.title}' provides tokens needed to exploit '{child_vuln.title}'."
            )

        return False, 0.0, ""

    async def _build_consolidated_path(
        self, 
        found_paths: List[List[str]], 
        jewel: TargetAsset, 
        asset_map: Dict[str, TargetAsset], 
        validated_vulns: List[VulnerabilityRecord]
    ):
        """
        Consolidates attack trajectories into a single, cohesive AttackPath record.
        Shows:
        1. A simpler, understandable narrative flow leading to the Crown Jewel DB.
        2. Consolidated grouping of all same-type ingress & exploit vectors.
        3. Full causal step-by-step technical details and MITRE ATT&CK mappings.
        """
        raw_path = found_paths[0]
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

            vuln_title = "Perimeter Ingress & Exploitation"
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

        chokepoint_vuln_id = vuln_ids_in_chain[0] if vuln_ids_in_chain else ""
        final_prob = round(max(0.1, min(0.99, cumulative_prob)), 2)
        total_risk = round(min(9.9, 6.0 + (final_prob * 3.9)), 1)

        # Group all discovered perimeter/exploit vectors together into a unified list
        grouped_vectors = []
        seen_titles = set()
        for v in validated_vulns:
            t_clean = v.title.split("(")[0].strip()
            if t_clean in seen_titles:
                continue
            seen_titles.add(t_clean)
            
            t_lower = v.title.lower()
            mitre_data = v.metadata.get("mitre", {})
            
            if any(k in t_lower for k in ["sql", "injection", "cwe-89"]):
                cat = "Web SQL Injection"
                icon = "fa-database"
                desc = "Parameter concatenation in queries allows extracting internal credentials and database schema."
            elif any(k in t_lower for k in ["env", "git", "dir", "dlr", "bruteforce", "cwe-538", "cwe-200"]):
                cat = "Sensitive File & Directory Exposure"
                icon = "fa-folder-open"
                desc = "Publicly accessible configuration or version control repository leaking database secrets."
            elif any(k in t_lower for k in ["api", "bola", "idor", "cwe-639", "cwe-306"]):
                cat = "API Broken Authorization"
                icon = "fa-code"
                desc = "Unprotected API endpoints disclosing backend service configurations and account hashes."
            elif any(k in t_lower for k in ["phish", "dmarc", "spf", "email", "t1566"]):
                cat = "Email Spoofing & Phishing Vector"
                icon = "fa-envelope-open-text"
                desc = "Weak email domain posture allowing spear-phishing lures to harvest staff credentials."
            elif any(k in t_lower for k in ["rce", "command", "cwe-78", "23017", "nginx"]):
                cat = "Remote Code Execution"
                icon = "fa-terminal"
                desc = "Memory corruption or shell execution permitting arbitrary commands and network routing."
            else:
                cat = "Perimeter Security Flaw"
                icon = "fa-shield-halved"
                desc = "Application configuration weakness providing initial unauthorized access."

            grouped_vectors.append({
                "vuln_id": v.id,
                "title": v.title,
                "category": cat,
                "icon": icon,
                "severity": "CRITICAL" if v.criticality_score >= 8.5 else "HIGH" if v.criticality_score >= 7.0 else "MEDIUM",
                "cvss_score": v.criticality_score,
                "cwe": v.title.split("(")[-1].replace(")", "") if "(" in v.title else "CWE-General",
                "mitre_technique": mitre_data.get("technique_id", "T1190"),
                "mitre_name": mitre_data.get("technique_name", "Exploit Public-Facing Application"),
                "description": desc
            })

        # Simplified, Human-Understandable 4-Stage Flow
        simplified_flow = [
            {
                "stage": 1,
                "stage_name": "Perimeter Ingress & Vector Exploitation",
                "actor": "External Adversary",
                "location": "The Public Internet",
                "badge": "Entry Point",
                "icon": "fa-globe",
                "color": "rose",
                "mitre_id": "T1190 / T1566",
                "mitre_name": "Initial Access",
                "headline": "Adversary probes and breaches public web perimeter",
                "explanation": "The attacker targets public-facing web surfaces, exploiting endpoints via SQL injection, exposed configuration directories (.env, .git), unauthenticated API routes, or deceptive phishing lures. This provides an initial unauthenticated entrypoint."
            },
            {
                "stage": 2,
                "stage_name": "Secrets Extraction & Privilege Elevation",
                "actor": "Threat Actor",
                "location": "DMZ / Web Tier",
                "badge": "Credential Harvesting",
                "icon": "fa-key",
                "color": "amber",
                "mitre_id": "T1552 / T1078",
                "mitre_name": "Credential Access",
                "headline": "Adversary harvests database credentials and backend service tokens",
                "explanation": "From the compromised endpoint, the attacker dumps environment variables, configuration files, or database query results to acquire cleartext connection credentials, API keys, and elevated administrative tokens."
            },
            {
                "stage": 3,
                "stage_name": "Lateral Movement & Firewall Bypass",
                "actor": "Threat Actor",
                "location": "Internal DMZ Pivot",
                "badge": "Lateral Pivot",
                "icon": "fa-arrows-split-up-and-left",
                "color": "purple",
                "mitre_id": "T1210 / T1021",
                "mitre_name": "Lateral Movement",
                "headline": "Adversary pivots past perimeter firewall into private subnet",
                "explanation": "Because internal firewall rules trust traffic originating from DMZ web servers, the attacker pivots through the compromised web host, establishing direct internal network socket connections to the isolated internal database subnet."
            },
            {
                "stage": 4,
                "stage_name": "Crown Jewel DB Compromise & Exfiltration",
                "actor": "Threat Actor",
                "location": f"Crown Jewel: {jewel.asset_identifier}",
                "badge": "Crown Jewel Breach",
                "icon": "fa-database",
                "color": "cyan",
                "mitre_id": "T1530 / T1005",
                "mitre_name": "Data Exfiltration & Impact",
                "headline": f"Direct authenticated breach of Crown Jewel DB ({jewel.asset_identifier})",
                "explanation": f"The attacker authenticates directly into the Crown Jewel database using the harvested credentials. The attacker gains full read/write access to customer records, credentials, and sensitive assets, fulfilling the primary attack objective."
            }
        ]

        # Plain English Narrative Storyline
        attack_narrative = (
            f"An external adversary on the public Internet identifies one or more vulnerable endpoints on the perimeter "
            f"(including SQL injection, exposed configuration files like .env, unauthenticated API routes, or phishing vectors). "
            f"By exploiting these weaknesses, the adversary extracts valid backend database credentials and service tokens. "
            f"Because internal network perimeter defenses permit incoming traffic from authorized DMZ hosts, the attacker "
            f"leverages these credentials to laterally pivot through the firewall directly into the internal subnet. "
            f"The attacker connects directly to the Crown Jewel database ({jewel.asset_identifier}), enabling unauthorized "
            f"data exfiltration and complete database compromise without triggering perimeter alarms."
        )

        # MITRE Tactics List
        mitre_tactics = [
            {"tactic": "Initial Access", "id": "TA0001", "technique": "T1190 (Exploit Public-Facing App) / T1566 (Phishing)"},
            {"tactic": "Discovery", "id": "TA0007", "technique": "T1083 (File & Directory Discovery)"},
            {"tactic": "Credential Access", "id": "TA0006", "technique": "T1552 (Unsecured Credentials)"},
            {"tactic": "Lateral Movement", "id": "TA0008", "technique": "T1210 (Exploitation of Remote Services)"},
            {"tactic": "Collection", "id": "TA0009", "technique": "T1530 (Data from Cloud / Database Object)"}
        ]

        consolidated_path = AttackPath(
            nodes=asset_ids_in_chain,
            edges=vuln_ids_in_chain,
            total_risk_score=total_risk,
            chokepoint_vuln_id=chokepoint_vuln_id,
            path_probability=final_prob,
            step_details=step_details,
            attack_narrative=attack_narrative,
            simplified_flow=simplified_flow,
            grouped_vectors=grouped_vectors,
            mitre_tactics=mitre_tactics
        )

        await self.db.save_attack_path(consolidated_path)
        logger.warning(
            f"Saved Consolidated Attack Chain: Likelihood={final_prob * 100:.1f}%, "
            f"Risk={total_risk}, Grouped Vectors={len(grouped_vectors)}, Chokepoint={chokepoint_vuln_id[:8]}"
        )

        if chokepoint_vuln_id:
            await self.db.boost_vulnerability_priority(chokepoint_vuln_id, multiplier=1.5)