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
                "chain_mechanism": "Credential Reuse & Authenticated Session Pivot",
                "exploitation_path": f"Adversary replays credentials harvested from '{parent_vuln.title}' to authenticate against '{child_vuln.title}'.",
                "causal_reason": f"Compromised credentials from '{parent_vuln.title}' satisfy authentication barriers required to trigger '{child_vuln.title}'."
            }
        if any(w in parent_vuln.title.lower() for w in ["ssrf", "rce", "command", "proxy", "metadata"]):
            return {
                "is_chainable": True,
                "transition_probability": 0.85,
                "chain_mechanism": "Internal Network Shell Tunneling",
                "exploitation_path": f"Adversary uses command execution shell on '{parent_vuln.title}' to pivot internal socket requests into '{child_vuln.title}'.",
                "causal_reason": f"Internal network pivot established via '{parent_vuln.title}' bypasses firewalls to expose '{child_vuln.title}'."
            }
        if any(w in parent_vuln.title.lower() for w in ["lfi", "traversal", "23017", "file", "env", "git", "secret"]):
            return {
                "is_chainable": True,
                "transition_probability": 0.80,
                "chain_mechanism": "Secret Token & Configuration Extraction",
                "exploitation_path": f"Sensitive database configuration strings leaked by '{parent_vuln.title}' are passed into '{child_vuln.title}'.",
                "causal_reason": f"Local file disclosure via '{parent_vuln.title}' leaks tokens and secrets required to target '{child_vuln.title}'."
            }
        return {
            "is_chainable": False,
            "transition_probability": 0.0,
            "chain_mechanism": "No direct causal link",
            "exploitation_path": "",
            "causal_reason": "No causal link."
        }

MockAttackPathCorrelator = MockAttackPathLLM


def derive_exploitation_path(vuln: VulnerabilityRecord, asset: Optional[TargetAsset] = None) -> Dict[str, Any]:
    """
    Constructs a concrete technical exploitation path showing:
    1. Vector / Endpoint
    2. Exploit payload / technique
    3. Granted capability
    """
    title_lower = vuln.title.lower()
    poc = vuln.proof_of_concept
    asset_name = asset.asset_identifier if asset else "target host"
    
    if any(k in title_lower for k in ["sql", "cwe-89"]):
        sql_poc = poc or "' OR '1'='1"
        return {
            "method": "POST /api/v1/auth/login or GET /api/search?id=",
            "payload": poc or "' OR '1'='1' UNION SELECT username, password_hash FROM users--",
            "technique": "CWE-89: SQL Injection Parameter Interpolation",
            "mitre": "T1190 - Exploit Public-Facing Application",
            "capability": "Database Query Execution & Credential Extraction",
            "summary": f"Attacker injects SQL payload '{sql_poc}' on {asset_name}, extracting database authentication hashes."
        }
    elif any(k in title_lower for k in ["rce", "command injection", "cwe-78"]):
        rce_poc = poc or "; whoami"
        return {
            "method": "POST /admin/exec or /diagnostic",
            "payload": poc or "; id; whoami; uname -a",
            "technique": "CWE-78: OS Command Injection via Shell Metacharacters",
            "mitre": "T1059 - Command and Scripting Interpreter",
            "capability": "Interactive Remote Shell Execution (RCE)",
            "summary": f"Attacker executes command injection payload '{rce_poc}', securing interactive shell control on {asset_name}."
        }
    elif any(k in title_lower for k in ["lfi", "traversal", "cwe-22", "file disclosure"]):
        return {
            "method": "GET /download?file=../../../../etc/passwd",
            "payload": poc or "../../../../etc/passwd or /.env",
            "technique": "CWE-22: Path Traversal / Arbitrary File Read",
            "mitre": "T1083 - File and Directory Discovery",
            "capability": "Local Sensitive Configuration & Key Disclosure",
            "summary": f"Attacker traverses file paths to extract sensitive system files and tokens from {asset_name}."
        }
    elif any(k in title_lower for k in ["cve-2021-23017", "nginx"]):
        return {
            "method": "DNS UDP/TCP Port 53 Response Packet",
            "payload": "Crafted 1-byte DNS PTR overwrite buffer",
            "technique": "CVE-2021-23017: NGINX DNS Resolver 1-Byte Memory Overwrite",
            "mitre": "T1190 - Exploit Public-Facing Application",
            "capability": "Remote Worker Memory Corruption & Hijack",
            "summary": "Attacker delivers malicious DNS payload triggering 1-byte overwrite in Nginx worker, seizing daemon control."
        }
    elif any(k in title_lower for k in ["cve-2020-15778", "openssh", "scp"]):
        return {
            "method": "SSH Port 22 scp Command Invocation",
            "payload": "scp -S '`id`' malicious_file host:",
            "technique": "CVE-2020-15778: OpenSSH scp Command Injection",
            "mitre": "T1059 - Command and Scripting Interpreter",
            "capability": "Remote Command Execution via scp Filename Evaluation",
            "summary": "Attacker abuses backtick command substitution in scp path arguments to achieve remote execution."
        }
    elif any(k in title_lower for k in ["cve-2022-22965", "spring4shell"]):
        return {
            "method": "POST /greeting?class.module.classLoader.resources.context...",
            "payload": "class.module.classLoader.resources.context.parent.pipeline.first.pattern=...",
            "technique": "CVE-2022-22965: Spring4Shell Remote Code Execution",
            "mitre": "T1190 - Exploit Public-Facing Application",
            "capability": "Persistent Webshell Drop & RCE",
            "summary": "Attacker exploits Spring DataBinder to drop a persistent web shell into document root, securing RCE."
        }
    elif any(k in title_lower for k in ["env", "git", "dir", "dlr", "bruteforce", "cwe-538", "cwe-200"]):
        return {
            "method": "HTTP GET /.env or /.git/HEAD",
            "payload": "Direct HTTP GET probe against unindexed path",
            "technique": "CWE-538: File and Directory Information Exposure",
            "mitre": "T1552 - Unsecured Credentials in Files",
            "capability": "Cleartext Database Credentials & Secret Keys",
            "summary": f"Attacker discovers publicly exposed configuration file on {asset_name}, recovering database connection credentials."
        }
    elif any(k in title_lower for k in ["api", "bola", "idor", "cwe-639", "cwe-306"]):
        return {
            "method": "GET /api/v1/users/{id} without authorization header",
            "payload": "IDOR parameter manipulation targeting administrative user IDs",
            "technique": "CWE-639: Broken Object Level Authorization (BOLA)",
            "mitre": "T1078 - Valid Accounts / Privilege Escalation",
            "capability": "Direct Tenant Data Extraction & Account Takeover",
            "summary": f"Attacker queries unprotected API routes on {asset_name}, extracting tenant data and administrative tokens."
        }
    elif any(k in title_lower for k in ["phish", "dmarc", "spf", "email", "t1566"]):
        return {
            "method": "Inbound SMTP Spearphishing Campaign",
            "payload": "Spoofed domain spearphishing lure with credential harvesting portal",
            "technique": "T1566: Phishing / Email Domain Spoofing",
            "mitre": "T1566 - Phishing",
            "capability": "Stolen Employee Credentials & Initial Perimeter Access",
            "summary": f"Attacker exploits missing SPF/DMARC to deliver spoofed corporate lures, harvesting employee access credentials."
        }
    else:
        return {
            "method": f"Targeted Protocol Audit Probe on {asset_name}",
            "payload": poc or "Crafted boundary validation exploit payload",
            "technique": "Application Logic & Security Boundary Flaw",
            "mitre": "T1190 - Exploit Public-Facing Application",
            "capability": "Unauthorized Perimeter Access & Lateral Pivot",
            "summary": f"Attacker exploits {vuln.title} to bypass security boundaries and establish a persistent lateral pivot."
        }


class AttackPathAgent:
    """
    Constructs a Bayesian Vulnerability-to-Vulnerability Attack Graph.
    Maps how individual vulnerabilities combine into sequential exploitation chains,
    traces concrete exploitation paths, and prioritizes fixes that break the attack chain.
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
            logger.info("No validated vulnerabilities found. Clearing attack paths.")
            await self.db.clear_attack_paths()
            return

        # Map assets by ID for quick lookup
        asset_map: Dict[str, TargetAsset] = {a.id: a for a in assets}
        crown_jewels = [a for a in assets if a.metadata.get("is_crown_jewel")]
        
        # If no explicit crown jewel was tagged, designate primary target asset as objective
        if not crown_jewels and assets:
            primary_asset = assets[0]
            obj_asset = TargetAsset(
                id=f"obj_{primary_asset.id}",
                asset_identifier=f"{primary_asset.asset_identifier} [Core Database & System Seizure]",
                layer="Database",
                is_authorized=True,
                metadata={"is_crown_jewel": True}
            )
            crown_jewels = [obj_asset]
            asset_map[obj_asset.id] = obj_asset

        # 2. Reset Graph
        self.graph.clear()
        self.graph.add_node("INTERNET", type="ROOT", label="The Public Internet")

        # Add Objective / Crown Jewel nodes
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
            asset = asset_map.get(vuln.asset_id)
            exploit_info = derive_exploitation_path(vuln, asset)
            caps["exploit_info"] = exploit_info
            vuln_capabilities[vuln.id] = caps
            
            asset_label = asset.asset_identifier if asset else "Target Asset"
            
            self.graph.add_node(
                vnode,
                type="VULNERABILITY",
                vuln_id=vuln.id,
                vuln=vuln,
                asset_id=vuln.asset_id,
                label=f"{vuln.title} on {asset_label}",
                capabilities=caps,
                exploit_info=exploit_info
            )

        # 4. Connect Ingress Edges: INTERNET -> Perimeter Vulnerabilities
        for vuln in validated_vulns:
            caps = vuln_capabilities[vuln.id]
            asset = asset_map.get(vuln.asset_id)
            is_perimeter = (vuln.layer in ["Network", "Web", "OSINT"]) or (not asset or not asset.metadata.get("is_crown_jewel"))

            if is_perimeter:
                p_ingress = caps["base_probability"]
                weight = -math.log(max(0.01, min(0.99, p_ingress)))
                vnode = f"VULN:{vuln.id}"
                
                asset_name = asset.asset_identifier if asset else "Perimeter"
                exploit_info = caps["exploit_info"]
                
                self.graph.add_edge(
                    "INTERNET", 
                    vnode, 
                    vuln_id=vuln.id, 
                    weight=weight,
                    probability=p_ingress,
                    from_label="The Public Internet",
                    to_label=f"{asset_name} ({vuln.title})",
                    exploitation_path=exploit_info["payload"],
                    technique=exploit_info["technique"],
                    mitre_technique=exploit_info["mitre"],
                    step_type="ingress",
                    reason=f"Direct perimeter exploit: {exploit_info['summary']}"
                )
                logger.info(f"Ingress Edge: [INTERNET] -> [{vuln.title[:25]}] (P={p_ingress:.2f})")

        # 5. Connect Vulnerability-to-Vulnerability Edges (V_parent -> V_child)
        # Evaluates how individual vulnerabilities combine and chain together
        for parent_vuln in validated_vulns:
            parent_node = f"VULN:{parent_vuln.id}"
            parent_caps = vuln_capabilities[parent_vuln.id]

            for child_vuln in validated_vulns:
                if parent_vuln.id == child_vuln.id:
                    continue

                child_node = f"VULN:{child_vuln.id}"
                child_caps = vuln_capabilities[child_vuln.id]
                
                # Check causal chaining
                can_chain, trans_prob, chain_mech, exploit_path, reason = await self._evaluate_vulnerability_chain(
                    parent_vuln, child_vuln, parent_caps, child_caps, asset_map
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
                        from_label=f"{parent_asset.asset_identifier if parent_asset else 'Asset'} ({parent_vuln.title})",
                        to_label=f"{child_asset.asset_identifier if child_asset else 'Asset'} ({child_vuln.title})",
                        exploitation_path=exploit_path,
                        technique=chain_mech,
                        mitre_technique="T1210 - Exploitation of Remote Services",
                        step_type="chain",
                        reason=reason
                    )
                    logger.info(f"Causal Chain Edge: [{parent_vuln.title[:15]}] -> [{child_vuln.title[:15]}] (P={trans_prob:.2f})")

        # 6. Connect Vulnerabilities to Crown Jewel Target Objectives
        for vuln in validated_vulns:
            caps = vuln_capabilities[vuln.id]
            vnode = f"VULN:{vuln.id}"
            asset = asset_map.get(vuln.asset_id)
            exploit_info = caps["exploit_info"]

            for jewel in crown_jewels:
                jnode = f"JEWEL:{jewel.id}"
                
                # Estimate pivot probability to crown jewel based on capability
                if caps["has_creds"]:
                    pivot_prob = 0.94
                    chain_mech = "Authenticated Database Login via Compromised Credentials"
                    pivot_reason = f"Compromised credentials from '{vuln.title}' enable authenticated login directly into Crown Jewel DB ({jewel.asset_identifier})."
                elif caps["is_internal_pivot"]:
                    pivot_prob = 0.88
                    chain_mech = "Internal DMZ Pivot & Direct Port Forwarding"
                    pivot_reason = f"Internal network pivot from '{vuln.title}' allows direct socket tunneling into Crown Jewel DB ({jewel.asset_identifier})."
                elif caps["is_code_exec"]:
                    pivot_prob = 0.86
                    chain_mech = "Remote Command Execution Shell Routing"
                    pivot_reason = f"Remote code execution from '{vuln.title}' allows routing internal database queries into Crown Jewel DB ({jewel.asset_identifier})."
                elif caps["is_db_access"]:
                    pivot_prob = 0.92
                    chain_mech = "Direct SQL Data Exfiltration & Database Dumping"
                    pivot_reason = f"SQL Injection on '{vuln.title}' directly dumps tables and records from Crown Jewel DB ({jewel.asset_identifier})."
                else:
                    pivot_prob = 0.65
                    chain_mech = "Privilege Escalation & Objective Impact"
                    pivot_reason = f"Exploitation of '{vuln.title}' enables privilege elevation leading to compromise of {jewel.asset_identifier}."

                weight = -math.log(max(0.01, min(0.99, pivot_prob)))
                self.graph.add_edge(
                    vnode,
                    jnode,
                    vuln_id=vuln.id,
                    weight=weight,
                    probability=pivot_prob,
                    from_label=asset.asset_identifier if asset else "Perimeter",
                    to_label=jewel.asset_identifier,
                    exploitation_path=f"Direct pivot to {jewel.asset_identifier} using capability: {exploit_info['capability']}",
                    technique=chain_mech,
                    mitre_technique="T1530 - Data from Cloud / Database Object",
                    step_type="objective",
                    reason=pivot_reason
                )
                logger.info(f"Objective Edge: [{vuln.title[:20]}] -> [{jewel.asset_identifier}] (P={pivot_prob:.2f})")

        # 7. Find and Rank Attack Paths to Crown Jewels by Maximum Likelihood
        await self.db.clear_attack_paths()

        for jewel in crown_jewels:
            jnode = f"JEWEL:{jewel.id}"
            if not nx.has_path(self.graph, "INTERNET", jnode):
                logger.info(f"Objective ({jewel.asset_identifier}) is unreachable from current graph state.")
                continue

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
                    await self._build_consolidated_path(found_paths, jewel, asset_map, validated_vulns, vuln_capabilities)

            except Exception as e:
                logger.error(f"Failed calculating attack paths to {jnode}: {e}", exc_info=True)

    def _infer_capabilities(self, vuln: VulnerabilityRecord) -> Dict[str, Any]:
        """Infers offensive capabilities granted by exploiting this vulnerability."""
        title_lower = vuln.title.lower()
        
        has_creds = bool(vuln.has_leaked_creds or any(w in title_lower for w in ["credential", "password", "token", "secret", ".env", "cwe-798", "cwe-200", "auth", "key"]))
        is_code_exec = bool(any(w in title_lower for w in ["rce", "command", "exec", "cwe-78", "spring4shell"]))
        is_internal_pivot = bool(any(w in title_lower for w in ["ssrf", "proxy", "metadata", "tunnel", "23017"]) or is_code_exec)
        is_info_disc = bool(any(w in title_lower for w in ["lfi", "traversal", "23017", "disclosure", "dir", "dlr", "swagger", "git", "cwe-200", "cwe-538"]))
        is_db_access = bool(any(w in title_lower for w in ["sql", "injection", "database", "cwe-89"]))
        is_phish = bool(any(w in title_lower for w in ["phish", "dmarc", "spf", "email", "t1566"]))
        is_api = bool(any(w in title_lower for w in ["api", "bola", "idor", "cwe-639", "cwe-306"]))
        
        base_prob = min(0.95, max(0.35, (vuln.criticality_score / 10.0) * vuln.confidence_score))

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
        child_caps: Dict[str, Any],
        asset_map: Dict[str, TargetAsset]
    ) -> Tuple[bool, float, str, str, str]:
        """
        Determines how individual vulnerabilities combine and chain together.
        Returns: (is_chainable, probability, chain_mechanism, exploitation_path, reason)
        """
        # Check if LLM provides specific chain reasoning
        if hasattr(self.llm, "evaluate_vuln_transition"):
            try:
                res = await self.llm.evaluate_vuln_transition(parent_vuln, child_vuln)
                if res.get("is_chainable"):
                    return (
                        True,
                        float(res.get("transition_probability", 0.85)),
                        str(res.get("chain_mechanism", "Sequential Vulnerability Chain")),
                        str(res.get("exploitation_path", f"Adversary pivots from '{parent_vuln.title}' to '{child_vuln.title}'.")),
                        str(res.get("causal_reason", ""))
                    )
            except Exception as e:
                logger.warning(f"LLM transition query failed ({e}), falling back to deterministic capability rules.")

        parent_title = parent_vuln.title
        child_title = child_vuln.title

        # Rule 1: Credentials / Secrets Leak -> Exploits Authenticated Target
        if parent_caps["has_creds"]:
            return (
                True, 
                0.92, 
                "Credential Extraction & Session Reuse",
                f"Adversary uses credentials extracted from '{parent_title}' to authenticate against '{child_title}'.",
                f"Credentials compromised via '{parent_title}' satisfy authentication requirements for '{child_title}'."
            )

        # Rule 2: Remote Code Execution -> Host Takeover & Internal Network Pivot
        if parent_caps["is_code_exec"]:
            return (
                True, 
                0.88, 
                "RCE Shell Pivoting & Internal Port Forwarding",
                f"From interactive shell on '{parent_title}', adversary issues local network requests targeting '{child_title}'.",
                f"Remote code execution on '{parent_title}' bypasses firewalls to expose internal interface of '{child_title}'."
            )

        # Rule 3: Information Disclosure / Config Leak -> Discloses Parameters / Keys
        if parent_caps["is_info_disc"] or parent_caps["is_api"]:
            return (
                True, 
                0.82, 
                "Configuration Token & Parameter Propagation",
                f"Adversary extracts configuration keys and hidden endpoints from '{parent_title}' to format exploit against '{child_title}'.",
                f"Secret tokens and endpoint discovery via '{parent_title}' provide parameters needed to target '{child_title}'."
            )

        # Rule 4: SSRF / Internal Proxy -> Direct DMZ Bypass
        if parent_caps["is_internal_pivot"]:
            return (
                True, 
                0.85, 
                "SSRF Internal Proxy Tunneling",
                f"Adversary crafts SSRF requests through '{parent_title}' reaching otherwise isolated '{child_title}'.",
                f"SSRF tunnel on '{parent_title}' routes across network boundaries directly into '{child_title}'."
            )

        # Rule 5: Database Injection -> Stored Data & DB Procedures
        if parent_caps["is_db_access"]:
            return (
                True, 
                0.80, 
                "Database Data Extraction & Privilege Escalation",
                f"Adversary uses SQL query execution on '{parent_title}' to recover secrets required for '{child_title}'.",
                f"Database access from '{parent_title}' unlocks internal credentials and procedures targeting '{child_title}'."
            )

        # Rule 6: Phishing -> User Session Access
        if parent_caps["is_phish"]:
            return (
                True, 
                0.78, 
                "Stolen User Session Replay",
                f"Adversary uses harvested session cookies from '{parent_title}' to access '{child_title}'.",
                f"Phishing campaign harvests active user sessions, permitting authenticated exploit of '{child_title}'."
            )

        return False, 0.0, "", "", ""

    async def _build_consolidated_path(
        self, 
        found_paths: List[List[str]], 
        jewel: TargetAsset, 
        asset_map: Dict[str, TargetAsset], 
        validated_vulns: List[VulnerabilityRecord],
        vuln_capabilities: Optional[Dict[str, Dict[str, Any]]] = None
    ):
        """
        Consolidates attack trajectories into an understandable AttackPath record:
        1. Explicitly maps out the exploitation path to every vulnerability in the chain.
        2. Shows how vulnerabilities chain together sequentially.
        3. Identifies the break-the-chain chokepoint and prioritizes fixes.
        4. Dynamically builds the attack narrative based on the actual execution plan.
        """
        if vuln_capabilities is None:
            vuln_capabilities = {}
        raw_path = found_paths[0]
        step_details = []
        vuln_ids_in_chain = []
        asset_ids_in_chain = []
        cumulative_prob = 1.0

        for u, v in zip(raw_path[:-1], raw_path[1:]):
            edge_data = self.graph.get_edge_data(u, v) or {}
            prob = edge_data.get("probability", 0.85)
            cumulative_prob *= prob
            vuln_id = edge_data.get("vuln_id")
            
            if vuln_id and vuln_id not in vuln_ids_in_chain:
                vuln_ids_in_chain.append(vuln_id)

            vuln_title = "Perimeter Exploitation"
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
                "exploitation_path": edge_data.get("exploitation_path", "Exploit payload executed against target service."),
                "technique": edge_data.get("technique", "Exploit Public-Facing Application"),
                "mitre_technique": edge_data.get("mitre_technique", "T1190"),
                "step_type": edge_data.get("step_type", "chain"),
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

        # ---------------------------------------------------------------------
        # Break-the-Chain Chokepoint Identification:
        # Prioritize the vulnerability that severs the attack chain with highest impact
        # ---------------------------------------------------------------------
        chokepoint_vuln_id = ""
        vulns_by_id = {v.id: v for v in validated_vulns}
        
        if vuln_ids_in_chain:
            # Score each candidate by: (severity * path_position_weight)
            # Early nodes break the chain sooner, preventing all downstream exploitation
            best_candidate = vuln_ids_in_chain[0]
            max_severance_score = 0.0
            
            for idx, vid in enumerate(vuln_ids_in_chain):
                v_obj = vulns_by_id.get(vid)
                score = v_obj.criticality_score if v_obj else 5.0
                # Earlier nodes in chain have higher multiplier for breaking the chain before escalation
                position_weight = 1.0 + (0.3 * (len(vuln_ids_in_chain) - idx))
                severance = score * position_weight
                if severance > max_severance_score:
                    max_severance_score = severance
                    best_candidate = vid

            chokepoint_vuln_id = best_candidate

        chokepoint_vuln = vulns_by_id.get(chokepoint_vuln_id)
        final_prob = round(max(0.1, min(0.99, cumulative_prob)), 2)
        total_risk = round(min(9.9, 5.5 + (final_prob * 4.4)), 1)

        # Group all discovered perimeter/exploit vectors together
        grouped_vectors = []
        seen_titles = set()
        for v in validated_vulns:
            t_clean = v.title.split("(")[0].strip()
            if t_clean in seen_titles:
                continue
            seen_titles.add(t_clean)
            
            caps = vuln_capabilities.get(v.id, self._infer_capabilities(v))
            exp = caps.get("exploit_info", derive_exploitation_path(v, asset_map.get(v.asset_id)))
            
            t_lower = v.title.lower()
            if any(k in t_lower for k in ["sql", "injection", "cwe-89"]):
                cat = "Web SQL Injection"
                icon = "fa-database"
            elif any(k in t_lower for k in ["env", "git", "dir", "dlr", "bruteforce", "cwe-538", "cwe-200"]):
                cat = "Sensitive File & Directory Exposure"
                icon = "fa-folder-open"
            elif any(k in t_lower for k in ["api", "bola", "idor", "cwe-639", "cwe-306"]):
                cat = "API Broken Authorization"
                icon = "fa-code"
            elif any(k in t_lower for k in ["phish", "dmarc", "spf", "email", "t1566"]):
                cat = "Email Spoofing & Phishing Vector"
                icon = "fa-envelope-open-text"
            elif any(k in t_lower for k in ["rce", "command", "cwe-78", "23017", "nginx", "spring4shell"]):
                cat = "Remote Code Execution"
                icon = "fa-terminal"
            else:
                cat = "Perimeter Security Flaw"
                icon = "fa-shield-halved"

            grouped_vectors.append({
                "vuln_id": v.id,
                "title": v.title,
                "category": cat,
                "icon": icon,
                "severity": "CRITICAL" if v.criticality_score >= 8.5 else "HIGH" if v.criticality_score >= 7.0 else "MEDIUM",
                "cvss_score": v.criticality_score,
                "cwe": v.title.split("(")[-1].replace(")", "") if "(" in v.title else "CWE-General",
                "mitre_technique": exp.get("mitre", "T1190"),
                "exploitation_path": exp.get("payload", "Audit probe"),
                "description": exp.get("summary", v.title)
            })

        # ---------------------------------------------------------------------
        # Dynamic Attack Narrative (Changes with actual execution plan)
        # ---------------------------------------------------------------------
        chain_vuln_objs = [vulns_by_id[vid] for vid in vuln_ids_in_chain if vid in vulns_by_id]
        target_name = jewel.asset_identifier
        
        narrative_parts = []
        narrative_parts.append(
            f"Adversary targeting '{target_name}' discovers {len(chain_vuln_objs)} sequential vulnerability exploit vector(s) "
            f"that combine to form an unauthenticated exploitation path."
        )

        for s_idx, v_obj in enumerate(chain_vuln_objs):
            caps = vuln_capabilities.get(v_obj.id, {})
            exp = caps.get("exploit_info", derive_exploitation_path(v_obj))
            if s_idx == 0:
                narrative_parts.append(
                    f"Initial Ingress (Stage 1): Attacker targets '{v_obj.title}' using vector '{exp['method']}' "
                    f"with payload: '{exp['payload']}'. Exploiting this flaw grants '{exp['capability']}'."
                )
            else:
                prev_obj = chain_vuln_objs[s_idx - 1]
                narrative_parts.append(
                    f"Causal Lateral Pivot (Stage {s_idx + 1}): Leveraging the capability from '{prev_obj.title}', "
                    f"attacker advances to exploit '{v_obj.title}'. Exploitation path: '{exp['payload']}', establishing deeper internal access."
                )

        narrative_parts.append(
            f"Final Objective Impact: The exploitation corridor culminates in direct compromise of '{target_name}', "
            f"granting unauthorized database read/write permissions with cumulative chain likelihood of {final_prob * 100:.1f}%."
        )

        if chokepoint_vuln:
            narrative_parts.append(
                f"Prioritized Break-The-Chain Remediation: Remediating '{chokepoint_vuln.title}' (CVSS {chokepoint_vuln.criticality_score:.1f}) "
                f"is prioritized as the strategic chokepoint fix. Applying this fix severs the attack chain at the root, "
                f"permanently denying the attacker the prerequisites needed to pivot into '{target_name}'."
            )

        attack_narrative = " ".join(narrative_parts)

        # ---------------------------------------------------------------------
        # Dynamic 4-Stage Simplified Flow (Reflects actual vulnerabilities)
        # ---------------------------------------------------------------------
        v1 = chain_vuln_objs[0] if chain_vuln_objs else None
        v1_exp = derive_exploitation_path(v1) if v1 else {}
        v2 = chain_vuln_objs[1] if len(chain_vuln_objs) > 1 else None
        v2_exp = derive_exploitation_path(v2) if v2 else {}

        simplified_flow = [
            {
                "stage": 1,
                "stage_name": "Perimeter Ingress & Exploitation",
                "actor": "External Adversary",
                "location": "Public Internet",
                "badge": "Entry Point",
                "icon": "fa-globe",
                "color": "rose",
                "mitre_id": v1_exp.get("mitre", "T1190"),
                "mitre_name": "Initial Access",
                "headline": f"Exploitation of {v1.title if v1 else 'Perimeter Vulnerability'}",
                "explanation": f"Vector: {v1_exp.get('method', 'HTTP Request')} with payload: '{v1_exp.get('payload', 'Exploit Payload')}'. Grants {v1_exp.get('capability', 'initial unauthorized access')}."
            },
            {
                "stage": 2,
                "stage_name": "Capability Escalation & Secrets Leak",
                "actor": "Threat Actor",
                "location": "DMZ / Web Tier",
                "badge": "Credential Harvesting",
                "icon": "fa-key",
                "color": "amber",
                "mitre_id": "T1552 / T1078",
                "mitre_name": "Credential & Token Access",
                "headline": "Attacker extracts credentials and service tokens",
                "explanation": f"From the initial compromised surface, attacker captures tokens, passwords, and connection strings necessary for lateral pivot."
            },
            {
                "stage": 3,
                "stage_name": "Lateral Chaining & Internal Pivot",
                "actor": "Threat Actor",
                "location": "Internal DMZ Pivot",
                "badge": "Lateral Movement",
                "icon": "fa-arrows-split-up-and-left",
                "color": "purple",
                "mitre_id": v2_exp.get("mitre", "T1210"),
                "mitre_name": "Lateral Movement",
                "headline": f"Chains to {v2.title if v2 else 'Internal Subnet Service'}",
                "explanation": f"Attacker leverages harvested credentials or shell pivot to bypass firewalls, triggering secondary vulnerability on internal network."
            },
            {
                "stage": 4,
                "stage_name": "Target Objective & DB Compromise",
                "actor": "Threat Actor",
                "location": target_name,
                "badge": "Objective Achieved",
                "icon": "fa-database",
                "color": "cyan",
                "mitre_id": "T1530 / T1005",
                "mitre_name": "Data Exfiltration & Impact",
                "headline": f"Breach of Crown Jewel ({target_name})",
                "explanation": f"Attacker connects to Crown Jewel target, extracting sensitive databases and seizing administrative control."
            }
        ]

        # MITRE Tactics Mapping
        mitre_tactics = [
            {"tactic": "Initial Access", "id": "TA0001", "technique": v1_exp.get("mitre", "T1190")},
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
            f"Saved Dynamic Attack Chain: Likelihood={final_prob * 100:.1f}%, "
            f"Risk={total_risk}, Chokepoint={chokepoint_vuln_id[:8]}, Steps={len(step_details)}"
        )

        if chokepoint_vuln_id:
            await self.db.boost_vulnerability_priority(chokepoint_vuln_id, multiplier=1.5)