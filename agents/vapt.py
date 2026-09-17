import logging
from typing import Dict, Any, List
from core.models import TargetAsset, VulnerabilityRecord, VulnStatus, TaskItem, AgentType
from tools.scanners import run_nmap, query_nvd, scan_web_vulnerabilities

logger = logging.getLogger("VAPTAgent")

class MockLLMClient:
    """Simulates an LLM parsing terminal output into JSON/CPE formats."""
    async def extract_cpe_from_nmap(self, nmap_output: str) -> List[str]:
        cpes = []
        output_lower = nmap_output.lower()
        if "nginx" in output_lower:
            cpes.append("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*")
        if "openssh" in output_lower or "ssh" in output_lower:
            cpes.append("cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*")
        return cpes

class VAPTAgent:
    def __init__(self, db_client, llm_client, nvd_api_key: str = None):
        self.db = db_client
        self.llm = llm_client
        self.nvd_api_key = nvd_api_key

    async def execute_task(self, payload: Dict[str, Any]):
        """The main execution flow for Recon and Discovery."""
        asset_id = payload.get("asset_id")
        
        # 1. ENFORCE SCOPE (Critical Security Boundary)
        asset: TargetAsset = await self.db.get_asset(asset_id)
        if not asset:
            logger.error(f"Asset {asset_id} not found. Aborting.")
            return
            
        if not asset.is_authorized:
            logger.warning(f"SECURITY BLOCK: Asset {asset.asset_identifier} is not authorized for testing.")
            return

        target = asset.asset_identifier
        logger.info(f"Starting VAPT scan on authorized target: {target}")

        # 2. Network Reconnaissance
        nmap_output = await run_nmap(target)
        if nmap_output:
            # 3. LLM Parsing (Convert messy text to structured Common Platform Enumerations)
            cpe_list = await self.llm.extract_cpe_from_nmap(nmap_output)
            logger.info(f"LLM extracted {len(cpe_list)} services for vulnerability correlation.")

            # 4. Threat Intel Cross-referencing
            for cpe in cpe_list:
                vulnerabilities = await query_nvd(cpe, self.nvd_api_key)
                for vuln in vulnerabilities:
                    await self._queue_validation_task(asset.id, cpe, vuln)

        # 5. Web Application Vulnerability Discovery (SQLi, XSS, Security Headers, CORS)
        if asset.layer in ["Web", "Cloud"] or "http" in target.lower() or any(c.isalpha() for c in target):
            logger.info(f"[VAPT] Auditing web application vulnerabilities (SQLi, XSS, Headers) on {target}...")
            web_findings = await scan_web_vulnerabilities(target)
            for w_vuln in web_findings:
                await self._queue_web_validation_task(asset.id, w_vuln)

        logger.info(f"VAPT scan complete for {target}.")

    async def _queue_validation_task(self, asset_id: str, cpe: str, vuln: Dict):
        """Creates the DB record and pushes it to the Orchestrator Queue."""
        cve_id = vuln['cve_id']
        cvss_score = vuln['cvss_score']
        
        # Write to Shared Database as UNVALIDATED
        vuln_record = VulnerabilityRecord(
            asset_id=asset_id,
            title=f"Potential {cve_id} in {cpe.split(':')[4]}",
            criticality_score=cvss_score,
            layer="Network",
            status=VulnStatus.UNVALIDATED, 
            discovery_source="TOOL_EVIDENCE",
            confidence_score=0.3 # Low confidence until mathematically proven
        )
        
        record_id = await self.db.insert_vulnerability(vuln_record)
        
        # Translate CVSS (0-10) to Queue Priority (0-100)
        # A CVSS 9.8 becomes Priority 98, ensuring the Orchestrator validates it first.
        priority = int(cvss_score * 10)
        
        task = TaskItem(
            target_agent=AgentType.VALIDATION,
            priority=priority,
            payload={
                "vulnerability_id": record_id,
                "cve_id": cve_id,
                "context": vuln['description']
            }
        )
        
        await self.db.insert_task(task)
        logger.info(f"Found {cve_id} (CVSS: {cvss_score}). Queued for Validation with Priority {priority}.")

    async def _queue_web_validation_task(self, asset_id: str, vuln: Dict):
        """Creates the DB record for web vulnerabilities (SQLi, XSS, headers) and queues for validation."""
        title = vuln.get("title", "Web Application Flaw")
        cvss_score = float(vuln.get("cvss_score", 7.5))
        cwe_id = vuln.get("cwe_id", "CWE-Web")
        
        vuln_record = VulnerabilityRecord(
            asset_id=asset_id,
            title=f"{title} ({cwe_id})",
            criticality_score=cvss_score,
            layer="Web",
            status=VulnStatus.UNVALIDATED,
            discovery_source="TOOL_WEB_SCANNER",
            confidence_score=0.4
        )
        record_id = await self.db.insert_vulnerability(vuln_record)
        priority = int(cvss_score * 10)
        
        task = TaskItem(
            target_agent=AgentType.VALIDATION,
            priority=priority,
            payload={
                "vulnerability_id": record_id,
                "cve_id": cwe_id,
                "context": f"{title}. Test payload: {vuln.get('test_payload', 'Standard web probe')}"
            }
        )
        await self.db.insert_task(task)
        logger.info(f"Queued {title} ({cwe_id}, CVSS: {cvss_score}) for Validation with Priority {priority}.")