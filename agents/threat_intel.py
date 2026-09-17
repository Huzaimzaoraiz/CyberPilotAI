import logging
from typing import Dict, Any
from core.models import TargetAsset, VulnerabilityRecord, VulnStatus, TaskItem, AgentType
from tools.api_connectors import check_virustotal, check_hibp, check_dns_takeover

logger = logging.getLogger("ThreatIntelAgent")

class ThreatIntelAgent:
    def __init__(self, db_client, config: Dict[str, str] = None):
        self.db = db_client
        self.config = config or {}
        self.vt_api_key = self.config.get("vt_api_key")
        self.hibp_api_key = self.config.get("hibp_api_key")

    async def execute_task(self, payload: Dict[str, Any]):
        asset_id = payload.get("asset_id")
        
        asset: TargetAsset = await self.db.get_asset(asset_id)
        if not asset or not asset.is_authorized:
            logger.warning("Threat Intel aborted: Asset not found or unauthorized.")
            return

        domain = asset.asset_identifier
        # Skip IP addresses, OSINT APIs generally require domains
        if any(c.isalpha() for c in domain) is False:
            logger.info(f"Skipping OSINT for IP address: {domain}")
            return

        logger.info(f"Running Intelligence checks on {domain}...")

        # 1. DNS Takeover Check
        is_dangling = await check_dns_takeover(domain)
        if is_dangling:
            await self._report_intel_finding(
                asset_id=asset.id,
                title="Potential Subdomain Takeover (Dangling DNS Record)",
                score=8.5,
                has_leaked_creds=False
            )

        # 2. Domain Reputation Check (VirusTotal)
        vt_results = await check_virustotal(domain, self.vt_api_key)
        if vt_results["malicious_votes"] > 2:
            await self._report_intel_finding(
                asset_id=asset.id,
                title=f"Domain flagged as Malicious by {vt_results['malicious_votes']} vendors",
                score=6.0,
                has_leaked_creds=False
            )

        # 3. Credential Breach Check (HIBP)
        breaches = await check_hibp(domain, self.hibp_api_key)
        for breach in breaches:
            if "Passwords" in breach["data_classes"]:
                logger.warning(f"Credential exposure found for {domain} in {breach['breach_name']}. ")
                
                # SECURITY RULE ENFORCED: Setting boolean flag, no raw data handled.
                await self._report_intel_finding(
                    asset_id=asset.id,
                    title=f"Corporate credentials exposed in {breach['breach_name']} breach",
                    score=7.5,
                    has_leaked_creds=True 
                )

    async def _report_intel_finding(self, asset_id: str, title: str, score: float, has_leaked_creds: bool):
        """Pushes Threat Intel findings directly to VALIDATED and queues downstream tasks."""
        
        vuln_record = VulnerabilityRecord(
            asset_id=asset_id,
            title=title,
            criticality_score=score,
            layer="OSINT",
            status=VulnStatus.VALIDATED,  # OSINT is deterministically validated
            discovery_source="THREAT_INTEL",
            confidence_score=0.95, 
            has_leaked_creds=has_leaked_creds
        )
        
        vuln_id = await self.db.insert_vulnerability(vuln_record)
        
        # Because it is validated, we immediately trigger the Remediation and Attack Path agents
        priority = int(score * 10)
        
        await self.db.insert_task(
            TaskItem(target_agent=AgentType.REMEDIATION, priority=priority, payload={"vulnerability_id": vuln_id})
        )
        
        await self.db.insert_task(
            TaskItem(target_agent=AgentType.ATTACK_PATH, priority=priority, payload={"trigger": "new_osint_validation"})
        )