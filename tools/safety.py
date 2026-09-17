import re
import logging
from typing import Tuple

logger = logging.getLogger("SafetyTools")

class SafetyValidator:
    """Hardcoded heuristics to prevent destructive payloads from being executed."""
    
    BANNED_SQL = r"(?i)\b(DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE|GRANT|REVOKE)\b"
    BANNED_BASH = r"(?i)(\brm\b|\bmv\b|\bmkfs\b|>|>>|\bkill\b|\breboot\b|\bshutdown\b|\bchmod\b)"
    
    @classmethod
    def validate_payload(cls, payload: str) -> Tuple[bool, str]:
        """Returns (is_safe: bool, reason: str)"""
        if not payload:
            return False, "Payload is empty."

        if re.search(cls.BANNED_SQL, payload):
            return False, "Payload contains destructive SQL keywords."
            
        if re.search(cls.BANNED_BASH, payload):
            return False, "Payload contains destructive shell commands."

        return True, "Payload passed safety heuristics."

class DataSanitizer:
    """Scrubs sensitive information from HTTP responses before evaluation or storage."""
    
    AWS_KEY_PATTERN = r"(?i)AKIA[0-9A-Z]{16}"
    PRIVATE_KEY_PATTERN = r"-----BEGIN [R|D]SA PRIVATE KEY-----.*?-----END [R|D]SA PRIVATE KEY-----"
    
    @classmethod
    def scrub_response(cls, response_text: str) -> Tuple[str, bool]:
        """Returns (scrubbed_text, found_secrets_boolean)."""
        found_secrets = False
        scrubbed = response_text
        
        if re.search(cls.AWS_KEY_PATTERN, scrubbed):
            scrubbed = re.sub(cls.AWS_KEY_PATTERN, "[REDACTED_AWS_KEY]", scrubbed)
            found_secrets = True
            
        if re.search(cls.PRIVATE_KEY_PATTERN, scrubbed, flags=re.DOTALL):
            scrubbed = re.sub(cls.PRIVATE_KEY_PATTERN, "[REDACTED_PRIVATE_KEY]", scrubbed, flags=re.DOTALL)
            found_secrets = True
            
        return scrubbed, found_secrets

async def execute_in_sandbox(payload: str, target: str) -> str:
    """
    Simulates executing a payload against a target over the network.
    In production, this would use httpx inside an isolated Docker container.
    """
    logger.info(f"[Sandbox] Firing payload at {target}...")
    
    # 1. Simulate a successful Command Injection response
    if "echo AGENT" in payload or "AGENT" in payload or "whoami" in payload or "id" in payload:
        return "root\nAGENT_VALIDATED_SUCCESS\nuid=0(root) gid=0(root)"
        
    # 2. Simulate an LFI (Local File Inclusion) reading an AWS key
    if "etc/passwd" in payload or "metadata" in payload or "path-as-is" in payload:
        return "HTTP/1.1 200 OK\nServer: nginx/1.18.0\n\nroot:x:0:0:root:/root:/bin/bash\nAKIAIOSFODNN7EXAMPLE"

    # 3. Simulate SQL injection response
    if "1=1" in payload or "OR" in payload or "union" in payload.lower():
        return "HTTP/1.1 200 OK\nServer: nginx/1.18.0\n\nDatabase error: syntax error near 'OR 1=1' in query\nroot"

    # 4. Simulate XSS reflection response
    if "<script>" in payload or "alert(" in payload or "canary" in payload:
        return f"HTTP/1.1 200 OK\nServer: nginx/1.18.0\nContent-Type: text/html\n\n<html><body><div id='search-results'>Query: {payload}</div></body></html>"

    # 5. Simulate HTTP service/header probe (e.g. curl -I, version checks)
    if "curl" in payload.lower() or "http" in payload.lower():
        return "HTTP/1.1 200 OK\nServer: nginx/1.18.0\nDate: Wed, 16 Sep 2026 21:45:00 GMT\nContent-Type: text/html\n\n<html><body>nginx 1.18.0 running</body></html>"
        
    # Default failure response
    return "HTTP/1.1 200 OK\nServer: nginx/1.18.0\n\n403 Forbidden"