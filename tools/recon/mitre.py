import os
import re
import math
import socket
import ssl
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import requests

logger = logging.getLogger("ReconTools")

from .cache import MITRE_TECHNIQUES_DB

def mitre_attack_lookup(technique_id: str) -> Dict[str, Any]:
    """
    Maps technique ID (e.g. T1190, T1059) to MITRE ATT&CK tactic, description, and mitigation.
    """
    t_id = technique_id.strip().upper()
    if t_id in MITRE_TECHNIQUES_DB:
        info = MITRE_TECHNIQUES_DB[t_id]
        return {
            "technique_id": t_id,
            "technique_name": info["technique_name"],
            "tactic": info["tactic"],
            "description": info["description"],
            "mitigation": info["mitigation"],
            "source": "tool"
        }

    # Generic lookup fallback
    return {
        "technique_id": t_id,
        "technique_name": f"Enterprise Technique {t_id}",
        "tactic": "Lateral Movement / Execution",
        "description": f"MITRE ATT&CK enterprise technique mapped under identifier {t_id}.",
        "mitigation": "Enforce strict host isolation, least privilege, and behavior-based monitoring.",
        "source": "tool"
    }


# -----------------------------------------------------------------------------
# 9. dir_bruteforce
# -----------------------------------------------------------------------------
