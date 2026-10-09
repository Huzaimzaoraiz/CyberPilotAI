import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from .pdf_export import generate_pdf_report
from .json_export import generate_json_report

def report_exporter(db_snapshot: Dict[str, Any], format: str = "pdf") -> bytes:
    """
    Unified report export helper returning raw bytes for either 'pdf' or 'json'.
    """
    fmt = format.lower().strip()
    if fmt == "json":
        data = generate_json_report(db_snapshot)
        return json.dumps(data, indent=2).encode("utf-8")
    return generate_pdf_report(db_snapshot)
