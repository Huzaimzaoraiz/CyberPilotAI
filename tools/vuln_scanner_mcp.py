#!/usr/bin/env python3
"""
Vulnerability Detection MCP Server
Standard Model Context Protocol (MCP) stdio server providing vulnerability detection tools.
"""

import sys
import json
import asyncio
from typing import Dict, Any

from tools.vuln_scanner.utils import log, tool_mitre_mapper
from tools.vuln_scanner.sast import tool_scan_sqli, tool_scan_xss, tool_scan_code_sast
from tools.vuln_scanner.web import tool_scan_web_vulnerabilities, tool_dlr_bruteforce, tool_api_endpoint_scanner, tool_scan_owasp_top10
from tools.vuln_scanner.intel import tool_query_cve_knowledgebase, tool_scan_phishing

async def handle_tool_call(name: str, arguments: Dict[str, Any]) -> Any:
    if name == "scan_sqli":
        return await tool_scan_sqli(arguments.get("target", ""), arguments.get("param_name"))
    elif name == "scan_xss":
        return await tool_scan_xss(arguments.get("target", ""))
    elif name == "scan_code_sast":
        return await tool_scan_code_sast(arguments.get("file_path_or_code", ""), arguments.get("language"))
    elif name == "scan_web_vulnerabilities":
        return await tool_scan_web_vulnerabilities(arguments.get("url", ""), arguments.get("check_injection", True))
    elif name == "query_cve_knowledgebase":
        return await tool_query_cve_knowledgebase(arguments.get("component", ""), arguments.get("version"))
    elif name == "scan_phishing":
        return await tool_scan_phishing(arguments.get("target_or_email", ""), arguments.get("sender_domain"))
    elif name in ["dlr_bruteforce", "dir_bruteforce"]:
        return await tool_dlr_bruteforce(arguments.get("target_url", ""), arguments.get("wordlist_type", "common"))
    elif name == "api_endpoint_scanner":
        return await tool_api_endpoint_scanner(arguments.get("target_url", ""), arguments.get("deep_scan", True))
    elif name == "mitre_mapper":
        return tool_mitre_mapper(arguments.get("finding_or_cwe", ""))
    elif name == "scan_owasp_top10":
        return await tool_scan_owasp_top10(arguments.get("target_url", ""))
    else:
        raise ValueError(f"Unknown tool: {name}")

async def run_mcp_server():
    """Main MCP JSON-RPC stdio event loop."""
    log("Vulnerability Detection MCP Server starting up...")
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

    while True:
        line_bytes = await reader.readline()
        if not line_bytes:
            break
            
        line = line_bytes.decode("utf-8").strip()
        if not line:
            continue

        try:
            req = json.loads(line)
        except Exception as e:
            log(f"Failed to parse JSON: {e}")
            continue

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        # Handle notifications
        if method == "notifications/initialized" or method == "initialized":
            log("Client initialized connection.")
            continue

        # Handle requests
        if method == "initialize":
            res = {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "vulnerability-detection-server",
                    "version": "1.0.0"
                }
            }
            out = json.dumps({"jsonrpc": "2.0", "id": req_id, "result": res})
            sys.stdout.write(out + "\n")
            sys.stdout.flush()

        elif method == "tools/list":
            res = {"tools": TOOLS_METADATA}
            out = json.dumps({"jsonrpc": "2.0", "id": req_id, "result": res})
            sys.stdout.write(out + "\n")
            sys.stdout.flush()

        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            log(f"Executing tool call '{tool_name}' with args: {tool_args}")
            try:
                tool_result = await handle_tool_call(tool_name, tool_args)
                res = {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(tool_result, indent=2)
                        }
                    ]
                }
                out = json.dumps({"jsonrpc": "2.0", "id": req_id, "result": res})
            except Exception as err:
                log(f"Tool execution failed: {err}")
                out = json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32000,
                        "message": str(err)
                    }
                })
            sys.stdout.write(out + "\n")
            sys.stdout.flush()

        elif method == "ping":
            out = json.dumps({"jsonrpc": "2.0", "id": req_id, "result": {}})
            sys.stdout.write(out + "\n")
            sys.stdout.flush()

        else:
            if req_id is not None:
                out = json.dumps({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}"
                    }
                })
                sys.stdout.write(out + "\n")
                sys.stdout.flush()

if __name__ == "__main__":
    asyncio.run(run_mcp_server())
