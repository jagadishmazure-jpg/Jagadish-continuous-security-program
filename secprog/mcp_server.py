"""Read-only exposure MCP-style server: get_exposure_score, top_choke_points, explain_cve_rank.

Speaks JSON-RPC 2.0 shapes over a function call (no network). Any write-like tool name is refused; writes go
through the approval inbox, never through this server.
"""
from __future__ import annotations

import json

TOOLS = {
    "get_exposure_score": {"args": {"scope": "org|bu name|asset id (optional)"}},
    "top_choke_points": {"args": {"limit": "int 1-10 (optional)"}},
    "explain_cve_rank": {"args": {"cve_id": "CVE-SYN-2026-NNNN (required)"}},
}
MAX_ARG_LEN = 64


def _err(i, code, msg):
    return {"jsonrpc": "2.0", "id": i, "error": {"code": code, "message": msg}}


def handle(req: dict) -> dict:
    from . import attack_paths, cve_rank, exposure
    i = req.get("id")
    if req.get("method") == "tools/list":
        return {"jsonrpc": "2.0", "id": i, "result": {"tools": [{"name": k, **v} for k, v in TOOLS.items()]}}
    if req.get("method") != "tools/call":
        return _err(i, -32601, "method not found")
    p = req.get("params") or {}
    name, args = p.get("name"), p.get("arguments") or {}
    if name not in TOOLS:
        return _err(i, -32602, "unknown or write tool refused (server is read-only)")
    for k, v in args.items():
        if k not in TOOLS[name]["args"]:
            return _err(i, -32602, f"unexpected argument {k}")
        if isinstance(v, str) and len(v) > MAX_ARG_LEN:
            return _err(i, -32602, "argument too long")
    try:
        if name == "get_exposure_score":
            s = exposure.scores()
            scope = args.get("scope", "org")
            if scope == "org":
                out = {"scope": "org", "score": s["org"]}
            elif scope in s["business_units"]:
                out = {"scope": scope, "score": s["business_units"][scope]}
            else:
                row = next(r for r in s["assets"] if r["asset"] == scope)
                out = {"scope": scope, "score": row["exposure"], "criticality": row["criticality"]}
        elif name == "top_choke_points":
            limit = args.get("limit", 5)
            if not isinstance(limit, int) or isinstance(limit, bool):
                return _err(i, -32602, "limit must be an integer")
            out = {"choke_points": attack_paths.choke_points(max(1, min(10, limit)))}
        else:
            if "cve_id" not in args:
                return _err(i, -32602, "cve_id is required")
            out = cve_rank.explain(args["cve_id"])
    except (KeyError, StopIteration):
        return _err(i, -32602, "not found")
    return {"jsonrpc": "2.0", "id": i, "result": {"content": [{"type": "text", "text": json.dumps(out)}]}}
