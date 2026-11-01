"""Use cases: each one names the problem, the command that shows it and the module that does it.

USE_CASES.md is generated from this list so the doc and the code cannot drift.
"""
from __future__ import annotations

USE_CASES = [
    ("UC-01", "Pick today's top 5 fixes", "python -m secprog five", "ctem.five_minute_list"),
    ("UC-02", "Rank dependency CVEs better than CVSS-only", "python -m secprog rank", "cve_rank.evaluate"),
    ("UC-03", "Exposure score per asset, business unit and company", "python -m secprog exposure",
     "exposure.scores"),
    ("UC-04", "Find attack-path choke points and toxic combinations", "python -m secprog paths", "attack_paths"),
    ("UC-05", "Close a ticket only after a rescan passes (CTEM)", "python -m secprog ctem", "ctem.Cycle"),
    ("UC-06", "Import code, secrets and DAST scans into one findings list", "python -m secprog findings",
     "findings"),
    ("UC-07", "Device posture, AV exclusions and exposed ports", "python -m secprog devices", "devices"),
    ("UC-08", "Access review with human decisions", "python -m secprog access", "access_review"),
    ("UC-09", "Answer a security questionnaire with citations and expert review", "python -m secprog questionnaire",
     "questionnaire"),
    ("UC-10", "Trust Center with NDA rules, AI disclosures and a KEV playbook", "python -m secprog trust",
     "trust_center"),
    ("UC-11", "Vendor risk assessment with human residual-risk decision", "python -m secprog tprm", "tprm"),
    ("UC-12", "Block spend approved before security review", "python -m secprog purchases", "tprm.purchase_gate"),
    ("UC-13", "Tier 0 identity checks and a clean-room recovery drill", "python -m secprog identity",
     "identity_recovery"),
    ("UC-14", "SOC authority registry and per-phase MTTR", "python -m secprog soc", "soc_authority"),
    ("UC-15", "Phishing training, insurance readiness and a consensus gate", "python -m secprog human",
     "endpoint_human"),
    ("UC-16", "Exposure validation with a safety reviewer", "python -m secprog validate", "exposure_validation"),
    ("UC-17", "Reject phantom pentest findings", "python -m secprog pentest", "pentest_agent"),
    ("UC-18", "MSP view: tenant isolation, roadmap, tiers, oversharing", "python -m secprog msp", "msp"),
    ("UC-19", "Framework readiness rings and coverage summary", "python -m secprog frameworks", "frameworks"),
    ("UC-20", "The 12 AI governance KPIs", "python -m secprog ai-gov", "ai_governance"),
    ("UC-21", "Govern our own agents (shadow -> recommend -> enforce)", "python -m secprog governance",
     "governance"),
    ("UC-22", "Daily and weekly report previews (never sent)", "python -m secprog report --kind weekly --out out",
     "reports"),
    ("UC-23", "Trust Dashboard HTML", "python -m secprog dashboard --out out", "dashboard"),
    ("UC-24", "GRC Copilot (12 questions)", "python -m secprog copilot q01", "copilot"),
    ("UC-25", "Read-only MCP server for exposure data", "python -m secprog mcp-demo", "mcp_server"),
    ("UC-26", "vCISO queue and mock audit", "python -m secprog audit", "vciso"),
    ("UC-27", "AI exposure discovery, register and outage drill", "python -m secprog ai-exposure", "ai_exposure"),
    ("UC-28", "Coordinator week: plans, gates and approvals", "python -m secprog coordinator", "coordinator"),
    ("UC-29", "Score browser extensions, gate unmanaged browsers, replay an infostealer case", "python -m secprog browser",
     "browser"),
]


def markdown() -> str:
    lines = ["| ID | Use case | Command | Module |", "|---|---|---|---|"]
    lines += [f"| {i} | {t} | `{c}` | `secprog.{m}` |" for i, t, c, m in USE_CASES]
    return "\n".join(lines) + "\n"
