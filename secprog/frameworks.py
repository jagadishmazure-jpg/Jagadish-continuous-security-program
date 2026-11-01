"""Framework crosswalks, readiness rings and a coverage summary.

Requirement ids are real section numbers; the short names are our own paraphrases, not official text.
Every mapping is our reading ("approximate") unless marked otherwise, and is not legal advice or an
auditor's opinion. Readiness comes only from the synthetic control results in controls.py.
"""
from __future__ import annotations

from . import svgchart
from .controls import SCORE, results

# framework -> (display name, mapping type, {requirement id: (short name, [controls])})
FRAMEWORKS: dict[str, tuple[str, str, dict]] = {
    "SOC2": ("SOC 2 (2017 TSC)", "approximate", {
        "CC1.4": ("Competence and training", ["CTL-12"]),
        "CC2.1": ("Information quality for control", ["CTL-16", "CTL-25"]),
        "CC3.4": ("Change in risk (vendors, AI)", ["CTL-11", "CTL-18"]),
        "CC5.2": ("General IT controls", ["CTL-24"]),
        "CC6.1": ("Logical access security", ["CTL-01", "CTL-02", "CTL-15"]),
        "CC6.2": ("User registration and removal", ["CTL-04"]),
        "CC6.3": ("Role-based access and reviews", ["CTL-03"]),
        "CC6.6": ("External threats and boundaries", ["CTL-21", "CTL-26"]),
        "CC6.8": ("Malware prevention", ["CTL-06", "CTL-05"]),
        "CC7.1": ("Vulnerability detection", ["CTL-08", "CTL-09", "CTL-10"]),
        "CC7.2": ("Monitoring for anomalies", ["CTL-17", "CTL-16"]),
        "CC7.4": ("Incident response", ["CTL-13"]),
        "CC8.1": ("Change management", ["CTL-22"]),
        "CC9.2": ("Vendor and partner risk", ["CTL-11"]),
        "A1.2": ("Backup and recovery", ["CTL-14"]),
    }),
    "ISO27001": ("ISO/IEC 27001:2022 Annex A", "approximate", {
        "A.5.9": ("Inventory of assets", ["CTL-25"]),
        "A.5.15": ("Access control", ["CTL-01", "CTL-03"]),
        "A.5.19": ("Supplier relationships", ["CTL-11"]),
        "A.5.24": ("Incident management planning", ["CTL-13"]),
        "A.6.3": ("Awareness and training", ["CTL-12"]),
        "A.8.2": ("Privileged access rights", ["CTL-02", "CTL-15"]),
        "A.8.7": ("Protection against malware", ["CTL-06"]),
        "A.8.8": ("Technical vulnerabilities", ["CTL-07", "CTL-08"]),
        "A.8.13": ("Information backup", ["CTL-14"]),
        "A.8.15": ("Logging", ["CTL-16"]),
        "A.8.24": ("Use of cryptography", ["CTL-05", "CTL-26"]),
        "A.8.32": ("Change management", ["CTL-22"]),
    }),
    "NIST_CSF": ("NIST CSF 2.0", "approximate", {
        "GV.SC": ("Supply chain risk management", ["CTL-11"]),
        "GV.RR": ("Roles and responsibilities", ["CTL-29"]),
        "ID.AM": ("Asset management", ["CTL-25", "CTL-18"]),
        "ID.RA": ("Risk assessment", ["CTL-07", "CTL-10"]),
        "PR.AA": ("Identity and access", ["CTL-01", "CTL-02", "CTL-03", "CTL-15"]),
        "PR.AT": ("Awareness and training", ["CTL-12"]),
        "PR.DS": ("Data security", ["CTL-05", "CTL-21"]),
        "PR.PS": ("Platform security", ["CTL-06", "CTL-26"]),
        "DE.CM": ("Continuous monitoring", ["CTL-08", "CTL-17"]),
        "RS.MA": ("Incident management", ["CTL-13"]),
        "RC.RP": ("Recovery plan execution", ["CTL-14"]),
    }),
    "PCI_DSS": ("PCI DSS v4.0", "approximate", {
        "5.2": ("Anti-malware deployed", ["CTL-06"]),
        "6.3.3": ("Patches installed on time", ["CTL-07"]),
        "7.2.4": ("User accounts reviewed every 6 months", ["CTL-03"]),
        "8.4.2": ("MFA into the cardholder environment", ["CTL-01", "CTL-02"]),
        "8.2.6": ("Inactive accounts removed in 90 days", ["CTL-04"]),
        "10.2": ("Audit logs", ["CTL-16"]),
        "11.3": ("Vulnerability scans", ["CTL-08"]),
        "11.4": ("Penetration testing and retest", ["CTL-10"]),
        "12.6": ("Security awareness", ["CTL-12"]),
        "12.8": ("Third-party service providers", ["CTL-11"]),
        "12.10": ("Incident response", ["CTL-13"]),
    }),
    "CCPA": ("CCPA / CPRA", "approximate", {
        "1798.100": ("Notice at collection", ["CTL-24"]),
        "1798.105": ("Right to delete", ["CTL-23"]),
        "1798.106": ("Right to correct", ["CTL-23"]),
        "1798.110": ("Right to know", ["CTL-23"]),
        "1798.120": ("Opt-out of sale or sharing", ["CTL-23"]),
        "1798.130": ("Respond within 45 days", ["CTL-23"]),
        "1798.150": ("Reasonable security (breach liability)", ["CTL-01", "CTL-05", "CTL-07"]),
        "1798.185(a)(15)": ("Cybersecurity audits and risk assessments (regulations)", ["CTL-07", "CTL-11"]),
        "ADMT": ("Automated decision-making technology rules", ["CTL-29", "CTL-18"]),
    }),
    "NIS2": ("NIS 2 Directive", "approximate", {
        "21(2)(a)": ("Risk analysis and security policies", ["CTL-24"]),
        "21(2)(b)": ("Incident handling", ["CTL-13"]),
        "21(2)(c)": ("Business continuity, backup, crisis management", ["CTL-14"]),
        "21(2)(d)": ("Supply chain security", ["CTL-11"]),
        "21(2)(e)": ("Secure acquisition, development, vulnerability handling", ["CTL-07", "CTL-20"]),
        "21(2)(f)": ("Assessing effectiveness of measures", ["CTL-10", "CTL-22"]),
        "21(2)(g)": ("Cyber hygiene and training", ["CTL-12"]),
        "21(2)(h)": ("Cryptography and encryption", ["CTL-05", "CTL-26"]),
        "21(2)(i)": ("HR security, access control, asset management", ["CTL-03", "CTL-04", "CTL-25"]),
        "21(2)(j)": ("Multi-factor authentication", ["CTL-01", "CTL-02"]),
        "23": ("Reporting: 24h early warning, 72h notification, 1 month final", ["CTL-28"]),
    }),
    "HITRUST": ("HITRUST CSF (control categories)", "approximate", {
        "00": ("Information security management program", ["CTL-24"]),
        "01": ("Access control", ["CTL-01", "CTL-02", "CTL-03"]),
        "02": ("Human resources security", ["CTL-04", "CTL-12"]),
        "03": ("Risk management", ["CTL-07"]),
        "05": ("Organization of information security", ["CTL-11"]),
        "06": ("Compliance", ["CTL-16"]),
        "07": ("Asset management", ["CTL-25"]),
        "09": ("Communications and operations management", ["CTL-06", "CTL-14"]),
        "10": ("Acquisition, development and maintenance", ["CTL-08", "CTL-22"]),
        "11": ("Incident management", ["CTL-13"]),
        "12": ("Business continuity", ["CTL-14"]),
        "13": ("Privacy practices", ["CTL-23"]),
    }),
    "ISO42001": ("ISO/IEC 42001:2023 (AI management)", "approximate", {
        "A.4": ("Resources for AI systems (inventory)", ["CTL-18"]),
        "A.6": ("AI system life cycle", ["CTL-30"]),
        "A.8": ("Information for interested parties", ["CTL-20"]),
        "A.9": ("Use of AI systems (human oversight)", ["CTL-29", "CTL-17"]),
        "A.10": ("Third-party and customer relationships", ["CTL-11", "CTL-19"]),
    }),
    "AIUC1": ("AIUC-1 (AI agent standard)", "approximate", {
        "A": ("Data and privacy", ["CTL-21", "CTL-23"]),
        "B": ("Security", ["CTL-16", "CTL-08"]),
        "C": ("Safety", ["CTL-29"]),
        "D": ("Reliability", ["CTL-30", "CTL-19"]),
        "E": ("Accountability", ["CTL-17", "CTL-18"]),
        "F": ("Society", []),
    }),
    "EU_CRA": ("EU Cyber Resilience Act", "approximate", {
        "AnnexI-I(2)(a)": ("No known exploitable vulnerabilities", ["CTL-07"]),
        "AnnexI-I(2)(b)": ("Secure by default configuration", ["CTL-22"]),
        "AnnexI-I(2)(d)": ("Access control", ["CTL-01"]),
        "AnnexI-I(2)(l)": ("Security logging", ["CTL-16"]),
        "AnnexI-II(1)": ("SBOM", ["CTL-27"]),
        "AnnexI-II(2)": ("Fix vulnerabilities without delay", ["CTL-07"]),
        "AnnexI-II(3)": ("Regular security testing", ["CTL-08", "CTL-10"]),
        "AnnexI-II(5)": ("Coordinated vulnerability disclosure policy", ["CTL-20"]),
        "Art.14": ("Report actively exploited vulnerabilities (24h early warning)", ["CTL-28"]),
    }),
    "EU_AI_ACT": ("EU AI Act (deployer duties, subset)", "approximate", {
        "Art.4": ("AI literacy", ["CTL-12"]),
        "Art.26(2)": ("Human oversight by competent people", ["CTL-29"]),
        "Art.26(5)": ("Monitor operation", ["CTL-17"]),
        "Art.26(6)": ("Keep logs", ["CTL-16"]),
        "Art.50": ("Transparency to people interacting with AI", ["CTL-20"]),
    }),
    "NIST_AI_RMF": ("NIST AI RMF 1.0", "approximate", {
        "GOVERN": ("Policies, roles, accountability", ["CTL-29"]),
        "MAP": ("Context and inventory", ["CTL-18"]),
        "MEASURE": ("Measure quality and risk", ["CTL-30", "CTL-17"]),
        "MANAGE": ("Manage risk and third parties", ["CTL-19", "CTL-11"]),
    }),
}


def readiness(fid: str) -> dict:
    name, mtype, reqs = FRAMEWORKS[fid]
    res = results()
    rows, total, mapped = [], 0.0, 0
    for rid, (short, ctls) in reqs.items():
        if not ctls:
            rows.append({"req": rid, "name": short, "status": "gap", "controls": []})
            continue
        mapped += 1
        s = min(SCORE[res[c]["status"]] for c in ctls)  # weakest control decides
        status = "ready" if s == 1 else "partial" if s == 0.5 else "not_ready"
        total += s
        rows.append({"req": rid, "name": short, "status": status, "controls": ctls})
    ready = sum(r["status"] == "ready" for r in rows)
    return {"id": fid, "name": name, "mapping": mtype, "requirements": len(reqs), "mapped": mapped,
            "ready": ready, "ready_pct": round(100 * total / mapped, 1) if mapped else 0.0,
            "gaps": [r["req"] for r in rows if r["status"] == "gap"], "rows": rows}


def all_readiness() -> list[dict]:
    return [readiness(f) for f in FRAMEWORKS]


def coverage_summary() -> dict:
    rs = all_readiness()
    used = {c for f in FRAMEWORKS.values() for _, ctls in f[2].values() for c in ctls}
    by_type: dict[str, int] = {}
    for _, mtype, _ in FRAMEWORKS.values():
        by_type[mtype] = by_type.get(mtype, 0) + 1
    return {"frameworks": len(rs), "requirements": sum(r["requirements"] for r in rs),
            "mapped": sum(r["mapped"] for r in rs), "gaps": sum(len(r["gaps"]) for r in rs),
            "controls_used": len(used), "controls_total": len(results()), "by_mapping_type": by_type,
            "rows": [{k: r[k] for k in ("id", "name", "requirements", "mapped", "ready", "ready_pct")} for r in rs]}


def rings_html() -> str:
    rows = [{"name": r["name"].split(" (")[0], "ready": r["ready"], "controls": r["mapped"],
             "ready_pct": r["ready_pct"], "coverage": r["mapping"]} for r in all_readiness()]
    return svgchart.cards(rows)


def crosswalk(control: str) -> list[str]:
    """Which framework requirements does one control support?"""
    return [f"{fid} {rid}" for fid, (_, _, reqs) in FRAMEWORKS.items() for rid, (_, ctls) in reqs.items()
            if control in ctls]
