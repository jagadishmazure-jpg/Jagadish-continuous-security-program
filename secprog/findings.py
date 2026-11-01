"""One findings model for every scanner: code (SARIF-style), secrets, dependencies, DAST (ZAP-style) and pentests.

Importers take synthetic JSON text shaped like common open formats. Findings are de-duplicated on a fingerprint
(source-independent: asset + rule/CVE + location) so two tools reporting the same issue count once.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

from . import data
from .core import Evidence, sha

SEVERITIES = ("critical", "high", "medium", "low", "info")
SARIF_LEVEL = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}
OWASP = {"sqli": "A03 Injection", "xss": "A03 Injection", "auth": "A07 Identification and Authentication Failures",
         "tls": "A02 Cryptographic Failures", "headers": "A05 Security Misconfiguration",
         "idor": "A01 Broken Access Control", "ssrf": "A10 Server-Side Request Forgery"}


@dataclass
class Finding:
    source: str
    asset: str
    rule: str
    title: str
    severity: str
    location: str = ""
    detected: str = data.day(-10)
    status: str = "open"
    cve: str | None = None
    sources: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity {self.severity}")
        if not self.sources:
            self.sources = [self.source]

    @property
    def fingerprint(self) -> str:
        return sha([self.asset, self.cve or self.rule, self.location])[:16]

    def to_dict(self) -> dict:
        return {**asdict(self), "fingerprint": self.fingerprint}


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Merge findings with the same fingerprint; keep the highest severity and every source that saw it."""
    out: dict[str, Finding] = {}
    for f in findings:
        k = f.fingerprint
        if k not in out:
            out[k] = Finding(**{**asdict(f), "sources": list(f.sources)})
            continue
        cur = out[k]
        if SEVERITIES.index(f.severity) < SEVERITIES.index(cur.severity):
            cur.severity = f.severity
        cur.sources = sorted(set(cur.sources) | set(f.sources))
        cur.detected = min(cur.detected, f.detected)
    return list(out.values())


# ---------- synthetic scanner outputs ----------

def sample_sarif() -> str:
    results = [
        {"ruleId": "py.sql-injection", "level": "error", "message": {"text": "SQL built from request input"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "loan_portal/search.py"},
                                             "region": {"startLine": 42}}}], "properties": {"asset": "A-003"}},
        {"ruleId": "py.weak-hash", "level": "warning", "message": {"text": "MD5 used for a token"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "gateway/tokens.py"},
                                             "region": {"startLine": 17}}}], "properties": {"asset": "A-001"}},
        {"ruleId": "py.debug-enabled", "level": "note", "message": {"text": "Debug flag left on"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "site/app.py"},
                                             "region": {"startLine": 5}}}], "properties": {"asset": "A-008"}},
        {"ruleId": "py.path-traversal", "level": "error", "message": {"text": "File path from user input"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "support_bot/files.py"},
                                             "region": {"startLine": 88}}}], "properties": {"asset": "A-007"}},
    ]
    return json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "synthetic-sast"}},
                                                      "results": results}]})


def sample_secrets() -> str:
    return json.dumps([
        {"RuleID": "generic-api-key", "File": "deploy/env.sample", "StartLine": 3, "Asset": "A-001",
         "Secret": "REDACTED", "Verified": False},
        {"RuleID": "cloud-access-key", "File": "scripts/backfill.py", "StartLine": 12, "Asset": "A-002",
         "Secret": "REDACTED", "Verified": True},
    ])


def sample_zap() -> str:
    return json.dumps({"site": [{"@name": f"https://loan-portal.{data.DOMAIN}", "asset": "A-003", "alerts": [
        {"pluginid": "40018", "alert": "SQL Injection", "riskcode": "3", "cat": "sqli", "uri": "/search?q="},
        {"pluginid": "10038", "alert": "Content Security Policy header not set", "riskcode": "2", "cat": "headers",
         "uri": "/"},
        {"pluginid": "10202", "alert": "Absence of anti-CSRF tokens", "riskcode": "1", "cat": "auth",
         "uri": "/apply"},
    ]}, {"@name": f"https://pay-gateway.{data.DOMAIN}", "asset": "A-001", "alerts": [
        {"pluginid": "10035", "alert": "Strict-Transport-Security header not set", "riskcode": "1", "cat": "tls",
         "uri": "/v1/charge"},
        {"pluginid": "90034", "alert": "Object reference not checked", "riskcode": "3", "cat": "idor",
         "uri": "/v1/charge/{id}"},
    ]}]})


def import_sarif(text: str) -> list[Finding]:
    out = []
    for run in json.loads(text)["runs"]:
        for res in run["results"]:
            loc = res["locations"][0]["physicalLocation"]
            out.append(Finding("code", res["properties"]["asset"], res["ruleId"], res["message"]["text"],
                               SARIF_LEVEL[res.get("level", "warning")],
                               f'{loc["artifactLocation"]["uri"]}:{loc["region"]["startLine"]}'))
    return out


def import_secrets(text: str) -> list[Finding]:
    out = []
    for s in json.loads(text):
        if s.get("Secret") not in (None, "REDACTED"):
            raise ValueError("secret values must be redacted before import")
        out.append(Finding("secrets", s["Asset"], s["RuleID"], f"Secret pattern {s['RuleID']}",
                           "critical" if s["Verified"] else "high", f'{s["File"]}:{s["StartLine"]}'))
    return out


def import_zap(text: str) -> list[Finding]:
    out = []
    for site in json.loads(text)["site"]:
        for a in site["alerts"]:
            out.append(Finding("dast", site["asset"], f'zap-{a["pluginid"]}', a["alert"], ZAP_RISK[a["riskcode"]],
                               a["uri"], extra={"owasp": OWASP.get(a["cat"], "unmapped")}))
    return out


def import_dependencies() -> list[Finding]:
    sev = lambda c: "critical" if c >= 9 else "high" if c >= 7 else "medium" if c >= 4 else "low"  # noqa: E731
    return [Finding("dependency", c["asset"], c["package"], f'{c["package"]} affected by {c["id"]}', sev(c["cvss"]),
                    c["package"], detected=data.day(-((i * 11) % 75 + 1)), cve=c["id"])
            for i, c in enumerate(data.cves())]


# ---------- pentest tracking ----------

PENTEST = [
    {"id": "PT-01", "asset": "A-003", "title": "SQL injection in loan search", "severity": "critical",
     "rule": "py.sql-injection", "location": "loan_portal/search.py:42", "retest": "fixed"},
    {"id": "PT-02", "asset": "A-001", "title": "IDOR on charge lookup", "severity": "high", "rule": "zap-90034",
     "location": "/v1/charge/{id}", "retest": "open"},
    {"id": "PT-03", "asset": "A-005", "title": "Kerberoastable service account", "severity": "high",
     "rule": "ad-kerberoast", "location": "svc-legacy", "retest": "not_retested"},
    {"id": "PT-04", "asset": "A-007", "title": "Prompt injection reaches file tool", "severity": "high",
     "rule": "llm-prompt-injection", "location": "support-bot", "retest": "fixed"},
]


def pentest_findings() -> list[Finding]:
    return [Finding("pentest", p["asset"], p["rule"], p["title"], p["severity"], p["location"],
                    status="closed" if p["retest"] == "fixed" else "open", extra={"pentest_id": p["id"],
                                                                                    "retest": p["retest"]})
            for p in PENTEST]


def pentest_status() -> dict:
    counts = {"fixed": 0, "open": 0, "not_retested": 0}
    for p in PENTEST:
        counts[p["retest"]] += 1
    return {**counts, "total": len(PENTEST), "retest_coverage_pct": round(100 * (counts["fixed"] + counts["open"])
                                                                          / len(PENTEST), 1)}


def all_findings() -> list[Finding]:
    raw = (import_sarif(sample_sarif()) + import_secrets(sample_secrets()) + import_zap(sample_zap())
           + import_dependencies() + pentest_findings())
    return dedupe(raw)


def as_evidence(fs: list[Finding]) -> Evidence:
    """Scanner output becomes control evidence (RA-5 / SI-2 / SOC 2 CC7.1)."""
    counts = {s: sum(f.severity == s for f in fs if f.status == "open") for s in SEVERITIES}
    return Evidence("scanners", "scan_result", "Consolidated scanner findings", {"open_by_severity": counts,
                    "total": len(fs)}, ("RA-5", "SI-2", "CC7.1"), produced_by="agent:scan-importer")
