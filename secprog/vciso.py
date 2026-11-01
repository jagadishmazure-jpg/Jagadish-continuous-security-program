"""vCISO decision queue and a mock audit (synthetic).

The queue gathers every item that needs a senior person: risk acceptances, roadmap approvals, vendor residual
risk, autonomy promotions and policy exceptions. The vCISO decides; agents never do.
The mock audit samples evidence, checks it like an auditor would (fresh, hashed, mapped to a control, produced by
a known source, approvals by people) and lists findings in plain English.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from . import TODAY, access_review, devices, findings, soc_authority
from .core import Evidence, HashLog, is_agent

QUEUE = [
    {"id": "VQ-01", "type": "risk_acceptance", "title": "Accept SMB signing gap on dc01 for 30 days",
     "due": "2026-11-03", "severity": "high"},
    {"id": "VQ-02", "type": "roadmap", "title": "Approve 12-month roadmap for Kestrel Community Bank",
     "due": "2026-11-07", "severity": "medium"},
    {"id": "VQ-03", "type": "vendor_residual", "title": "Residual risk for Copperline Model Hosting",
     "due": "2026-11-02", "severity": "high"},
    {"id": "VQ-04", "type": "autonomy_promotion", "title": "Promote quarantine-email to proven",
     "due": "2026-11-10", "severity": "low"},
    {"id": "VQ-05", "type": "exception", "title": "Exception: legacy svc account without MFA (U-099)",
     "due": "2026-10-30", "severity": "critical"},
]
ACCEPT_MAX_DAYS = 90


@dataclass
class Queue:
    items: list = field(default_factory=lambda: [dict(i) for i in QUEUE])
    log: HashLog = field(default_factory=HashLog)

    def ordered(self, today: str = TODAY) -> list[dict]:
        sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for i in self.items:
            i["overdue"] = i["due"] < today and "decision" not in i
        return sorted(self.items, key=lambda i: (not i["overdue"], sev[i["severity"]], i["due"]))

    def decide(self, qid: str, by: str, role: str, decision: str, reason: str, expires_days: int | None = None):
        if is_agent(by) or role not in ("vciso", "ciso"):
            raise PermissionError("the vCISO or CISO decides")
        if decision not in ("approve", "reject", "defer"):
            raise ValueError("approve, reject or defer")
        if not reason:
            raise ValueError("reason required")
        it = next(i for i in self.items if i["id"] == qid)
        if it["type"] in ("risk_acceptance", "exception") and decision == "approve":
            if not expires_days or expires_days > ACCEPT_MAX_DAYS:
                raise ValueError("risk acceptances and exceptions need an expiry of 90 days or less")
            it["expires_days"] = expires_days
        it["decision"], it["by"] = decision, by
        self.log.append(by, "vciso_decision", item=qid, decision=decision, reason=reason)
        return it


def sample_evidence() -> list[Evidence]:
    res = soc_authority.verify_action("isolate-endpoint", {"network": "connected"}, {"network": "isolated"})
    stale = Evidence("legacy-share", "document", "Firewall review 2025", {"note": "old export"}, ("CC6.6",),
                     collected_at="2025-09-01")
    agent_approved = Evidence("change-log", "approval_record", "Change CH-09 approval",
                              {"approved_by": "agent:coordinator"}, ("CC8.1",))
    return [access_review.as_evidence(), devices.as_evidence(), findings.as_evidence(findings.all_findings()),
            soc_authority.verified_fix_evidence("INC-01", "isolate-endpoint", res), stale, agent_approved]


KNOWN_SOURCES = {"access-review", "device-posture", "scanners", "soc-authority", "change-log", "mdm"}
FRESH_DAYS = 90


def mock_audit(evidence: list[Evidence] | None = None, today: str = TODAY) -> dict:
    evidence = sample_evidence() if evidence is None else evidence
    out = []
    for e in evidence:
        issues = []
        age = (date.fromisoformat(today) - date.fromisoformat(e.collected_at)).days
        if age > FRESH_DAYS:
            issues.append(f"stale: {age} days old (limit {FRESH_DAYS})")
        if e.source not in KNOWN_SOURCES:
            issues.append(f"unknown source {e.source!r}")
        if e.kind == "approval_record" and is_agent(str(e.content.get("approved_by", ""))):
            issues.append("approval recorded by an agent, not a person")
        if len(e.content_sha256) != 64:
            issues.append("missing content hash")
        out.append({"evidence": e.evidence_id, "title": e.title, "controls": list(e.control_hints),
                    "result": "pass" if not issues else "finding", "issues": issues})
    return {"sampled": len(out), "passed": sum(r["result"] == "pass" for r in out),
            "findings": [r for r in out if r["result"] == "finding"], "rows": out}
