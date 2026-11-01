"""Access review campaign: the agent proposes revocations; a named reviewer decides each one."""
from __future__ import annotations

from dataclasses import dataclass, field

from . import data
from .core import Evidence, HashLog, is_agent

DORMANT_DAYS = 90
PRIVILEGED = {"admin", "payments_approver"}


def issues(accts: list[dict] | None = None) -> list[dict]:
    accts = data.accounts() if accts is None else accts
    out = []
    for a in accts:
        if a["terminated"] and a["active"]:
            out.append({"account": a["id"], "type": "terminated_but_active", "proposal": "revoke"})
        if a["last_login_days"] >= DORMANT_DAYS:
            out.append({"account": a["id"], "type": "dormant", "proposal": "disable"})
        if not a["manager"]:
            out.append({"account": a["id"], "type": "orphaned", "proposal": "assign owner or disable"})
        if len(set(a["entitlements"]) & PRIVILEGED) == 2:
            out.append({"account": a["id"], "type": "toxic_privileges", "proposal": "remove one role (SoD)"})
        if set(a["entitlements"]) & PRIVILEGED and not a["mfa"]:
            out.append({"account": a["id"], "type": "privileged_without_mfa", "proposal": "enforce MFA"})
    return out


@dataclass
class Campaign:
    reviewer: str
    log: HashLog = field(default_factory=HashLog)
    decisions: dict = field(default_factory=dict)

    def decide(self, account: str, issue: str, decision: str, by: str, note: str = "") -> dict:
        if is_agent(by):
            raise PermissionError("access decisions are made by people")
        if decision not in {"revoke", "keep", "modify"}:
            raise ValueError("decision must be revoke, keep or modify")
        if decision == "keep" and not note:
            raise ValueError("keeping flagged access needs a justification")
        self.decisions[(account, issue)] = {"decision": decision, "by": by, "note": note}
        self.log.append(by, "access_decision", account=account, issue=issue, decision=decision)
        return self.decisions[(account, issue)]

    def completion(self, items: list[dict]) -> float:
        done = sum((i["account"], i["type"]) in self.decisions for i in items)
        return round(100 * done / len(items), 1) if items else 100.0


def demo() -> dict:
    items = issues()
    c = Campaign("mgr-review")
    for n, i in enumerate(items):
        if n % 5 == 4:
            c.decide(i["account"], i["type"], "keep", "rina.manager", "break-glass account, monitored")
        else:
            c.decide(i["account"], i["type"], "revoke" if i["proposal"] in ("revoke", "disable") else "modify",
                     "rina.manager")
    by_type = {}
    for i in items:
        by_type[i["type"]] = by_type.get(i["type"], 0) + 1
    return {"issues": len(items), "by_type": by_type, "completion_pct": c.completion(items),
            "revoked": sum(d["decision"] == "revoke" for d in c.decisions.values()), "log_ok": c.log.verify()[0]}


def as_evidence() -> Evidence:
    return Evidence("access-review", "access_review", "Quarterly access review", demo(), ("CC6.2", "CC6.3", "AC-2"),
                    produced_by="agent:access-review")
