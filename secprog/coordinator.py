"""Coordinator: plans which agents run for a goal, pre-checks each proposed action through the governance gate,
routes risky actions to the approval inbox and keeps the tamper-evident log. It also computes per-agent KPIs.
"""
from __future__ import annotations

from .agents import AGENTS, by_id
from .core import ApprovalInbox, HashLog, rubber_stamp
from .governance import Gate

PLANS = {
    "weekly exposure review": ["scan-importer", "dependency-ranker", "dast-surface", "exposure", "vuln-sla",
                               "reporter"],
    "customer questionnaire": ["questionnaire", "trust-center"],
    "new vendor": ["tprm"],
    "quarterly access review": ["access-review", "reporter"],
    "audit prep": ["device-posture", "access-review", "vuln-sla", "vciso", "reporter"],
    "identity incident": ["recovery-runbook", "post-action-verifier"],
}


def plan(goal: str) -> list[str]:
    g = goal.lower().strip()
    if g not in PLANS:
        raise KeyError(f"no plan for {goal!r}; known goals: {sorted(PLANS)}")
    for a in PLANS[g]:
        by_id(a)
    return list(PLANS[g])


class Coordinator:
    def __init__(self) -> None:
        self.log = HashLog()
        self.inbox = ApprovalInbox(self.log)
        self.gate = Gate()
        for p in self.gate.policies:  # the shipped configuration enforces every policy
            p.stage = "enforce"
        self.stats = {a.id: {"proposed": 0, "approved": 0, "rejected": 0, "blocked": 0, "reverted": 0}
                      for a in AGENTS}

    def propose(self, agent_id: str, tool: str, target: str, reversible: bool = True, tenant: str = "brightwater"):
        a = by_id(agent_id)
        self.stats[agent_id]["proposed"] += 1
        verdict = self.gate.check(a.identity, {"tool": tool, "resource": target, "reversible": reversible,
                                               "tenant": tenant})
        # The gate's approval-type policies say "needs approval": route those to the inbox instead of blocking.
        approval_only = verdict["verdict"] == "block" and all(
            p.rule["kind"] in ("approval_tool", "approval_irreversible")
            for p in self.gate.policies if p.id in verdict["enforced"])
        if verdict["verdict"] == "block" and not approval_only:
            self.stats[agent_id]["blocked"] += 1
            return {"status": "blocked", "policies": verdict["enforced"]}
        if approval_only or a.autonomy != "act_then_notify" or not reversible:
            r = self.inbox.request(tool, a.identity, target, destructive=not reversible, reversible=reversible)
            return {"status": "awaiting_approval", "request": r.id}
        self.log.append(a.identity, "executed_simulated", tool=tool, target=target)
        return {"status": "executed (simulated)"}

    def decide(self, rid: str, approver: str, role: str, approve: bool, reason: str = "", seconds: float = 60):
        r = self.inbox.items[rid]
        aid = r.requested_by.split(":", 1)[1]
        if approve:
            self.inbox.approve(rid, approver, role, seconds)
            if r.status == "approved":
                self.stats[aid]["approved"] += 1
        else:
            self.inbox.reject(rid, approver, reason)
            self.stats[aid]["rejected"] += 1
        return r

    def kpis(self) -> dict:
        tot = {k: sum(s[k] for s in self.stats.values()) for k in ("proposed", "approved", "rejected", "blocked")}
        secs = [s for r in self.inbox.items.values() for s in r.review_seconds]
        decided = tot["approved"] + tot["rejected"]
        return {**tot, "pending": len(self.inbox.pending()),
                "override_rate_pct": round(100 * tot["rejected"] / decided, 1) if decided else 0.0,
                "median_review_s": sorted(secs)[len(secs) // 2] if secs else None,
                "rubber_stamp_flag": rubber_stamp(secs), "log_ok": self.log.verify()[0]}


def demo_week() -> Coordinator:
    c = Coordinator()
    props = [
        ("dependency-ranker", "open_ticket", "pkg-03", True), ("dependency-ranker", "open_ticket", "pkg-07", True),
        ("trust-center", "publish_trust_update", "trust:vuln-update", True),
        ("trust-center", "send_email", "customer-list", True),
        ("access-review", "disable_account", "U-099", False), ("access-review", "disable_account", "U-004", False),
        ("scan-importer", "import_sarif", "repo:loan-portal", True),
        ("questionnaire", "draft_answer", "Q-07", True), ("tprm", "draft_followup", "V-03", True),
        ("ai-exposure", "read_bucket", "kyc-bucket", True), ("vciso", "draft_roadmap", "roadmap-2027", True),
        ("exposure", "open_ticket", "TOX-08", True),
    ]
    reqs = []
    for a, t, tgt, rev in props:
        out = c.propose(a, t, tgt, rev)
        if out["status"] == "awaiting_approval":
            reqs.append(out["request"])
    reviewers = [("maria.secops", "secops_lead"), ("ciso.amara", "ciso")]
    for n, rid in enumerate(reqs):
        if n == 3:
            c.decide(rid, "maria.secops", "secops_lead", False, "duplicate of an existing ticket")
            continue
        r = c.inbox.items[rid]
        for who, role in reviewers[: r.needed]:
            c.decide(rid, who, role, True, seconds=8 if n % 4 == 0 else 95)
    return c
