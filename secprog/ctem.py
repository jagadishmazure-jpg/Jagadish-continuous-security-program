"""CTEM cycle (scope -> discover -> prioritize -> validate -> mobilize) and the daily 5-minute priority list.

A remediation ticket closes only after a simulated rescan passes. Each stage has an owner and an exit check.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import data
from .core import HashLog, is_agent

STAGES = ("scope", "discover", "prioritize", "validate", "mobilize")
EXIT_CHECKS = {
    "scope": "business service and crown jewels named",
    "discover": "asset inventory and findings imported",
    "prioritize": "ranked list with reasons",
    "validate": "simulated rescan or exploit check recorded",
    "mobilize": "ticket with owner, SLA and approval",
}

# Simulated rescan results: fingerprint/ticket id -> passes after fix?
RESCAN = {"TKT-001": True, "TKT-002": False, "TKT-003": True, "TKT-004": True}


@dataclass
class Ticket:
    id: str
    finding: str
    owner: str
    status: str = "open"
    history: list = field(default_factory=list)


class Cycle:
    def __init__(self, service: str, owner: str, log: HashLog | None = None) -> None:
        self.service, self.owner = service, owner
        self.stage = "scope"
        self.artifacts: dict[str, str] = {}
        self.log = log or HashLog()
        self.tickets: dict[str, Ticket] = {}

    def complete_stage(self, artifact: str, by: str) -> str:
        if not artifact:
            raise ValueError(f"exit check for {self.stage}: {EXIT_CHECKS[self.stage]}")
        self.artifacts[self.stage] = artifact
        self.log.append(by, "stage_done", service=self.service, stage=self.stage)
        i = STAGES.index(self.stage)
        self.stage = STAGES[i + 1] if i + 1 < len(STAGES) else "done"
        return self.stage

    def open_ticket(self, tid: str, finding: str, owner: str) -> Ticket:
        t = Ticket(tid, finding, owner)
        self.tickets[tid] = t
        return t

    def mark_fixed(self, tid: str, by: str) -> Ticket:
        t = self.tickets[tid]
        t.status = "fixed_pending_rescan"
        t.history.append(("fixed", by))
        return t

    def close(self, tid: str, by: str, rescan: dict | None = None) -> Ticket:
        rescan = RESCAN if rescan is None else rescan
        t = self.tickets[tid]
        if is_agent(by):
            raise PermissionError("a person closes tickets")
        if t.status != "fixed_pending_rescan":
            raise ValueError("ticket must be marked fixed first")
        if not rescan.get(tid, False):
            t.status = "reopened"
            t.history.append(("rescan_failed", by))
            self.log.append(by, "rescan_failed", ticket=tid)
            return t
        t.status = "closed"
        t.history.append(("closed_after_rescan", by))
        self.log.append(by, "ticket_closed", ticket=tid)
        return t


def demo() -> dict:
    c = Cycle("loan origination", "secops_lead")
    for art in ("loan-portal, kyc-bucket in scope", "40 assets, 73 findings", "v2 ranked list",
                "simulated rescans recorded", "4 tickets opened"):
        c.complete_stage(art, "maria.secops")
    for i, f in enumerate(("PT-02 IDOR", "TOX-08 exposed secret", "CVE on loan-portal", "missing CSP"), 1):
        c.open_ticket(f"TKT-{i:03d}", f, "owner-lending")
        c.mark_fixed(f"TKT-{i:03d}", "dev.lending")
        c.close(f"TKT-{i:03d}", "maria.secops")
    st = [t.status for t in c.tickets.values()]
    return {"stage": c.stage, "closed": st.count("closed"), "reopened": st.count("reopened"),
            "fix_validation_pass_pct": round(100 * st.count("closed") / len(st), 1), "log_ok": c.log.verify()[0]}


def five_minute_list(n: int = 5) -> list[dict]:
    """The daily 'if you only have 5 minutes' list: actions that remove the most exposure."""
    from .attack_paths import choke_points, toxic
    from .cve_rank import rank_v2
    items = []
    for cp in choke_points(3):
        items.append({"action": f"Cut {cp['edge']} ({cp['why']})", "impact": cp["closes_paths"] * 100,
                      "why": f"closes {cp['closes_paths']} of {cp['of']} attack paths"})
    seen = set()
    for t in toxic():
        if t["asset"] not in seen:
            seen.add(t["asset"])
            items.append({"action": f"Fix {t['name']} ({t['rule']})", "impact": 250, "why": t["title"]})
    for c in rank_v2()[:3]:
        items.append({"action": f"Patch {c['package']} for {c['id']} on {c['asset']}", "impact": round(c["score"] * 3),
                      "why": c["reason"]})
    items.sort(key=lambda x: (-x["impact"], x["action"]))
    return items[:n]


def unknown_assets() -> list[dict]:
    """Simulated external discovery: hostnames seen in certificate logs that are not in the inventory."""
    known = {a["name"] for a in data.assets()}
    seen = ["loan-portal", "pay-gateway", "marketing-site", "staging-loans", "old-promo", "api-v0"]
    return [{"host": f"{h}.{data.DOMAIN}", "owner": None} for h in seen if h not in known]


CERTS = [("loan-portal", 12), ("pay-gateway", 75), ("marketing-site", 25), ("api-v0", -3), ("staging-loans", 140)]


def expiring_certs(days: int = 30) -> list[dict]:
    return [{"host": f"{h}.{data.DOMAIN}", "days_left": d, "expired": d < 0} for h, d in CERTS if d <= days]
