"""MSP / vCISO view across 8 fictional clients (synthetic).

* Tenant isolation: each client has a secret canary. Every query is scoped to one tenant; a test proves no other
  tenant's canary ever appears in a result.
* MBR/QBR packs are HTML previews only.
* Assessment -> costed 12-month roadmap. Items are scored on value, effort, risk, feasibility and readiness; a
  vCISO approves the roadmap before it is shown to the client.
* Service tiers (Essential, Advanced, Regulated) with SLA tracking.
* Copilot / M365 oversharing check, co-managed RACI and an outcome/ROI tracker (SIMULATED).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from html import escape

from . import data
from .core import HashLog, is_agent

TIERS = {
    "essential": {"critical_response_hours": 8, "patch_critical_days": 14, "qbr": False, "price_per_user": 45},
    "advanced": {"critical_response_hours": 4, "patch_critical_days": 7, "qbr": True, "price_per_user": 75},
    "regulated": {"critical_response_hours": 1, "patch_critical_days": 3, "qbr": True, "price_per_user": 110},
}


class TenantError(Exception):
    pass


class TenantStore:
    def __init__(self, clients: list[dict] | None = None) -> None:
        self._rows = {c["id"]: c for c in (data.clients() if clients is None else clients)}

    def query(self, tenant: str, caller_tenant: str) -> dict:
        if tenant != caller_tenant:
            raise TenantError("cross-tenant read refused")
        if tenant not in self._rows:
            raise TenantError("unknown tenant")
        return dict(self._rows[tenant])

    def canary_test(self) -> dict:
        leaks, refused = 0, 0
        ids = list(self._rows)
        for me in ids:
            row = self.query(me, me)
            others = [self._rows[o]["secret_canary"] for o in ids if o != me]
            leaks += sum(c in repr(row) for c in others)
            for o in ids:
                if o != me:
                    try:
                        self.query(o, me)
                    except TenantError:
                        refused += 1
        return {"tenants": len(ids), "canary_leaks": leaks, "cross_tenant_refused": refused,
                "passed": leaks == 0 and refused == len(ids) * (len(ids) - 1)}


def sla_tracking(clients: list[dict] | None = None) -> list[dict]:
    clients = data.clients() if clients is None else clients
    out = []
    for c in clients:
        t = TIERS[c["tier"]]
        out.append({"client": c["name"], "tier": c["tier"], "tickets": c["tickets"],
                    "sla_breaches": c["sla_breaches"],
                    "sla_met_pct": round(100 * (c["tickets"] - c["sla_breaches"]) / c["tickets"], 1),
                    "critical_response_hours": t["critical_response_hours"]})
    return out


# ---------- roadmap ----------

GAPS = [  # id, title, value, effort, risk, feasibility, readiness (1-5), cost (USD), months
    ("RM-01", "Phishing-resistant MFA for admins", 5, 2, 5, 5, 4, 6000, 1),
    ("RM-02", "Immutable backups + quarterly restore test", 5, 3, 5, 4, 3, 18000, 2),
    ("RM-03", "EDR on remaining servers", 4, 2, 4, 5, 5, 9000, 1),
    ("RM-04", "SIEM with 24x7 monitoring", 4, 4, 4, 3, 2, 60000, 4),
    ("RM-05", "Vendor risk program for critical vendors", 3, 3, 3, 4, 3, 12000, 3),
    ("RM-06", "Data classification + DLP in M365", 3, 4, 3, 3, 2, 25000, 4),
    ("RM-07", "Tabletop exercise and IR retainer", 3, 1, 3, 5, 4, 7000, 1),
    ("RM-08", "AI acceptable-use policy + shadow AI register", 3, 1, 3, 5, 5, 3000, 1),
]
WEIGHTS = {"value": 0.3, "effort": 0.15, "risk": 0.25, "feasibility": 0.15, "readiness": 0.15}


def score(g: tuple) -> float:
    _, _, v, e, r, f, rd, _, _ = g
    return round(WEIGHTS["value"] * v + WEIGHTS["effort"] * (6 - e) + WEIGHTS["risk"] * r
                 + WEIGHTS["feasibility"] * f + WEIGHTS["readiness"] * rd, 2)


@dataclass
class Roadmap:
    client: str
    items: list = field(default_factory=list)
    status: str = "draft"
    approved_by: str | None = None
    log: HashLog = field(default_factory=HashLog)

    def build(self, gaps: list[tuple] | None = None, months: int = 12) -> list[dict]:
        ranked = sorted(gaps or GAPS, key=lambda g: (-score(g), g[0]))
        month, out = 1, []
        for g in ranked:
            if month + g[8] - 1 > months:
                out.append({"id": g[0], "title": g[1], "score": score(g), "cost": g[7], "start_month": None,
                            "note": "next year"})
                continue
            out.append({"id": g[0], "title": g[1], "score": score(g), "cost": g[7], "start_month": month,
                        "end_month": month + g[8] - 1})
            month += max(1, g[8] // 2)  # overlap: start the next item halfway through
        self.items = out
        self.log.append("agent:vciso", "roadmap_drafted", client=self.client, items=len(out))
        return out

    def approve(self, by: str, role: str) -> str:
        if is_agent(by) or role != "vciso":
            raise PermissionError("a vCISO approves the roadmap")
        if not self.items:
            raise ValueError("build the roadmap first")
        self.status, self.approved_by = "approved", by
        self.log.append(by, "roadmap_approved", client=self.client)
        return self.status

    def total_cost(self) -> int:
        return sum(i["cost"] for i in self.items if i.get("start_month"))


# ---------- Copilot / M365 oversharing ----------

SITES = [
    {"site": "Finance-Board", "sensitivity": "confidential", "sharing": "org-wide", "copilot_indexed": True},
    {"site": "HR-Salaries", "sensitivity": "restricted", "sharing": "everyone-except-external",
     "copilot_indexed": True},
    {"site": "Marketing", "sensitivity": "general", "sharing": "org-wide", "copilot_indexed": True},
    {"site": "Legal-Matters", "sensitivity": "restricted", "sharing": "members", "copilot_indexed": True},
    {"site": "IT-Runbooks", "sensitivity": "confidential", "sharing": "anyone-with-link", "copilot_indexed": False},
]


def oversharing(sites: list[dict] | None = None) -> list[dict]:
    sites = SITES if sites is None else sites
    broad = {"org-wide", "everyone-except-external", "anyone-with-link"}
    out = []
    for s in sites:
        if s["sensitivity"] in ("confidential", "restricted") and s["sharing"] in broad:
            out.append({"site": s["site"], "risk": "high" if s["copilot_indexed"] else "medium",
                        "proposal": "restrict to members and exclude from Copilot until reviewed (needs approval)"})
    return out


RACI = {  # activity -> (Responsible, Accountable, Consulted, Informed)
    "Endpoint patching": ("MSP", "Client IT lead", "vCISO", "Client exec"),
    "Alert triage 24x7": ("MSP SOC", "MSP SOC lead", "Client IT lead", "Client exec"),
    "Access reviews": ("Client managers", "Client IT lead", "MSP", "vCISO"),
    "Vendor risk decisions": ("Client procurement", "Client exec", "vCISO", "MSP"),
    "Incident declaration": ("MSP SOC lead", "Client exec", "vCISO, legal", "Insurer"),
    "Policy approval": ("vCISO", "Client exec", "MSP", "All staff"),
    "Backup restore tests": ("MSP", "Client IT lead", "vCISO", "Client exec"),
    "Shadow AI approvals": ("Client AI governance lead", "Client exec", "vCISO", "MSP"),
}


DECISIONS = {"Vendor risk decisions", "Incident declaration", "Policy approval", "Shadow AI approvals",
             "Access reviews"}


def raci_check(raci: dict | None = None) -> list[str]:
    """Problems: more than one Accountable party, or a risk decision not owned by the client."""
    raci = RACI if raci is None else raci
    bad = []
    for k, (_, a, _, _) in raci.items():
        if "," in a:
            bad.append(f"{k}: more than one Accountable")
        elif k in DECISIONS and not a.startswith("Client"):
            bad.append(f"{k}: risk decision must be owned by the client")
    return bad


OUTCOMES = [  # SIMULATED
    {"client": "C-02", "metric": "critical vulns open", "before": 41, "after": 9},
    {"client": "C-03", "metric": "phish click %", "before": 18.0, "after": 6.5},
    {"client": "C-05", "metric": "EDR coverage %", "before": 61.0, "after": 97.0},
    {"client": "C-06", "metric": "hours to answer questionnaires / month", "before": 30, "after": 9},
]


def roi(hourly: float = 95.0) -> dict:
    saved_hours = sum(o["before"] - o["after"] for o in OUTCOMES if "hours" in o["metric"])
    return {"outcomes": OUTCOMES, "hours_saved_per_month": saved_hours,
            "value_per_month": round(saved_hours * hourly, 2), "basis": "SIMULATED outcomes"}


def qbr_pack(client_id: str, caller_tenant: str) -> str:
    store = TenantStore()
    c = store.query(client_id, caller_tenant)
    t = TIERS[c["tier"]]
    sla = next(s for s in sla_tracking() if s["client"] == c["name"])
    rm = Roadmap(c["name"])
    rm.build()
    rows = "".join(f"<tr><td>{escape(i['title'])}</td><td>{i['score']}</td><td>{i.get('start_month') or '-'}"
                   f"</td><td>${i['cost']:,}</td></tr>" for i in rm.items[:5])
    return (f"<html><body style='font-family:Arial'><h1>QBR preview: {escape(c['name'])}</h1>"
            "<p style='color:#a00'>Synthetic preview. Not sent.</p>"
            f"<p>Tier: {c['tier']} (critical response {t['critical_response_hours']}h). Readiness "
            f"{c['readiness_pct']}%. Open critical: {c['open_critical']}. SLA met {sla['sla_met_pct']}%.</p>"
            "<h2>Roadmap (draft until vCISO approves)</h2><table border=1 cellpadding=4><tr><th>Item</th>"
            f"<th>Score</th><th>Start month</th><th>Cost</th></tr>{rows}</table></body></html>")
