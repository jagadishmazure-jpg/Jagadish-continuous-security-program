"""Endpoint, identity and human risk: security awareness training (SAT), cyber-insurance readiness and a
multi-check consensus gate (synthetic).

SAT: phishing simulations give click, report and compromise (entered credentials) rates. A user who clicks gets a
short coaching module; a second click in 90 days goes to their manager (escalation is a drafted note, never sent).
Consensus gate: an alert only becomes an action proposal when at least 2 independent checks agree.
"""
from __future__ import annotations

from . import data
from .access_review import issues as access_issues
from .devices import summary as device_summary

CAMPAIGNS = ("PH-2026-07", "PH-2026-08", "PH-2026-09", "PH-2026-10")


def sat_results() -> list[dict]:
    """Deterministic synthetic results: 26 users x 4 campaigns."""
    out = []
    for i, a in enumerate(data.accounts()):
        for j, c in enumerate(CAMPAIGNS):
            k = (i * 7 + j * 3) % 20
            clicked = k < (5 - j)  # click rate falls over time
            compromised = clicked and k == 0
            reported = (not clicked) and (k % 3 == 0 or j >= 2 and k % 2 == 0)
            out.append({"user": a["id"], "manager": a["manager"], "campaign": c, "clicked": clicked,
                        "reported": reported, "compromised": compromised})
    return out


def sat_rates(rows: list[dict] | None = None) -> dict:
    rows = sat_results() if rows is None else rows
    by = {}
    for c in CAMPAIGNS:
        rs = [r for r in rows if r["campaign"] == c]
        by[c] = {"click_pct": round(100 * sum(r["clicked"] for r in rs) / len(rs), 1),
                 "report_pct": round(100 * sum(r["reported"] for r in rs) / len(rs), 1),
                 "compromise_pct": round(100 * sum(r["compromised"] for r in rs) / len(rs), 1)}
    return by


def coaching_and_escalation(rows: list[dict] | None = None) -> dict:
    rows = sat_results() if rows is None else rows
    clicks = {}
    for r in rows:
        if r["clicked"]:
            clicks.setdefault(r["user"], []).append(r)
    coached = sorted(clicks)
    repeat = sorted(u for u, rs in clicks.items() if len(rs) >= 2)
    notes = [{"to_manager": clicks[u][0]["manager"], "user": u, "status": "draft (not sent)",
              "text": f"{u} clicked {len(clicks[u])} simulated phishing emails in 90 days; please book a "
                      "15-minute coaching session."} for u in repeat]
    return {"coached": len(coached), "manager_escalations": len(repeat), "drafts": notes}


INSURANCE_QUESTIONS = [
    ("MFA for all remote access and email", lambda c: c["mfa_pct"] >= 95),
    ("MFA for all privileged accounts", lambda c: c["priv_mfa_pct"] == 100),
    ("EDR on all endpoints", lambda c: c["edr_pct"] >= 95),
    ("Immutable or offline backups tested in the last 6 months", lambda c: c["backup_tested"]),
    ("Critical patches applied within 30 days", lambda c: c["patched_pct"] >= 90),
    ("Phishing training at least yearly", lambda c: c["sat_campaigns"] >= 1),
    ("Incident response plan tested yearly", lambda c: c["ir_tested"]),
    ("No RDP exposed to the internet", lambda c: c["exposed_ports"] == 0),
    ("Email filtering with attachment sandboxing", lambda c: c["email_sandbox"]),
    ("24x7 monitoring (MDR or SOC)", lambda c: c["mdr"]),
]


def insurance_context() -> dict:
    accts = data.accounts()
    dev = device_summary()
    priv = [a for a in accts if a["role"] in ("admin", "payments_approver")]
    return {"mfa_pct": round(100 * sum(a["mfa"] for a in accts) / len(accts), 1),
            "priv_mfa_pct": round(100 * sum(a["mfa"] for a in priv) / len(priv), 1),
            "edr_pct": dev["pass_pct_by_check"]["edr_running"], "backup_tested": True,
            "patched_pct": dev["pass_pct_by_check"]["patched_30d"], "sat_campaigns": len(CAMPAIGNS),
            "ir_tested": True, "exposed_ports": dev["exposed_ports"], "email_sandbox": True, "mdr": True}


def insurance_readiness(ctx: dict | None = None) -> dict:
    ctx = insurance_context() if ctx is None else ctx
    res = [{"question": q, "ready": bool(f(ctx))} for q, f in INSURANCE_QUESTIONS]
    return {"ready": sum(r["ready"] for r in res), "total": len(res),
            "readiness_pct": round(100 * sum(r["ready"] for r in res) / len(res), 1),
            "gaps": [r["question"] for r in res if not r["ready"]], "basis": "synthetic controls"}


# ---------- consensus gate ----------

ALERTS = [
    {"id": "AL-01", "host": "WS-0007", "edr": True, "identity": True, "network": False, "reputation": True},
    {"id": "AL-02", "host": "WS-0012", "edr": True, "identity": False, "network": False, "reputation": False},
    {"id": "AL-03", "host": "WS-0019", "edr": False, "identity": True, "network": True, "reputation": False},
    {"id": "AL-04", "host": "WS-0021", "edr": False, "identity": False, "network": False, "reputation": True},
    {"id": "AL-05", "host": "WS-0003", "edr": True, "identity": True, "network": True, "reputation": True},
]
MIN_AGREEING = 2


def consensus(alert: dict, need: int = MIN_AGREEING) -> dict:
    votes = [k for k in ("edr", "identity", "network", "reputation") if alert[k]]
    ok = len(votes) >= need
    return {"alert": alert["id"], "agreeing_checks": votes,
            "decision": "propose action (needs approval)" if ok else "hold for analyst", "passed": ok}


def kpis() -> dict:
    dev = device_summary()
    rates = sat_rates()
    last = rates[CAMPAIGNS[-1]]
    acc = access_issues()
    gate = [consensus(a) for a in ALERTS]
    ins = insurance_readiness()
    return {
        "endpoint": {"edr_pct": dev["pass_pct_by_check"]["edr_running"], "compliant_pct": dev["compliant_pct"],
                     "risky_av_exclusions": dev["risky_exclusions"], "exposed_ports": dev["exposed_ports"]},
        "identity": {"privileged_without_mfa": sum(i["type"] == "privileged_without_mfa" for i in acc),
                     "dormant": sum(i["type"] == "dormant" for i in acc)},
        "human": {"click_pct": last["click_pct"], "report_pct": last["report_pct"],
                  "compromise_pct": last["compromise_pct"]},
        "business": {"insurance_readiness_pct": ins["readiness_pct"],
                     "alerts_held_by_consensus_gate": sum(not g["passed"] for g in gate)},
        "basis": "synthetic",
    }
