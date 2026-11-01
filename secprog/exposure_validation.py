"""Exposure validation (simulated, no packets are sent).

* The validator agent proposes a safe test for each finding. A separate safety-reviewer gate checks the test
  against rules (no production writes, no denial of service, in-scope asset, business hours off) before it runs.
* A finding that cannot be proven exploitable (or is blocked by a compensating control) is dropped from the
  urgent list; compensating controls earn partial credit instead of hiding the finding.
* Leaked-credential feed: synthetic records are matched to accounts; a match proposes a reset (needs approval).
* Test-before-enforce: a policy change shows a dry-run diff and an impact check, and has a rollback plan.
* KPIs: MTTSR (mean time to safe remediation: from finding to verified fix with no outage) and zero-disruption rate.
"""
from __future__ import annotations

from statistics import mean

from . import data
from .core import sha

SAFETY_RULES = {
    "no_prod_write": lambda t: not t["writes"],
    "no_dos": lambda t: t["rate_per_sec"] <= 5,
    "in_scope": lambda t: t["asset_in_inventory"],
    "change_window": lambda t: not t["business_hours"] or t["read_only"],
}

FINDINGS = [
    {"id": "XV-01", "asset": "pay-gateway", "issue": "CVE-SYN-2026-0003 reachable", "test_result": "exploitable",
     "control": None},
    {"id": "XV-02", "asset": "loan-portal", "issue": "admin panel exposed", "test_result": "exploitable",
     "control": "WAF virtual patch"},
    {"id": "XV-03", "asset": "marketing-site", "issue": "old jQuery", "test_result": "not_exploitable",
     "control": None},
    {"id": "XV-04", "asset": "dc01", "issue": "SMB signing off", "test_result": "exploitable", "control": None},
    {"id": "XV-05", "asset": "kyc-bucket", "issue": "public listing", "test_result": "inconclusive",
     "control": "bucket policy deny"},
    {"id": "XV-06", "asset": "ghost-host-9", "issue": "open RDP", "test_result": "exploitable", "control": None},
    {"id": "XV-07", "asset": "fraud-model", "issue": "model endpoint without auth", "test_result": "exploitable",
     "control": "private network only"},
]
CONTROL_CREDIT = {"WAF virtual patch": 0.5, "bucket policy deny": 0.7, "private network only": 0.6}


def propose_test(f: dict) -> dict:
    inv = {a["name"] for a in data.assets()}
    return {"finding": f["id"], "asset": f["asset"], "writes": False, "rate_per_sec": 2,
            "asset_in_inventory": f["asset"] in inv, "business_hours": False, "read_only": True,
            "proposed_by": "agent:exposure-validator"}


def safety_review(test: dict, reviewer: str = "agent:safety-reviewer") -> dict:
    """Separate agent with its own rules; the validator cannot approve its own test."""
    if reviewer == test["proposed_by"]:
        raise PermissionError("the validator cannot review its own test")
    failed = [k for k, rule in SAFETY_RULES.items() if not rule(test)]
    return {"finding": test["finding"], "approved": not failed, "failed_rules": failed, "reviewer": reviewer}


def validate(findings: list[dict] | None = None) -> dict:
    findings = FINDINGS if findings is None else findings
    urgent, dropped, credited, refused = [], [], [], []
    for f in findings:
        t = propose_test(f)
        rv = safety_review(t)
        if not rv["approved"]:
            refused.append({"finding": f["id"], "why": rv["failed_rules"]})
            continue
        if f["test_result"] != "exploitable":
            dropped.append({"finding": f["id"], "why": f"not proven ({f['test_result']})"})
            continue
        credit = CONTROL_CREDIT.get(f["control"], 0.0)
        row = {"finding": f["id"], "asset": f["asset"], "residual": round(1 - credit, 2), "control": f["control"]}
        (credited if credit else urgent).append(row)
    return {"urgent": urgent, "credited": credited, "dropped": dropped, "refused_by_safety": refused}


LEAKS = [
    {"source": "paste-site-sim", "email": "user03@brightwater-ledger.example", "password_sha1_prefix": "5BAA6",
     "seen": "2026-10-29"},
    {"source": "combo-list-sim", "email": "user11@brightwater-ledger.example", "password_sha1_prefix": "7C4A8",
     "seen": "2026-10-27"},
    {"source": "combo-list-sim", "email": "former@brightwater-ledger.example", "password_sha1_prefix": "B1B37",
     "seen": "2026-10-20"},
    {"source": "stealer-log-sim", "email": "svc-legacy@brightwater-ledger.example",
     "password_sha1_prefix": "E38AD", "seen": "2026-10-30"},
]


def leaked_credentials(leaks: list[dict] | None = None) -> list[dict]:
    leaks = LEAKS if leaks is None else leaks
    accts = {a["email"]: a for a in data.accounts()}
    out = []
    for lk in leaks:
        a = accts.get(lk["email"])
        if not a:
            out.append({"email": lk["email"], "match": False, "proposal": "none (no such account)"})
            continue
        prop = "force reset + revoke sessions (needs approval)"
        if a["role"] == "admin":
            prop += "; privileged: two approvals"
        out.append({"email": lk["email"], "match": True, "account": a["id"], "proposal": prop,
                    "status": "pending approval"})
    return out


# ---------- test-before-enforce ----------

def dry_run(policy: dict, current: dict, traffic: list[dict]) -> dict:
    """Compare old and new rule sets on recorded (synthetic) traffic before enforcing."""
    def allowed(rules, flow):
        return flow["port"] in rules["allow_ports"] and flow["src"] not in rules.get("deny_src", [])

    diff = {"added_ports": sorted(set(policy["allow_ports"]) - set(current["allow_ports"])),
            "removed_ports": sorted(set(current["allow_ports"]) - set(policy["allow_ports"]))}
    newly_blocked = [f for f in traffic if allowed(current, f) and not allowed(policy, f)]
    business = [f for f in newly_blocked if f.get("business")]
    return {"diff": diff, "newly_blocked_flows": len(newly_blocked), "business_flows_broken": len(business),
            "safe_to_enforce": not business, "rollback": {"restore": current, "sha": sha(current)[:12]}}


TRAFFIC = [{"src": "10.0.1.5", "port": 443, "business": True}, {"src": "10.0.1.8", "port": 3389},
           {"src": "10.0.2.9", "port": 8443, "business": True}, {"src": "198.51.100.7", "port": 22}]

CHANGES = [  # finding->verified fix hours, caused outage?
    ("CH-01", 30, False), ("CH-02", 52, False), ("CH-03", 18, False), ("CH-04", 70, True),
    ("CH-05", 26, False), ("CH-06", 40, False), ("CH-07", 22, False), ("CH-08", 64, False),
]


def kpis() -> dict:
    v = validate()
    safe = [h for _, h, outage in CHANGES if not outage]
    return {"validated_urgent": len(v["urgent"]), "dropped_unproven": len(v["dropped"]),
            "credited_by_controls": len(v["credited"]), "refused_by_safety_reviewer": len(v["refused_by_safety"]),
            "mttsr_hours": round(mean(safe), 1),
            "zero_disruption_pct": round(100 * len(safe) / len(CHANGES), 1),
            "leaked_credential_matches": sum(x["match"] for x in leaked_credentials()),
            "basis": "simulated validation; synthetic change history"}
