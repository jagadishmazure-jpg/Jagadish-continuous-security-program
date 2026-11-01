"""SOC authority registry, post-action verification and SOC KPIs (synthetic incidents).

Authority is granted per action, not per platform. Each entry moves through
advise -> act_with_approval -> act_within_policy -> proven. A board (people) promotes one step at a time with
evidence that meets the threshold. Any failed verification demotes the entry automatically by one step.
We do not report a blended MTTR or a platform-wide autonomy %; we report MTTR per stage and actions per stage.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from statistics import median

from .core import Evidence, HashLog, is_agent, rubber_stamp

STAGES = ("advise", "act_with_approval", "act_within_policy", "proven")
BOARD_ROLES = {"ciso", "soc_lead", "secops_lead"}


@dataclass
class Authority:
    action: str
    evidence_needed: str
    threshold: int  # verified successes needed at the current stage before promotion
    scope: str
    owner: str
    blast_radius: str
    rollback: str
    stage: str = "advise"
    verified: int = 0
    failures: int = 0
    history: list = field(default_factory=list)


CURRENT_STAGES = {"quarantine-email": "act_within_policy", "block-ip": "act_with_approval",
                  "isolate-endpoint": "act_with_approval", "delete-mailbox-rule": "act_with_approval"}


def registry(current: bool = False) -> dict[str, Authority]:
    """Fresh registry (everything at advise) or, with current=True, the synthetic present-day stages."""
    rows = [
        Authority("isolate-endpoint", "10 verified isolations with no false positive", 10, "workstations only",
                  "soc_lead", "1 device", "release isolation"),
        Authority("disable-user", "10 verified disables, 0 wrong user", 10, "non-privileged users", "it_lead",
                  "1 user", "re-enable account"),
        Authority("block-ip", "20 verified blocks, no business outage", 20, "edge firewall, 24h TTL",
                  "secops_lead", "1 IP for 24h", "remove block"),
        Authority("revoke-sessions", "10 verified revokes", 10, "Entra users", "it_lead", "1 user's sessions",
                  "user signs in again"),
        Authority("quarantine-email", "25 verified quarantines", 25, "inbound mail", "soc_lead", "1 message",
                  "release message"),
        Authority("delete-mailbox-rule", "15 verified removals", 15, "malicious forwarding rules", "it_lead",
                  "1 rule", "recreate rule from snapshot"),
        Authority("reset-password", "never automatic for admins", 999, "standard users", "it_lead", "1 user",
                  "user resets again"),
        Authority("patch-server", "board only; maintenance windows", 999, "non-prod first", "secops_lead",
                  "1 server", "snapshot restore"),
    ]
    if current:
        for a in rows:
            a.stage = CURRENT_STAGES.get(a.action, "advise")
    return {a.action: a for a in rows}


def promote(a: Authority, by: str, role: str, reason: str) -> str:
    if is_agent(by) or role not in BOARD_ROLES:
        raise PermissionError("the authority board (people) promotes")
    if not reason:
        raise ValueError("record the evidence reviewed")
    if a.stage == STAGES[-1]:
        raise ValueError("already proven")
    if a.verified < a.threshold:
        raise ValueError(f"needs {a.threshold} verified actions, has {a.verified}")
    old, a.stage = a.stage, STAGES[STAGES.index(a.stage) + 1]
    a.history.append({"from": old, "to": a.stage, "by": by, "reason": reason})
    a.verified = 0
    return a.stage


def record_outcome(a: Authority, verified: bool) -> str:
    """Post-action verification result. A failure demotes automatically."""
    if verified:
        a.verified += 1
    else:
        a.failures += 1
        if a.stage != STAGES[0]:
            old, a.stage = a.stage, STAGES[STAGES.index(a.stage) - 1]
            a.history.append({"from": old, "to": a.stage, "by": "automatic", "reason": "verification failed"})
        a.verified = 0
    return a.stage


def needs_approval(a: Authority) -> bool:
    return a.stage in ("advise", "act_with_approval")


UNDO = {a.action: a.rollback for a in registry().values()}


def verify_action(action: str, before: dict, after: dict) -> dict:
    """Post-action verification agent: checks the intended effect really happened (deterministic)."""
    checks = {
        "isolate-endpoint": lambda b, a: a.get("network") == "isolated",
        "disable-user": lambda b, a: a.get("enabled") is False,
        "block-ip": lambda b, a: a.get("blocked") is True,
        "revoke-sessions": lambda b, a: a.get("sessions", 1) == 0,
        "quarantine-email": lambda b, a: a.get("folder") == "quarantine",
        "delete-mailbox-rule": lambda b, a: a.get("forwarding_rule") is None,
    }
    ok = checks.get(action, lambda b, a: False)(before, after)
    return {"action": action, "verified": ok, "undo": UNDO.get(action), "label": "deterministic"}


def verified_fix_evidence(incident: str, action: str, result: dict) -> Evidence:
    if not result["verified"]:
        raise ValueError("only a verified fix becomes evidence")
    return Evidence("soc-authority", "verified_fix", f"{incident} {action} verified",
                    {"incident": incident, "action": action, "result": result}, ("CC7.4", "IR-4"),
                    produced_by="agent:post-action-verifier")


# ---------- synthetic incidents (minutes per stage) ----------

INCIDENTS = [
    # id, detect_min, triage, investigate, approve, act, verify, document, action, auto_triage_correct,
    # override_reason, verified, label
    ("INC-01", 6, 3, 18, 7, 1, 2, 4, "isolate-endpoint", True, None, True, "reasoning"),
    ("INC-02", 14, 2, 25, 42, 1, 3, 5, "disable-user", True, None, True, "reasoning"),
    ("INC-03", 4, 1, 6, 0, 1, 1, 2, "quarantine-email", True, None, True, "deterministic"),
    ("INC-04", 22, 5, 40, 12, 2, 2, 6, "block-ip", False, "wrong severity", True, "reasoning"),
    ("INC-05", 9, 2, 15, 0, 1, 1, 2, "quarantine-email", True, None, True, "deterministic"),
    ("INC-06", 31, 4, 55, 95, 3, 4, 9, "revoke-sessions", True, None, False, "reasoning"),
    ("INC-07", 5, 2, 12, 6, 1, 2, 3, "delete-mailbox-rule", False, "benign rule (user's own)", True, "reasoning"),
    ("INC-08", 12, 3, 20, 9, 1, 2, 4, "isolate-endpoint", True, None, True, "reasoning"),
    ("INC-09", 7, 1, 9, 0, 1, 1, 2, "quarantine-email", True, None, True, "deterministic"),
    ("INC-10", 18, 6, 35, 14, 2, 2, 5, "disable-user", False, "service account, business critical", False,
     "reasoning"),
    ("INC-11", 3, 1, 8, 4, 1, 1, 3, "block-ip", True, None, True, "deterministic"),
    ("INC-12", 11, 2, 22, 8, 1, 2, 4, "isolate-endpoint", True, None, True, "reasoning"),
]
PHASES = ("triage", "investigate", "approve", "act", "verify", "document")
COST_PER_ANALYST_MIN = 1.5  # synthetic loaded cost, dollars


def soc_kpis(incidents: list | None = None, approvals_seconds: dict | None = None) -> dict:
    inc = INCIDENTS if incidents is None else incidents
    approvals_seconds = approvals_seconds or {"sam.soc": [8, 9, 12, 40, 11], "lee.soc": [95, 120, 60, 80]}
    stage_mins = {p: median(r[2 + i] for r in inc) for i, p in enumerate(PHASES)}
    reg = registry(current=True)
    by_stage = {s: 0 for s in STAGES}
    for r in inc:
        by_stage[reg[r[8]].stage] += 1
        record_outcome(reg[r[8]], r[11])
    verified = [r for r in inc if r[11]]
    analyst_mins = sum(r[2] + r[3] + r[4] + r[7] for r in inc)
    overrides = {}
    for r in inc:
        if r[10]:
            overrides[r[10]] = overrides.get(r[10], 0) + 1
    return {
        "mttd_median_min": median(r[1] for r in inc),
        "mttr_median_min_by_phase": stage_mins,
        "auto_triage_accuracy_pct": round(100 * sum(r[9] for r in inc) / len(inc), 1),
        "override_reasons": overrides,
        "actions_by_authority_stage": by_stage,
        "demotions": sum(1 for a in reg.values() for h in a.history if h["by"] == "automatic"),
        "false_actions": sum(not r[11] for r in inc), "undos_run": sum(not r[11] for r in inc),
        "approval_delay_median_min": median(r[4] for r in inc if r[4]),
        "cost_per_verified_fix": round(analyst_mins * COST_PER_ANALYST_MIN / len(verified), 2),
        "labels": {k: sum(r[12] == k for r in inc) for k in ("deterministic", "reasoning")},
        "rubber_stamp_flags": sorted(a for a, s in approvals_seconds.items() if rubber_stamp(s)),
        "basis": "synthetic incidents; no blended MTTR or platform-wide autonomy % reported",
    }


def run_demo() -> dict:
    reg = registry()
    q = reg["quarantine-email"]
    for _ in range(25):
        record_outcome(q, True)
    promote(q, "ciso.amara", "ciso", "25 verified quarantines reviewed")
    for _ in range(25):
        record_outcome(q, True)
    promote(q, "sol.soc", "soc_lead", "25 more verified at act_with_approval")
    stage_after_promotions = q.stage
    record_outcome(q, False)
    log = HashLog()
    res = verify_action("isolate-endpoint", {"network": "connected"}, {"network": "isolated"})
    ev = verified_fix_evidence("INC-01", "isolate-endpoint", res)
    log.append("agent:post-action-verifier", "verified", evidence=ev.evidence_id)
    return {"promoted_to": stage_after_promotions, "after_failure": q.stage, "history": len(q.history),
            "evidence": ev.evidence_id, "controls": list(ev.control_hints)}
