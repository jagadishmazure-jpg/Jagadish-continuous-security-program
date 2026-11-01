"""Governance for our own agents.

* Plain-English policies are compiled into rules by a small fixed grammar. A sentence the grammar cannot read
  is rejected; the compiler never guesses.
* Each policy sits on a Trust Ladder: shadow (log what it would block) -> recommend (warn) -> enforce (block).
  Only a person moves a policy, one step at a time.
* The gate runs before every agent action. Irreversible tools always need an approved request.
* Drift detection compares what an agent did with what it is registered to do.
* Monitoring coverage: an agent with no heartbeat for more than 24 hours fails the control.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field

from .agents import AGENTS, Agent
from .core import HashLog, is_agent, sha

LADDER = ("shadow", "recommend", "enforce")
HEARTBEAT_LIMIT_H = 24

GRAMMAR = [
    (re.compile(r"^agents may not (?:use|call) (?P<tool>[\w*-]+)$"), "deny_tool"),
    (re.compile(r"^agents may not (?:touch|access) (?P<res>[\w*.-]+)$"), "deny_resource"),
    (re.compile(r"^(?P<tool>[\w*-]+) needs approval$"), "approval_tool"),
    (re.compile(r"^irreversible actions need approval$"), "approval_irreversible"),
    (re.compile(r"^agents may only act in tenant (?P<tenant>[\w-]+)$"), "tenant_only"),
    (re.compile(r"^agents may not send (?:email|messages)$"), "deny_send"),
]


class PolicyError(ValueError):
    pass


@dataclass
class Policy:
    id: str
    text: str
    rule: dict
    stage: str = "shadow"
    history: list = field(default_factory=list)

    @property
    def version(self) -> str:
        return sha([self.text, self.rule])[:10]


def compile_policy(pid: str, text: str) -> Policy:
    t = " ".join(text.strip().lower().rstrip(".").split())
    for rx, kind in GRAMMAR:
        m = rx.match(t)
        if m:
            return Policy(pid, text, {"kind": kind, **m.groupdict()})
    raise PolicyError(f"cannot compile policy {pid!r}; rewrite it using the documented grammar")


DEFAULT_POLICIES = [
    ("POL-01", "Agents may not send email."),
    ("POL-02", "Irreversible actions need approval."),
    ("POL-03", "Agents may not touch kyc-bucket."),
    ("POL-04", "Agents may only act in tenant brightwater."),
    ("POL-05", "publish_trust_update needs approval."),
    ("POL-06", "Agents may not use delete_*."),
]


class Gate:
    def __init__(self, policies: list[Policy] | None = None) -> None:
        self.policies = policies if policies is not None else [compile_policy(p, t) for p, t in DEFAULT_POLICIES]
        self.log = HashLog()
        self.blocked: list[dict] = []
        self.would_block: list[dict] = []

    def _get(self, pid: str) -> Policy:
        for p in self.policies:
            if p.id == pid:
                return p
        raise KeyError(pid)

    def promote(self, pid: str, by: str, reason: str) -> Policy:
        if is_agent(by):
            raise PermissionError("only a person moves a policy up the ladder")
        if not reason:
            raise ValueError("a promotion needs a reason")
        p = self._get(pid)
        i = LADDER.index(p.stage)
        if i == len(LADDER) - 1:
            raise ValueError("already enforced")
        p.history.append((p.stage, LADDER[i + 1], by, reason))
        p.stage = LADDER[i + 1]
        self.log.append(by, "policy_promoted", policy=pid, stage=p.stage, version=p.version)
        return p

    def demote(self, pid: str, by: str, reason: str) -> Policy:
        if is_agent(by):
            raise PermissionError("only a person moves a policy")
        p = self._get(pid)
        i = LADDER.index(p.stage)
        if i == 0:
            raise ValueError("already in shadow")
        p.history.append((p.stage, LADDER[i - 1], by, reason))
        p.stage = LADDER[i - 1]
        self.log.append(by, "policy_demoted", policy=pid, stage=p.stage)
        return p

    @staticmethod
    def _matches(rule: dict, action: dict) -> bool:
        k = rule["kind"]
        if k == "deny_tool":
            return fnmatch.fnmatch(action["tool"], rule["tool"])
        if k == "deny_resource":
            return fnmatch.fnmatch(action.get("resource", ""), rule["res"])
        if k == "approval_tool":
            return fnmatch.fnmatch(action["tool"], rule["tool"]) and not action.get("approved")
        if k == "approval_irreversible":
            return not action.get("reversible", True) and not action.get("approved")
        if k == "tenant_only":
            return action.get("tenant") != rule["tenant"]
        if k == "deny_send":
            return action["tool"] in {"send_email", "send_message", "post_message"}
        return False

    def check(self, agent: str, action: dict) -> dict:
        """Return allow / warn / block plus every policy that matched and at what stage."""
        hits = [p for p in self.policies if self._matches(p.rule, action)]
        enforced = [p.id for p in hits if p.stage == "enforce"]
        warned = [p.id for p in hits if p.stage == "recommend"]
        shadow = [p.id for p in hits if p.stage == "shadow"]
        verdict = "block" if enforced else "warn" if warned else "allow"
        rec = {"agent": agent, "tool": action["tool"], "verdict": verdict, "enforced": enforced, "warned": warned,
               "shadow": shadow}
        if enforced:
            self.blocked.append(rec)
        if shadow:
            self.would_block.append(rec)
        self.log.append(agent, "gate", tool=action["tool"], verdict=verdict, policies=[p.id for p in hits])
        return rec


SAMPLE_ACTIONS = [
    ("agent:trust-center", {"tool": "send_email", "tenant": "brightwater"}),
    ("agent:trust-center", {"tool": "publish_trust_update", "tenant": "brightwater"}),
    ("agent:trust-center", {"tool": "publish_trust_update", "tenant": "brightwater", "approved": True}),
    ("agent:exposure", {"tool": "read_findings", "tenant": "brightwater"}),
    ("agent:ai-exposure", {"tool": "read_bucket", "resource": "kyc-bucket", "tenant": "brightwater"}),
    ("agent:vciso", {"tool": "read_findings", "tenant": "kestrel"}),
    ("agent:access-review", {"tool": "disable_account", "reversible": False, "tenant": "brightwater"}),
    ("agent:access-review", {"tool": "disable_account", "reversible": False, "tenant": "brightwater",
                             "approved": True}),
    ("agent:scan-importer", {"tool": "delete_finding", "tenant": "brightwater"}),
    ("agent:reporter", {"tool": "build_report", "tenant": "brightwater"}),
]


def ladder_demo() -> dict:
    """Run the same 10 actions at each ladder stage (people promote every policy one step between runs)."""
    g = Gate()
    out = {}
    for stage_i, stage in enumerate(LADDER):
        if stage_i:
            for p in g.policies:
                g.promote(p.id, "ciso.amara", f"{stage} after a clean week in the previous stage")
        res = [g.check(a, act) for a, act in SAMPLE_ACTIONS]
        out[stage] = {v: sum(r["verdict"] == v for r in res) for v in ("allow", "warn", "block")}
    out["log_ok"] = g.log.verify()[0]
    return out


# ---------- drift ----------

BASELINE_CONFIG = {a.id: sha([a.scopes, a.tools, a.provider, a.autonomy]) for a in AGENTS}

OBSERVED = {  # synthetic: what each agent actually did this week
    "trust-center": {"tools": ["draft_update", "nda_decision", "send_email"]},
    "tprm": {"tools": ["assess_criterion", "draft_followup"], "provider": "model-provider-c"},
    "copilot": {"tools": ["answer"]},
    "exposure": {"tools": ["scores", "choke_points"]},
}


def drift(agents: list[Agent] | None = None, observed: dict | None = None) -> list[dict]:
    agents = AGENTS if agents is None else agents
    observed = OBSERVED if observed is None else observed
    out = []
    for a in agents:
        o = observed.get(a.id)
        if not o:
            continue
        extra = sorted(set(o.get("tools", [])) - set(a.tools))
        if extra:
            out.append({"agent": a.id, "type": "unregistered_tool", "detail": extra})
        if o.get("provider") and o["provider"] != a.provider:
            out.append({"agent": a.id, "type": "provider_changed", "detail": [a.provider, o["provider"]]})
    return out


def config_drift(agent: Agent) -> bool:
    return sha([agent.scopes, agent.tools, agent.provider, agent.autonomy]) != BASELINE_CONFIG[agent.id]


# ---------- monitoring, autonomy, decision rights ----------

def monitoring(agents: list[Agent] | None = None) -> dict:
    agents = AGENTS if agents is None else agents
    failing = [a.id for a in agents if a.heartbeat_hours > HEARTBEAT_LIMIT_H]
    return {"agents": len(agents), "monitored": len(agents) - len(failing),
            "coverage_pct": round(100 * (len(agents) - len(failing)) / len(agents), 1), "failing": failing,
            "control": "pass" if not failing else "fail"}


def autonomy_mix(agents: list[Agent] | None = None) -> dict:
    agents = AGENTS if agents is None else agents
    from .agents import AUTONOMY
    return {lvl: sum(a.autonomy == lvl for a in agents) for lvl in AUTONOMY}


def decision_rights(agents: list[Agent] | None = None) -> float:
    agents = AGENTS if agents is None else agents
    ok = sum(bool(a.owner and a.approver and a.escalation) for a in agents)
    return round(100 * ok / len(agents), 1)
