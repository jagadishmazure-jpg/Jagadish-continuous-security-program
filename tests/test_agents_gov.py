import pytest

from secprog import agents, coordinator, governance
from secprog.core import ApprovalError
from secprog.governance import Gate, PolicyError

AG = agents.AGENTS


def test_agent_counts():
    assert len(AG) == 19 and len(agents.core()) == 13


@pytest.mark.parametrize("a", AG, ids=lambda a: a.id)
def test_agent_fields(a):
    assert a.owner and not a.owner.startswith("agent:")
    assert a.autonomy in agents.AUTONOMY
    assert a.identity == f"agent:{a.id}"
    assert a.outcome and a.metric and a.failure_threshold


@pytest.mark.parametrize("a", AG, ids=lambda a: a.id)
def test_no_agent_acts_then_notifies(a):
    assert a.autonomy != "act_then_notify"


@pytest.mark.parametrize("a", AG, ids=lambda a: a.id)
def test_by_id_round_trip(a):
    assert agents.by_id(a.id) is a


@pytest.mark.parametrize("a", AG, ids=lambda a: a.id)
def test_no_config_drift(a):
    assert not governance.config_drift(a)


def test_unknown_agent():
    with pytest.raises(KeyError):
        agents.by_id("nope")


def test_agents_md_has_every_agent():
    md = agents.agents_md()
    assert all(f"| {a.id} |" in md for a in AG)


# ----- policy compiler -----

@pytest.mark.parametrize("text,kind", [
    ("Agents may not send email.", "deny_send"), ("agents may not send messages", "deny_send"),
    ("Irreversible actions need approval.", "approval_irreversible"),
    ("Agents may not touch kyc-bucket.", "deny_resource"), ("Agents may not access ledger.db", "deny_resource"),
    ("Agents may only act in tenant brightwater.", "tenant_only"),
    ("publish_trust_update needs approval.", "approval_tool"), ("Agents may not use delete_*.", "deny_tool"),
    ("AGENTS   MAY NOT CALL run_shell", "deny_tool")])
def test_compile(text, kind):
    assert governance.compile_policy("P", text).rule["kind"] == kind


@pytest.mark.parametrize("text", ["be careful", "agents should not send email", "", "delete everything",
                                  "agents may not"])
def test_compile_rejects(text):
    with pytest.raises(PolicyError):
        governance.compile_policy("P", text)


def test_policy_version_stable():
    a = governance.compile_policy("P", "Agents may not send email.")
    b = governance.compile_policy("P", "Agents may not send email.")
    assert a.version == b.version


def test_ladder_demo():
    d = governance.ladder_demo()
    assert d["shadow"] == {"allow": 10, "warn": 0, "block": 0}
    assert d["recommend"] == {"allow": 4, "warn": 6, "block": 0}
    assert d["enforce"] == {"allow": 4, "warn": 0, "block": 6}
    assert d["log_ok"]


def test_promote_needs_human_and_reason():
    g = Gate()
    with pytest.raises(PermissionError):
        g.promote("POL-01", "agent:x", "r")
    with pytest.raises(ValueError):
        g.promote("POL-01", "amara", "")


def test_promote_and_demote_path():
    g = Gate()
    assert g.promote("POL-01", "amara", "ok").stage == "recommend"
    assert g.promote("POL-01", "amara", "ok").stage == "enforce"
    with pytest.raises(ValueError):
        g.promote("POL-01", "amara", "ok")
    assert g.demote("POL-01", "amara", "noise").stage == "recommend"


def test_demote_floor_and_agent():
    g = Gate()
    with pytest.raises(ValueError):
        g.demote("POL-01", "amara", "x")
    with pytest.raises(PermissionError):
        g.demote("POL-01", "agent:x", "x")


def test_unknown_policy():
    with pytest.raises(KeyError):
        Gate().promote("POL-99", "amara", "x")


def _enforced():
    g = Gate()
    for p in g.policies:
        p.stage = "enforce"
    return g


@pytest.mark.parametrize("action,verdict", [
    ({"tool": "send_email", "tenant": "brightwater"}, "block"),
    ({"tool": "read_findings", "tenant": "brightwater"}, "allow"),
    ({"tool": "read_findings", "tenant": "kestrel"}, "block"),
    ({"tool": "read", "resource": "kyc-bucket", "tenant": "brightwater"}, "block"),
    ({"tool": "delete_finding", "tenant": "brightwater"}, "block"),
    ({"tool": "publish_trust_update", "tenant": "brightwater"}, "block"),
    ({"tool": "publish_trust_update", "tenant": "brightwater", "approved": True}, "allow"),
    ({"tool": "disable", "reversible": False, "tenant": "brightwater"}, "block"),
    ({"tool": "disable", "reversible": False, "tenant": "brightwater", "approved": True}, "allow")])
def test_gate_enforced(action, verdict):
    assert _enforced().check("agent:x", action)["verdict"] == verdict


def test_shadow_records_would_block():
    g = Gate()
    r = g.check("agent:x", {"tool": "send_email", "tenant": "brightwater"})
    assert r["verdict"] == "allow" and g.would_block


def test_drift():
    d = governance.drift()
    assert {x["type"] for x in d} == {"unregistered_tool", "provider_changed"}


def test_monitoring():
    m = governance.monitoring()
    assert m["coverage_pct"] == 89.5 and m["control"] == "fail" and len(m["failing"]) == 2


def test_autonomy_mix_and_rights():
    assert governance.autonomy_mix() == {"suggest": 17, "act_with_approval": 2, "act_then_notify": 0}
    assert governance.decision_rights() == 100.0


# ----- coordinator -----

@pytest.mark.parametrize("goal", sorted(coordinator.PLANS))
def test_plans_valid(goal):
    assert coordinator.plan(goal.upper()) == coordinator.PLANS[goal]


def test_unknown_goal():
    with pytest.raises(KeyError):
        coordinator.plan("take over the world")


def test_demo_week():
    k = coordinator.demo_week().kpis()
    assert k == {"proposed": 12, "approved": 9, "rejected": 1, "blocked": 2, "pending": 0, "override_rate_pct": 10.0,
                 "median_review_s": 95, "rubber_stamp_flag": False, "log_ok": True}


def test_coordinator_blocks_send():
    c = coordinator.Coordinator()
    assert c.propose("trust-center", "send_email", "x")["status"] == "blocked"


def test_coordinator_routes_to_inbox():
    c = coordinator.Coordinator()
    out = c.propose("dependency-ranker", "open_ticket", "pkg")
    assert out["status"] == "awaiting_approval"
    with pytest.raises(ApprovalError):
        c.decide(out["request"], "agent:coordinator", "ciso", True)


def test_irreversible_needs_two():
    c = coordinator.Coordinator()
    out = c.propose("access-review", "disable_account", "U-1", reversible=False)
    c.decide(out["request"], "maria", "secops_lead", True)
    assert c.inbox.items[out["request"]].status != "approved"
    c.decide(out["request"], "amara", "ciso", True)
    assert c.inbox.items[out["request"]].status == "approved"
