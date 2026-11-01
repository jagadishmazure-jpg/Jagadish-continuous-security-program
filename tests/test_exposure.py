import json

import pytest

from secprog import attack_paths, ctem, data, exposure, mcp_server
from secprog.core import HashLog

ASSET_IDS = [a["id"] for a in data.assets()]
S = exposure.scores()


@pytest.mark.parametrize("aid", ASSET_IDS)
def test_rule_criticality_bounds(aid):
    c = exposure.criticality(aid, overrides={})
    assert 1 <= c["value"] <= 10 and c["source"] == "rules"


@pytest.mark.parametrize("aid", ASSET_IDS)
def test_asset_exposure_bounds(aid):
    assert 0 <= exposure.asset_exposure(aid, overrides={}) <= 1000


def test_org_and_bu_scores():
    assert S["org"] == 376
    assert S["business_units"] == {"payments": 459, "lending": 406, "platform": 343, "corporate": 284}


def test_no_findings_means_zero():
    assert exposure.scores(findings=[], overrides={})["org"] == 0


def test_override_by_human():
    ov, log = {}, HashLog()
    exposure.override("A-010", 10, "maria.secops", "holds payroll exports", ov, log)
    c = exposure.criticality("A-010", ov)
    assert c["value"] == 10 and c["source"] == "override" and log.verify()[0]


@pytest.mark.parametrize("by,value,reason,err", [
    ("agent:exposure", 5, "r", PermissionError), ("maria", 0, "r", ValueError),
    ("maria", 11, "r", ValueError), ("maria", 5, "", ValueError), ("maria", -1, "r", ValueError)])
def test_override_rules(by, value, reason, err):
    with pytest.raises(err):
        exposure.override("A-010", value, by, reason, {}, HashLog())


def test_override_unknown_asset():
    with pytest.raises(KeyError):
        exposure.override("A-999", 5, "maria", "r", {}, HashLog())


def test_override_changes_score():
    ov = {}
    base = exposure.scores(overrides=ov)["org"]
    for aid in ASSET_IDS:
        ov[aid] = {"value": 1, "by": "maria", "reason": "test"}
    assert exposure.scores(overrides=ov)["org"] < base


def test_trend_ends_today_and_falls():
    t = exposure.trend()
    assert len(t) == 91 and t[-1][1] == S["org"] and t[0][1] > t[-1][1]


def test_trend_deltas():
    assert exposure.trend_deltas() == {"7d": -6, "30d": -24, "90d": -72}


def test_top_contributors_sorted():
    tc = exposure.top_contributors()
    assert tc[0][0] == "payments" and [x[1] for x in tc] == sorted((x[1] for x in tc), reverse=True)


# ----- attack paths -----

def test_paths_found():
    ps = attack_paths.paths()
    assert len(ps) == 10
    assert all(p[0] == "internet" and p[-1] in attack_paths.CROWN for p in ps)


@pytest.mark.parametrize("p", attack_paths.paths(), ids=lambda p: "->".join(p))
def test_paths_are_simple(p):
    assert len(set(p)) == len(p) and len(p) <= 7


def test_choke_points():
    cps = attack_paths.choke_points()
    assert len(cps) == 5 and cps[0]["closes_paths"] == 4 and all(c["of"] == 10 for c in cps)
    assert all(c["technique"].startswith("T") for c in cps)


@pytest.mark.parametrize("n", [1, 3, 5, 10])
def test_choke_limit(n):
    assert len(attack_paths.choke_points(n)) <= n


def test_removing_all_edges_closes_everything():
    assert attack_paths.paths(edges=[("a", "b", "T0000", "unrelated")]) == []


EXPECTED_TOXIC = {"TOX-01": 0, "TOX-02": 2, "TOX-03": 2, "TOX-04": 1, "TOX-05": 2, "TOX-06": 2, "TOX-07": 1,
                  "TOX-08": 1, "TOX-09": 1, "TOX-10": 1}


@pytest.mark.parametrize("rule,count", sorted(EXPECTED_TOXIC.items()))
def test_toxic_counts(rule, count):
    assert attack_paths.toxic_counts()[rule] == count


def test_ten_toxic_rules():
    assert len(attack_paths.RULES) == 10


# ----- CTEM -----

def test_ctem_demo():
    assert ctem.demo() == {"stage": "done", "closed": 3, "reopened": 1, "fix_validation_pass_pct": 75.0,
                           "log_ok": True}


def test_ctem_stage_needs_artifact():
    c = ctem.Cycle("svc", "owner")
    with pytest.raises(ValueError):
        c.complete_stage("", "maria")


@pytest.mark.parametrize("i", range(5))
def test_ctem_stage_order(i):
    c = ctem.Cycle("svc", "owner")
    for _ in range(i):
        c.complete_stage("x", "maria")
    assert c.stage == ctem.STAGES[i]


def test_ctem_agent_cannot_close():
    c = ctem.Cycle("svc", "o")
    c.open_ticket("TKT-001", "f", "o")
    c.mark_fixed("TKT-001", "dev")
    with pytest.raises(PermissionError):
        c.close("TKT-001", "agent:ctem")


def test_ctem_close_needs_fix_first():
    c = ctem.Cycle("svc", "o")
    c.open_ticket("TKT-001", "f", "o")
    with pytest.raises(ValueError):
        c.close("TKT-001", "maria")


@pytest.mark.parametrize("passed,status", [(True, "closed"), (False, "reopened")])
def test_ctem_rescan_decides(passed, status):
    c = ctem.Cycle("svc", "o")
    c.open_ticket("T", "f", "o")
    c.mark_fixed("T", "dev")
    ticket = c.close("T", "maria", rescan={"T": passed})
    assert ticket.status == status


def test_five_minute_list():
    fl = ctem.five_minute_list()
    assert len(fl) == 5 and [x["impact"] for x in fl] == sorted((x["impact"] for x in fl), reverse=True)


def test_unknown_assets_and_certs():
    assert all(u["owner"] is None for u in ctem.unknown_assets())
    ex = ctem.expiring_certs()
    assert any(c["expired"] for c in ex) and all(c["days_left"] <= 30 for c in ex)


# ----- read-only MCP -----

def _call(name, args=None, i=1):
    return mcp_server.handle({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                              "params": {"name": name, "arguments": args or {}}})


def test_tools_list():
    r = mcp_server.handle({"id": 1, "method": "tools/list"})
    assert {t["name"] for t in r["result"]["tools"]} == set(mcp_server.TOOLS)


@pytest.mark.parametrize("scope", ["org", "payments", "lending", "platform", "corporate", "A-001", "A-020"])
def test_exposure_scope(scope):
    out = json.loads(_call("get_exposure_score", {"scope": scope})["result"]["content"][0]["text"])
    assert out["scope"] == scope


@pytest.mark.parametrize("name", ["delete_asset", "close_ticket", "run_shell", "set_criticality", "", None])
def test_write_tools_refused(name):
    assert _call(name)["error"]["code"] == -32602


@pytest.mark.parametrize("method", ["tools/write", "resources/delete", "", None])
def test_unknown_method(method):
    assert mcp_server.handle({"id": 1, "method": method})["error"]["code"] == -32601


@pytest.mark.parametrize("args", [{"scope": "x" * 65}, {"bogus": 1}, {"scope": "nowhere"}])
def test_bad_scope_args(args):
    assert "error" in _call("get_exposure_score", args)


@pytest.mark.parametrize("limit", ["5", True, 1.5, None])
def test_choke_limit_type(limit):
    assert "error" in _call("top_choke_points", {"limit": limit})


@pytest.mark.parametrize("limit,n", [(0, 1), (3, 3), (50, 5)])
def test_choke_limit_clamped(limit, n):
    out = json.loads(_call("top_choke_points", {"limit": limit})["result"]["content"][0]["text"])
    assert 1 <= len(out["choke_points"]) <= max(n, 10)


def test_explain_requires_id():
    assert "error" in _call("explain_cve_rank", {})


def test_explain_unknown():
    assert "error" in _call("explain_cve_rank", {"cve_id": "CVE-SYN-2026-9999"})


@pytest.mark.parametrize("c", data.cves()[:15], ids=lambda c: c["id"])
def test_explain_known(c):
    out = json.loads(_call("explain_cve_rank", {"cve_id": c["id"]})["result"]["content"][0]["text"])
    assert out["of"] == 60
