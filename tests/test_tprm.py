import json

import pytest

from secprog import data, tprm
from secprog.tprm import Assessment

VENDORS = {v["id"]: v for v in data.vendors()}

EXPECTED = {"V-03": (12, 7, 2, 1, 2, 5), "V-04": (7, 7, 0, 0, 0, 0), "V-09": (12, 4, 0, 1, 7, 8)}


@pytest.mark.parametrize("vid", sorted(EXPECTED))
def test_assessment_results(vid):
    s = tprm.run(vid).summary()
    assert (s["criteria"], s["Met"], s["Partially Met"], s["Not Met"], s["Inconclusive"], s["followups"]) == \
        EXPECTED[vid]
    assert s["state"] == "monitoring"


@pytest.mark.parametrize("vid", sorted(VENDORS))
def test_criteria_pack_by_profile(vid):
    v = VENDORS[vid]
    a = Assessment(v)
    ids = [c[0] for c in a.draft_criteria()]
    assert ("AI-01" in ids) == bool(v["ai_features"])
    assert ("R-01" in ids) == (v["tier"] in ("critical", "high"))


@pytest.mark.parametrize("vid", sorted(VENDORS))
def test_every_vendor_runs(vid):
    a = tprm.run(vid)
    assert a.state == "monitoring" and a.log.verify()[0]
    for r in a.results:
        assert r["outcome"] in tprm.OUTCOMES
        assert bool(r["citations"]) == (r["outcome"] != "Inconclusive")


@pytest.mark.parametrize("val,outcome", [("48h", "Met"), ("72h", "Met"), ("96h", "Partially Met"),
                                         ("120h", "Partially Met"), ("168h", "Not Met")])
def test_breach_notice_grading(val, outcome):
    assert tprm.grade("C-04", ("breach_notice",), {"breach_notice": (val, "doc")})["outcome"] == outcome


@pytest.mark.parametrize("rto,outcome", [(4, "Met"), (24, "Met"), (25, "Not Met"), (72, "Not Met")])
def test_rto_grading(rto, outcome):
    assert tprm.grade("R-02", ("rto",), {"rto": (rto, "doc")})["outcome"] == outcome


@pytest.mark.parametrize("val,outcome", [(True, "Met"), (False, "Not Met"), ("partial", "Partially Met")])
def test_bool_grading(val, outcome):
    assert tprm.grade("C-02", ("mfa",), {"mfa": (val, "doc")})["outcome"] == outcome


def test_missing_evidence_inconclusive():
    assert tprm.grade("C-02", ("mfa",), {})["outcome"] == "Inconclusive"


def _to(state):
    a = Assessment(VENDORS["V-03"])
    steps = [lambda: a.draft_criteria(), lambda: a.approve_criteria("paul"), lambda: a.assess(),
             lambda: a.draft_followups(), lambda: a.approve_followups("paul")]
    for s in steps[:state]:
        s()
    return a


def test_agent_cannot_approve_criteria():
    with pytest.raises(PermissionError):
        _to(1).approve_criteria("agent:tprm")


def test_agent_cannot_approve_followups():
    with pytest.raises(PermissionError):
        _to(4).approve_followups("agent:tprm")


def test_assess_needs_approved_criteria():
    with pytest.raises(ValueError):
        _to(1).assess()


def test_cannot_skip_states():
    a = _to(0)
    with pytest.raises(ValueError):
        a.approve_criteria("paul")


def test_remove_criteria_on_approval():
    a = _to(1)
    a.approve_criteria("paul", remove=("C-05",))
    assert "C-05" not in [c[0] for c in a.criteria]


def test_drop_followups():
    a = _to(4)
    a.approve_followups("paul", drop=("AI-01",))
    assert "AI-01" not in [f["criterion"] for f in a.followups]
    assert all("not sent" in f["status"] for f in a.followups)


@pytest.mark.parametrize("by,role,res,note,err", [
    ("agent:tprm", "ciso", "low", "n", PermissionError), ("amara", "sales", "low", "n", PermissionError),
    ("amara", "ciso", "tiny", "n", ValueError), ("amara", "ciso", "low", "", ValueError)])
def test_residual_rules(by, role, res, note, err):
    with pytest.raises(err):
        _to(5).decide_residual(by, role, res, note)


@pytest.mark.parametrize("role", ["ciso", "procurement", "cro"])
def test_residual_roles(role):
    a = _to(5)
    assert a.decide_residual("amara", role, "reject", "fails AI-01") == "reject"


def test_writeback_json():
    w = json.loads(tprm.run("V-03").writeback())
    assert w["event"] == "vendor.assessment.decided" and w["decided_by"] == "ciso.amara"


@pytest.mark.parametrize("tier,months", sorted(tprm.CADENCE_MONTHS.items()))
def test_next_review(tier, months):
    from datetime import date
    d = date.fromisoformat(tprm.next_review(tier, "2026-01-01"))
    assert abs((d - date(2026, 1, 1)).days - months * 30.44) <= 1


def test_reassessment_due():
    due = tprm.reassessment_due()
    assert [d["vendor"] for d in due] == ["V-03", "V-07", "V-08"]
    assert tprm.reassessment_due(ai_changes=set()) != due


def test_tprm_kpis():
    k = tprm.kpis()
    assert k["coverage_pct"] == 30.0 and k["avg_criteria_per_assessment"] == 10.3 and k["overdue_or_triggered"] == 3


@pytest.mark.parametrize("pid,status", [("PR-101", "ok"), ("PR-102", "BLOCKED"), ("PR-103", "ok (exempt"),
                                        ("PR-104", "ok"), ("PR-105", "BLOCKED")])
def test_purchase_gate(pid, status):
    pr = next(p for p in tprm.PURCHASES if p["id"] == pid)
    r = tprm.purchase_gate(pr)
    assert r["status"].startswith(status)
    assert r["writeback"]["procurement_status"] == ("hold" if status == "BLOCKED" else "clear")


def test_purchase_waiting():
    r = tprm.purchase_gate({"id": "X", "vendor": "V-06", "amount": 5000, "spend_approved_day": None,
                            "security_review_done_day": None})
    assert r["status"] == "waiting for security review"


def test_exemption_needs_low_tier():
    r = tprm.purchase_gate({"id": "X", "vendor": "V-03", "amount": 10, "spend_approved_day": 1,
                            "security_review_done_day": None})
    assert r["status"].startswith("BLOCKED")


def test_purchase_summary():
    assert tprm.purchase_summary()["blocked"] == 2
