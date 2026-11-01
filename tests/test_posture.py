import pytest

from secprog import access_review, ai_exposure, data, devices, vuln_sla
from secprog.ai_exposure import Register

DEV_ROWS = devices.evaluate()


def test_device_summary():
    s = devices.summary()
    assert (s["devices"], s["compliant"], s["compliant_pct"]) == (30, 5, 16.7)
    assert (s["risky_exclusions"], s["exposed_ports"], s["plaintext_creds"], s["stale_agents"]) == (2, 15, 4, 5)


@pytest.mark.parametrize("row", DEV_ROWS, ids=lambda r: r["device"])
def test_device_row_consistent(row):
    assert row["compliant"] == (not row["failed"])
    assert set(row["checks"]) == set(devices.CHECKS)


@pytest.mark.parametrize("check", sorted(devices.CHECKS))
def test_each_check_returns_bool(check):
    assert all(isinstance(r["checks"][check], bool) for r in DEV_ROWS)


@pytest.mark.parametrize("excl,risky", [("C:\\Users\\Public\\x", True), ("*.ps1", True), ("C:\\Temp\\a", True),
                                        ("*.exe", True), ("C:\\Program Files\\Vendor", False), ("/opt/app", False)])
def test_risky_exclusions(excl, risky):
    assert bool(devices.risky_exclusions({"av_exclusions": [excl]})) is risky


def test_device_evidence():
    e = devices.as_evidence()
    assert e.kind and e.control_hints


# ----- access review -----

ISSUES = access_review.issues()


def test_access_issue_counts():
    d = access_review.demo()
    assert d["issues"] == 16 and d["completion_pct"] == 100.0 and d["revoked"] == 10 and d["log_ok"]
    assert d["by_type"] == {"terminated_but_active": 2, "toxic_privileges": 2, "dormant": 10, "orphaned": 1,
                            "privileged_without_mfa": 1}


@pytest.mark.parametrize("item", ISSUES, ids=lambda i: f"{i['account']}-{i['type']}")
def test_issue_has_proposal(item):
    assert item["proposal"]


def _acct(**kw):
    base = {"id": "U-1", "terminated": False, "active": True, "last_login_days": 1, "manager": "m",
            "entitlements": [], "mfa": True}
    return {**base, **kw}


@pytest.mark.parametrize("kw,kind", [
    ({"terminated": True}, "terminated_but_active"), ({"last_login_days": 90}, "dormant"),
    ({"manager": ""}, "orphaned"), ({"entitlements": ["admin", "payments_approver"]}, "toxic_privileges"),
    ({"entitlements": ["admin"], "mfa": False}, "privileged_without_mfa")])
def test_issue_rules(kw, kind):
    assert kind in {i["type"] for i in access_review.issues([_acct(**kw)])}


def test_clean_account_has_no_issues():
    assert access_review.issues([_acct()]) == []


def test_agent_cannot_decide_access():
    c = access_review.Campaign("r")
    with pytest.raises(PermissionError):
        c.decide("U-1", "dormant", "revoke", "agent:access-review")


@pytest.mark.parametrize("decision", ["delete", "approve", "", "ignore"])
def test_bad_access_decision(decision):
    with pytest.raises(ValueError):
        access_review.Campaign("r").decide("U-1", "dormant", decision, "rina")


def test_keep_needs_note():
    c = access_review.Campaign("r")
    with pytest.raises(ValueError):
        c.decide("U-1", "dormant", "keep", "rina")
    assert c.decide("U-1", "dormant", "keep", "rina", "break-glass")["decision"] == "keep"


def test_completion_empty():
    assert access_review.Campaign("r").completion([]) == 100.0


# ----- vulnerability SLA -----

@pytest.mark.parametrize("sev,crit,days", [("critical", 9, 4), ("critical", 3, 7), ("high", 8, 15), ("high", 7, 30),
                                           ("medium", 10, 45), ("low", 1, 180), ("info", 9, 182)])
def test_due_days(sev, crit, days):
    assert vuln_sla.due_days(sev, crit) == days


def test_age():
    assert vuln_sla.age("2026-10-01") == 30


def test_sla_summary():
    s = vuln_sla.summary()
    assert (s["open"], s["passing"], s["adherence_pct"]) == (72, 52, 72.2)
    assert s["by_severity"]["critical"] == {"open": 6, "breached": 6}


@pytest.mark.parametrize("row", vuln_sla.evaluate(), ids=lambda r: r["fingerprint"])
def test_sla_rows(row):
    assert row["passed"] == (row["days_over"] == 0)


@pytest.mark.parametrize("sev,median", [("critical", 70.0), ("high", 330.0), ("medium", 1500.0), ("low", 3050.0)])
def test_mttr_median(sev, median):
    assert vuln_sla.mttr()[sev]["median_h"] == median


def test_sla_no_findings():
    assert vuln_sla.evaluate([]) == []


# ----- AI exposure -----

def test_discover():
    d = ai_exposure.discover()
    assert len(d["tools"]) == 5 and d["vulnerable_ai_libraries"]


def test_concentration():
    c = ai_exposure.concentration()
    assert c["top1_share_pct"] == 66.7 and c["hhi"] == 0.556 and c["with_fallback_pct"] == 66.7


@pytest.mark.parametrize("provider,stopped", [("model-provider-a", ["WF-trust-drafts"]),
                                              ("model-provider-b", ["WF-vendor-criteria"]),
                                              ("model-provider-z", [])])
def test_outage_drill(provider, stopped):
    r = ai_exposure.outage_drill(provider)
    assert r["stopped"] == stopped and r["result"] == ("fail" if stopped else "pass")


def test_register_demo():
    r = ai_exposure.demo_register()
    assert ai_exposure.inventory_completeness(r) == 50.0
    assert r.entries["free-ai-notes"].status == "rejected" and r.log.verify()[0]


def test_register_agent_cannot_decide():
    r = Register()
    r.request("x", "o", "p", ("internal",), "low")
    with pytest.raises(PermissionError):
        r.decide("x", "approve", "agent:ai-exposure", "ok")


@pytest.mark.parametrize("fields,ok", [
    (("o", "p", ("internal",), "low"), True), (("", "p", ("internal",), "low"), False),
    (("o", "", ("internal",), "low"), False), (("o", "p", (), "low"), False), (("o", "p", ("internal",), ""), False),
    (("o", "p", ("x",), "prohibited"), False), (("o", "p", ("pii",), "low"), False),
    (("o", "p", ("pii",), "medium"), True)])
def test_register_approval_rules(fields, ok):
    r = Register()
    r.request("tool", *fields)
    if ok:
        assert r.decide("tool", "approve", "chair", "fine").status == "approved"
    else:
        with pytest.raises(ValueError):
            r.decide("tool", "approve", "chair", "fine")


def test_register_bad_tier():
    with pytest.raises(ValueError):
        Register().request("t", "o", "p", (), "extreme")


def test_register_bad_decision():
    r = Register()
    r.request("t", "o", "p", ("internal",), "low")
    with pytest.raises(ValueError):
        r.decide("t", "maybe", "chair", "x")


def test_completeness_empty():
    assert ai_exposure.inventory_completeness(Register()) == 0.0


def test_vendor_ai_count():
    assert sum(bool(v["ai_provider"]) for v in data.vendors()) >= 3
