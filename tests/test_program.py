import email
import json

import pytest

from secprog import (
    ai_governance,
    controls,
    copilot,
    dashboard,
    frameworks,
    kpis,
    minipdf,
    msp,
    reports,
    svgchart,
    usecases,
    vciso,
)
from secprog import data as sdata
from secprog.__main__ import COMMANDS, main

# ----- MSP view -----

CLIENT_IDS = [c["id"] for c in sdata.clients()]


def test_canary():
    c = msp.TenantStore().canary_test()
    assert c == {"tenants": 8, "canary_leaks": 0, "cross_tenant_refused": 56, "passed": True}


@pytest.mark.parametrize("me", CLIENT_IDS)
@pytest.mark.parametrize("other", CLIENT_IDS)
def test_tenant_isolation_matrix(me, other):
    store = msp.TenantStore()
    if me == other:
        assert store.query(other, me)["id"] == me
    else:
        with pytest.raises(msp.TenantError):
            store.query(other, me)


def test_unknown_tenant():
    with pytest.raises(msp.TenantError):
        msp.TenantStore().query("C-99", "C-99")


@pytest.mark.parametrize("row", msp.sla_tracking(), ids=lambda r: r["client"])
def test_sla_rows(row):
    assert 0 <= row["sla_met_pct"] <= 100 and row["tier"] in msp.TIERS


def test_roadmap():
    r = msp.Roadmap("Kestrel")
    items = r.build()
    assert items[0]["id"] == "RM-01" and r.total_cost() == 140000
    with pytest.raises(PermissionError):
        r.approve("agent:vciso", "vciso")
    with pytest.raises(PermissionError):
        r.approve("amara", "ciso")
    assert r.approve("val.vciso", "vciso") == "approved"


def test_roadmap_needs_items():
    with pytest.raises(ValueError):
        msp.Roadmap("x").approve("val", "vciso")


def test_roadmap_overflow_goes_next_year():
    items = msp.Roadmap("x").build(months=3)
    assert any(i["start_month"] is None for i in items)


@pytest.mark.parametrize("g", msp.GAPS, ids=lambda g: g[0])
def test_gap_score_bounds(g):
    assert 1 <= msp.score(g) <= 5


def test_oversharing():
    o = msp.oversharing()
    assert [x["site"] for x in o] == ["Finance-Board", "HR-Salaries", "IT-Runbooks"]


def test_raci():
    assert msp.raci_check() == []
    bad = {"Policy approval": ("vCISO", "MSP", "x", "y"), "Endpoint patching": ("MSP", "A, B", "x", "y")}
    assert len(msp.raci_check(bad)) == 2


def test_msp_roi():
    r = msp.roi()
    assert r["hours_saved_per_month"] == 21 and "SIMULATED" in r["basis"]


@pytest.mark.parametrize("cid", CLIENT_IDS)
def test_qbr_pack_scoped(cid):
    html = msp.qbr_pack(cid, cid)
    assert "Not sent" in html
    others = [c["secret_canary"] for c in sdata.clients() if c["id"] != cid]
    assert not any(o in html for o in others)


def test_qbr_cross_tenant_refused():
    with pytest.raises(msp.TenantError):
        msp.qbr_pack("C-02", "C-03")


# ----- controls and frameworks -----

RES = controls.results()


def test_thirty_controls():
    assert len(RES) == 30
    assert sorted(r["status"] for r in RES.values()).count("pass") == 12


@pytest.mark.parametrize("cid", sorted(RES))
def test_control_status(cid):
    assert RES[cid]["status"] in controls.SCORE and RES[cid]["name"]


@pytest.mark.parametrize("cid", sorted(RES))
def test_every_control_is_used(cid):
    assert frameworks.crosswalk(cid)


SUMMARY = frameworks.coverage_summary()


def test_coverage_summary():
    assert (SUMMARY["frameworks"], SUMMARY["requirements"], SUMMARY["mapped"], SUMMARY["gaps"]) == (12, 110, 109, 1)
    assert SUMMARY["by_mapping_type"] == {"approximate": 12}


READY = {"SOC2": 53.3, "ISO27001": 62.5, "NIST_CSF": 50.0, "PCI_DSS": 63.6, "CCPA": 44.4, "NIS2": 54.5,
         "HITRUST": 58.3, "ISO42001": 40.0, "AIUC1": 40.0, "EU_CRA": 77.8, "EU_AI_ACT": 90.0, "NIST_AI_RMF": 37.5}


@pytest.mark.parametrize("fid,pct", sorted(READY.items()))
def test_readiness(fid, pct):
    assert frameworks.readiness(fid)["ready_pct"] == pct


@pytest.mark.parametrize("fid", sorted(frameworks.FRAMEWORKS))
def test_weakest_control_decides(fid):
    for row in frameworks.readiness(fid)["rows"]:
        if row["status"] == "gap":
            continue
        worst = min(controls.SCORE[RES[c]["status"]] for c in row["controls"])
        assert row["status"] == {1.0: "ready", 0.5: "partial", 0.0: "not_ready"}[worst]


def test_aiuc1_gap():
    assert frameworks.readiness("AIUC1")["gaps"] == ["F"]


@pytest.mark.parametrize("fid", ["CCPA", "NIS2", "HITRUST"])
def test_new_crosswalks_have_rings(fid):
    name = frameworks.FRAMEWORKS[fid][0].split(" (")[0]
    assert name in frameworks.rings_html()


@pytest.mark.parametrize("v,p,q,hib,out", [(95, 90, 75, True, "pass"), (80, 90, 75, True, "partial"),
                                           (10, 90, 75, True, "fail"), (2, 5, 10, False, "pass"),
                                           (7, 5, 10, False, "partial"), (20, 5, 10, False, "fail")])
def test_band(v, p, q, hib, out):
    assert controls._band(v, p, q, hib) == out


def test_dsr_on_time():
    assert 0 <= controls.dsr_on_time() <= 100


def test_ai_generated_test_needs_approval():
    t = controls.draft_test("CTL-01", "ai_answer_accuracy", ">=", 80)
    with pytest.raises(PermissionError):
        t.run()
    with pytest.raises(PermissionError):
        t.approve("agent:copilot", "ok")
    with pytest.raises(ValueError):
        t.approve("amara", "")
    t.approve("amara", "threshold matches policy")
    assert t.run() == "pass" and t.log.verify()[0]


@pytest.mark.parametrize("metric", sorted(controls.measurements()))
@pytest.mark.parametrize("op", sorted(controls.OPS))
def test_draft_test_ops(metric, op):
    t = controls.draft_test("CTL-01", metric, op, 0)
    t.approve("amara", "test")
    assert t.run() in ("pass", "fail")


def test_draft_test_rejects_bad_input():
    with pytest.raises(ValueError):
        controls.draft_test("CTL-01", "ai_answer_accuracy", "!=", 1)
    with pytest.raises(KeyError):
        controls.draft_test("CTL-01", "nope", ">=", 1)


# ----- AI governance (12 KPIs) -----

AIK = ai_governance.kpis()


def test_twelve_ai_kpis():
    keys = [k for k in AIK if k != "basis" and k != "resilience_test"]
    assert len(keys) == 13 - 1  # 12 KPIs plus the resilience drill result


@pytest.mark.parametrize("key,val", [("explainability_rate_pct", 100.0), ("decision_audit_pass_pct", 100.0),
                                     ("monitoring_coverage_pct", 89.5), ("approval_sla_pct", 88.9),
                                     ("override_rate_pct", 10.0), ("decision_rights_coverage_pct", 100.0),
                                     ("ai_regulatory_readiness_pct", 51.9), ("agent_legal_risk_blocked", 3),
                                     ("ai_roi", 2.99), ("resilience_test", "fail")])
def test_ai_kpi_values(key, val):
    assert AIK[key] == val


def test_roi_subtracts_review():
    r = ai_governance.roi()
    assert r["hours_saved_net"] < r["hours_saved_gross"] and "SYNTHETIC" in r["basis"]


@pytest.mark.parametrize("cost,ratio_up", [(100.0, True), (100000.0, False)])
def test_roi_sensitivity(cost, ratio_up):
    base = ai_governance.roi()["roi_ratio"]
    assert (ai_governance.roi({"ai_monthly_cost": cost})["roi_ratio"] > base) is ratio_up


def test_decision_audit_checks():
    assert all(ai_governance.decision_audit()["checks"].values())


# ----- 16 exposure KPIs and program scorecards -----

EX = kpis.exposure_16()


def test_sixteen_exposure_kpis():
    assert len(EX) == 16 and all(k.split("_")[0].isdigit() for k in EX)


@pytest.mark.parametrize("k", sorted(EX))
def test_exposure_kpi_present(k):
    assert EX[k] is not None


def test_program_scorecards():
    p = kpis.program()
    assert set(p) == {"efficiency", "risk", "trust", "basis"} and "SIMULATED" in p["basis"]
    assert p["trust"]["ai_accuracy_pct"] == 86.7


# ----- reports (previews only) -----

M = reports.metrics()


@pytest.mark.parametrize("kind", ["daily", "weekly"])
def test_rows(kind):
    rs = reports.rows(M, kind)
    assert rs and all(len(r) == 3 for r in rs)


def test_daily_is_subset():
    assert len(reports.rows(M, "daily")) < len(reports.rows(M, "weekly"))


@pytest.mark.parametrize("kind", ["daily", "weekly"])
def test_csv(kind):
    lines = reports.to_csv(M, kind).strip().splitlines()
    assert lines[0] == "section,metric,value,basis" and len(lines) == len(reports.rows(M, kind)) + 1


@pytest.mark.parametrize("kind", ["daily", "weekly"])
def test_html(kind):
    h = reports.to_html(M, kind)
    assert "<svg" in h and "<script" not in h.lower()


@pytest.mark.parametrize("kind", ["daily", "weekly"])
def test_pdf(kind):
    pdf = reports.to_pdf(M, kind)
    assert pdf.startswith(b"%PDF-") and minipdf.page_count(pdf) >= 1
    assert pdf == reports.to_pdf(M, kind)


@pytest.mark.parametrize("kind", ["daily", "weekly"])
def test_eml_preview(kind):
    raw = reports.to_eml(M, kind)
    msg = email.message_from_bytes(raw)
    assert msg["Subject"].startswith("[PREVIEW - NOT SENT]") and msg["X-SECPROG-Preview"] == "true"
    names = [p.get_filename() for p in msg.walk() if p.get_filename()]
    assert names == [f"{kind}-report.pdf", f"{kind}-report.csv"]
    assert raw == reports.to_eml(M, kind)


@pytest.mark.parametrize("kind", ["daily", "weekly"])
def test_write_previews(tmp_path, kind):
    files = reports.write_previews(tmp_path, kind, M)
    assert len(files) == 4 and all((tmp_path / "reports").exists() for _ in files)


@pytest.mark.parametrize("config,approved,transport", [
    (None, True, lambda e, t: "ok"),
    ({"enabled": True, "transport": "smtp", "to": ["a@brightwater-ledger.example"],
      "allowed_domains": ["brightwater-ledger.example"]}, False, lambda e, t: "ok"),
    ({"enabled": True, "transport": "smtp", "to": ["a@brightwater-ledger.example"],
      "allowed_domains": ["brightwater-ledger.example"]}, True, None),
    ({"enabled": False, "transport": "smtp", "to": ["a@x.example"], "allowed_domains": ["x.example"]}, True,
     lambda e, t: "ok"),
    ({"enabled": True, "transport": "fax", "to": ["a@x.example"], "allowed_domains": ["x.example"]}, True,
     lambda e, t: "ok"),
    ({"enabled": True, "transport": "smtp", "to": ["a@evil.example"], "allowed_domains": ["x.example"]}, True,
     lambda e, t: "ok"),
    ({"enabled": True, "transport": "smtp", "to": [], "allowed_domains": ["x.example"]}, True, lambda e, t: "ok"),
    ({"enabled": True, "transport": "sendgrid", "to": ["a@x.example"], "allowed_domains": ["x.example"],
      "api_key": "SG.x"}, True, lambda e, t: "ok")])
def test_send_refused(config, approved, transport):
    with pytest.raises(reports.SendRefused):
        reports.send(b"x", config, approved, transport)


@pytest.mark.parametrize("tr", ["smtp", "sendgrid", "logic_apps"])
def test_send_only_with_config_approval_and_transport(tr):
    calls = []
    cfg = {"enabled": True, "transport": tr, "to": ["ciso@brightwater-ledger.example"],
           "allowed_domains": ["brightwater-ledger.example"]}
    out = reports.send(b"x", cfg, True, lambda e, t: calls.append(t) or "fake-receipt")
    assert out["sent"] and calls == [["ciso@brightwater-ledger.example"]]


def test_schedule():
    assert "CRON_TZ=America/New_York" in reports.crontab()
    s = json.loads(reports.schedule_json())
    assert s["daily"]["cron"] == "0 7 * * 1-5" and s["weekly"]["cron"] == "0 7 * * 1"


# ----- vCISO -----

def test_queue_order():
    assert [i["id"] for i in vciso.Queue().ordered()] == ["VQ-05", "VQ-03", "VQ-01", "VQ-02", "VQ-04"]


@pytest.mark.parametrize("by,role", [("agent:vciso", "vciso"), ("amara", "secops_lead")])
def test_queue_decider(by, role):
    with pytest.raises(PermissionError):
        vciso.Queue().decide("VQ-02", by, role, "approve", "r")


@pytest.mark.parametrize("days,ok", [(None, False), (0, False), (30, True), (90, True), (91, False)])
def test_acceptance_expiry(days, ok):
    q = vciso.Queue()
    if ok:
        assert q.decide("VQ-01", "val", "vciso", "approve", "r", days)["expires_days"] == days
    else:
        with pytest.raises(ValueError):
            q.decide("VQ-01", "val", "vciso", "approve", "r", days)


def test_queue_reason_and_decision():
    q = vciso.Queue()
    with pytest.raises(ValueError):
        q.decide("VQ-02", "val", "vciso", "approve", "")
    with pytest.raises(ValueError):
        q.decide("VQ-02", "val", "vciso", "maybe", "r")


def test_mock_audit():
    a = vciso.mock_audit()
    assert a["sampled"] == 6 and a["passed"] == 4
    issues = " ".join(i for f in a["findings"] for i in f["issues"])
    assert "stale" in issues and "agent" in issues


# ----- Copilot -----

@pytest.mark.parametrize("qid", sorted(copilot.QUESTIONS))
def test_copilot_answers(qid):
    r = copilot.ask(qid)
    assert r["answer"] and r["source"] and r["basis"] == "synthetic data"


def test_copilot_refuses_other_questions():
    assert copilot.ask("q99")["source"] is None


@pytest.mark.parametrize("qid", sorted(copilot.QUESTIONS))
def test_copilot_find_own_question(qid):
    assert copilot.find(copilot.QUESTIONS[qid][0]) == qid


def test_copilot_find_none():
    assert copilot.find("weather") is None


# ----- dashboard, charts, PDF -----

def test_dashboard_static():
    h = dashboard.render()
    external = h.replace('xmlns="http://www.w3.org/2000/svg"', "")
    assert "<script" not in h.lower() and "http://" not in external and "https://" not in external and "<svg" in h


@pytest.mark.parametrize("pct", [0, 12.5, 50, 99.9, 100])
def test_ring(pct):
    assert "<svg" in svgchart.ring(pct, "x")


def test_hbar_escapes():
    assert "<b>" not in svgchart.hbar([("<b>", 3)], 10)


def test_sparkline_flat():
    assert "<svg" in svgchart.sparkline([5, 5, 5])


def test_minipdf_latin1():
    d = minipdf.Doc()
    d.text("caf\u00e9 \u2713 (x)")
    d.bar("a", 5, 10)
    assert d.to_bytes().startswith(b"%PDF")


def test_minipdf_pages():
    d = minipdf.Doc()
    for i in range(200):
        d.text(f"line {i}")
    assert minipdf.page_count(d.to_bytes()) > 1


# ----- use cases and CLI -----

@pytest.mark.parametrize("uc", usecases.USE_CASES, ids=lambda u: u[0])
def test_use_case_command_exists(uc):
    cmd = uc[2].split()
    assert cmd[:3] == ["python", "-m", "secprog"] and cmd[3] in COMMANDS


def test_use_cases_markdown():
    md = usecases.markdown()
    assert md.count("| UC-") == 29


@pytest.mark.parametrize("cmd", sorted(COMMANDS))
def test_cli_command_runs(cmd, tmp_path, capsys):
    assert main([cmd, "--out", str(tmp_path)]) == 0
    assert capsys.readouterr().out.strip()


@pytest.mark.parametrize("q", ["q01", "q06", "which vendors need reassessment"])
def test_cli_copilot(q, capsys):
    main(["copilot", q])
    assert json.loads(capsys.readouterr().out)["answer"]


def test_cli_report_writes_only_files(tmp_path, capsys):
    main(["report", "--kind", "daily", "--out", str(tmp_path)])
    out = capsys.readouterr().out
    assert "nothing was sent" in out and (tmp_path / "reports" / "daily.eml").exists()
