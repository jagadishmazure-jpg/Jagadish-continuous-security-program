"""Command line: python -m secprog <command>. Every command is offline and uses synthetic data."""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

from . import (
    access_review,
    agents,
    ai_exposure,
    ai_governance,
    attack_paths,
    browser,
    coordinator,
    copilot,
    ctem,
    cve_rank,
    dashboard,
    devices,
    endpoint_human,
    exposure,
    exposure_validation,
    findings,
    frameworks,
    governance,
    identity_recovery,
    kpis,
    mcp_server,
    msp,
    pentest_agent,
    questionnaire,
    reports,
    soc_authority,
    tprm,
    trust_center,
    usecases,
    vciso,
)


def _p(obj) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True, default=str))


def _five(_):
    for i, x in enumerate(ctem.five_minute_list(), 1):
        print(f"{i}. {x['action']}  [{x['why']}]")


def _rank(_):
    ev = cve_rank.evaluate()
    print(f"{'method':<14}{'coverage%':>10}{'efficiency%':>13}")
    for k in ("threat_v2", "kev_epss_v1", "epss_only", "cvss_only"):
        print(f"{k:<14}{ev[k]['coverage_pct']:>10}{ev[k]['efficiency_pct']:>13}")
    print(ev["note"])


def _exposure(_):
    s = exposure.scores()
    print(f"org {s['org']} / 1000")
    for bu, v in sorted(s["business_units"].items(), key=lambda x: -x[1]):
        print(f"  {bu:<10}{v}")
    print("trend", exposure.trend_deltas())


def _paths(_):
    for c in attack_paths.choke_points():
        print(f"{c['edge']:<28} closes {c['closes_paths']}/{c['of']}  ({c['technique']})")
    print("toxic combinations:", attack_paths.toxic_counts())


def _findings(_):
    fs = findings.all_findings()
    print(f"{len(fs)} findings after de-duplication; pentest {findings.pentest_status()}")


def _questionnaire(_):
    _, m = questionnaire.run_demo()
    _p(m)


def _trust(_):
    for r in trust_center.ACCESS_REQUESTS:
        d = trust_center.nda_decision(r)
        print(f"{r['id']} {d['decision']:<8} {d['rule']}")
    _p(trust_center.run_playbook())


def _tprm(_):
    for v in ("V-03", "V-04", "V-09"):
        _p(tprm.run(v).summary())


def _purchases(_):
    for r in tprm.purchase_summary()["rows"]:
        print(f"{r['id']} {r['vendor']:<28} {r['status']}")


def _identity(_):
    for c in identity_recovery.tier0_checks():
        print(f"{'PASS' if c['passed'] else 'FAIL'} {c['id']}")
    _p(identity_recovery.drill())


def _soc(_):
    _p(soc_authority.soc_kpis())


def _human(_):
    _p(endpoint_human.kpis())


def _validate(_):
    _p(exposure_validation.kpis())


def _pentest(_):
    for r in pentest_agent.run()["rows"]:
        print(f"{r['id']} {r['result']:<34} {r['why']}")


def _msp(_):
    _p(msp.TenantStore().canary_test())
    for r in msp.sla_tracking():
        print(f"{r['client']:<28}{r['tier']:<11}{r['sla_met_pct']}%")


def _frameworks(_):
    s = frameworks.coverage_summary()
    for r in s["rows"]:
        print(f"{r['name']:<40}{r['ready_pct']:>6}%  ({r['ready']}/{r['mapped']} ready)")
    print(f"{s['frameworks']} frameworks, {s['requirements']} requirements, {s['gaps']} gap(s)")


def _aigov(_):
    _p(ai_governance.kpis())


def _governance(_):
    _p(governance.ladder_demo())


def _report(a):
    for f in reports.write_previews(a.out, a.kind):
        print(f)
    print("previews only; nothing was sent")


def _dashboard(a):
    p = pathlib.Path(a.out)
    p.mkdir(parents=True, exist_ok=True)
    (p / "dashboard.html").write_text(dashboard.render())
    (p / "trust_center.html").write_text(trust_center.render_html(_published_tc()))
    print(p / "dashboard.html")
    print(p / "trust_center.html")


def _published_tc():
    tc = trust_center.TrustCenter()
    trust_center.run_playbook(tc)
    return tc


def _copilot(a):
    qid = a.q or "q01"
    if not qid.startswith("q"):
        qid = copilot.find(qid) or qid
    _p(copilot.ask(qid))


def _mcp(_):
    _p(mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "top_choke_points", "arguments": {"limit": 3}}}))


def _audit(_):
    a = vciso.mock_audit()
    print(f"sampled {a['sampled']}, passed {a['passed']}")
    for f in a["findings"]:
        print(" -", f["title"], "|", "; ".join(f["issues"]))


def _aiexp(_):
    _p({"concentration": ai_exposure.concentration(), "drill": ai_exposure.outage_drill()})


def _coord(_):
    _p(coordinator.demo_week().kpis())


def _devices(_):
    _p(devices.summary())


def _access(_):
    _p(access_review.demo())


def _ctem(_):
    _p(ctem.demo())


def _agents_md(_):
    print(agents.agents_md())


def _schedule(_):
    print(reports.crontab())


def _usecases(_):
    print(usecases.markdown())


def _coverage(_):
    s = frameworks.coverage_summary()
    print("| Framework | Requirements | Mapped | Ready | Readiness |")
    print("|---|---:|---:|---:|---:|")
    for r in s["rows"]:
        print(f"| {r['name']} | {r['requirements']} | {r['mapped']} | {r['ready']} | {r['ready_pct']}% |")
    types = ", ".join(f"{k} {v}" for k, v in s["by_mapping_type"].items())
    print(f"\n**Total:** {s['frameworks']} frameworks, {s['requirements']} requirements, {s['mapped']} mapped, "
          f"{s['gaps']} gap; mapping type: {types}; {s['controls_used']}/{s['controls_total']} controls used.")


def _browser(_):
    for e in browser.score_extensions():
        print(f"{e['id']} {e['name']:<28} risk {e['risk']:>3}  {e['recommendation']}")
    for r in browser.posture_summary()["rows"]:
        print(f"{r['device']:<8} {r['access']}  {','.join(r['failed'])}")
    _p({"kpis": browser.kpis(), "infostealer": browser.infostealer_scenario()})


def _kpis(_):
    _p({"exposure_16": kpis.exposure_16(), "program": kpis.program()})


def _trust_metrics(_):
    _p({"analytics": trust_center.analytics(), "trust_to_revenue": trust_center.trust_to_revenue(),
        "ai_roi": ai_governance.roi(), "insurance": endpoint_human.insurance_readiness()})


COMMANDS = {
    "five": _five, "rank": _rank, "exposure": _exposure, "paths": _paths, "findings": _findings,
    "questionnaire": _questionnaire, "trust": _trust, "tprm": _tprm, "purchases": _purchases,
    "identity": _identity, "soc": _soc, "human": _human, "validate": _validate, "pentest": _pentest, "msp": _msp,
    "frameworks": _frameworks, "ai-gov": _aigov, "governance": _governance, "report": _report,
    "dashboard": _dashboard, "copilot": _copilot, "mcp-demo": _mcp, "audit": _audit, "ai-exposure": _aiexp,
    "coordinator": _coord, "devices": _devices, "access": _access, "ctem": _ctem, "agents-md": _agents_md,
    "schedule": _schedule, "usecases": _usecases, "coverage": _coverage, "kpis": _kpis,
    "trust-metrics": _trust_metrics, "browser": _browser,
}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="secprog", description="Continuous security program (synthetic, offline)")
    ap.add_argument("command", choices=sorted(COMMANDS))
    ap.add_argument("q", nargs="?", help="copilot question id or text")
    ap.add_argument("--out", default="out")
    ap.add_argument("--kind", choices=("daily", "weekly"), default="weekly")
    a = ap.parse_args(argv)
    COMMANDS[a.command](a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
