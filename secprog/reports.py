"""Daily and weekly leadership reports as HTML, PDF, CSV and .eml previews.

By default this only writes preview files to an out/ folder and never sends. Real sending needs a valid config
(enabled, allowed recipient domains, no secrets in the file), an explicit approved=True flag and a transport
function supplied by the caller; this repo ships no transport.
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import json
import pathlib
from email.message import EmailMessage
from email.utils import format_datetime
from html import escape

from . import (
    DOMAIN,
    ORG,
    TODAY,
    ai_governance,
    browser,
    coordinator,
    ctem,
    endpoint_human,
    exposure,
    exposure_validation,
    frameworks,
    governance,
    identity_recovery,
    kpis,
    minipdf,
    soc_authority,
    svgchart,
)

FROM = f"security-reports@{DOMAIN}"
DEFAULT_TO = {"daily": [f"ciso@{DOMAIN}"], "weekly": [f"leadership@{DOMAIN}"]}


class SendRefused(Exception):
    pass


def metrics() -> dict:
    ex = kpis.exposure_16()
    c = coordinator.demo_week()
    return {
        "org": ORG, "as_of": TODAY,
        "exposure": ex,
        "five_minute_list": ctem.five_minute_list(),
        "approvals": c.kpis(),
        "monitoring": governance.monitoring(),
        "frameworks": frameworks.coverage_summary()["rows"],
        "ai_governance": ai_governance.kpis(),
        "soc": soc_authority.soc_kpis(),
        "endpoint_human": endpoint_human.kpis(),
        "exposure_validation": exposure_validation.kpis(),
        "identity": identity_recovery.kpis(),
        "program": kpis.program(),
        "browser": browser.kpis(),
    }


def rows(m: dict, kind: str) -> list[tuple[str, str, str]]:
    """(section, metric, value) rows; the daily report is a short subset."""
    ex, ag = m["exposure"], m["ai_governance"]
    out = [
        ("Exposure", "Org exposure score (0-1000)", str(ex["1_exposure_score"]["org"])),
        ("Exposure", "Change 7d / 30d / 90d", " / ".join(str(v) for v in ex["1_exposure_score"]["trend"].values())),
        ("Exposure", "Known-exploited CVEs open", str(ex["5_kev_exposure"])),
        ("Exposure", "SLA adherence %", str(ex["8_sla_adherence_pct"])),
        ("Approvals", "Pending approvals", str(m["approvals"]["pending"])),
        ("Agents", "Monitoring coverage %", str(m["monitoring"]["coverage_pct"])),
        ("Agents", "Agents failing heartbeat", ", ".join(m["monitoring"]["failing"]) or "none"),
    ]
    if kind == "daily":
        return out
    out += [
        ("Exposure", "Toxic combinations open", str(ex["4_toxic_combinations_open"])),
        ("Exposure", "Crown-jewel paths / open choke points",
         f"{ex['3_crown_jewel_paths']['paths']} / {ex['3_crown_jewel_paths']['open_choke_points']}"),
        ("Exposure", "Prioritization coverage / efficiency %",
         f"{ex['6_prioritization']['coverage_pct']} / {ex['6_prioritization']['efficiency_pct']}"),
        ("Exposure", "Fix validation pass % (reopened)",
         f"{ex['9_fix_validation']['pass_pct']} ({ex['9_fix_validation']['reopened']})"),
        ("Exposure", "Unknown external assets", str(ex["10_unknown_external_assets"])),
        ("Exposure", "Certificates expiring in 30 days", str(ex["11_expiring_certs_30d"])),
        ("Browser", "High-risk extensions (of total)",
         f"{m['browser']['high_risk_extensions']} / {m['browser']['extensions']}"),
        ("Browser", "Sessions on the managed browser %", str(m["browser"]["sessions_on_managed_browser_pct"])),
        ("SOC", "MTTD median (min)", str(m["soc"]["mttd_median_min"])),
        ("SOC", "MTTR by phase (min)", ", ".join(f"{k} {v:g}" for k, v in m["soc"]["mttr_median_min_by_phase"].items())),
        ("SOC", "Auto-triage accuracy %", str(m["soc"]["auto_triage_accuracy_pct"])),
        ("SOC", "Cost per verified fix ($, synthetic)", str(m["soc"]["cost_per_verified_fix"])),
        ("Identity", "Tier 0 checks passed", (f"{m['identity']['tier0_checks_passed']} / "
                                              f"{m['identity']['tier0_checks_total']}")),
        ("Human risk", "Phish click / report %", (f"{m['endpoint_human']['human']['click_pct']} / "
                                                  f"{m['endpoint_human']['human']['report_pct']}")),
        ("Validation", "MTTSR hours / zero-disruption %", (f"{m['exposure_validation']['mttsr_hours']} / "
                                                           f"{m['exposure_validation']['zero_disruption_pct']}")),
        ("AI governance", "Explainability rate %", str(ag["explainability_rate_pct"])),
        ("AI governance", "Decision-audit pass %", str(ag["decision_audit_pass_pct"])),
        ("AI governance", "Approval SLA % / override rate %", f"{ag['approval_sla_pct']} / {ag['override_rate_pct']}"),
        ("AI governance", "Autonomy mix", ", ".join(f"{k} {v}" for k, v in ag["autonomy_mix"].items())),
        ("AI governance", "Decision-rights coverage %", str(ag["decision_rights_coverage_pct"])),
        ("AI governance", "Shadow AI (tools / users)", (f"{ag['shadow_ai_exposure']['unapproved_tools']} / "
                                                       f"{ag['shadow_ai_exposure']['users']}")),
        ("AI governance", "AI vendor top-1 share % (HHI)", (f"{ag['ai_vendor_concentration']['top1_share_pct']} "
                                                            f"({ag['ai_vendor_concentration']['hhi']})")),
        ("AI governance", "AI regulatory readiness %", str(ag["ai_regulatory_readiness_pct"])),
        ("AI governance", "Agent legal-risk actions blocked", str(ag["agent_legal_risk_blocked"])),
        ("AI governance", "AI ROI ratio (synthetic)", str(ag["ai_roi"])),
        ("AI governance", "Provider-outage drill", ag["resilience_test"]),
        ("Trust", "Questionnaire turnaround (days)", str(m["program"]["efficiency"]["questionnaire_turnaround_days"])),
        ("Trust", "AI answer accuracy %", str(m["program"]["trust"]["ai_accuracy_pct"])),
        ("Trust", "Hours to first vulnerability update", str(m["program"]["risk"]["time_to_first_vuln_update_h"])),
    ]
    out += [("Frameworks", f["name"], f"{f['ready_pct']}% ready") for f in m["frameworks"]]
    return out


def to_csv(m: dict, kind: str = "weekly") -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["section", "metric", "value", "basis"])
    for r in rows(m, kind):
        w.writerow([*r, "synthetic"])
    return buf.getvalue()


def to_text(m: dict, kind: str) -> str:
    lines = [f"{m['org']} {kind} security report - {m['as_of']} (synthetic preview, not sent)", ""]
    lines += [f"{s}: {k} = {v}" for s, k, v in rows(m, kind)]
    return "\n".join(lines) + "\n"


def to_html(m: dict, kind: str = "weekly") -> str:
    trs = "".join(f"<tr><td>{escape(s)}</td><td>{escape(k)}</td><td><b>{escape(v)}</b></td></tr>"
                  for s, k, v in rows(m, kind))
    five = "".join(f"<li>{escape(x['action'])} <i>({escape(x['why'])})</i></li>" for x in m["five_minute_list"])
    trend = svgchart.sparkline([v for _, v in exposure.trend()])
    extra = ""
    if kind == "weekly":
        extra = "<h2>Framework readiness</h2>" + frameworks.rings_html()
    return (f"<html><body style='font-family:Arial;max-width:760px'>"
            f"<h1>{escape(m['org'])} {kind} security report</h1>"
            f"<p style='color:#a00'>PREVIEW, NOT SENT. Synthetic data for a fictional company. As of {m['as_of']}."
            "</p>"
            f"<h2>Today's 5-minute list</h2><ol>{five}</ol>"
            f"<p>Exposure trend (90 days): {trend}</p>"
            f"<table border=1 cellpadding=4 style='border-collapse:collapse'><tr><th>Area</th><th>Metric</th>"
            f"<th>Value</th></tr>{trs}</table>{extra}</body></html>")


def to_pdf(m: dict, kind: str = "weekly") -> bytes:
    d = minipdf.Doc()
    d.text(f"{m['org']} {kind} security report - {m['as_of']}", 14, True)
    d.text("Synthetic preview. Not sent.", 9)
    d.gap()
    for s, k, v in rows(m, kind):
        d.text(f"{s} | {k}: {v}", 9)
    if kind == "weekly":
        d.gap()
        d.text("Framework readiness", 12, True)
        for f in m["frameworks"]:
            d.bar(f["name"][:28], f["ready_pct"], 100, f"{f['ready_pct']}%")
    return d.to_bytes()


def to_eml(m: dict, kind: str = "weekly", to: list[str] | None = None) -> bytes:
    msg = EmailMessage()
    msg["From"] = FROM
    msg["To"] = ", ".join(to or DEFAULT_TO[kind])
    msg["Subject"] = f"[PREVIEW - NOT SENT] {m['org']} {kind} security report {m['as_of']}"
    msg["Date"] = format_datetime(dt.datetime.fromisoformat(m["as_of"] + "T07:00:00-04:00"))
    msg["Message-ID"] = f"<{kind}-{m['as_of']}@reports.{DOMAIN}>"
    msg["X-SECPROG-Preview"] = "true"
    msg.set_content(to_text(m, kind))
    msg.add_alternative(to_html(m, kind), subtype="html")
    msg.add_attachment(to_pdf(m, kind), maintype="application", subtype="pdf", filename=f"{kind}-report.pdf")
    msg.add_attachment(to_csv(m, kind).encode(), maintype="text", subtype="csv", filename=f"{kind}-report.csv")
    for i, part in enumerate(p for p in msg.walk() if p.is_multipart()):
        part.set_boundary(f"==secprog-{kind}-{i}==")
    return bytes(msg)


def write_previews(out_dir, kind: str = "weekly", m: dict | None = None) -> list[str]:
    m = m or metrics()
    d = pathlib.Path(out_dir) / "reports"
    d.mkdir(parents=True, exist_ok=True)
    files = {f"{kind}.html": to_html(m, kind).encode(), f"{kind}.eml": to_eml(m, kind),
             f"{kind}.pdf": to_pdf(m, kind), f"{kind}.csv": to_csv(m, kind).encode()}
    for name, blob in files.items():
        (d / name).write_bytes(blob)
    return sorted(str(d / n) for n in files)


def check_send_config(config: dict | None) -> list[str]:
    if not config:
        return ["no send config: previews only"]
    errs = []
    if config.get("enabled") is not True:
        errs.append("config.enabled is not true")
    if config.get("transport") not in ("smtp", "sendgrid", "logic_apps"):
        errs.append("config.transport must be smtp, sendgrid or logic_apps")
    to = config.get("to") or []
    if not to:
        errs.append("config.to is empty")
    allowed = config.get("allowed_domains") or []
    errs += [f"recipient {a} is not in allowed_domains" for a in to if a.split("@")[-1] not in allowed]
    if any(k in config for k in ("api_key", "password", "token")):
        errs.append("secrets must not be in the config file; use a vault reference")
    return errs


def send(eml: bytes, config: dict | None = None, approved: bool = False, transport=None) -> dict:
    errs = check_send_config(config)
    if not approved:
        errs.append("approval flag not set")
    if transport is None:
        errs.append("no transport supplied (this repo ships none)")
    if errs:
        raise SendRefused("; ".join(errs))
    return {"sent": True, "transport": config["transport"], "to": list(config["to"]),
            "receipt": transport(eml, list(config["to"]))}


SCHEDULE = {"timezone": "America/New_York",
            "daily": {"cron": "0 7 * * 1-5", "kind": "daily"},
            "weekly": {"cron": "0 7 * * 1", "kind": "weekly"}}


def crontab(python: str = "python", repo: str = "/opt/continuous-security-program") -> str:
    return "\n".join([
        "# Continuous security program reports (previews only unless sending is configured AND approved)",
        "CRON_TZ=America/New_York",
        f"{SCHEDULE['daily']['cron']} cd {repo} && {python} -m secprog report --kind daily --out out",
        f"{SCHEDULE['weekly']['cron']} cd {repo} && {python} -m secprog report --kind weekly --out out",
    ]) + "\n"


def schedule_json() -> str:
    return json.dumps(SCHEDULE, indent=2, sort_keys=True)
