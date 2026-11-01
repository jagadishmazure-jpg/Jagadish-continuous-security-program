"""Trust Dashboard: one static HTML page (no JavaScript, no external assets) built from the synthetic data."""
from __future__ import annotations

from html import escape

from . import ORG, TODAY, agents, ai_governance, frameworks, governance, kpis, svgchart, vciso
from .exposure import scores, trend


def _kv(rows: list[tuple[str, object]]) -> str:
    return "".join(f"<tr><td>{escape(k)}</td><td><b>{escape(str(v))}</b></td></tr>" for k, v in rows)


def render() -> str:
    ex = kpis.exposure_16()
    ag = ai_governance.kpis()
    sc = scores()
    mon = governance.monitoring()
    bu = svgchart.hbar(sorted(sc["business_units"].items(), key=lambda x: -x[1]), 1000, title="Exposure by business unit")
    agent_rows = "".join(
        f"<tr><td>{escape(a.id)}</td><td>{escape(a.owner)}</td><td>{escape(a.autonomy)}</td>"
        f"<td>{a.heartbeat_hours:g}h</td><td>{'FAIL' if a.id in mon['failing'] else 'ok'}</td></tr>"
        for a in agents.AGENTS)
    q = vciso.Queue().ordered()
    queue = "".join(f"<li>{'<b>OVERDUE</b> ' if i['overdue'] else ''}{escape(i['title'])} (due {i['due']})</li>"
                    for i in q)
    return (f"<html><head><meta charset='utf-8'><title>{escape(ORG)} Trust Dashboard</title></head>"
            "<body style='font-family:Arial;max-width:980px;margin:auto'>"
            f"<h1>{escape(ORG)} Trust Dashboard</h1>"
            f"<p style='color:#a00'>Synthetic data for a fictional company. As of {TODAY}.</p>"
            f"<h2>Exposure {ex['1_exposure_score']['org']} / 1000</h2>"
            f"<p>90-day trend {svgchart.sparkline([v for _, v in trend()], 300, 40)}</p>{bu}"
            "<h2>Framework readiness</h2>" + frameworks.rings_html() +
            "<h2>AI governance</h2><table border=1 cellpadding=4 style='border-collapse:collapse'>" + _kv([
                ("Explainability rate %", ag["explainability_rate_pct"]),
                ("Monitoring coverage %", ag["monitoring_coverage_pct"]),
                ("Override rate %", ag["override_rate_pct"]),
                ("Shadow AI tools", ag["shadow_ai_exposure"]["unapproved_tools"]),
                ("AI vendor top-1 share %", ag["ai_vendor_concentration"]["top1_share_pct"]),
                ("Provider-outage drill", ag["resilience_test"])]) + "</table>"
            "<h2>Agents</h2><table border=1 cellpadding=4 style='border-collapse:collapse'><tr><th>Agent</th>"
            f"<th>Owner</th><th>Autonomy</th><th>Heartbeat</th><th>Monitor</th></tr>{agent_rows}</table>"
            f"<h2>vCISO queue</h2><ol>{queue}</ol></body></html>")
