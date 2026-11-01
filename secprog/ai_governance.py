"""The 12 AI Governance KPIs and a synthetic AI ROI estimate.

Every value is computed from this repo's synthetic data at run time. Nothing here is a survey or vendor figure.
"""
from __future__ import annotations

from . import (
    access_review,
    ai_exposure,
    coordinator,
    cve_rank,
    frameworks,
    governance,
    identity_recovery,
    questionnaire,
    soc_authority,
    tprm,
)

AI_FRAMEWORKS = ("ISO42001", "AIUC1", "EU_AI_ACT", "NIST_AI_RMF")
APPROVAL_SLA_MIN = 60

# ROI inputs (SYNTHETIC assumptions, editable)
ROI_INPUTS = {
    "minutes_saved_per_auto_answer": 12,
    "questionnaires_per_month": 6,
    "minutes_saved_per_vendor_assessment": 240,
    "vendor_assessments_per_month": 3,
    "minutes_saved_per_ranked_cve_review": 6,
    "cve_reviews_per_month": 60,
    "loaded_hourly_cost": 95.0,
    "ai_monthly_cost": 900.0,
    "review_minutes_per_ai_output": 3,
}


def explainability() -> float:
    q, _ = questionnaire.run_demo()
    drafted = [a for a in q.answers if a.kb]
    cited = sum(bool(a.citations) for a in drafted)
    ranked = cve_rank.rank_v2()[: cve_rank.TOP_K]
    cited += sum(bool(r.get("reason")) for r in ranked)
    tp = [tprm.run(v) for v in ("V-03", "V-04", "V-09")]
    graded = [r for a in tp for r in a.results if r["outcome"] != "Inconclusive"]
    cited += sum(bool(r["citations"]) for r in graded)
    total = len(drafted) + len(ranked) + len(graded)
    return round(100 * cited / total, 1)


def decision_audit() -> dict:
    c = coordinator.demo_week()
    checks = {
        "coordinator_log": c.log.verify()[0],
        "access_review_log": access_review.demo()["log_ok"],
        "recovery_drill_log": identity_recovery.drill()["log_ok"],
        "every_approval_by_person": all(not a.startswith("agent:") for r in c.inbox.items.values()
                                        for a in r.approvals),
        "no_self_approval": all(r.requested_by not in r.approvals for r in c.inbox.items.values()),
        "rejections_have_reasons": all(r.reason for r in c.inbox.items.values() if r.status == "rejected"),
    }
    return {"checks": checks, "pass_pct": round(100 * sum(checks.values()) / len(checks), 1)}


def roi(inputs: dict | None = None) -> dict:
    i = {**ROI_INPUTS, **(inputs or {})}
    _, qm = questionnaire.run_demo()
    auto = qm["drafted_by_agent"] * i["questionnaires_per_month"]
    saved_min = (auto * i["minutes_saved_per_auto_answer"]
                 + i["vendor_assessments_per_month"] * i["minutes_saved_per_vendor_assessment"]
                 + i["cve_reviews_per_month"] * i["minutes_saved_per_ranked_cve_review"])
    outputs = auto + i["vendor_assessments_per_month"] + i["cve_reviews_per_month"]
    review_min = outputs * i["review_minutes_per_ai_output"]
    net_hours = (saved_min - review_min) / 60
    value = net_hours * i["loaded_hourly_cost"]
    return {"hours_saved_gross": round(saved_min / 60, 1), "review_hours": round(review_min / 60, 1),
            "hours_saved_net": round(net_hours, 1), "value_per_month": round(value, 2),
            "ai_cost_per_month": i["ai_monthly_cost"], "roi_ratio": round(value / i["ai_monthly_cost"], 2),
            "basis": "SYNTHETIC inputs; review time by people is subtracted"}


def kpis() -> dict:
    c = coordinator.demo_week()
    ck = c.kpis()
    soc = soc_authority.INCIDENTS
    approvals = [r[4] for r in soc if r[4]]
    disc = ai_exposure.discover()
    conc = ai_exposure.concentration()
    ai_ready = [frameworks.readiness(f)["ready_pct"] for f in AI_FRAMEWORKS]
    drill = ai_exposure.outage_drill()
    drift = governance.drift()
    return {
        "explainability_rate_pct": explainability(),
        "decision_audit_pass_pct": decision_audit()["pass_pct"],
        "monitoring_coverage_pct": governance.monitoring()["coverage_pct"],
        "approval_sla_pct": round(100 * sum(a <= APPROVAL_SLA_MIN for a in approvals) / len(approvals), 1),
        "override_rate_pct": ck["override_rate_pct"],
        "autonomy_mix": governance.autonomy_mix(),
        "decision_rights_coverage_pct": governance.decision_rights(),
        "shadow_ai_exposure": {"unapproved_tools": sum(t["status"] == "unapproved" for t in disc["tools"]),
                               "users": len(disc["unapproved_users"])},
        "ai_vendor_concentration": {"top1_share_pct": conc["top1_share_pct"], "hhi": conc["hhi"]},
        "ai_regulatory_readiness_pct": round(sum(ai_ready) / len(ai_ready), 1),
        "agent_legal_risk_blocked": ck["blocked"] + sum(d["type"] == "unregistered_tool" for d in drift),
        "ai_roi": roi()["roi_ratio"],
        "resilience_test": drill["result"],
        "basis": "computed from synthetic data",
    }
