"""Program KPIs: the 16 exposure-management KPIs and the Efficiency / Risk / Trust program KPIs.

All values are computed from synthetic data. Labels say SIMULATED where a number comes from an assumption.
"""
from __future__ import annotations

from functools import lru_cache

from . import (
    access_review,
    agents,
    ai_exposure,
    attack_paths,
    ctem,
    cve_rank,
    data,
    exposure,
    governance,
    identity_recovery,
    questionnaire,
    tprm,
    trust_center,
    vuln_sla,
)

QUESTIONNAIRE_SLA_DAYS = (2, 5)


@lru_cache(maxsize=1)
def exposure_16() -> dict:
    sc = exposure.scores()
    paths = attack_paths.paths()
    chokes = attack_paths.choke_points()
    ev = cve_rank.evaluate()["threat_v2"]
    open_kev = sum(1 for c in data.cves() if c["kev"])
    mt = vuln_sla.mttr()
    cyc = ctem.demo()
    inv = len(data.assets())
    unknown = len(ctem.unknown_assets())
    acc = access_review.issues()
    t0 = identity_recovery.tier0_checks()
    disc = ai_exposure.discover()
    return {
        "1_exposure_score": {"org": sc["org"], "trend": exposure.trend_deltas()},
        "2_top_contributors": exposure.top_contributors()[:3],
        "3_crown_jewel_paths": {"paths": len(paths), "open_choke_points": len(chokes),
                                "top_choke": chokes[0]["edge"] if chokes else None},
        "4_toxic_combinations_open": sum(attack_paths.toxic_counts().values()),
        "5_kev_exposure": open_kev,
        "6_prioritization": {k: ev[k] for k in ("coverage_pct", "efficiency_pct", "workload_pct")},
        "7_mttr_by_band": {s: {"median_h": v["median_h"], "p90_h": v["p90_h"]} for s, v in mt.items()},
        "8_sla_adherence_pct": vuln_sla.summary()["adherence_pct"],
        "9_fix_validation": {"pass_pct": cyc["fix_validation_pass_pct"], "reopened": cyc["reopened"]},
        "10_unknown_external_assets": unknown,
        "11_expiring_certs_30d": len(ctem.expiring_certs()),
        "12_scan_coverage_pct": round(100 * inv / (inv + unknown), 1),
        "13_ai_inventory": {"tools_seen": len(disc["tools"]), "unapproved": sum(t["status"] == "unapproved"
                                                                                 for t in disc["tools"])},
        "14_identity_exposure": {"privileged_without_mfa": sum(i["type"] == "privileged_without_mfa" for i in acc),
                                 "tier0_checks_failing": sum(not c["passed"] for c in t0)},
        "15_ctem_cycle_health": {"stage": cyc["stage"], "log_ok": cyc["log_ok"]},
        "16_agent_accountability": {"agents": len(agents.AGENTS),
                                    "decision_rights_pct": governance.decision_rights(),
                                    "monitored_pct": governance.monitoring()["coverage_pct"]},
    }


@lru_cache(maxsize=1)
def program() -> dict:
    """Efficiency / Risk / Trust KPIs for the trust and assurance program."""
    _, qm = questionnaire.run_demo()
    pb = trust_center.run_playbook()
    an = trust_center.analytics()
    rev = trust_center.trust_to_revenue()
    tk = tprm.kpis()
    return {
        "efficiency": {"questionnaire_turnaround_days": qm["turnaround_days"],
                       "within_2_5_day_sla": qm["turnaround_days"] <= QUESTIONNAIRE_SLA_DAYS[1],
                       "auto_answer_rate_pct": qm["auto_answer_rate_pct"],
                       "self_service_pct": an["questions_self_served_pct"]},
        "risk": {"vendor_coverage_pct": tk["coverage_pct"], "vendors_overdue_or_triggered": tk["overdue_or_triggered"],
                 "time_to_first_vuln_update_h": pb["median_hours_to_first_update"]},
        "trust": {"ai_accuracy_pct": qm["accuracy_pct"], "engagement_visits_30d": an["visits_30d"],
                  "revenue_influenced": rev["pipeline_influenced"]},
        "basis": "measured from synthetic workflows; visits, self-service and revenue are SIMULATED",
    }
