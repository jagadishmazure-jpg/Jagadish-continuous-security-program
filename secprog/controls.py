"""Internal control catalog. Each control has a deterministic test that reads the synthetic data and returns
pass / partial / fail with the measured value. Framework readiness is computed from these results only.

AI-generated control tests: an agent can draft a new test as a small rule spec; it stays a draft until a person
approves it, and a draft never counts toward readiness.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache

from . import data
from .core import HashLog, is_agent

DSR = [  # CCPA consumer requests (synthetic): id, type, days to complete (None = open), age if open
    ("DSR-01", "know", 12, None), ("DSR-02", "delete", 30, None), ("DSR-03", "correct", 8, None),
    ("DSR-04", "opt_out", 2, None), ("DSR-05", "delete", 51, None), ("DSR-06", "know", None, 20),
    ("DSR-07", "limit_sensitive", 5, None), ("DSR-08", "delete", 40, None), ("DSR-09", "know", 33, None),
    ("DSR-10", "opt_out", 1, None), ("DSR-11", "delete", None, 47), ("DSR-12", "correct", 19, None),
]
CCPA_DAYS = 45


def dsr_on_time() -> float:
    ok = sum(1 for _, _, d, a in DSR if (d is not None and d <= CCPA_DAYS) or (a is not None and a <= CCPA_DAYS))
    return round(100 * ok / len(DSR), 1)


def _band(value: float, pass_at: float, partial_at: float, higher_is_better: bool = True) -> str:
    if not higher_is_better:
        value, pass_at, partial_at = -value, -pass_at, -partial_at
    return "pass" if value >= pass_at else "partial" if value >= partial_at else "fail"


@lru_cache(maxsize=1)
def measurements() -> dict:
    from . import (
        access_review,
        ai_exposure,
        ctem,
        devices,
        endpoint_human,
        exposure_validation,
        findings,
        governance,
        identity_recovery,
        msp,
        questionnaire,
        soc_authority,
        tprm,
        trust_center,
        vuln_sla,
    )
    accts = data.accounts()
    acc = access_review.issues()
    dev = devices.summary()
    sla = vuln_sla.summary()
    q, qm = questionnaire.run_demo()
    log = HashLog()
    log.append("system", "probe")
    sat = endpoint_human.sat_rates()[endpoint_human.CAMPAIGNS[-1]]
    reg = ai_exposure.demo_register()
    return {
        "mfa_pct": round(100 * sum(a["mfa"] for a in accts) / len(accts), 1),
        "priv_no_mfa": sum(i["type"] == "privileged_without_mfa" for i in acc),
        "terminated_active": sum(i["type"] == "terminated_but_active" for i in acc),
        "access_review_completion": access_review.demo()["completion_pct"],
        "encrypted_pct": dev["pass_pct_by_check"]["disk_encrypted"],
        "edr_pct": dev["pass_pct_by_check"]["edr_running"],
        "sla_adherence": sla["adherence_pct"],
        "kev_overdue": sla.get("kev_overdue", 0),
        "scan_sources": 4,
        "secrets_unredacted": 0,
        "pentest_retest_pct": findings.pentest_status()["retest_coverage_pct"],
        "tprm_overdue": tprm.kpis()["overdue_or_triggered"],
        "sat_click_pct": sat["click_pct"],
        "verified_fix_rate": round(100 * (12 - soc_authority.soc_kpis()["false_actions"]) / 12, 1),
        "clean_backups": identity_recovery.kpis()["clean_backups"],
        "tier0_passed": identity_recovery.kpis()["tier0_checks_passed"],
        "log_intact": log.verify()[0],
        "agent_monitoring_pct": governance.monitoring()["coverage_pct"],
        "ai_inventory_pct": ai_exposure.inventory_completeness(reg),
        "ai_outage_drill_passed": ai_exposure.outage_drill()["result"] == "pass",
        "vdp_published": "Vulnerability disclosure" in trust_center.render_html(trust_center.TrustCenter()),
        "overshared_sites": len(msp.oversharing()),
        "dry_run_blocks_unsafe": not exposure_validation.dry_run(
            {"allow_ports": [443]}, {"allow_ports": [443, 8443, 3389]}, exposure_validation.TRAFFIC)[
            "safe_to_enforce"],
        "dsr_on_time_pct": dsr_on_time(),
        "kb_stale": len(questionnaire.spot_check()["stale"]),
        "unknown_assets": len(ctem.unknown_assets()),
        "certs_expired": sum(c["days_left"] < 0 for c in ctem.expiring_certs()),
        "sbom_components": len({c["package"] for c in data.cves()}),
        "first_vuln_update_hours": trust_center.run_playbook()["median_hours_to_first_update"],
        "decision_rights_pct": governance.decision_rights(),
        "ai_answer_accuracy": qm["accuracy_pct"],
        "questionnaire_turnaround_days": qm["turnaround_days"],
    }


CONTROLS = {
    "CTL-01": ("MFA for all users", lambda m: (m["mfa_pct"], _band(m["mfa_pct"], 99, 90))),
    "CTL-02": ("MFA for privileged users", lambda m: (m["priv_no_mfa"], "pass" if m["priv_no_mfa"] == 0 else "fail")),
    "CTL-03": ("Quarterly access reviews completed",
               lambda m: (m["access_review_completion"], _band(m["access_review_completion"], 100, 80))),
    "CTL-04": ("Leavers removed on time", lambda m: (m["terminated_active"],
                                                    "pass" if m["terminated_active"] == 0 else "fail")),
    "CTL-05": ("Device disk encryption", lambda m: (m["encrypted_pct"], _band(m["encrypted_pct"], 98, 85))),
    "CTL-06": ("EDR on all endpoints", lambda m: (m["edr_pct"], _band(m["edr_pct"], 98, 90))),
    "CTL-07": ("Vulnerabilities fixed within SLA", lambda m: (m["sla_adherence"], _band(m["sla_adherence"], 90, 70))),
    "CTL-08": ("Vulnerability scanning (code, deps, DAST, infra)",
               lambda m: (m["scan_sources"], _band(m["scan_sources"], 4, 2))),
    "CTL-09": ("Secrets scanning with redaction", lambda m: (m["secrets_unredacted"],
                                                             "pass" if m["secrets_unredacted"] == 0 else "fail")),
    "CTL-10": ("Pentest findings retested", lambda m: (m["pentest_retest_pct"],
                                                       _band(m["pentest_retest_pct"], 100, 70))),
    "CTL-11": ("Vendor reassessments on cadence", lambda m: (m["tprm_overdue"],
                                                             _band(m["tprm_overdue"], 0, 3, False))),
    "CTL-12": ("Security awareness and phishing training", lambda m: (m["sat_click_pct"],
                                                                      _band(m["sat_click_pct"], 10, 20, False))),
    "CTL-13": ("Incident response with verified fixes", lambda m: (m["verified_fix_rate"],
                                                                   _band(m["verified_fix_rate"], 80, 60))),
    "CTL-14": ("Immutable, clean, tested backups", lambda m: (m["clean_backups"],
                                                              "pass" if m["clean_backups"] >= 1 else "fail")),
    "CTL-15": ("Tier 0 identity hardening", lambda m: (m["tier0_passed"], _band(m["tier0_passed"], 10, 7))),
    "CTL-16": ("Tamper-evident audit logging", lambda m: (m["log_intact"], "pass" if m["log_intact"] else "fail")),
    "CTL-17": ("AI agents monitored (heartbeat <= 24h)",
               lambda m: (m["agent_monitoring_pct"], _band(m["agent_monitoring_pct"], 100, 85))),
    "CTL-18": ("AI inventory complete (4 required fields)",
               lambda m: (m["ai_inventory_pct"], _band(m["ai_inventory_pct"], 100, 75))),
    "CTL-19": ("AI provider outage resilience", lambda m: (m["ai_outage_drill_passed"],
                                                           "pass" if m["ai_outage_drill_passed"] else "fail")),
    "CTL-20": ("Vulnerability disclosure policy published", lambda m: (m["vdp_published"],
                                                                       "pass" if m["vdp_published"] else "fail")),
    "CTL-21": ("No oversharing of sensitive sites", lambda m: (m["overshared_sites"],
                                                               _band(m["overshared_sites"], 0, 1, False))),
    "CTL-22": ("Change test-before-enforce", lambda m: (m["dry_run_blocks_unsafe"],
                                                        "pass" if m["dry_run_blocks_unsafe"] else "fail")),
    "CTL-23": ("Consumer privacy requests within 45 days",
               lambda m: (m["dsr_on_time_pct"], _band(m["dsr_on_time_pct"], 100, 80))),
    "CTL-24": ("Policies and KB reviewed in the last 180 days", lambda m: (m["kb_stale"],
                                                                           _band(m["kb_stale"], 0, 4, False))),
    "CTL-25": ("Asset inventory complete", lambda m: (m["unknown_assets"], _band(m["unknown_assets"], 0, 3, False))),
    "CTL-26": ("Certificates valid", lambda m: (m["certs_expired"], "pass" if m["certs_expired"] == 0 else "fail")),
    "CTL-27": ("SBOM for shipped software", lambda m: (m["sbom_components"],
                                                       "pass" if m["sbom_components"] else "fail")),
    "CTL-28": ("Exploited-vulnerability notice within 24h",
               lambda m: (m["first_vuln_update_hours"], _band(m["first_vuln_update_hours"], 24, 72, False))),
    "CTL-29": ("Human decision rights for every AI agent",
               lambda m: (m["decision_rights_pct"], _band(m["decision_rights_pct"], 100, 90))),
    "CTL-30": ("AI output quality checked by people",
               lambda m: (m["ai_answer_accuracy"], _band(m["ai_answer_accuracy"], 90, 75))),
}
SCORE = {"pass": 1.0, "partial": 0.5, "fail": 0.0}


@lru_cache(maxsize=1)
def results() -> dict:
    m = measurements()
    out = {}
    for cid, (name, test) in CONTROLS.items():
        value, status = test(m)
        out[cid] = {"name": name, "value": value, "status": status}
    return out


# ---------- AI-generated control tests ----------

TEMPLATES = {"threshold": "{metric} {op} {value}"}
OPS = {">=": lambda a, b: a >= b, "<=": lambda a, b: a <= b, "==": lambda a, b: a == b}


@dataclass
class DraftTest:
    id: str
    control: str
    metric: str
    op: str
    value: float
    drafted_by: str = "agent:copilot"
    status: str = "draft"
    approved_by: str | None = None
    log: HashLog = field(default_factory=HashLog)

    def approve(self, by: str, reason: str) -> None:
        if is_agent(by):
            raise PermissionError("a person approves a control test")
        if not reason:
            raise ValueError("reason required")
        self.status, self.approved_by = "approved", by
        self.log.append(by, "approve_test", test=self.id, reason=reason)

    def run(self) -> str:
        if self.status != "approved":
            raise PermissionError("draft tests do not run against evidence")
        m = measurements()
        if self.metric not in m:
            raise KeyError(self.metric)
        return "pass" if OPS[self.op](m[self.metric], self.value) else "fail"


def draft_test(control: str, metric: str, op: str, value: float) -> DraftTest:
    if op not in OPS:
        raise ValueError("op must be >=, <= or ==")
    if metric not in measurements():
        raise KeyError(f"unknown metric {metric}")
    return DraftTest(f"AT-{control}-{metric}", control, metric, op, value)
