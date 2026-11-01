"""GRC Copilot: 12 canned questions answered from live (synthetic) data, each with its source module.

No model is called. The copilot only reads; it cannot approve, publish or send anything.
"""
from __future__ import annotations

from . import (
    ai_exposure,
    ai_governance,
    attack_paths,
    ctem,
    cve_rank,
    frameworks,
    governance,
    identity_recovery,
    kpis,
    questionnaire,
    tprm,
    vuln_sla,
)


def _top_cve() -> str:
    top = cve_rank.rank_v2()[0]
    return f"{top['id']} on {top['asset']}: {top['reason']}"


QUESTIONS = {
    "q01": ("What should I fix first today?",
            lambda: "; ".join(x["action"] for x in ctem.five_minute_list(3)), "ctem.five_minute_list"),
    "q02": ("Which CVE is riskiest and why?", _top_cve, "cve_rank.rank_v2"),
    "q03": ("What is our exposure score and trend?",
            lambda: f"{kpis.exposure_16()['1_exposure_score']['org']} / 1000; change "
                    f"{kpis.exposure_16()['1_exposure_score']['trend']}", "exposure.scores"),
    "q04": ("Which single fix cuts the most attack paths?",
            lambda: f"{attack_paths.choke_points(1)[0]['edge']} closes {attack_paths.choke_points(1)[0]['closes_paths']}"
                    f" of {attack_paths.choke_points(1)[0]['of']} paths", "attack_paths.choke_points"),
    "q05": ("Are we meeting vulnerability SLAs?",
            lambda: f"{vuln_sla.summary()['adherence_pct']}% of open findings are within SLA", "vuln_sla.summary"),
    "q06": ("How ready are we for SOC 2?",
            lambda: f"{frameworks.readiness('SOC2')['ready_pct']}% (weakest-control scoring)", "frameworks.readiness"),
    "q07": ("Which vendors need reassessment?",
            lambda: ", ".join(f"{d['vendor']} ({d['reason']})" for d in tprm.reassessment_due()),
            "tprm.reassessment_due"),
    "q08": ("Which AI agents are not monitored?",
            lambda: ", ".join(governance.monitoring()["failing"]) or "none", "governance.monitoring"),
    "q09": ("What shadow AI is in use?",
            lambda: ", ".join(t["name"] for t in ai_exposure.discover()["tools"] if t["status"] == "unapproved"),
            "ai_exposure.discover"),
    "q10": ("Which Tier 0 identity checks fail?",
            lambda: ", ".join(c["id"] for c in identity_recovery.tier0_checks() if not c["passed"]),
            "identity_recovery.tier0_checks"),
    "q11": ("How accurate are AI questionnaire drafts?",
            lambda: f"{questionnaire.run_demo()[1]['accuracy_pct']}% approved without edits by reviewers",
            "questionnaire.metrics"),
    "q12": ("What did AI save us this month?",
            lambda: f"{ai_governance.roi()['hours_saved_net']} net hours (synthetic inputs, review time subtracted)",
            "ai_governance.roi"),
}


def ask(qid: str) -> dict:
    if qid not in QUESTIONS:
        return {"question": qid, "answer": "I only answer the 12 listed questions.", "source": None}
    q, fn, src = QUESTIONS[qid]
    return {"question": q, "answer": fn(), "source": src, "basis": "synthetic data"}


def find(text: str) -> str | None:
    words = set(text.lower().split())
    best, score = None, 0
    for qid, (q, _, _) in QUESTIONS.items():
        s = len(words & set(q.lower().rstrip("?").split()))
        if s > score:
            best, score = qid, s
    return best if score >= 2 else None
