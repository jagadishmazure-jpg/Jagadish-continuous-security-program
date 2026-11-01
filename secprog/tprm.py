"""Agentic third-party risk management (TPRM) with every decision kept by a person.

State machine per vendor assessment:
intake -> criteria_drafted -> criteria_approved -> assessed -> followups_drafted -> followups_approved ->
residual_decided -> monitoring. The agent drafts criteria and follow-up questions and grades each criterion as
Met / Partially Met / Not Met / Inconclusive with citations. A person approves the criteria, approves follow-ups
before anything could be sent (nothing is sent here) and makes the final residual-risk decision.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, timedelta

from . import TODAY, data
from .core import HashLog, is_agent

STATES = ("intake", "criteria_drafted", "criteria_approved", "assessed", "followups_drafted",
          "followups_approved", "residual_decided", "monitoring")
OUTCOMES = ("Met", "Partially Met", "Not Met", "Inconclusive")
CADENCE_MONTHS = {"critical": 12, "high": 12, "medium": 24, "low": 36}

BASE_CRITERIA = [
    ("C-01", "Independent security attestation (SOC 2 Type II or ISO 27001) within 12 months", ("soc2",)),
    ("C-02", "MFA for all administrative access", ("mfa",)),
    ("C-03", "Encryption of our data at rest and in transit", ("encryption",)),
    ("C-04", "Breach notification within 72 hours", ("breach_notice",)),
    ("C-05", "Sub-processor list and change notice", ("subprocessors",)),
]
AI_CRITERIA = [
    ("AI-01", "Our data is not used to train the vendor's or a third party's models", ("no_training",)),
    ("AI-02", "AI features can be disabled per customer", ("ai_opt_out",)),
    ("AI-03", "Named model providers and data residency for AI processing", ("ai_providers",)),
    ("AI-04", "Human review for AI outputs that affect our customers", ("ai_human_review",)),
    ("AI-05", "AI incident and model-change notification", ("ai_change_notice",)),
]
RESILIENCE_CRITERIA = [
    ("R-01", "Backups are immutable (cannot be changed or deleted) for at least 30 days", ("immutable_backups",)),
    ("R-02", "Recovery time objective is 24 hours or less and restore-tested", ("rto",)),
]

# Synthetic vendor documents: vendor -> {fact: (value, citation)}
DOCS = {
    "V-03": {"soc2": (True, "Copperline SOC 2 report p.6"), "mfa": (True, "Copperline SOC 2 report p.11"),
             "encryption": (True, "Copperline security whitepaper s.2"),
             "breach_notice": ("96h", "Copperline DPA s.9"), "subprocessors": (True, "Copperline trust page"),
             "no_training": (False, "Copperline AI terms s.4 (opt-in training by default)"),
             "ai_opt_out": (True, "Copperline admin guide p.22"), "ai_providers": ("partial",
                                                                                  "Copperline AI terms s.2"),
             "immutable_backups": (True, "Copperline SOC 2 report p.30"), "rto": (12, "Copperline BCP s.3")},
    "V-04": {"soc2": (True, "Tidewater ISO certificate"), "mfa": (True, "Tidewater questionnaire Q12"),
             "encryption": (True, "Tidewater questionnaire Q15"), "breach_notice": ("72h", "Tidewater MSA s.11"),
             "subprocessors": (True, "Tidewater trust page"), "immutable_backups": (True, "Tidewater runbook p.4"),
             "rto": (4, "Tidewater BCP s.2")},
    "V-09": {"soc2": (False, "Silverbrook questionnaire Q1 (report expired 2025-03)"),
             "mfa": (True, "Silverbrook questionnaire Q8"), "encryption": (True, "Silverbrook questionnaire Q9"),
             "no_training": (True, "Silverbrook AI addendum s.1"), "ai_human_review": (True,
                                                                                       "Silverbrook AI addendum s.3")},
}


def grade(cid: str, keys: tuple, vdocs: dict) -> dict:
    if not all(k in vdocs for k in keys):
        return {"criterion": cid, "outcome": "Inconclusive", "citations": [], "why": "no evidence in vendor docs"}
    k = keys[0]
    val, cite = vdocs[k]
    if k == "breach_notice":
        hours = int(str(val).rstrip("h"))
        outcome = "Met" if hours <= 72 else "Partially Met" if hours <= 120 else "Not Met"
    elif k == "rto":
        outcome = "Met" if val <= 24 else "Not Met"
    elif val == "partial":
        outcome = "Partially Met"
    else:
        outcome = "Met" if val else "Not Met"
    return {"criterion": cid, "outcome": outcome, "citations": [cite], "why": f"{k} = {val}"}


@dataclass
class Assessment:
    vendor: dict
    state: str = "intake"
    criteria: list = field(default_factory=list)
    results: list = field(default_factory=list)
    followups: list = field(default_factory=list)
    residual: str | None = None
    decided_by: str | None = None
    log: HashLog = field(default_factory=HashLog)

    def _move(self, to: str, by: str) -> None:
        if STATES.index(to) != STATES.index(self.state) + 1:
            raise ValueError(f"cannot go from {self.state} to {to}")
        self.state = to
        self.log.append(by, "state", to=to, vendor=self.vendor["id"])

    def draft_criteria(self) -> list:
        crit = list(BASE_CRITERIA)
        if self.vendor["ai_features"]:
            crit += AI_CRITERIA
        if self.vendor["tier"] in ("critical", "high"):
            crit += RESILIENCE_CRITERIA
        self.criteria = crit
        self._move("criteria_drafted", "agent:tprm")
        return crit

    def approve_criteria(self, by: str, remove: tuple = ()) -> None:
        if is_agent(by):
            raise PermissionError("criteria are approved by a person")
        self.criteria = [c for c in self.criteria if c[0] not in remove]
        self._move("criteria_approved", by)

    def assess(self, docs: dict | None = None) -> list:
        if self.state != "criteria_approved":
            raise ValueError("criteria must be approved first")
        vdocs = (DOCS if docs is None else docs).get(self.vendor["id"], {})
        self.results = [grade(cid, keys, vdocs) for cid, _, keys in self.criteria]
        self._move("assessed", "agent:tprm")
        return self.results

    def draft_followups(self) -> list:
        text = {c[0]: c[1] for c in self.criteria}
        self.followups = [{"criterion": r["criterion"], "question": f"Please provide evidence for: "
                           f"{text[r['criterion']]}", "status": "draft"}
                          for r in self.results if r["outcome"] != "Met"]
        self._move("followups_drafted", "agent:tprm")
        return self.followups

    def approve_followups(self, by: str, drop: tuple = ()) -> list:
        if is_agent(by):
            raise PermissionError("follow-up questions are approved by a person before sending")
        self.followups = [f for f in self.followups if f["criterion"] not in drop]
        for f in self.followups:
            f["status"] = "approved (ready to send; not sent)"
        self._move("followups_approved", by)
        return self.followups

    def decide_residual(self, by: str, role: str, residual: str, note: str) -> str:
        if is_agent(by):
            raise PermissionError("residual risk is decided by a person")
        if role not in ("ciso", "procurement", "cro"):
            raise PermissionError("CISO, CRO or procurement lead decides")
        if residual not in ("low", "medium", "high", "reject"):
            raise ValueError("low, medium, high or reject")
        if not note:
            raise ValueError("record the reason")
        self.residual, self.decided_by = residual, by
        self._move("residual_decided", by)
        self._move("monitoring", by)
        return residual

    def summary(self) -> dict:
        counts = {o: sum(r["outcome"] == o for r in self.results) for o in OUTCOMES}
        return {"vendor": self.vendor["id"], "state": self.state, "criteria": len(self.criteria), **counts,
                "cited_pct": round(100 * sum(bool(r["citations"]) for r in self.results) / len(self.results), 1)
                if self.results else 0.0, "followups": len(self.followups), "residual": self.residual}

    def writeback(self) -> str:
        """Payload for the procurement system webhook. Written to a file by the CLI; never posted."""
        return json.dumps({"event": "vendor.assessment.decided", "vendor": self.vendor["id"],
                           "residual": self.residual, "decided_by": self.decided_by,
                           "next_review": next_review(self.vendor["tier"], TODAY)}, sort_keys=True)


def next_review(tier: str, last: str) -> str:
    d = date.fromisoformat(last)
    return (d + timedelta(days=round(CADENCE_MONTHS[tier] * 30.44))).isoformat()


def run(vendor_id: str) -> Assessment:
    v = next(x for x in data.vendors() if x["id"] == vendor_id)
    a = Assessment(v)
    a.draft_criteria()
    a.approve_criteria("paul.procurement")
    a.assess()
    a.draft_followups()
    a.approve_followups("paul.procurement")
    a.decide_residual("ciso.amara", "ciso", "medium" if a.summary()["Not Met"] else "low", "see criteria results")
    return a


def reassessment_due(vendors: list[dict] | None = None, today: str = TODAY, ai_changes: set | None = None) -> list:
    """Overdue by cadence, or triggered early because the vendor shipped a new AI feature."""
    vendors = data.vendors() if vendors is None else vendors
    ai_changes = {"V-07"} if ai_changes is None else ai_changes
    out = []
    for v in vendors:
        due = next_review(v["tier"], v["last_assessed"])
        if due <= today:
            out.append({"vendor": v["id"], "reason": "cadence", "due": due})
        elif v["id"] in ai_changes:
            out.append({"vendor": v["id"], "reason": "new AI feature", "due": today})
    return out


def kpis(vendors: list[dict] | None = None) -> dict:
    """Coverage, depth and cadence (B2)."""
    vendors = data.vendors() if vendors is None else vendors
    assessed = {"V-03", "V-04", "V-09"}
    due = reassessment_due(vendors)
    crit = [v for v in vendors if v["tier"] == "critical"]
    depth = [run(v).summary()["criteria"] for v in sorted(assessed)]
    ai_v = [v for v in vendors if v["ai_features"]]
    return {"vendors": len(vendors), "assessed_with_agent": len(assessed),
            "coverage_pct": round(100 * len(assessed) / len(vendors), 1),
            "critical_on_cadence_pct": round(100 * sum(1 for v in crit if v["id"] not in
                                                       {d["vendor"] for d in due}) / len(crit), 1),
            "avg_criteria_per_assessment": round(sum(depth) / len(depth), 1),
            "overdue_or_triggered": len(due),
            "ai_vendors_with_ai_criteria_pct": round(100 * sum(v["id"] in assessed for v in ai_v) / len(ai_v), 1)}


# ---------- procurement intake gate ----------

PURCHASES = [
    {"id": "PR-101", "vendor": "V-03", "amount": 48000, "spend_approved_day": 5, "security_review_done_day": 3},
    {"id": "PR-102", "vendor": "V-06", "amount": 12000, "spend_approved_day": 2, "security_review_done_day": None},
    {"id": "PR-103", "vendor": "V-10", "amount": 900, "spend_approved_day": 1, "security_review_done_day": None},
    {"id": "PR-104", "vendor": "V-09", "amount": 150000, "spend_approved_day": None, "security_review_done_day": 4},
    {"id": "PR-105", "vendor": "V-07", "amount": 22000, "spend_approved_day": 6, "security_review_done_day": 8},
]
REVIEW_EXEMPT_BELOW = 1000  # tiny, low-tier purchases skip review (documented exception)


def purchase_gate(pr: dict) -> dict:
    v = next(x for x in data.vendors() if x["id"] == pr["vendor"])
    exempt = pr["amount"] < REVIEW_EXEMPT_BELOW and v["tier"] == "low"
    rev, spend = pr["security_review_done_day"], pr["spend_approved_day"]
    if exempt:
        status = "ok (exempt: low tier, small amount)"
    elif spend is not None and (rev is None or spend < rev):
        status = "BLOCKED: spend approved before security review"
    elif rev is None:
        status = "waiting for security review"
    else:
        status = "ok"
    return {"id": pr["id"], "vendor": v["name"], "status": status,
            "writeback": {"procurement_status": "hold" if status.startswith("BLOCKED") else "clear"}}


def purchase_summary() -> dict:
    res = [purchase_gate(p) for p in PURCHASES]
    return {"requests": len(res), "blocked": sum(r["status"].startswith("BLOCKED") for r in res),
            "rows": res}
