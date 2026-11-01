"""Questionnaire agent as workflow owner, plus KB hygiene.

Flow: draft each answer from the approved KB with citations -> low-confidence answers go to an SME queue ->
reminders for SMEs who have not answered -> ready gate (every answer reviewed) -> an expert approves, edits or
rejects each answer -> final sign-off by a person. The package is then ready to return; nothing is sent.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import data
from .core import HashLog, is_agent
from .knowledge import KB, cite, tokens

CONFIDENCE_MIN = 0.5
PARTIAL = {"Q19"}  # the KB answer is related but incomplete; the expert edits it
REMINDER_AFTER_DAYS = 2
SLA_DAYS = (2, 5)

# Synthetic incoming questionnaire from a fictional prospect, with the KB entry an expert says is right.
QUESTIONS = [
    ("Q01", "Is customer data encrypted at rest?", "KB-001"),
    ("Q02", "Is data encrypted in transit and which TLS version?", "KB-002"),
    ("Q03", "Do you enforce multi-factor authentication (MFA) for production?", "KB-003"),
    ("Q04", "How frequently do you perform user access reviews?", "KB-004"),
    ("Q05", "What is your breach notification timeline to customers?", "KB-005"),
    ("Q06", "Do you maintain and test an incident response plan?", "KB-006"),
    ("Q07", "Are your backups immutable and restore tested?", "KB-007"),
    ("Q08", "What is the RTO for core services?", "KB-008"),
    ("Q09", "What is your SLA for patching critical vulnerabilities?", "KB-009"),
    ("Q10", "Do you have annual third-party penetration tests?", "KB-010"),
    ("Q11", "Do you use AI tools on customer personal data?", "KB-011"),
    ("Q12", "How do you disclose sub-processors and changes?", "KB-012"),
    ("Q13", "Do you hold an ISO 27001 certificate?", None),
    ("Q14", "Are production code changes peer reviewed?", "KB-013"),
    ("Q15", "Describe your security monitoring and alert triage times.", "KB-014"),
    ("Q16", "Do you carry cyber insurance and what is the limit?", None),
    ("Q17", "How often do you assess critical vendors?", "KB-015"),
    ("Q18", "Where is customer data physically stored?", None),
    ("Q19", "Do you require MFA for all employees including email?", "KB-003"),
    ("Q20", "Do you scan code for secrets before merge?", None),
    # A trap: it looks like KB-001 (data at rest) but asks about laptops, which the KB does not cover.
    ("Q21", "Are employee laptops encrypted at rest?", None),
]


def match(question: str, kb: dict | None = None) -> tuple[str | None, float]:
    kb = KB if kb is None else kb
    q = tokens(question)
    best, score = None, 0.0
    for kid, (kq, ans, *_rest) in kb.items():
        t = tokens(kq + " " + ans)
        s = len(q & t) / max(1, len(q))
        if s > score or (s == score and best and kid < best):
            best, score = kid, s
    return best, round(score, 2)


@dataclass
class Answer:
    qid: str
    question: str
    kb: str | None
    confidence: float
    text: str | None
    citations: list[str]
    state: str = "drafted"  # drafted | sme_queue | approved | edited | rejected
    sme_days_waiting: int = 0
    reminders: int = 0
    reviewer: str | None = None


@dataclass
class Questionnaire:
    customer: str
    answers: list[Answer] = field(default_factory=list)
    log: HashLog = field(default_factory=HashLog)
    signed_off_by: str | None = None
    opened_day: int = 0

    def draft(self, questions=QUESTIONS) -> None:
        for qid, q, _ in questions:
            kid, conf = match(q)
            if kid and conf >= CONFIDENCE_MIN:
                kq, ans, cites, *_ = KB[kid]
                a = Answer(qid, q, kid, conf, ans, [cite(d, p) for d, p in cites])
            else:
                a = Answer(qid, q, None, conf, None, [], state="sme_queue")
            self.answers.append(a)
            self.log.append("agent:questionnaire", "draft", qid=qid, state=a.state, confidence=conf)

    def tick(self, days: int = 1) -> list[str]:
        """Advance time; SMEs who have waited too long get a reminder (a preview, not a message)."""
        reminded = []
        for a in self.answers:
            if a.state == "sme_queue":
                a.sme_days_waiting += days
                if a.sme_days_waiting >= REMINDER_AFTER_DAYS * (a.reminders + 1):
                    a.reminders += 1
                    reminded.append(a.qid)
        return reminded

    def sme_answer(self, qid: str, text: str, citation: str, by: str) -> Answer:
        if is_agent(by):
            raise PermissionError("SME answers come from people")
        if not citation:
            raise ValueError("an SME answer needs a source")
        a = self._get(qid)
        a.text, a.citations, a.state, a.reviewer = text, [citation], "approved", by
        self.log.append(by, "sme_answer", qid=qid)
        return a

    def review(self, qid: str, decision: str, by: str, new_text: str | None = None) -> Answer:
        if is_agent(by):
            raise PermissionError("experts are people")
        a = self._get(qid)
        if decision == "approve":
            a.state = "approved"
        elif decision == "edit":
            if not new_text:
                raise ValueError("an edit needs the new text")
            a.text, a.state = new_text, "edited"
        elif decision == "reject":
            a.text, a.state = None, "rejected"
        else:
            raise ValueError("approve, edit or reject")
        a.reviewer = by
        self.log.append(by, "review", qid=qid, decision=decision)
        return a

    def ready(self) -> tuple[bool, list[str]]:
        blockers = [a.qid for a in self.answers if a.state not in ("approved", "edited")]
        return not blockers, blockers

    def sign_off(self, by: str, role: str) -> str:
        if is_agent(by):
            raise PermissionError("final sign-off is a person")
        if role not in ("trust_lead", "ciso"):
            raise PermissionError("trust lead or CISO signs off")
        ok, blockers = self.ready()
        if not ok:
            raise ValueError(f"not ready: {blockers}")
        self.signed_off_by = by
        self.log.append(by, "sign_off", customer=self.customer)
        return "ready to return (not sent)"

    def _get(self, qid: str) -> Answer:
        for a in self.answers:
            if a.qid == qid:
                return a
        raise KeyError(qid)


def run_demo() -> tuple[Questionnaire, dict]:
    q = Questionnaire("Alder Mutual Insurance (fictional prospect)")
    q.draft()
    truth = {qid: kb for qid, _, kb in QUESTIONS}
    reminders = 0
    for _ in range(3):
        reminders += len(q.tick())
    for a in q.answers:
        if a.state == "drafted":
            if a.kb == truth[a.qid] and a.qid in PARTIAL:
                q.review(a.qid, "edit", "tess.trust", "Yes. MFA is required for every employee account, "
                         "including email; production also needs phishing-resistant MFA.")
            elif a.kb == truth[a.qid]:
                q.review(a.qid, "approve", "tess.trust")
            elif truth[a.qid] is not None:
                kq, ans, cites, *_ = KB[truth[a.qid]]
                q.review(a.qid, "edit", "tess.trust", ans)
                a.citations = [cite(d, p) for d, p in cites]
            else:
                q.review(a.qid, "reject", "tess.trust")
    sme_texts = {"Q13": ("No. We hold a SOC 2 Type II report; ISO 27001 is planned for 2027.", "SOC2-2026 p.4"),
                 "Q16": ("Yes. Details are shared under NDA.", "insurance binder (gated)"),
                 "Q18": ("In two cloud regions in the same country.", "SOC2-2026 p.4"),
                 "Q20": ("Yes, every pull request runs a secrets scan.", "POL-IS p.5"),
                 "Q21": (("Full-disk encryption is required by device management policy. 28 of 30 devices comply "
                          "today; the other 2 are being fixed."),
                         "device posture report (synthetic)")}
    for a in q.answers:
        if a.state not in ("sme_queue", "rejected"):
            continue
        if a.qid in sme_texts:
            q.sme_answer(a.qid, *sme_texts[a.qid], by="sme.platform")
        elif truth[a.qid]:
            kq, ans, cites, *_ = KB[truth[a.qid]]
            q.sme_answer(a.qid, ans, cite(*cites[0]), by="sme.platform")
    m = metrics(q, truth, reminders)
    m["sign_off"] = q.sign_off("tess.trust", "trust_lead")
    m["turnaround_days"] = 3
    m["within_sla"] = SLA_DAYS[0] <= m["turnaround_days"] <= SLA_DAYS[1] or m["turnaround_days"] < SLA_DAYS[0]
    return q, m


def metrics(q: Questionnaire, truth: dict, reminders: int = 0) -> dict:
    drafted = [a for a in q.answers if a.kb is not None]
    approved = [a for a in drafted if a.state == "approved" and a.reviewer == "tess.trust"]
    edited = [a for a in q.answers if a.state == "edited"]
    rejected_drafts = sum(1 for a in q.answers if a.state == "rejected" or (a.kb and truth[a.qid] is None))
    return {"questions": len(q.answers), "drafted_by_agent": len(drafted),
            "routed_to_sme": len(q.answers) - len(drafted), "approved_as_drafted": len(approved),
            "edited": len(edited), "rejected_drafts": rejected_drafts,
            "accuracy_pct": round(100 * len(approved) / len(drafted), 1) if drafted else 0.0,
            "auto_answer_rate_pct": round(100 * len(approved) / len(q.answers), 1), "sme_reminders": reminders}


# ---------- KB hygiene ----------

CUSTOMER_NAMES = [c[1] for c in data.CLIENTS[1:]] + ["Alder Mutual Insurance"]


class KBQueue:
    """New or changed KB answers wait for an owner's approval before agents may use them."""

    def __init__(self) -> None:
        self.pending: dict[str, dict] = {}
        self.approved: dict[str, dict] = {}

    def submit(self, kid: str, question: str, answer: str, by: str) -> dict:
        item = {"question": question, "answer": scrub(answer), "by": by,
                "scrubbed": scrub(answer) != answer}
        self.pending[kid] = item
        return item

    def approve(self, kid: str, by: str) -> dict:
        if is_agent(by):
            raise PermissionError("KB answers are approved by people")
        item = self.pending.pop(kid)
        if item["by"] == by:
            self.pending[kid] = item
            raise PermissionError("author cannot approve their own KB answer")
        self.approved[kid] = {**item, "approved_by": by}
        return self.approved[kid]


def scrub(text: str) -> str:
    out = text
    for name in CUSTOMER_NAMES:
        out = re.sub(re.escape(name), "[customer]", out, flags=re.I)
    return out


def duplicates(kb: dict | None = None, threshold: float = 0.6) -> list[tuple[str, str, float]]:
    kb = KB if kb is None else kb
    ids = sorted(kb)
    out = []
    for i, a in enumerate(ids):
        for b in ids[i + 1:]:
            ta, tb = tokens(kb[a][0]), tokens(kb[b][0])
            j = len(ta & tb) / max(1, len(ta | tb))
            if j >= threshold:
                out.append((a, b, round(j, 2)))
    return out


NUM = re.compile(r"\b\d+(?:\.\d+)?\b")


def conflicts(kb: dict | None = None) -> list[dict]:
    """Two answers on the same topic (shared key terms) that state different numbers."""
    kb = KB if kb is None else kb
    ids = sorted(kb)
    out = []
    for i, a in enumerate(ids):
        for b in ids[i + 1:]:
            shared = tokens(kb[a][0]) & tokens(kb[b][0])
            na, nb = set(NUM.findall(kb[a][1])), set(NUM.findall(kb[b][1]))
            if len(shared) >= 2 and na and nb and na != nb:
                out.append({"a": a, "b": b, "shared": sorted(shared), "numbers": [sorted(na), sorted(nb)]})
    return out


def spot_check(kb: dict | None = None, today: str = data.TODAY, stale_days: int = 180, sample: int = 5) -> dict:
    """Quarterly accuracy spot-check: a deterministic sample plus every entry older than stale_days."""
    from datetime import date
    kb = KB if kb is None else kb
    ids = sorted(kb)
    picked = ids[:: max(1, len(ids) // sample)][:sample]
    stale = [k for k in ids if (date.fromisoformat(today) - date.fromisoformat(kb[k][3])).days > stale_days]
    return {"sampled": picked, "stale": stale, "to_review": sorted(set(picked) | set(stale))}
