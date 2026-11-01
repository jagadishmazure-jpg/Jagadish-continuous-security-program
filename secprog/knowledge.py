"""Approved knowledge base (KB) and synthetic source documents with page and section numbers.

Questionnaire answers, Trust Center items and Copilot answers all cite these. The SOC 2 report text is
synthetic and written for this repo.
"""
from __future__ import annotations

DOCS = {
    "SOC2-2026": {"title": "Brightwater Ledger SOC 2 Type II report (synthetic)", "pages": {
        4: ("Section 3 System description", ("Brightwater Ledger runs its payment and lending services in two "
             "cloud regions. Customer data is encrypted at rest with AES-256 and in transit with TLS 1.2 or higher.")),
        9: ("Section 4 CC6.1 Logical access", ("Access to production requires single sign-on with phishing-resistant "
             "multi-factor authentication. Access is reviewed every quarter by system owners.")),
        12: ("Section 4 CC7.2 Monitoring", ("Security events are collected centrally and reviewed every day. Alerts "
              "are triaged within 30 minutes during business hours and within 2 hours at night.")),
        15: ("Section 4 CC7.4 Incident response", ("The incident response plan is tested twice a year. Customers are "
              "notified of a confirmed breach affecting their data within 72 hours.")),
        18: ("Section 4 CC8.1 Change management", ("Every production change is peer reviewed and passes automated "
              "tests before deployment.")),
        21: ("Section 4 A1.2 Backups", ("Backups run every 4 hours, are immutable for 35 days and are restore-tested "
              "every quarter. The recovery time objective is 8 hours.")),
        24: ("Section 5 Exceptions", "One exception: 2 of 40 sampled access reviews were completed 6 days late."),
        27: ("Section 4 CC9.2 Vendor management", ("Critical vendors are assessed every year against approved "
              "criteria; high-risk vendors every 2 years.")),
    }},
    "POL-IS": {"title": "Information security policy v4.2", "pages": {
        2: ("1 Scope", ("This policy applies to all employees, contractors and AI agents acting for Brightwater "
             "Ledger.")),
        5: ("4 Vulnerability management", ("Critical vulnerabilities are fixed within 7 days, high within 30 days, "
             "medium within 90 days.")),
        7: ("6 AI use", ("AI tools must be approved by the AI review board. Customer personal data may not be sent "
             "to unapproved AI tools. Every AI agent action that changes data needs a named human approver.")),
        9: ("8 Penetration testing", "An independent penetration test runs every year and after major changes."),
    }},
    "DPA-TEMPLATE": {"title": "Data processing addendum template", "pages": {
        3: ("Annex II Sub-processors", ("Sub-processors are listed on the Trust Center and customers get 30 days "
             "notice of changes.")),
    }},
}

# Approved KB answers: id -> (question, answer, citations[(doc, page)], last_reviewed, owner)
KB = {
    "KB-001": ("Do you encrypt data at rest?", "Yes. Customer data is encrypted at rest with AES-256.",
               [("SOC2-2026", 4)], "2026-08-01", "sme.platform"),
    "KB-002": ("Do you encrypt data in transit?", "Yes, with TLS 1.2 or higher.", [("SOC2-2026", 4)],
               "2026-08-01", "sme.platform"),
    "KB-003": ("Do you require MFA?", "Yes. Production access needs single sign-on with phishing-resistant MFA.",
               [("SOC2-2026", 9)], "2026-07-15", "sme.identity"),
    "KB-004": ("How often are access reviews performed?", "Every quarter, by system owners.", [("SOC2-2026", 9)],
               "2026-07-15", "sme.identity"),
    "KB-005": ("How fast do you notify customers of a breach?", ("Within 72 hours of confirming a breach that "
                "affects their data."), [("SOC2-2026", 15)], "2026-06-30", "sme.legal"),
    "KB-006": ("Do you have an incident response plan?", "Yes, tested twice a year.", [("SOC2-2026", 15)],
               "2026-06-30", "sme.secops"),
    "KB-007": ("Are backups immutable?", "Yes, immutable for 35 days, restore-tested every quarter.",
               [("SOC2-2026", 21)], "2026-09-10", "sme.platform"),
    "KB-008": ("What is your RTO?", "8 hours.", [("SOC2-2026", 21)], "2026-09-10", "sme.platform"),
    "KB-009": ("What is your patching SLA?", "Critical 7 days, high 30 days, medium 90 days.", [("POL-IS", 5)],
               "2026-05-01", "sme.secops"),
    "KB-010": ("Do you perform penetration tests?", "Yes, an independent test every year and after major changes.",
               [("POL-IS", 9)], "2026-05-01", "sme.secops"),
    "KB-011": ("Do you use AI with customer data?", ("Only approved AI tools; personal data may not go to "
                "unapproved tools and every data-changing agent action has a named human approver."),
               [("POL-IS", 7)], "2026-09-30", "sme.ai"),
    "KB-012": ("How are sub-processors disclosed?", "On the Trust Center, with 30 days notice of changes.",
               [("DPA-TEMPLATE", 3)], "2026-04-12", "sme.legal"),
    "KB-013": ("Are production changes reviewed?", "Yes, peer reviewed and tested before deployment.",
               [("SOC2-2026", 18)], "2026-08-20", "sme.platform"),
    "KB-014": ("How do you monitor security events?", ("Central collection with daily review; alerts triaged "
                "within 30 minutes in business hours."), [("SOC2-2026", 12)], "2026-08-20", "sme.secops"),
    "KB-015": ("How often are critical vendors assessed?", "Every year, against approved criteria.",
               [("SOC2-2026", 27)], "2026-03-01", "sme.procurement"),
}

STOP = {"do", "you", "your", "the", "a", "an", "of", "is", "are", "how", "what", "with", "for", "to", "in", "on",
        "and", "or", "we", "our", "does", "have", "any", "it", "be", "by", "at", "data", "which", "yes", "all",
        "including", "describe", "where", "version", "every"}


SYNONYMS = {"multi": "mfa", "factor": "mfa", "authentication": "mfa", "frequently": "often", "frequency": "often",
            "rto": "recovery", "tls": "transit", "timeline": "notify", "notification": "notify", "notified": "notify",
            "reviewed": "review", "reviews": "review", "tested": "test", "testing": "test", "tests": "test",
            "penetration": "pentest", "pen": "pentest", "patching": "patch", "fixed": "patch", "alert": "alerts",
            "assessed": "assess", "assessment": "assess", "subprocessor": "sub", "processors": "processor"}


def tokens(text: str) -> set[str]:
    out = set()
    for w in "".join(c.lower() if c.isalnum() else " " for c in text).split():
        if w in STOP or len(w) < 2:
            continue
        w = SYNONYMS.get(w, w)
        for suf in ("ed", "ing", "ion"):
            if w.endswith(suf) and len(w) > len(suf) + 4:
                w = w[: -len(suf)]
                break
        out.add(w[:-1] if w.endswith("s") and len(w) > 3 else w)
    return out


def cite(doc: str, page: int) -> str:
    sec = DOCS[doc]["pages"][page][0]
    return f"{doc} p.{page} ({sec})"


def search_docs(question: str, docs: dict | None = None) -> list[dict]:
    """Long-document Q&A: return passages ranked by overlap, each with page and section citation."""
    docs = DOCS if docs is None else docs
    q = tokens(question)
    hits = []
    for did, d in docs.items():
        for page, (sec, text) in d["pages"].items():
            score = len(q & tokens(text + " " + sec))
            if score:
                hits.append({"doc": did, "page": page, "section": sec, "score": score, "text": text,
                             "citation": f"{did} p.{page} ({sec})"})
    return sorted(hits, key=lambda h: (-h["score"], h["doc"], h["page"]))


def answer_long_doc(question: str, min_score: int = 2) -> dict:
    hits = search_docs(question)
    if not hits or hits[0]["score"] < min_score:
        return {"answer": None, "citations": [], "status": "not found in the documents; ask an SME"}
    top = hits[0]
    return {"answer": top["text"], "citations": [top["citation"]], "status": "found", "score": top["score"]}
