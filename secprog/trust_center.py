"""Trust Center (simulated, offline HTML preview).

* Documents are public or gated. A gated request is decided by a pure, versioned NDA rules engine; unclear cases
  go to a person.
* Items come from the evidence library. AI-drafted items stay drafts until a person publishes them.
* Visitor search only sees published items.
* "How we use AI" section and AI Feature disclosures.
* Vulnerability-response playbook: a known-exploited CVE produces a draft Trust Center update, a KB answer and a
  subscriber email preview. A person approves; nothing is emailed. Time to first update is measured.
* Analytics and trust-to-revenue numbers are SIMULATED.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from html import escape

from . import DOMAIN, ORG, data
from .core import HashLog, is_agent, sha
from .knowledge import tokens

NDA_RULES_VERSION = "2026.10-r3"


def nda_decision(req: dict) -> dict:
    """Pure function: same input -> same output. Returns approve / deny / review with the rule that fired."""
    domain = req.get("email", "").split("@")[-1].lower()
    free_mail = {"freemail.example", "webmail.example"}
    if req.get("doc_level") == "public":
        return {"decision": "approve", "rule": "R0 public document", "version": NDA_RULES_VERSION}
    if domain in free_mail:
        return {"decision": "deny", "rule": "R1 personal email domain", "version": NDA_RULES_VERSION}
    if req.get("competitor"):
        return {"decision": "deny", "rule": "R2 listed competitor", "version": NDA_RULES_VERSION}
    if req.get("nda_on_file") and req.get("crm_stage") in ("opportunity", "customer"):
        return {"decision": "approve", "rule": "R3 NDA on file and active deal", "version": NDA_RULES_VERSION}
    if req.get("crm_stage") == "customer":
        return {"decision": "approve", "rule": "R4 existing customer (MSA covers confidentiality)",
                "version": NDA_RULES_VERSION}
    return {"decision": "review", "rule": "R9 no rule matched; a person decides", "version": NDA_RULES_VERSION}


ACCESS_REQUESTS = [
    {"id": "AR-01", "email": "ciso@alder-mutual.example", "doc_level": "gated", "nda_on_file": True,
     "crm_stage": "opportunity", "deal_value": 180000},
    {"id": "AR-02", "email": "someone@freemail.example", "doc_level": "gated", "crm_stage": None},
    {"id": "AR-03", "email": "it@kestrel-bank.example", "doc_level": "gated", "crm_stage": "customer",
     "deal_value": 95000},
    {"id": "AR-04", "email": "analyst@rival-ledger.example", "doc_level": "gated", "competitor": True},
    {"id": "AR-05", "email": "buyer@oakmere-legal.example", "doc_level": "gated", "crm_stage": "lead"},
    {"id": "AR-06", "email": "anyone@visitor.example", "doc_level": "public"},
    {"id": "AR-07", "email": "sec@lumen-ridge.example", "doc_level": "gated", "nda_on_file": True,
     "crm_stage": "opportunity", "deal_value": 240000},
]


@dataclass
class Item:
    id: str
    title: str
    body: str
    level: str  # public | gated
    source: str  # evidence id or doc
    drafted_by: str
    status: str = "draft"
    published_by: str | None = None
    ai_feature: bool = False


@dataclass
class TrustCenter:
    items: dict = field(default_factory=dict)
    log: HashLog = field(default_factory=HashLog)

    def sync_from_evidence(self, evidence: list) -> int:
        """Evidence-library sync: each evidence record becomes a draft summary item (never auto-published)."""
        n = 0
        for e in evidence:
            iid = "TC-" + e.evidence_id[3:11]
            if iid not in self.items:
                self.items[iid] = Item(iid, e.title, f"Collected {e.collected_at}; controls "
                                       f"{', '.join(e.control_hints)}.", "gated", e.evidence_id, "agent:trust-center")
                n += 1
        return n

    def draft(self, iid: str, title: str, body: str, level: str = "public", by: str = "agent:trust-center",
              ai_feature: bool = False) -> Item:
        self.items[iid] = Item(iid, title, body, level, "drafted", by, ai_feature=ai_feature)
        self.log.append(by, "draft", item=iid)
        return self.items[iid]

    def publish(self, iid: str, by: str) -> Item:
        if is_agent(by):
            raise PermissionError("only a person publishes to the Trust Center")
        it = self.items[iid]
        it.status, it.published_by = "published", by
        self.log.append(by, "publish", item=iid, sha=sha([it.title, it.body]))
        return it

    def search(self, query: str, visitor_level: str = "public") -> list[str]:
        q = tokens(query)
        out = []
        for it in self.items.values():
            if it.status != "published":
                continue
            if it.level == "gated" and visitor_level != "gated":
                continue
            if q & tokens(it.title + " " + it.body):
                out.append(it.id)
        return sorted(out)


HOW_WE_USE_AI = [
    ("Where AI is used", ("Drafting questionnaire answers, Trust Center drafts, vendor criteria and plain-English "
      "explanations of CVE rankings. Scoring, SLA tests and approvals are deterministic code.")),
    ("What AI never does", "Approve anything, publish anything, send email, or change production systems."),
    ("Human review", ("Every AI draft is reviewed by a named person before use; reviewers can approve, edit or "
      "reject each answer.")),
    ("Data", "Customer personal data is not sent to unapproved AI tools; approved providers have data sharing off."),
    ("Monitoring", ("Every agent has an owner, a heartbeat and a hash-chained log. Agents silent for more than 24 "
      "hours fail a control.")),
    ("Resilience", ("Each AI workflow has a fallback or is listed as stopping during a provider outage; the last "
      "outage drill result is shown on the dashboard.")),
]

AI_FEATURES = [
    {"feature": "Smart dispute summaries", "model_provider": "model-provider-a", "data_used": "dispute text",
     "trains_on_customer_data": False, "human_in_loop": True, "opt_out": True},
    {"feature": "Fraud risk score", "model_provider": "model-provider-b", "data_used": "transaction metadata",
     "trains_on_customer_data": False, "human_in_loop": True, "opt_out": False},
]


# ---------- vulnerability-response playbook ----------

PLAYBOOK = [
    ("Hour 0-2", "Confirm whether the CVE affects us (asset inventory, SBOM, reachability)."),
    ("Hour 2-4", "Draft the first Trust Center update with the status template; a person approves it."),
    ("Hour 4-8", "Draft the KB answer for incoming questions; a person approves it."),
    ("Hour 8-24", "Patch or mitigate; post-action verification; draft a follow-up update."),
    ("Day 2+", "Close out with a final update and lessons learned."),
]
TEMPLATE_FIELDS = ("Status", "Scope", "Remediation", "Timeline", "Contact")


def vuln_update(cve: dict, affected: bool, hours_since_kev: float) -> dict:
    status = "Investigating - affected" if affected else "Not affected"
    body = {
        "Status": status,
        "Scope": f"{cve['package']} on {cve['asset']}" if affected else "No production system uses the component.",
        "Remediation": "Patch scheduled within the critical SLA (7 days)" if affected else "No action needed.",
        "Timeline": f"Detected {hours_since_kev:.0f}h after the CVE was added to the known-exploited list.",
        "Contact": f"security@{DOMAIN}",
    }
    return {"cve": cve["id"], "update": body, "kb_answer": f"{cve['id']}: {status}. {body['Remediation']}",
            "subscriber_preview": f"Subject: [{ORG}] Security update on {cve['id']}\n\n"
                                  + "\n".join(f"{k}: {v}" for k, v in body.items()),
            "sent": False}


def run_playbook(tc: TrustCenter | None = None) -> dict:
    """Simulated: KEV CVEs in our feed. Draft at hour 2.5, a person approves at hour 3.25."""
    tc = tc or TrustCenter()
    kev = [c for c in data.cves() if c["kev"]]
    times = []
    for i, c in enumerate(kev):
        affected = c["reachable"]
        u = vuln_update(c, affected, 1.0)
        it = tc.draft(f"VU-{i + 1:02d}", f"Security update: {c['id']}", "\n".join(
            f"{k}: {v}" for k, v in u["update"].items()))
        tc.publish(it.id, "tess.trust")
        times.append(2.5 + 0.75 + 0.25 * i)
    return {"kev_cves": len(kev), "updates_published": len(times),
            "median_hours_to_first_update": sorted(times)[len(times) // 2] if times else None,
            "emails_sent": 0, "template_fields": list(TEMPLATE_FIELDS)}


# ---------- analytics and trust-to-revenue (SIMULATED) ----------

def analytics() -> dict:
    decisions = [nda_decision(r) for r in ACCESS_REQUESTS]
    auto = sum(d["decision"] != "review" for d in decisions)
    return {"visits_30d": 1420, "doc_downloads_30d": 233, "access_requests": len(ACCESS_REQUESTS),
            "auto_decided_pct": round(100 * auto / len(decisions), 1),
            "questions_self_served_pct": 58.0, "basis": "SIMULATED visit and download counts; decisions measured"}


def trust_to_revenue() -> dict:
    won = [r for r in ACCESS_REQUESTS if nda_decision(r)["decision"] == "approve" and r.get("deal_value")]
    return {"deals_touching_trust_center": len(won), "pipeline_influenced": sum(r["deal_value"] for r in won),
            "basis": "SIMULATED deal values"}


def render_html(tc: TrustCenter) -> str:
    pub = [it for it in tc.items.values() if it.status == "published" and it.level == "public"]
    rows = "".join(f"<li><b>{escape(it.title)}</b><br>{escape(it.body).replace(chr(10), '<br>')}</li>" for it in pub)
    ai = "".join(f"<li><b>{escape(h)}</b>: {escape(t)}</li>" for h, t in HOW_WE_USE_AI)
    feats = "".join(f"<tr><td>{escape(f['feature'])}</td><td>{escape(f['model_provider'])}</td>"
                    f"<td>{'no' if not f['trains_on_customer_data'] else 'yes'}</td>"
                    f"<td>{'yes' if f['human_in_loop'] else 'no'}</td></tr>" for f in AI_FEATURES)
    vdp = (f"<p>Report a vulnerability to security@{DOMAIN}. We reply within 2 business days and will not take "
           "legal action against good-faith research.</p>")
    return (f"<html><body style='font-family:Arial;max-width:760px'><h1>{escape(ORG)} Trust Center (preview)</h1>"
            "<p style='color:#a00'>Synthetic preview. Not a real company.</p>"
            f"<h2>Updates</h2><ul>{rows}</ul><h2>How we use AI</h2><ul>{ai}</ul>"
            "<h2>AI features</h2><table border=1 cellpadding=4><tr><th>Feature</th><th>Provider</th>"
            f"<th>Trains on your data</th><th>Human in loop</th></tr>{feats}</table>"
            f"<h2>Vulnerability disclosure</h2>{vdp}</body></html>")
