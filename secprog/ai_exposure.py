"""AI exposure discovery, the AI inventory (4 required fields), the shadow-AI register and AI vendor concentration.

Discovery reads synthetic package manifests, browser-extension lists, proxy logs and cloud resources. Every AI
tool found lands in the register as approved, unapproved or embedded. Approving a tool is a review-board
decision made by a person.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import data
from .core import HashLog, is_agent

AI_DOMAINS = {"api.model-provider-a.example": "model-provider-a", "api.model-provider-b.example": "model-provider-b",
              "chat.free-ai-notes.example": "free-ai-notes", "app.slide-genie.example": "slide-genie"}
AI_PACKAGES = {"llm-client": "2.1.0", "vector-lite": "0.4.1", "prompt-kit": "1.0.3"}
VULNERABLE_AI_PACKAGES = {("vector-lite", "0.4.1"): "CVE-SYN-2026-0101 (path traversal in index loader)"}
AI_EXTENSIONS = {"ai-summarizer-ext": "free-ai-notes", "grammar-ai-ext": "grammar-ai"}

MANIFESTS = {"fraud-model": {"llm-client": "2.1.0", "numpy-lite": "1.0"},
             "support-bot": {"llm-client": "2.1.0", "vector-lite": "0.4.1", "prompt-kit": "1.0.3"},
             "loan-portal": {"web-kit": "4.2"}}
EXTENSIONS = {"user03": ["ai-summarizer-ext"], "user07": ["grammar-ai-ext", "ad-block"], "user11": []}
PROXY = [("user03", "chat.free-ai-notes.example", 41), ("user09", "app.slide-genie.example", 12),
         ("support-bot", "api.model-provider-a.example", 5200), ("fraud-model", "api.model-provider-b.example", 900),
         ("user14", "chat.free-ai-notes.example", 7)]
CLOUD = [{"name": "support-bot", "data_sharing": True, "identity_scopes": ["kyc-bucket:read", "files:write"],
          "endpoint_public": True},
         {"name": "fraud-model", "data_sharing": False, "identity_scopes": ["ledger-db:read"],
          "endpoint_public": False},
         {"name": "training-bucket", "public": True, "contains": "model training data"}]

APPROVED = {"model-provider-a", "model-provider-b", "grammar-ai"}
REQUIRED_FIELDS = ("owner", "purpose", "data_classes", "risk_tier")


def discover() -> dict:
    tools: dict[str, dict] = {}

    def add(name: str, how: str, who: str) -> None:
        t = tools.setdefault(name, {"name": name, "seen_by": set(), "users": set()})
        t["seen_by"].add(how)
        t["users"].add(who)

    for user, exts in EXTENSIONS.items():
        for e in exts:
            if e in AI_EXTENSIONS:
                add(AI_EXTENSIONS[e], "browser_extension", user)
    for user, dom, _ in PROXY:
        if dom in AI_DOMAINS:
            add(AI_DOMAINS[dom], "network", user)
    vuln = []
    embedded = []
    for app, pkgs in MANIFESTS.items():
        for p, v in pkgs.items():
            if p in AI_PACKAGES:
                embedded.append({"app": app, "package": p, "version": v})
            if (p, v) in VULNERABLE_AI_PACKAGES:
                vuln.append({"app": app, "package": p, "version": v, "issue": VULNERABLE_AI_PACKAGES[(p, v)]})
    unsafe = []
    for c in CLOUD:
        if c.get("data_sharing"):
            unsafe.append({"resource": c["name"], "issue": "provider data sharing is on"})
        if any(s.endswith(":write") for s in c.get("identity_scopes", [])) and c.get("endpoint_public"):
            unsafe.append({"resource": c["name"], "issue": "public endpoint with a write-capable identity"})
        if c.get("public"):
            unsafe.append({"resource": c["name"], "issue": "public bucket with training data"})
    rows = []
    for t in sorted(tools.values(), key=lambda x: x["name"]):
        status = "approved" if t["name"] in APPROVED else "unapproved"
        rows.append({"name": t["name"], "status": status, "seen_by": sorted(t["seen_by"]),
                     "users": sorted(t["users"])})
    return {"tools": rows, "embedded": embedded, "vulnerable_ai_libraries": vuln, "unsafe_settings": unsafe,
            "unapproved_users": sorted({u for r in rows if r["status"] == "unapproved" for u in r["users"]})}


@dataclass
class Entry:
    name: str
    owner: str = ""
    purpose: str = ""
    data_classes: tuple = ()
    risk_tier: str = ""
    status: str = "requested"
    history: list = field(default_factory=list)

    def missing(self) -> list[str]:
        return [f for f in REQUIRED_FIELDS if not getattr(self, f)]


class Register:
    """Shadow-AI register: request -> review board decision. Approval needs all 4 required fields."""

    TIERS = ("low", "medium", "high", "prohibited")

    def __init__(self) -> None:
        self.entries: dict[str, Entry] = {}
        self.log = HashLog()

    def request(self, name: str, owner: str, purpose: str, data_classes: tuple, risk_tier: str) -> Entry:
        if risk_tier and risk_tier not in self.TIERS:
            raise ValueError("unknown risk tier")
        e = Entry(name, owner, purpose, tuple(data_classes), risk_tier)
        self.entries[name] = e
        self.log.append(owner or "unknown", "ai_request", tool=name)
        return e

    def decide(self, name: str, decision: str, by: str, reason: str) -> Entry:
        e = self.entries[name]
        if is_agent(by):
            raise PermissionError("the AI review board is people")
        if decision == "approve":
            if e.missing():
                raise ValueError(f"missing required fields: {e.missing()}")
            if e.risk_tier == "prohibited":
                raise ValueError("prohibited tools cannot be approved")
            if "pii" in e.data_classes and e.risk_tier == "low":
                raise ValueError("a tool that touches PII cannot be low risk")
        if decision not in ("approve", "reject"):
            raise ValueError("approve or reject")
        e.status = "approved" if decision == "approve" else "rejected"
        e.history.append((decision, by, reason))
        self.log.append(by, "ai_decision", tool=name, decision=decision, reason=reason)
        return e


def inventory_completeness(reg: Register) -> float:
    es = list(reg.entries.values())
    return round(100 * sum(not e.missing() for e in es) / len(es), 1) if es else 0.0


def demo_register() -> Register:
    r = Register()
    r.request("model-provider-a", "dana.ai", "support bot answers", ("pii",), "high")
    r.request("model-provider-b", "dana.ai", "fraud scoring", ("financial",), "high")
    r.request("free-ai-notes", "user03", "meeting notes", ("internal",), "")
    r.request("slide-genie", "user09", "", (), "")
    r.decide("model-provider-a", "approve", "ai.board.chair", "DPA signed, data sharing off")
    r.decide("model-provider-b", "approve", "ai.board.chair", "no customer PII sent")
    r.decide("free-ai-notes", "reject", "ai.board.chair", "trains on customer data")
    return r


# ---------- AI vendor concentration and provider-outage drill ----------

AI_WORKFLOWS = [
    {"id": "WF-support-answers", "provider": "model-provider-a", "fallback": "rules + human queue"},
    {"id": "WF-questionnaire-drafts", "provider": "model-provider-a", "fallback": "approved KB only"},
    {"id": "WF-fraud-scoring", "provider": "model-provider-b", "fallback": "rules engine v3"},
    {"id": "WF-cve-reasons", "provider": "none (deterministic)", "fallback": "n/a"},
    {"id": "WF-trust-drafts", "provider": "model-provider-a", "fallback": None},
    {"id": "WF-copilot", "provider": "model-provider-a", "fallback": "canned answers"},
    {"id": "WF-vendor-criteria", "provider": "model-provider-b", "fallback": None},
]


def concentration() -> dict:
    ai = [w for w in AI_WORKFLOWS if not w["provider"].startswith("none")]
    counts: dict[str, int] = {}
    for w in ai:
        counts[w["provider"]] = counts.get(w["provider"], 0) + 1
    ranked = sorted(counts.values(), reverse=True)
    hhi = round(sum((c / len(ai)) ** 2 for c in counts.values()), 3)
    vendor_ai = [v for v in data.vendors() if v["ai_provider"]]
    return {"ai_workflows": len(ai), "top1_share_pct": round(100 * ranked[0] / len(ai), 1),
            "top2_share_pct": round(100 * sum(ranked[:2]) / len(ai), 1), "hhi": hhi,
            "with_fallback_pct": round(100 * sum(bool(w["fallback"]) for w in ai) / len(ai), 1),
            "vendors_on_provider_a": sum(v["ai_provider"] == "model-provider-a" for v in vendor_ai)}


def outage_drill(provider: str = "model-provider-a") -> dict:
    """Tabletop: what keeps running if one AI provider is down for a day? Synthetic, no real calls."""
    hit = [w for w in AI_WORKFLOWS if w["provider"] == provider]
    degraded = [w["id"] for w in hit if w["fallback"]]
    stopped = [w["id"] for w in hit if not w["fallback"]]
    return {"provider": provider, "affected": len(hit), "degraded_to_fallback": degraded, "stopped": stopped,
            "result": "pass" if not stopped else "fail", "date": data.day(-6)}
