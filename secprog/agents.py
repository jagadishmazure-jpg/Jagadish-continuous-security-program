"""Agent registry: 13 core agents plus 6 specialist agents.

Each agent has an owner (a person), an identity, scopes, an autonomy level (suggest-only by default), a
heartbeat, an outcome with a metric and failure threshold (the AGENTS.md scorecard) and the AI provider it
uses ("none" means deterministic code).
"""
from __future__ import annotations

from dataclasses import dataclass, field

AUTONOMY = ("suggest", "act_with_approval", "act_then_notify")


@dataclass
class Agent:
    id: str
    purpose: str
    owner: str
    scopes: tuple[str, ...]
    outcome: str
    metric: str
    failure_threshold: str
    autonomy: str = "suggest"
    heartbeat_hours: float = 1.0
    provider: str = "none"
    core: bool = True
    escalation: str = "ciso"
    approver: str = "secops_lead"
    tools: tuple[str, ...] = field(default=())

    @property
    def identity(self) -> str:
        return f"agent:{self.id}"


def _a(id_, purpose, owner, scopes, outcome, metric, thr, **kw) -> Agent:
    return Agent(id_, purpose, owner, tuple(scopes), outcome, metric, thr, **kw)


AGENTS = [
    _a("scan-importer", "Import code and secrets scan results into the findings model", "maria.secops",
       ["findings:write", "repos:read"], "Every scan imported and de-duplicated", "import success rate", "< 99%",
       autonomy="act_with_approval", tools=("import_sarif", "import_secrets")),
    _a("dependency-ranker", "Rank dependency CVEs with EPSS, KEV and reachability", "maria.secops",
       ["findings:read", "cve-feed:read"], "Exploited CVEs fixed first", "coverage at top 12", "< 40%",
       tools=("rank_v2",)),
    _a("dast-surface", "Simulated DAST and external attack-surface discovery", "maria.secops",
       ["assets:read", "dast:run-simulated"], "No unknown internet-facing assets", "unowned hosts", "> 0 for 7 days",
       heartbeat_hours=30.0, tools=("import_zap", "discover_hosts")),
    _a("device-posture", "Check device and MDM posture", "omar.it", ["mdm:read"],
       "Devices meet the baseline", "compliant devices", "< 80%", tools=("evaluate_devices",)),
    _a("access-review", "Propose access revocations for review", "rina.manager", ["idp:read"],
       "Quarterly review completed", "campaign completion", "< 100% by due date",
       autonomy="act_with_approval", tools=("propose_revocation",)),
    _a("vuln-sla", "Test open findings against SLA", "maria.secops", ["findings:read"],
       "Findings fixed within SLA", "SLA adherence", "< 85%", tools=("evaluate_sla",)),
    _a("exposure", "Exposure scores, attack paths, toxic combinations", "maria.secops",
       ["assets:read", "findings:read", "identity-graph:read"], "Exposure score trending down",
       "org score 30-day change", "> 0 (rising)", tools=("scores", "choke_points")),
    _a("trust-center", "Draft Trust Center updates and handle access requests", "tess.trust",
       ["trust-center:draft", "crm:read"], "Customers self-serve security answers", "self-service rate", "< 50%",
       provider="model-provider-a", approver="trust_lead", tools=("draft_update", "nda_decision")),
    _a("questionnaire", "Draft questionnaire answers with citations", "tess.trust", ["kb:read", "sme-queue:write"],
       "Questionnaires returned within SLA", "turnaround days", "> 5", provider="model-provider-a",
       approver="sme", tools=("draft_answer", "route_to_sme")),
    _a("tprm", "Assess vendors against approved criteria", "paul.procurement", ["vendors:read", "docs:read"],
       "Critical vendors assessed on cadence", "critical vendors overdue", "> 0", provider="model-provider-b",
       approver="procurement", tools=("assess_criterion", "draft_followup")),
    _a("vciso", "Build the costed roadmap and mock audit", "vic.vciso", ["all:read"],
       "Roadmap approved each quarter", "roadmap items on track", "< 70%", approver="vciso",
       tools=("draft_roadmap", "mock_audit")),
    _a("reporter", "Build daily and weekly leadership reports (previews only)", "maria.secops", ["metrics:read"],
       "Reports on time with real numbers", "report build success", "< 100%", tools=("build_report",)),
    _a("copilot", "Answer canned GRC questions with citations", "maria.secops", ["metrics:read"],
       "Answers cite their source", "answers with citations", "< 100%", provider="model-provider-a",
       tools=("answer",)),
    _a("recovery-runbook", "Propose identity recovery steps", "ian.identity", ["directory:read"],
       "Safe, ordered recovery plan", "destructive steps with 2 approvals", "< 100%", core=False,
       approver="isso", tools=("propose_step",)),
    _a("post-action-verifier", "Verify that a fix really worked", "maria.secops", ["assets:read"],
       "No unverified fix counted as done", "verified fixes", "< 100% of closed", core=False, tools=("verify",)),
    _a("exposure-validator", "Propose safe validation probes for findings", "maria.secops", ["assets:read"],
       "Only proven exposures reach the queue", "unproven findings dropped", "n/a", core=False,
       heartbeat_hours=50.0, tools=("propose_probe",)),
    _a("safety-reviewer", "Review each probe for safety and scope before it runs", "maria.secops",
       ["probes:review"], "No unsafe probe runs", "unsafe probes run", "> 0", core=False, tools=("review_probe",)),
    _a("ai-exposure", "Discover AI tools, libraries and unsafe AI settings", "dana.ai", ["proxy:read", "mdm:read"],
       "Every AI tool registered", "unregistered AI tools", "> 0 for 14 days", core=False, tools=("discover_ai",)),
    _a("pentest-triage", "Triage AI-assisted pentest output", "maria.secops", ["findings:write"],
       "No phantom findings", "phantom findings accepted", "> 0", core=False, provider="model-provider-b",
       tools=("triage_pentest",)),
]


def by_id(aid: str) -> Agent:
    for a in AGENTS:
        if a.id == aid:
            return a
    raise KeyError(aid)


def core() -> list[Agent]:
    return [a for a in AGENTS if a.core]


def agents_md() -> str:
    """The AGENTS.md scorecard: outcome, metric plus failure threshold, accountable human."""
    lines = ["# AGENTS.md scorecard (generated)", "",
             "| Agent | Outcome | Metric | Fails when | Accountable human | Autonomy |", "|---|---|---|---|---|---|"]
    for a in AGENTS:
        lines.append(f"| {a.id} | {a.outcome} | {a.metric} | {a.failure_threshold} | {a.owner} | {a.autonomy} |")
    return "\n".join(lines) + "\n"
