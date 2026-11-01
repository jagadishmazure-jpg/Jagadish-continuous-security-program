"""Shared building blocks: hash-chained log, approval inbox, typed evidence, agent identity and decision records.

The evidence record uses the same fields as the companion compliance repo (evidence_id, source, kind,
control_hints, content_sha256, collected_at) so files can be read by either tool. There is no code dependency.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field

from . import TODAY

HUMAN_ROLES = {"ciso", "vciso", "isso", "secops_lead", "engineer", "it_admin", "procurement", "legal", "sme",
               "cro", "board", "privacy_officer", "ai_governance_lead", "trust_lead", "client_owner", "auditor",
               "identity_lead", "soc_lead", "manager", "it_lead"}


def sha(obj) -> str:
    data = obj if isinstance(obj, str) else json.dumps(obj, sort_keys=True, default=str)
    return hashlib.sha256(data.encode()).hexdigest()


def is_agent(actor: str) -> bool:
    return actor.startswith("agent:")


class HashLog:
    """Append-only log; each entry stores the hash of the previous entry, so any edit breaks the chain."""

    GENESIS = "0" * 64

    def __init__(self) -> None:
        self.entries: list[dict] = []

    def append(self, actor: str, action: str, **details) -> dict:
        prev = self.entries[-1]["hash"] if self.entries else self.GENESIS
        body = {"seq": len(self.entries), "actor": actor, "action": action, "details": details, "prev": prev}
        entry = {**body, "hash": sha(body)}
        self.entries.append(entry)
        return entry

    def verify(self) -> tuple[bool, int | None]:
        prev = self.GENESIS
        for i, e in enumerate(self.entries):
            body = {k: e[k] for k in ("seq", "actor", "action", "details", "prev")}
            if e["prev"] != prev or sha(body) != e["hash"] or e["seq"] != i:
                return False, i
            prev = e["hash"]
        return True, None

    def by_actor(self, actor: str) -> list[dict]:
        return [e for e in self.entries if e["actor"] == actor]


class ApprovalError(Exception):
    pass


@dataclass
class Request:
    id: str
    action: str
    requested_by: str
    target: str
    destructive: bool = False
    reversible: bool = True
    status: str = "pending"
    approvals: list[str] = field(default_factory=list)
    rejected_by: str | None = None
    reason: str = ""
    review_seconds: list[float] = field(default_factory=list)

    @property
    def needed(self) -> int:
        return 2 if self.destructive else 1


class ApprovalInbox:
    """Every risky action waits here. Only named humans approve; destructive actions need two different people."""

    def __init__(self, log: HashLog | None = None) -> None:
        self.log = log or HashLog()
        self.items: dict[str, Request] = {}

    def request(self, action: str, requested_by: str, target: str, destructive: bool = False,
                reversible: bool = True) -> Request:
        rid = f"REQ-{len(self.items) + 1:04d}"
        r = Request(rid, action, requested_by, target, destructive, reversible)
        self.items[rid] = r
        self.log.append(requested_by, "request", id=rid, requested_action=action, target=target, destructive=destructive)
        return r

    def approve(self, rid: str, approver: str, role: str, review_seconds: float = 60.0) -> Request:
        r = self.items[rid]
        if r.status != "pending":
            raise ApprovalError(f"{rid} is {r.status}")
        if is_agent(approver):
            raise ApprovalError("agents cannot approve")
        if role not in HUMAN_ROLES:
            raise ApprovalError(f"role {role!r} cannot approve")
        if approver == r.requested_by:
            raise ApprovalError("requester cannot approve their own request")
        if approver in r.approvals:
            raise ApprovalError("the same person cannot approve twice")
        r.approvals.append(approver)
        r.review_seconds.append(review_seconds)
        if len(r.approvals) >= r.needed:
            r.status = "approved"
        self.log.append(approver, "approve", id=rid, role=role, review_seconds=review_seconds)
        return r

    def reject(self, rid: str, approver: str, reason: str) -> Request:
        r = self.items[rid]
        if is_agent(approver):
            raise ApprovalError("agents cannot reject on behalf of people")
        if not reason:
            raise ApprovalError("a rejection needs a reason")
        r.status, r.rejected_by, r.reason = "rejected", approver, reason
        self.log.append(approver, "reject", id=rid, reason=reason)
        return r

    def pending(self) -> list[Request]:
        return [r for r in self.items.values() if r.status == "pending"]

    def is_approved(self, rid: str) -> bool:
        return rid in self.items and self.items[rid].status == "approved"


RUBBER_STAMP_SECONDS = 15


def rubber_stamp(review_seconds: list[float], threshold: float = RUBBER_STAMP_SECONDS, share: float = 0.5) -> bool:
    """Flag an approver when more than `share` of their approvals took under `threshold` seconds."""
    if not review_seconds:
        return False
    fast = sum(s < threshold for s in review_seconds)
    return fast / len(review_seconds) > share


EVIDENCE_KINDS = {"scan_result", "config_snapshot", "device_posture", "access_review", "test_result",
                  "approval_record", "document", "verified_fix", "questionnaire_answer", "vendor_assessment",
                  "drill_record", "training_record"}


@dataclass(frozen=True)
class Evidence:
    """Typed evidence (harness rule: no free-form blobs). Same field names as the companion compliance repo."""

    source: str
    kind: str
    title: str
    content: dict
    control_hints: tuple[str, ...]
    collected_at: str = TODAY
    produced_by: str = "system"

    def __post_init__(self) -> None:
        if self.kind not in EVIDENCE_KINDS:
            raise ValueError(f"unknown evidence kind {self.kind!r}")
        if not self.control_hints:
            raise ValueError("evidence must name at least one control")

    @property
    def content_sha256(self) -> str:
        return sha(self.content)

    @property
    def evidence_id(self) -> str:
        return "EV-" + sha([self.source, self.kind, self.title, self.content_sha256])[:12]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["control_hints"] = list(self.control_hints)
        d.update(evidence_id=self.evidence_id, content_sha256=self.content_sha256)
        return d


@dataclass(frozen=True)
class Identity:
    """Three-axis identity for every agent action: which agent, for which person, in which tenant."""

    agent: str
    on_behalf_of: str
    tenant: str

    def __post_init__(self) -> None:
        if not self.agent.startswith("agent:"):
            raise ValueError("agent ids start with 'agent:'")
        if not self.on_behalf_of or is_agent(self.on_behalf_of):
            raise ValueError("on_behalf_of must be a person")
        if not self.tenant:
            raise ValueError("tenant is required")


@dataclass(frozen=True)
class Tool:
    name: str
    reversible: bool
    writes: bool = True


@dataclass
class DecisionRecord:
    identity: Identity
    tool: str
    inputs: dict
    decision: str
    citations: list[str]
    model: str = "deterministic-rules-v1"
    approver: str | None = None
    label: str = "deterministic"  # or "reasoning" when a model produced the step

    @property
    def complete(self) -> bool:
        return bool(self.inputs) and bool(self.citations) and bool(self.model) and (
            self.approver is not None or self.decision in {"suggested", "read"})


class Harness:
    """Runs tools for agents. Irreversible tools always need an approved request; every call leaves a record."""

    def __init__(self, inbox: ApprovalInbox | None = None) -> None:
        self.inbox = inbox or ApprovalInbox()
        self.records: list[DecisionRecord] = []

    def call(self, ident: Identity, tool: Tool, inputs: dict, citations: list[str], request_id: str | None = None,
             label: str = "deterministic") -> DecisionRecord:
        approver = None
        if tool.writes and not tool.reversible:
            if not request_id or not self.inbox.is_approved(request_id):
                rec = DecisionRecord(ident, tool.name, inputs, "blocked: irreversible tool needs approval", citations,
                                     label=label)
                self.records.append(rec)
                self.inbox.log.append(ident.agent, "blocked", tool=tool.name, tenant=ident.tenant)
                return rec
            approver = self.inbox.items[request_id].approvals[-1]
        decision = "executed (simulated)" if tool.writes else "read"
        rec = DecisionRecord(ident, tool.name, inputs, decision, citations, approver=approver, label=label)
        if tool.writes and tool.reversible and approver is None:
            rec.decision = "suggested"
        self.records.append(rec)
        self.inbox.log.append(ident.agent, "tool", tool=tool.name, decision=rec.decision, tenant=ident.tenant,
                              on_behalf_of=ident.on_behalf_of)
        return rec
