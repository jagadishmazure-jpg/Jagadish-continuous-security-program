import pytest

from secprog import core
from secprog.core import ApprovalError, ApprovalInbox, Evidence, HashLog, Identity, Tool


def test_hashlog_verifies():
    log = HashLog()
    for i in range(5):
        log.append("alice", "step", n=i)
    assert log.verify() == (True, None)


@pytest.mark.parametrize("field,value", [("actor", "mallory"), ("action", "other"), ("details", {"n": 99})])
def test_hashlog_detects_tamper(field, value):
    log = HashLog()
    for i in range(3):
        log.append("alice", "step", n=i)
    log.entries[1][field] = value
    ok, at = log.verify()
    assert not ok and at == 1


def test_hashlog_detects_deletion():
    log = HashLog()
    for i in range(3):
        log.append("alice", "step", n=i)
    del log.entries[1]
    assert log.verify()[0] is False


def test_hashlog_by_actor():
    log = HashLog()
    log.append("a", "x")
    log.append("b", "y")
    log.append("a", "z")
    assert len(log.by_actor("a")) == 2


@pytest.mark.parametrize("who,expected", [("agent:x", True), ("alice", False), ("agentx", False), ("", False)])
def test_is_agent(who, expected):
    assert core.is_agent(who) is expected


def test_sha_is_stable_and_order_independent_for_dicts():
    assert core.sha({"a": 1, "b": 2}) == core.sha({"b": 2, "a": 1})
    assert len(core.sha("x")) == 64


def _inbox():
    return ApprovalInbox()


def test_single_approval_for_non_destructive():
    ib = _inbox()
    r = ib.request("open_ticket", "agent:x", "t")
    ib.approve(r.id, "alice", "secops_lead")
    assert ib.is_approved(r.id)


def test_destructive_needs_two_people():
    ib = _inbox()
    r = ib.request("delete", "agent:x", "t", destructive=True)
    ib.approve(r.id, "alice", "secops_lead")
    assert not ib.is_approved(r.id)
    ib.approve(r.id, "bob", "ciso")
    assert ib.is_approved(r.id)


def test_same_person_cannot_approve_twice():
    ib = _inbox()
    r = ib.request("delete", "agent:x", "t", destructive=True)
    ib.approve(r.id, "alice", "secops_lead")
    with pytest.raises(ApprovalError):
        ib.approve(r.id, "alice", "ciso")


@pytest.mark.parametrize("approver", ["agent:coordinator", "agent:x", "agent:copilot"])
def test_agents_cannot_approve(approver):
    ib = _inbox()
    r = ib.request("t", "agent:y", "t")
    with pytest.raises(ApprovalError):
        ib.approve(r.id, approver, "ciso")


@pytest.mark.parametrize("role", ["intern", "agent", "", "admin", "root"])
def test_unknown_roles_cannot_approve(role):
    ib = _inbox()
    r = ib.request("t", "agent:y", "t")
    with pytest.raises(ApprovalError):
        ib.approve(r.id, "alice", role)


@pytest.mark.parametrize("role", sorted(core.HUMAN_ROLES))
def test_every_human_role_can_approve(role):
    ib = _inbox()
    r = ib.request("t", "agent:y", "t")
    ib.approve(r.id, "alice", role)
    assert ib.is_approved(r.id)


def test_requester_cannot_self_approve():
    ib = _inbox()
    r = ib.request("t", "alice", "t")
    with pytest.raises(ApprovalError):
        ib.approve(r.id, "alice", "ciso")


def test_reject_needs_reason():
    ib = _inbox()
    r = ib.request("t", "agent:y", "t")
    with pytest.raises(ApprovalError):
        ib.reject(r.id, "alice", "")
    ib.reject(r.id, "alice", "duplicate")
    assert r.status == "rejected"


def test_cannot_approve_after_reject():
    ib = _inbox()
    r = ib.request("t", "agent:y", "t")
    ib.reject(r.id, "alice", "no")
    with pytest.raises(ApprovalError):
        ib.approve(r.id, "bob", "ciso")


def test_agents_cannot_reject():
    ib = _inbox()
    r = ib.request("t", "agent:y", "t")
    with pytest.raises(ApprovalError):
        ib.reject(r.id, "agent:z", "because")


def test_pending_list():
    ib = _inbox()
    a = ib.request("t", "agent:y", "t")
    ib.request("t", "agent:y", "u")
    ib.approve(a.id, "alice", "ciso")
    assert len(ib.pending()) == 1


def test_inbox_log_chain_ok():
    ib = _inbox()
    r = ib.request("t", "agent:y", "t")
    ib.approve(r.id, "alice", "ciso")
    assert ib.log.verify()[0]


@pytest.mark.parametrize("secs,flag", [([], False), ([5, 6, 7], True), ([60, 90], False), ([5, 60], False),
                                       ([5, 5, 60], True), ([14.9, 15, 16], False)])
def test_rubber_stamp(secs, flag):
    assert core.rubber_stamp(secs) is flag


@pytest.mark.parametrize("kind", sorted(core.EVIDENCE_KINDS))
def test_evidence_kinds_accepted(kind):
    e = Evidence("src", kind, "t", {"a": 1}, ("CC1.1",))
    assert e.evidence_id.startswith("EV-") and len(e.evidence_id) == 15
    assert e.to_dict()["content_sha256"] == e.content_sha256


def test_evidence_rejects_unknown_kind():
    with pytest.raises(ValueError):
        Evidence("src", "blob", "t", {}, ("CC1.1",))


def test_evidence_needs_control():
    with pytest.raises(ValueError):
        Evidence("src", "document", "t", {}, ())


def test_evidence_id_changes_with_content():
    a = Evidence("s", "document", "t", {"x": 1}, ("C",))
    b = Evidence("s", "document", "t", {"x": 2}, ("C",))
    assert a.evidence_id != b.evidence_id


@pytest.mark.parametrize("agent,person,tenant", [("x", "alice", "t"), ("agent:x", "agent:y", "t"),
                                                 ("agent:x", "", "t"), ("agent:x", "alice", "")])
def test_identity_validation(agent, person, tenant):
    with pytest.raises(ValueError):
        Identity(agent, person, tenant)


def _ident():
    return Identity("agent:x", "alice", "brightwater")


def test_harness_blocks_irreversible_without_approval():
    h = core.Harness()
    rec = h.call(_ident(), Tool("delete_user", reversible=False), {"u": 1}, ["policy"])
    assert rec.decision.startswith("blocked")


def test_harness_allows_irreversible_with_approval():
    h = core.Harness()
    r = h.inbox.request("delete_user", "agent:x", "u1", destructive=True)
    h.inbox.approve(r.id, "alice", "ciso")
    h.inbox.approve(r.id, "bob", "secops_lead")
    rec = h.call(_ident(), Tool("delete_user", reversible=False), {"u": 1}, ["policy"], request_id=r.id)
    assert not rec.decision.startswith("blocked")


def test_harness_reversible_write_is_suggested():
    h = core.Harness()
    rec = h.call(_ident(), Tool("open_ticket", reversible=True), {"t": 1}, ["c"])
    assert rec.decision == "suggested"
    assert rec.complete


def test_harness_read():
    h = core.Harness()
    rec = h.call(_ident(), Tool("read", reversible=True, writes=False), {"t": 1}, ["c"])
    assert rec.decision == "read"


def test_decision_record_incomplete_without_citations():
    h = core.Harness()
    rec = h.call(_ident(), Tool("read", reversible=True, writes=False), {"t": 1}, [])
    assert not rec.complete
