import pytest

from secprog import data, knowledge, questionnaire, trust_center
from secprog.questionnaire import KBQueue, Questionnaire
from secprog.trust_center import TrustCenter

Q, M = questionnaire.run_demo()


def test_questionnaire_metrics():
    assert M["questions"] == 21 and M["drafted_by_agent"] == 15 and M["routed_to_sme"] == 6
    assert M["approved_as_drafted"] == 13 and M["edited"] == 1 and M["rejected_drafts"] == 1
    assert M["accuracy_pct"] == 86.7 and M["sign_off"] == "ready to return (not sent)"


@pytest.mark.parametrize("a", Q.answers, ids=lambda a: a.qid)
def test_every_final_answer_cited_and_reviewed(a):
    assert a.state in ("approved", "edited")
    assert a.citations and a.text and a.reviewer and not a.reviewer.startswith("agent:")


@pytest.mark.parametrize("qid,q,truth", questionnaire.QUESTIONS, ids=lambda x: x if isinstance(x, str) else "")
def test_match_is_deterministic(qid, q, truth):
    assert questionnaire.match(q) == questionnaire.match(q)


def test_trap_question_rejected_in_demo():
    log_decisions = [e["details"].get("decision") for e in Q.log.entries if e["action"] == "review"]
    assert "reject" in log_decisions


def _fresh():
    q = Questionnaire("test")
    q.draft()
    return q


def test_draft_routes_low_confidence():
    q = _fresh()
    assert sum(a.state == "sme_queue" for a in q.answers) == 6


@pytest.mark.parametrize("decision", ["approve", "edit", "reject"])
def test_agent_cannot_review(decision):
    with pytest.raises(PermissionError):
        _fresh().review("Q01", decision, "agent:questionnaire", "x")


def test_edit_needs_text():
    with pytest.raises(ValueError):
        _fresh().review("Q01", "edit", "tess")


def test_bad_review_decision():
    with pytest.raises(ValueError):
        _fresh().review("Q01", "maybe", "tess")


def test_unknown_question():
    with pytest.raises(KeyError):
        _fresh().review("Q99", "approve", "tess")


def test_sme_rules():
    q = _fresh()
    with pytest.raises(PermissionError):
        q.sme_answer("Q13", "x", "src", "agent:q")
    with pytest.raises(ValueError):
        q.sme_answer("Q13", "x", "", "sme")


def test_sign_off_blocked_until_ready():
    q = _fresh()
    with pytest.raises(ValueError):
        q.sign_off("tess", "trust_lead")


@pytest.mark.parametrize("by,role", [("agent:q", "ciso"), ("tess", "sales"), ("tess", "secops_lead")])
def test_sign_off_roles(by, role):
    with pytest.raises(PermissionError):
        Q.sign_off(by, role)


def test_tick_reminders():
    q = _fresh()
    assert q.tick(1) == []
    assert len(q.tick(1)) == 6


def test_kb_queue():
    k = KBQueue()
    item = k.submit("KB-100", "q", "Kestrel Community Bank asked this", "sme.a")
    assert item["scrubbed"] and "[customer]" in item["answer"]
    with pytest.raises(PermissionError):
        k.approve("KB-100", "sme.a")
    with pytest.raises(PermissionError):
        k.approve("KB-100", "agent:q")
    assert k.approve("KB-100", "sme.b")["approved_by"] == "sme.b"


def test_kb_hygiene():
    assert questionnaire.duplicates() == [] and questionnaire.conflicts() == []
    sc = questionnaire.spot_check()
    assert sc["stale"] == ["KB-009", "KB-010", "KB-012", "KB-015"] and len(sc["sampled"]) == 5


def test_duplicates_and_conflicts_detected():
    kb = {"K1": ("What is your RTO for core?", "8 hours."), "K2": ("What is your RTO for core?", "12 hours.")}
    assert questionnaire.duplicates(kb) and questionnaire.conflicts(kb)


@pytest.mark.parametrize("kid", sorted(knowledge.KB))
def test_kb_entries_cite_real_pages(kid):
    _, ans, cites, updated, owner = knowledge.KB[kid]
    assert ans and cites and owner.startswith("sme.")
    for d, p in cites:
        assert knowledge.cite(d, p).startswith(f"{d} p.{p}")


@pytest.mark.parametrize("question,found", [
    ("How often do you run penetration tests?", True), ("Are backups immutable and restore tested?", True),
    ("What colour is the office carpet?", False)])
def test_long_doc_answers(question, found):
    r = knowledge.answer_long_doc(question)
    assert (r["status"] == "found") is found
    assert bool(r["citations"]) is found


@pytest.mark.parametrize("word", ["the", "do", "you", "which", "every"])
def test_stopwords_removed(word):
    assert word not in knowledge.tokens(f"{word} encryption")


# ----- Trust Center -----

@pytest.mark.parametrize("req,decision,rule", [
    ({"doc_level": "public"}, "approve", "R0"),
    ({"email": "a@freemail.example", "doc_level": "gated"}, "deny", "R1"),
    ({"email": "a@x.example", "doc_level": "gated", "competitor": True}, "deny", "R2"),
    ({"email": "a@x.example", "doc_level": "gated", "nda_on_file": True, "crm_stage": "opportunity"}, "approve", "R3"),
    ({"email": "a@x.example", "doc_level": "gated", "crm_stage": "customer"}, "approve", "R4"),
    ({"email": "a@x.example", "doc_level": "gated", "crm_stage": "lead"}, "review", "R9"),
    ({"email": "a@x.example", "doc_level": "gated", "nda_on_file": True, "crm_stage": "lead"}, "review", "R9")])
def test_nda_rules(req, decision, rule):
    d = trust_center.nda_decision(req)
    assert d["decision"] == decision and d["rule"].startswith(rule) and d["version"] == "2026.10-r3"


@pytest.mark.parametrize("r", trust_center.ACCESS_REQUESTS, ids=lambda r: r["id"])
def test_nda_pure(r):
    assert trust_center.nda_decision(dict(r)) == trust_center.nda_decision(dict(r))


def test_publish_is_human_only():
    tc = TrustCenter()
    tc.draft("X", "t", "b")
    with pytest.raises(PermissionError):
        tc.publish("X", "agent:trust-center")
    assert tc.publish("X", "tess").status == "published"


def test_search_hides_drafts_and_gated():
    tc = TrustCenter()
    tc.draft("P", "encryption policy", "AES")
    tc.draft("G", "encryption report", "gated details", level="gated")
    tc.draft("D", "encryption draft", "unpublished")
    tc.publish("P", "tess")
    tc.publish("G", "tess")
    assert tc.search("encryption") == ["P"]
    assert tc.search("encryption", "gated") == ["G", "P"]


def test_sync_from_evidence_drafts_only():
    from secprog import devices
    tc = TrustCenter()
    assert tc.sync_from_evidence([devices.as_evidence()]) == 1
    assert all(i.status == "draft" for i in tc.items.values())
    assert tc.sync_from_evidence([devices.as_evidence()]) == 0


def test_playbook():
    r = trust_center.run_playbook()
    assert r["kev_cves"] == 6 and r["emails_sent"] == 0 and r["median_hours_to_first_update"] == 4.0


@pytest.mark.parametrize("c", [c for c in data.cves() if c["kev"]], ids=lambda c: c["id"])
@pytest.mark.parametrize("affected", [True, False])
def test_vuln_update_template(c, affected):
    u = trust_center.vuln_update(c, affected, 2)
    assert tuple(u["update"]) == trust_center.TEMPLATE_FIELDS and u["sent"] is False


def test_analytics_simulated():
    a = trust_center.analytics()
    assert "SIMULATED" in a["basis"] and a["auto_decided_pct"] == 85.7
    r = trust_center.trust_to_revenue()
    assert r["pipeline_influenced"] == 515000 and "SIMULATED" in r["basis"]


def test_render_html_escapes_and_has_vdp():
    tc = TrustCenter()
    tc.draft("X", "<script>alert(1)</script>", "b")
    tc.publish("X", "tess")
    html = trust_center.render_html(tc)
    assert "<script>" not in html and "security@" in html and "How we use AI" in html


@pytest.mark.parametrize("f", trust_center.AI_FEATURES, ids=lambda f: f["feature"])
def test_ai_features_disclosed(f):
    assert f["model_provider"] and f["trains_on_customer_data"] is False and f["human_in_loop"]


def test_how_we_use_ai_sections():
    assert len(trust_center.HOW_WE_USE_AI) == 6
