import pytest

from secprog import browser

EXT = {e["id"]: e for e in browser.score_extensions()}


@pytest.mark.parametrize("eid,score,rec", [("EXT-06", 75, "block"), ("EXT-03", 70, "block"), ("EXT-04", 50, "block"),
                                          ("EXT-07", 31, "review"), ("EXT-08", 15, "allow"), ("EXT-02", 11, "allow"),
                                          ("EXT-01", 6, "allow"), ("EXT-05", 6, "allow")])
def test_extension_scores(eid, score, rec):
    assert EXT[eid]["risk"] == score and EXT[eid]["recommendation"] == rec
    assert EXT[eid]["decided_by"] is None  # the agent only recommends


@pytest.mark.parametrize("perm,w", sorted(browser.PERMISSION_WEIGHTS.items()))
def test_permission_weight(perm, w):
    assert browser.risk([perm]) == w and browser.risk([perm], store_listed=False) == w + 20


def test_unknown_permission():
    with pytest.raises(ValueError):
        browser.risk(["nativeMessaging"])


@pytest.mark.parametrize("s,rec", [(0, "allow"), (19, "allow"), (20, "review"), (49, "review"), (50, "block")])
def test_thresholds(s, rec):
    assert browser.recommend(s) == rec


def test_sorted_by_risk():
    risks = [e["risk"] for e in browser.score_extensions()]
    assert risks == sorted(risks, reverse=True)


@pytest.mark.parametrize("who", ["agent:ext-risk", "agent:coordinator"])
def test_agent_cannot_decide(who):
    with pytest.raises(PermissionError):
        browser.ExtensionReview().decide("EXT-06", who, "block", "risky")


@pytest.mark.parametrize("decision,reason,exc", [("maybe", "r", ValueError), ("block", "", ValueError)])
def test_decision_validation(decision, reason, exc):
    with pytest.raises(exc):
        browser.ExtensionReview().decide("EXT-06", "omar.it", decision, reason)


def test_person_decides_and_logs():
    r = browser.ExtensionReview()
    row = r.decide("EXT-06", "omar.it", "block", "steals cookies")
    assert row["decided_by"] == "omar.it" and r.log.verify()[0]


ROWS = {r["device"]: r for r in browser.posture_summary()["rows"]}


@pytest.mark.parametrize("dev,prefix", [("D-001", "full"), ("D-002", "degraded"), ("BYOD-01", "degraded"),
                                        ("BYOD-02", "deny"), ("CTR-01", "full"), ("CTR-02", "deny")])
def test_posture_access(dev, prefix):
    assert ROWS[dev]["access"].startswith(prefix)


@pytest.mark.parametrize("dev", list(ROWS))
def test_non_full_is_only_a_recommendation(dev):
    a = ROWS[dev]["access"]
    assert a == "full" or a.endswith("(recommend)")


def test_posture_summary():
    s = browser.posture_summary()
    assert (s["sessions"], s["full"], s["degraded"], s["deny"]) == (6, 2, 2, 2) and s["managed_browser_pct"] == 66.7


@pytest.mark.parametrize("rule", list(browser.POSTURE_RULES))
def test_each_rule_can_fail(rule):
    good = dict(browser.SESSIONS[0])
    key = {"os_supported": "os_version_ok", "browser_current": "browser_version_ok", "not_rooted": "rooted",
           "disk_encrypted": "encrypted", "screen_lock": "screen_lock", "managed_browser_enrolled": "managed_browser"}[rule]
    good[key] = not good[key]
    assert browser.posture(good)["failed"] == [rule]


@pytest.mark.parametrize("content", ["card 4111 1111 1111 1111", "hello", ""])
def test_event_never_stores_content(content):
    e = browser.browser_event("user01", "ai-writer", "paste", "block", content)
    assert content not in [v for k, v in e.items() if k != "verdict"] or content == ""
    assert set(e) == {"user", "app", "action", "verdict", "content_sha256"} and len(e["content_sha256"]) == 64


def test_infostealer_scenario():
    s = browser.infostealer_scenario()
    assert s["time_to_revoke_min"] == 9 and s["time_to_block_min"] == 67 and s["log_ok"]
    assert set(s["approvals"].values()) == {"approved"} and "simulated" in s["basis"]
    actors = [t[1] for t in s["timeline"] if "approv" in t[2] and not t[2].startswith("proposed")]
    assert actors and not any(a.startswith("agent:") for a in actors)


def test_browser_kpis():
    k = browser.kpis()
    assert (k["extensions"], k["high_risk_extensions"], k["high_risk_pct"]) == (8, 3, 37.5)
    assert (k["unmanaged_device_sessions"], k["degraded_access_recommended"], k["deny_recommended"]) == (4, 2, 2)
