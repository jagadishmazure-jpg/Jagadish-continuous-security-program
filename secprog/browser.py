"""Managed-browser controls (synthetic): extension risk scoring, managed-browser posture with degraded access,
and an infostealer -> session-theft scenario.

* Extension risk comes from manifest permissions. The agent recommends allow / review / block; the device or app
  owner signs off. Nothing is blocked by the agent.
* A device that fails posture is not hard-blocked: the recommendation is "degraded access" (governed browser only,
  no download, no paste), which a person approves.
* Monitoring logs metadata and policy verdicts only (who, app, action, verdict, content hash), never raw content.
"""
from __future__ import annotations

from .core import ApprovalInbox, HashLog, is_agent, sha

PERMISSION_WEIGHTS = {"<all_urls>": 30, "cookies": 25, "clipboardRead": 20, "webRequest": 15, "downloads": 10,
                      "tabs": 5, "storage": 1}
BLOCK_AT, REVIEW_AT = 50, 20

EXTENSIONS = [  # synthetic inventory: (id, name, permissions, users, store_listed)
    ("EXT-01", "Ledger Password Helper", ["storage", "tabs"], 41, True),
    ("EXT-02", "PDF Quick Viewer", ["downloads", "storage"], 18, True),
    ("EXT-03", "Coupon Finder Plus", ["<all_urls>", "cookies", "webRequest"], 3, True),
    ("EXT-04", "AI Writing Buddy", ["<all_urls>", "clipboardRead"], 9, True),
    ("EXT-05", "Tab Organizer", ["tabs", "storage"], 22, True),
    ("EXT-06", "Session Sync (sideloaded)", ["<all_urls>", "cookies"], 1, False),
    ("EXT-07", "Grammar Checker Lite", ["<all_urls>", "storage"], 30, True),
    ("EXT-08", "Screen Recorder", ["tabs", "downloads"], 4, True),
]


def risk(perms: list[str], store_listed: bool = True) -> int:
    unknown = [p for p in perms if p not in PERMISSION_WEIGHTS]
    if unknown:
        raise ValueError(f"unknown permission(s): {unknown}")
    return sum(PERMISSION_WEIGHTS[p] for p in perms) + (0 if store_listed else 20)


def recommend(score: int) -> str:
    return "block" if score >= BLOCK_AT else "review" if score >= REVIEW_AT else "allow"


def score_extensions(exts: list | None = None) -> list[dict]:
    exts = EXTENSIONS if exts is None else exts
    out = []
    for eid, name, perms, users, listed in exts:
        s = risk(perms, listed)
        out.append({"id": eid, "name": name, "risk": s, "users": users, "recommendation": recommend(s),
                    "decided_by": None})
    return sorted(out, key=lambda e: (-e["risk"], e["id"]))


class ExtensionReview:
    """The agent's recommendation is a proposal; an owner decides each extension."""

    def __init__(self) -> None:
        self.rows = {e["id"]: e for e in score_extensions()}
        self.log = HashLog()

    def decide(self, eid: str, who: str, decision: str, reason: str) -> dict:
        if is_agent(who):
            raise PermissionError("extension decisions are made by people")
        if decision not in ("allow", "block", "force_install"):
            raise ValueError("allow, block or force_install")
        if not reason:
            raise ValueError("record the reason")
        row = self.rows[eid]
        row.update(decided_by=who, decision=decision)
        self.log.append(who, "extension_decision", id=eid, decision=decision, reason=reason)
        return row


# ---------- managed-browser posture ----------

POSTURE_RULES = {
    "os_supported": lambda d: d["os_version_ok"],
    "browser_current": lambda d: d["browser_version_ok"],
    "not_rooted": lambda d: not d["rooted"],
    "disk_encrypted": lambda d: d["encrypted"],
    "screen_lock": lambda d: d["screen_lock"],
    "managed_browser_enrolled": lambda d: d["managed_browser"],
}

SESSIONS = [  # synthetic: one row per device used to reach internal web apps
    {"device": "D-001", "managed": True, "os_version_ok": True, "browser_version_ok": True, "rooted": False,
     "encrypted": True, "screen_lock": True, "managed_browser": True},
    {"device": "D-002", "managed": True, "os_version_ok": True, "browser_version_ok": False, "rooted": False,
     "encrypted": True, "screen_lock": True, "managed_browser": True},
    {"device": "BYOD-01", "managed": False, "os_version_ok": True, "browser_version_ok": True, "rooted": False,
     "encrypted": False, "screen_lock": True, "managed_browser": True},
    {"device": "BYOD-02", "managed": False, "os_version_ok": False, "browser_version_ok": True, "rooted": True,
     "encrypted": False, "screen_lock": False, "managed_browser": False},
    {"device": "CTR-01", "managed": False, "os_version_ok": True, "browser_version_ok": True, "rooted": False,
     "encrypted": True, "screen_lock": True, "managed_browser": True},
    {"device": "CTR-02", "managed": False, "os_version_ok": True, "browser_version_ok": True, "rooted": False,
     "encrypted": True, "screen_lock": True, "managed_browser": False},
]


def posture(session: dict) -> dict:
    failed = [k for k, f in POSTURE_RULES.items() if not f(session)]
    if not failed:
        access = "full"
    elif "not_rooted" in failed or "managed_browser_enrolled" in failed:
        access = "deny (recommend)"
    else:
        access = "degraded: governed browser only, no download, no paste (recommend)"
    return {"device": session["device"], "failed": failed, "access": access}


def posture_summary(sessions: list | None = None) -> dict:
    rows = [posture(s) for s in (SESSIONS if sessions is None else sessions)]
    n = len(rows)
    return {"sessions": n, "full": sum(r["access"] == "full" for r in rows),
            "degraded": sum(r["access"].startswith("degraded") for r in rows),
            "deny": sum(r["access"].startswith("deny") for r in rows),
            "managed_browser_pct": round(100 * sum(s["managed_browser"] for s in SESSIONS) / n, 1),
            "rows": rows}


# ---------- metadata-only event log ----------

def browser_event(user: str, app: str, action: str, verdict: str, content: str) -> dict:
    """What is kept: who, app, action, verdict and a content hash. The content itself is never stored."""
    return {"user": user, "app": app, "action": action, "verdict": verdict, "content_sha256": sha(content)}


# ---------- infostealer scenario ----------

def infostealer_scenario() -> dict:
    """Malicious extension -> stolen session cookie -> impossible-travel sign-in -> revoke sessions (approved)
    -> extension blocked org-wide (approved). Simulated; nothing is revoked or blocked for real."""
    inbox = ApprovalInbox()
    timeline = [
        ("T+0m", "agent:ext-risk", ("EXT-06 'Session Sync (sideloaded)' installed; risk "
                                    f"{risk(['<all_urls>', 'cookies'], False)} (cookies + all sites + not store listed)")),
        ("T+42m", "agent:soc-triage", ("sign-in for user07 from a second country 9 minutes after a local sign-in "
                                       "(impossible travel) with the same session cookie")),
    ]
    r1 = inbox.request("revoke_sessions", "agent:soc-triage", "user07", destructive=False)
    timeline.append(("T+44m", "agent:soc-triage", f"proposed revoke_sessions for user07 ({r1.id})"))
    inbox.approve(r1.id, "lee.soc", "soc_lead", review_seconds=95)
    timeline.append(("T+51m", "lee.soc", "approved session revocation (simulated)"))
    r2 = inbox.request("block_extension", "agent:ext-risk", "EXT-06 org-wide", destructive=True)
    timeline.append(("T+53m", "agent:ext-risk", f"proposed org-wide block of EXT-06 ({r2.id}); needs two people"))
    inbox.approve(r2.id, "lee.soc", "soc_lead", review_seconds=120)
    inbox.approve(r2.id, "omar.it", "it_admin", review_seconds=80)
    timeline.append(("T+67m", "omar.it", "second approval; EXT-06 blocked org-wide (simulated)"))
    return {"timeline": timeline, "time_to_revoke_min": 51 - 42, "time_to_block_min": 67 - 0,
            "approvals": {r1.id: r1.status, r2.id: r2.status}, "log_ok": inbox.log.verify()[0],
            "basis": "simulated scenario on synthetic telemetry"}


def kpis() -> dict:
    ext = score_extensions()
    p = posture_summary()
    return {"extensions": len(ext), "high_risk_extensions": sum(e["recommendation"] == "block" for e in ext),
            "high_risk_pct": round(100 * sum(e["recommendation"] == "block" for e in ext) / len(ext), 1),
            "sessions_on_managed_browser_pct": p["managed_browser_pct"],
            "unmanaged_device_sessions": sum(not s["managed"] for s in SESSIONS),
            "degraded_access_recommended": p["degraded"], "deny_recommended": p["deny"],
            "basis": "synthetic browser telemetry"}
