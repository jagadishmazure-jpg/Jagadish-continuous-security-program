"""Deterministic synthetic estate for Brightwater Ledger (a fictional payments and lending company).

No real systems, people or vendors. Every random draw uses the fixed seed, so every number in the docs
can be reproduced exactly.
"""
from __future__ import annotations

import random
from datetime import date, timedelta

from . import DOMAIN, SEED, TODAY

BUSINESS_UNITS = ("payments", "lending", "platform", "corporate")
D0 = date.fromisoformat(TODAY)


def day(offset: int) -> str:
    return (D0 + timedelta(days=offset)).isoformat()


def _rng(salt: str) -> random.Random:
    return random.Random(f"{SEED}-{salt}")


KINDS = ("web", "api", "host", "db", "bucket", "ai_workload", "endpoint", "identity_store")
DATA_CLASSES = ("public", "internal", "financial", "pii")


def assets() -> list[dict]:
    r = _rng("assets")
    out = []
    fixed = [
        ("pay-gateway", "payments", "api", True, "financial", True),
        ("ledger-db", "payments", "db", False, "financial", True),
        ("loan-portal", "lending", "web", True, "pii", True),
        ("kyc-bucket", "lending", "bucket", False, "pii", True),
        ("dc01", "platform", "identity_store", False, "internal", True),
        ("fraud-model", "platform", "ai_workload", True, "financial", False),
        ("support-bot", "corporate", "ai_workload", True, "pii", False),
        ("marketing-site", "corporate", "web", True, "public", False),
    ]
    for i, (name, bu, kind, net, dc, crown) in enumerate(fixed, 1):
        out.append({"id": f"A-{i:03d}", "name": name, "bu": bu, "kind": kind, "internet_facing": net,
                    "data_class": dc, "crown_jewel": crown, "owner": f"owner-{bu}"})
    for i in range(len(fixed) + 1, 41):
        bu = BUSINESS_UNITS[i % 4]
        kind = KINDS[r.randrange(len(KINDS))]
        out.append({"id": f"A-{i:03d}", "name": f"{bu}-{kind}-{i:02d}", "bu": bu, "kind": kind,
                    "internet_facing": r.random() < 0.3, "data_class": DATA_CLASSES[r.randrange(4)],
                    "crown_jewel": False, "owner": f"owner-{bu}" if r.random() < 0.9 else ""})
    return out


MATURITY = ("none", "poc", "functional", "weaponized")


def cves() -> list[dict]:
    """60 synthetic CVEs. `exploited_later` is the evaluation label.

    Honest caveat: the label is drawn from the same kind of threat signals the ranker uses (plus noise), so
    the evaluation is a regression check of the ranking logic, not proof of real-world accuracy.
    """
    r = _rng("cves")
    asset_ids = [a["id"] for a in assets()]
    out = []
    for i in range(1, 61):
        cvss = round(r.uniform(3.0, 10.0), 1)
        epss = round(min(0.97, r.betavariate(0.6, 6)), 3)
        mat = MATURITY[min(3, int(r.random() ** 1.8 * 4))]
        kev = mat == "weaponized" and r.random() < 0.7
        news = r.randrange(0, 6) if mat in ("functional", "weaponized") else r.randrange(0, 2)
        targeted = r.random() < 0.2
        reachable = r.random() < 0.55
        p = 0.02 + 0.5 * kev + 0.25 * (mat == "functional") + 0.4 * epss + 0.1 * targeted + 0.08 * reachable
        exploited = r.random() < min(0.95, p)
        out.append({"id": f"CVE-SYN-2026-{i:04d}", "cvss": cvss, "epss": epss, "kev": kev, "maturity": mat,
                    "news": news, "industry_targeted": targeted, "reachable": reachable,
                    "asset": asset_ids[r.randrange(len(asset_ids))], "package": f"pkg-{i % 17:02d}",
                    "exploited_later": exploited})
    return out


def devices() -> list[dict]:
    r = _rng("devices")
    oses = ("windows", "macos", "linux")
    out = []
    for i in range(1, 31):
        os_ = oses[i % 3]
        out.append({
            "id": f"D-{i:03d}", "owner": f"user{i:02d}@{DOMAIN}", "os": os_,
            "encrypted": r.random() > 0.1, "edr": r.random() > 0.12, "firewall": r.random() > 0.08,
            "screen_lock": r.random() > 0.1, "patch_age_days": r.randrange(0, 60),
            "last_checkin_days": r.choice([0, 0, 0, 1, 2, 9]),
            "av_healthy": os_ != "windows" or r.random() > 0.1,
            "av_exclusions": (["C:\\Users\\Public\\*"] if os_ == "windows" and r.random() < 0.2 else [])
            + (["*.ps1"] if os_ == "windows" and r.random() < 0.1 else []),
            "open_ports": sorted(r.sample([22, 80, 443, 445, 3389, 5900, 8080], r.randrange(0, 3))),
            "plaintext_creds": r.random() < 0.07,
        })
    return out


ROLES = ("viewer", "analyst", "engineer", "admin", "payments_approver")


def accounts() -> list[dict]:
    r = _rng("accounts")
    out = []
    for i in range(1, 26):
        role = ROLES[r.randrange(len(ROLES))]
        out.append({"id": f"U-{i:03d}", "email": f"user{i:02d}@{DOMAIN}", "role": role,
                    "dept": BUSINESS_UNITS[i % 4], "active": True, "terminated": r.random() < 0.08,
                    "last_login_days": r.choice([0, 1, 3, 7, 30, 95, 120]), "manager": f"mgr{(i % 4) + 1}",
                    "mfa": r.random() > 0.1, "phishing_resistant": role == "admin" and r.random() > 0.4,
                    "entitlements": sorted({role, *r.sample(ROLES, r.randrange(0, 2))})})
    out.append({"id": "U-099", "email": f"svc-legacy@{DOMAIN}", "role": "admin", "dept": "platform", "active": True,
                "terminated": False, "last_login_days": 200, "manager": "", "mfa": False,
                "phishing_resistant": False, "entitlements": ["admin"]})
    return out


VENDORS = (
    ("V-01", "Northwind Payroll Cloud", "high", "pii", True),
    ("V-02", "Larkspur Card Processing", "critical", "financial", False),
    ("V-03", "Copperline Model Hosting", "high", "pii", True),
    ("V-04", "Tidewater Backup Vault", "critical", "financial", False),
    ("V-05", "Quillfeather Docs", "medium", "internal", True),
    ("V-06", "Ashgrove Analytics", "medium", "internal", True),
    ("V-07", "Harborview Help Desk", "medium", "pii", True),
    ("V-08", "Pinecrest Email Security", "high", "internal", False),
    ("V-09", "Silverbrook KYC", "critical", "pii", True),
    ("V-10", "Meadowlark Swag Store", "low", "public", False),
)


def vendors() -> list[dict]:
    r = _rng("vendors")
    out = []
    for vid, name, tier, data, ai in VENDORS:
        out.append({"id": vid, "name": name, "tier": tier, "data": data, "ai_features": ai,
                    "ai_provider": ("model-provider-a" if r.random() < 0.6 else "model-provider-b") if ai else None,
                    "last_assessed": day(-r.randrange(30, 500)), "soc2": r.random() > 0.25,
                    "immutable_backups": vid == "V-04" or r.random() > 0.5, "rto_hours": r.choice([4, 8, 24, 72])})
    return out


CLIENTS = (
    ("C-01", "Brightwater Ledger", "fintech", "advanced"),
    ("C-02", "Kestrel Community Bank", "bank", "regulated"),
    ("C-03", "Fernhill Credit Union", "credit_union", "regulated"),
    ("C-04", "Oakmere Legal LLP", "legal", "advanced"),
    ("C-05", "Redwing Precision Parts", "manufacturing", "essential"),
    ("C-06", "Lumen Ridge Clinic", "healthcare", "advanced"),
    ("C-07", "Saltmarsh Wealth Advisors", "ria", "regulated"),
    ("C-08", "Briar Lane Nonprofit", "nonprofit", "essential"),
)


def clients() -> list[dict]:
    r = _rng("clients")
    out = []
    for cid, name, vertical, tier in CLIENTS:
        out.append({"id": cid, "name": name, "vertical": vertical, "tier": tier,
                    "readiness_pct": round(r.uniform(48, 92), 1), "open_critical": r.randrange(0, 6),
                    "sla_breaches": r.randrange(0, 4), "tickets": r.randrange(12, 60),
                    "secret_canary": f"canary-{cid}-{r.randrange(10**6):06d}"})
    return out
