"""Device and MDM posture checks, Defender-style AV exclusions, exposed listening ports and plaintext credentials.

Results become device-posture evidence (B11) for SOC 2 CC6.8 and NIST CM-6/SI-3.
"""
from __future__ import annotations

from . import data
from .core import Evidence

PATCH_MAX_DAYS = 30
CHECKIN_MAX_DAYS = 7
RISKY_PORTS = {445, 3389, 5900, 22}
RISKY_EXCLUSION_HINTS = ("\\Users\\Public", "*.ps1", "\\Temp", "*.exe")

CHECKS = {
    "disk_encrypted": lambda d: d["encrypted"],
    "edr_running": lambda d: d["edr"],
    "firewall_on": lambda d: d["firewall"],
    "screen_lock": lambda d: d["screen_lock"],
    "patched_30d": lambda d: d["patch_age_days"] <= PATCH_MAX_DAYS,
    "checked_in_7d": lambda d: d["last_checkin_days"] <= CHECKIN_MAX_DAYS,
    "av_healthy": lambda d: d["av_healthy"],
    "no_risky_av_exclusions": lambda d: not risky_exclusions(d),
    "no_risky_open_ports": lambda d: not (set(d["open_ports"]) & RISKY_PORTS),
    "no_plaintext_credentials": lambda d: not d["plaintext_creds"],
}


def risky_exclusions(d: dict) -> list[str]:
    return [x for x in d["av_exclusions"] if any(h in x for h in RISKY_EXCLUSION_HINTS)]


def evaluate(devs: list[dict] | None = None) -> list[dict]:
    devs = data.devices() if devs is None else devs
    out = []
    for d in devs:
        res = {k: bool(f(d)) for k, f in CHECKS.items()}
        out.append({"device": d["id"], "owner": d["owner"], "os": d["os"], "checks": res,
                    "compliant": all(res.values()), "failed": [k for k, v in res.items() if not v]})
    return out


def summary(devs: list[dict] | None = None) -> dict:
    rows = evaluate(devs)
    n = len(rows)
    by_check = {k: round(100 * sum(r["checks"][k] for r in rows) / n, 1) for k in CHECKS}
    by_os = {}
    for os_ in ("windows", "macos", "linux"):
        rs = [r for r in rows if r["os"] == os_]
        by_os[os_] = round(100 * sum(r["checks"]["edr_running"] for r in rs) / len(rs), 1) if rs else 0.0
    return {"devices": n, "compliant": sum(r["compliant"] for r in rows),
            "compliant_pct": round(100 * sum(r["compliant"] for r in rows) / n, 1), "pass_pct_by_check": by_check,
            "edr_coverage_by_os": by_os,
            "risky_exclusions": sum(not r["checks"]["no_risky_av_exclusions"] for r in rows),
            "exposed_ports": sum(not r["checks"]["no_risky_open_ports"] for r in rows),
            "plaintext_creds": sum(not r["checks"]["no_plaintext_credentials"] for r in rows),
            "stale_agents": sum(not r["checks"]["checked_in_7d"] for r in rows)}


def as_evidence() -> Evidence:
    s = summary()
    return Evidence("mdm", "device_posture", "Device posture snapshot", s, ("CC6.8", "CM-6", "SI-3"),
                    produced_by="agent:device-posture")
