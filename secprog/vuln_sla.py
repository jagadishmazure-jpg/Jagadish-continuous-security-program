"""Vulnerability SLA tests: due dates by severity and asset criticality, pass/fail per finding, MTTR."""
from __future__ import annotations

from datetime import date

from . import TODAY

SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180, "info": 365}
CROWN_FACTOR = 0.5  # crown-jewel / criticality >= 8 assets get half the time


def due_days(severity: str, criticality: int) -> int:
    d = SLA_DAYS[severity]
    return max(1, round(d * CROWN_FACTOR)) if criticality >= 8 else d


def age(detected: str, today: str = TODAY) -> int:
    return (date.fromisoformat(today) - date.fromisoformat(detected)).days


def evaluate(fs: list | None = None, today: str = TODAY) -> list[dict]:
    from .exposure import criticality
    from .findings import all_findings
    fs = all_findings() if fs is None else fs
    out = []
    for f in fs:
        if f.status != "open":
            continue
        crit = criticality(f.asset)["value"]
        due = due_days(f.severity, crit)
        a = age(f.detected, today)
        out.append({"fingerprint": f.fingerprint, "asset": f.asset, "severity": f.severity, "criticality": crit,
                    "age": a, "due_days": due, "passed": a <= due, "days_over": max(0, a - due)})
    return out


# Synthetic closed-ticket history: (severity, hours from detection to verified fix)
HISTORY = [("critical", 30), ("critical", 70), ("critical", 190), ("high", 120), ("high", 400), ("high", 260),
           ("high", 900), ("medium", 700), ("medium", 1500), ("medium", 2600), ("low", 2000), ("low", 4100)]


def _pct(xs: list[float], p: float) -> float:
    xs = sorted(xs)
    k = (len(xs) - 1) * p
    lo = int(k)
    hi = min(lo + 1, len(xs) - 1)
    return round(xs[lo] + (xs[hi] - xs[lo]) * (k - lo), 1)


def mttr() -> dict:
    out = {}
    for sev in ("critical", "high", "medium", "low"):
        xs = [h for s, h in HISTORY if s == sev]
        out[sev] = {"median_h": _pct(xs, 0.5), "p90_h": _pct(xs, 0.9), "n": len(xs),
                    "within_sla_pct": round(100 * sum(h <= SLA_DAYS[sev] * 24 for h in xs) / len(xs), 1)}
    return out


def summary() -> dict:
    rows = evaluate()
    by_sev = {}
    for s in SLA_DAYS:
        rs = [r for r in rows if r["severity"] == s]
        if rs:
            by_sev[s] = {"open": len(rs), "breached": sum(not r["passed"] for r in rs)}
    return {"open": len(rows), "passing": sum(r["passed"] for r in rows),
            "adherence_pct": round(100 * sum(r["passed"] for r in rows) / len(rows), 1) if rows else 100.0,
            "by_severity": by_sev}
