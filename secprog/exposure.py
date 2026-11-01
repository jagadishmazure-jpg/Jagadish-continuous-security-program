"""Exposure score stack.

asset criticality 1-10 from rules (data class, internet exposure, crown-jewel tag, kind) with a human override
that always wins and is logged; asset exposure 0-1000 = criticality x worst open finding risk; business-unit and
organisation scores 0-1000 (criticality-weighted mean) with a 90-day synthetic trend. The formula is published
here on purpose: a reviewer can recompute every number.
"""
from __future__ import annotations

from . import data
from .core import HashLog, is_agent

DATA_W = {"public": 0, "internal": 1, "financial": 3, "pii": 3}
KIND_W = {"identity_store": 3, "db": 2, "ai_workload": 1, "api": 1, "bucket": 1, "web": 1, "host": 0,
          "endpoint": 0}
SEV_RISK = {"critical": 1.0, "high": 0.75, "medium": 0.45, "low": 0.2, "info": 0.05}

OVERRIDES: dict[str, dict] = {}
OVERRIDE_LOG = HashLog()


def _asset(aid: str) -> dict:
    for a in data.assets():
        if a["id"] == aid:
            return a
    raise KeyError(aid)


def rule_criticality(a: dict) -> int:
    v = 2 + DATA_W[a["data_class"]] + KIND_W[a["kind"]] + (2 if a["internet_facing"] else 0) + (
        2 if a["crown_jewel"] else 0)
    return max(1, min(10, v))


def override(aid: str, value: int, by: str, reason: str, overrides: dict | None = None,
             log: HashLog | None = None) -> dict:
    overrides = OVERRIDES if overrides is None else overrides
    log = OVERRIDE_LOG if log is None else log
    if is_agent(by):
        raise PermissionError("only a person can override criticality")
    if not 1 <= value <= 10:
        raise ValueError("criticality is 1-10")
    if not reason:
        raise ValueError("an override needs a reason")
    _asset(aid)
    overrides[aid] = {"value": value, "by": by, "reason": reason}
    log.append(by, "criticality_override", asset=aid, value=value, reason=reason)
    return overrides[aid]


def criticality(aid: str, overrides: dict | None = None) -> dict:
    overrides = OVERRIDES if overrides is None else overrides
    rule = rule_criticality(_asset(aid))
    if aid in overrides:
        return {"value": overrides[aid]["value"], "rule": rule, "source": "override", "by": overrides[aid]["by"]}
    return {"value": rule, "rule": rule, "source": "rules", "by": None}


def asset_exposure(aid: str, findings: list | None = None, overrides: dict | None = None) -> int:
    from .findings import all_findings
    fs = all_findings() if findings is None else findings
    risks = [SEV_RISK[f.severity] for f in fs if f.asset == aid and f.status == "open"]
    worst = max(risks, default=0.0)
    return round(criticality(aid, overrides)["value"] * 100 * worst)


def scores(findings: list | None = None, overrides: dict | None = None) -> dict:
    from .findings import all_findings
    fs = all_findings() if findings is None else findings
    rows = []
    for a in data.assets():
        rows.append({"asset": a["id"], "name": a["name"], "bu": a["bu"],
                     "criticality": criticality(a["id"], overrides)["value"],
                     "exposure": asset_exposure(a["id"], fs, overrides)})

    def wmean(rs: list[dict]) -> int:
        w = sum(r["criticality"] for r in rs)
        return round(sum(r["exposure"] * r["criticality"] for r in rs) / w) if w else 0

    bus = {bu: wmean([r for r in rows if r["bu"] == bu]) for bu in data.BUSINESS_UNITS}
    return {"assets": rows, "business_units": bus, "org": wmean(rows)}


def trend(days: int = 90) -> list[tuple[str, int]]:
    """Synthetic 90-day org score history ending at today's measured score (fixes slowly lower it)."""
    today = scores()["org"]
    out = []
    for i in range(days, -1, -1):
        drift = round(i * 0.8)
        out.append((data.day(-i), today + drift))
    return out


def trend_deltas() -> dict:
    t = trend()
    now = t[-1][1]
    return {f"{d}d": now - t[-1 - d][1] for d in (7, 30, 90)}


def top_contributors() -> list[tuple[str, int]]:
    rows = scores()["assets"]
    bus = {}
    for r in rows:
        bus[r["bu"]] = bus.get(r["bu"], 0) + r["exposure"]
    return sorted(bus.items(), key=lambda x: -x[1])
