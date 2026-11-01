"""Dependency CVE ranking.

v1: EPSS and KEV only. v2 (threat-informed): priority = impact x threat, where threat combines KEV, EPSS,
exploit maturity, news mentions, industry targeting and reachability, and impact comes from asset criticality.
Every rank carries a one-line reason. The evaluation compares v2 with CVSS-only and EPSS-only baselines on a
synthetic labelled set (regression check, not a real-world accuracy claim).
"""
from __future__ import annotations

from . import data
from .exposure import criticality

MATURITY_W = {"none": 0.0, "poc": 0.25, "functional": 0.6, "weaponized": 1.0}
TOP_K = 12  # how many CVEs the team can fix this sprint


def rank_v1(cves: list[dict] | None = None) -> list[dict]:
    cves = cves if cves is not None else data.cves()
    scored = [{**c, "score": round((1.0 if c["kev"] else 0.0) + c["epss"], 3)} for c in cves]
    return sorted(scored, key=lambda c: (-c["score"], c["id"]))


def threat(c: dict) -> float:
    t = (0.35 * c["kev"] + 0.25 * c["epss"] / 0.97 + 0.2 * MATURITY_W[c["maturity"]]
         + 0.05 * min(c["news"], 5) / 5 + 0.05 * c["industry_targeted"] + 0.1 * c["reachable"])
    return round(t, 4)


def reason(c: dict) -> str:
    parts = []
    if c["kev"]:
        parts.append("on the known-exploited list")
    if c["epss"] >= 0.1:
        parts.append(f"EPSS {c['epss']:.2f}")
    if c["maturity"] in ("functional", "weaponized"):
        parts.append(f"{c['maturity']} exploit")
    if c["reachable"]:
        parts.append("reachable code path")
    if c["industry_targeted"]:
        parts.append("targets our industry")
    crit = criticality(c["asset"])["value"]
    parts.append(f"asset criticality {crit}")
    return ", ".join(parts)


def rank_v2(cves: list[dict] | None = None) -> list[dict]:
    cves = cves if cves is not None else data.cves()
    out = []
    for c in cves:
        impact = criticality(c["asset"])["value"] / 10
        out.append({**c, "threat": threat(c), "impact": impact,
                    "score": round(100 * threat(c) * (0.5 + 0.5 * impact), 2), "reason": reason(c)})
    return sorted(out, key=lambda c: (-c["score"], c["id"]))


def rank_cvss(cves: list[dict] | None = None) -> list[dict]:
    cves = cves if cves is not None else data.cves()
    return sorted(cves, key=lambda c: (-c["cvss"], c["id"]))


def rank_epss(cves: list[dict] | None = None) -> list[dict]:
    cves = cves if cves is not None else data.cves()
    return sorted(cves, key=lambda c: (-c["epss"], c["id"]))


def metrics(ranked: list[dict], k: int = TOP_K) -> dict:
    """coverage = exploited CVEs in the top k / all exploited; efficiency = exploited in top k / k."""
    top = ranked[:k]
    exploited = sum(c["exploited_later"] for c in ranked)
    hit = sum(c["exploited_later"] for c in top)
    return {"k": k, "coverage_pct": round(100 * hit / exploited, 1) if exploited else 0.0,
            "efficiency_pct": round(100 * hit / k, 1), "workload_pct": round(100 * k / len(ranked), 1),
            "exploited_total": exploited, "hits": hit}


def evaluate(k: int = TOP_K) -> dict:
    cves = data.cves()
    cvss_high = [c for c in cves if c["cvss"] >= 7.0]
    return {"threat_v2": metrics(rank_v2(cves), k), "epss_only": metrics(rank_epss(cves), k),
            "cvss_only": metrics(rank_cvss(cves), k), "kev_epss_v1": metrics(rank_v1(cves), k),
            "cvss_7_plus_workload": len(cvss_high), "n": len(cves),
            "note": "synthetic labels; regression check, not a real-world accuracy claim"}


def explain(cve_id: str) -> dict:
    ranked = rank_v2()
    for i, c in enumerate(ranked, 1):
        if c["id"] == cve_id:
            return {"id": cve_id, "rank": i, "of": len(ranked), "score": c["score"], "reason": c["reason"]}
    raise KeyError(cve_id)
