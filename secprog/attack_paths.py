"""Attack path graph with choke points, and toxic-combination rules.

Nodes: internet, assets, vulnerabilities, identities, roles and data stores. Edges are labelled with an
ATT&CK technique id. A choke point is an edge whose removal cuts the most simple paths from the internet to a
crown jewel ("fix X closes N paths").
"""
from __future__ import annotations

from . import data

EDGES = [
    ("internet", "loan-portal", "T1190", "exploit public-facing app (SQLi)"),
    ("internet", "pay-gateway", "T1190", "IDOR on charge lookup"),
    ("internet", "support-bot", "T1190", "prompt injection reaches file tool"),
    ("internet", "marketing-site", "T1190", "outdated CMS plugin"),
    ("marketing-site", "web-svc", "T1078", "reused service credential"),
    ("loan-portal", "app-identity", "T1552", "credentials in config file"),
    ("pay-gateway", "app-identity", "T1552", "token in environment"),
    ("support-bot", "bot-identity", "T1078", "over-privileged managed identity"),
    ("bot-identity", "kyc-bucket", "T1530", "read access to KYC bucket"),
    ("app-identity", "ledger-db", "T1078", "db owner role"),
    ("app-identity", "dc01", "T1558", "kerberoastable service account"),
    ("web-svc", "dc01", "T1558", "kerberoastable service account"),
    ("dc01", "ledger-db", "T1003", "domain admin to any host"),
    ("dc01", "kyc-bucket", "T1098", "admin can grant bucket access"),
    ("loan-portal", "kyc-bucket", "T1530", "direct bucket read from app"),
]
CROWN = ("ledger-db", "kyc-bucket")  # crown-jewel data stores (both tagged crown_jewel in the asset list)


def graph(edges=None) -> dict[str, list[str]]:
    g: dict[str, list[str]] = {}
    for s, d, _, _ in edges or EDGES:
        g.setdefault(s, []).append(d)
    return g


def paths(edges=None, src: str = "internet", targets=CROWN, max_len: int = 6) -> list[list[str]]:
    g = graph(edges)
    out = []

    def walk(node: str, seen: list[str]) -> None:
        if node in targets and len(seen) > 1:
            out.append(seen)
            return
        if len(seen) > max_len:
            return
        for n in g.get(node, []):
            if n not in seen:
                walk(n, seen + [n])

    walk(src, [src])
    return out


def choke_points(top: int = 5) -> list[dict]:
    base = paths()
    out = []
    for e in EDGES:
        rest = [x for x in EDGES if x != e]
        closed = len(base) - len(paths(rest))
        if closed:
            out.append({"edge": f"{e[0]} -> {e[1]}", "technique": e[2], "why": e[3], "closes_paths": closed,
                        "of": len(base)})
    return sorted(out, key=lambda r: (-r["closes_paths"], r["edge"]))[:top]


# ---------- toxic combinations ----------

def _ctx():
    from .findings import all_findings
    fs = all_findings()
    by_asset: dict[str, list] = {}
    for f in fs:
        if f.status == "open":
            by_asset.setdefault(f.asset, []).append(f)
    cves = {c["id"]: c for c in data.cves()}
    return {a["id"]: {**a, "findings": by_asset.get(a["id"], []),
                      "kev": any(cves.get(f.cve or "", {}).get("kev") for f in by_asset.get(a["id"], []))}
            for a in data.assets()}


ADMIN_ASSETS = {"A-001", "A-005"}  # assets with an admin identity attached (synthetic)
OVERPRIV_AI = {"A-007"}


def _r(rule_id, title, pred):
    return {"id": rule_id, "title": title, "pred": pred}


RULES = [
    _r("TOX-01", "Internet-facing + known-exploited CVE + admin identity",
       lambda a: a["internet_facing"] and a["kev"] and a["id"] in ADMIN_ASSETS),
    _r("TOX-02", "Internet-facing + known-exploited CVE", lambda a: a["internet_facing"] and a["kev"]),
    _r("TOX-03", "Bucket or DB with PII/financial data + any high finding",
       lambda a: a["kind"] in ("bucket", "db") and a["data_class"] in ("pii", "financial")
       and any(f.severity in ("critical", "high") for f in a["findings"])),
    _r("TOX-04", "AI workload + over-privileged identity + exposed endpoint",
       lambda a: a["kind"] == "ai_workload" and a["id"] in OVERPRIV_AI and a["internet_facing"]),
    _r("TOX-05", "Crown jewel with a critical finding",
       lambda a: a["crown_jewel"] and any(f.severity == "critical" for f in a["findings"])),
    _r("TOX-06", "Sitting duck: internet-facing, no owner, open findings",
       lambda a: a["internet_facing"] and not a["owner"] and a["findings"]),
    _r("TOX-07", "Identity store with a high finding",
       lambda a: a["kind"] == "identity_store" and any(f.severity in ("critical", "high") for f in a["findings"])),
    _r("TOX-08", "Secret exposed on an internet-facing asset",
       lambda a: a["internet_facing"] and any(f.source == "secrets" for f in a["findings"])),
    _r("TOX-09", "Injection flaw on an asset holding PII",
       lambda a: a["data_class"] == "pii" and any("inject" in f.title.lower() or "sql" in f.rule
                                                   for f in a["findings"])),
    _r("TOX-10", "Three or more high/critical findings on one internet-facing asset",
       lambda a: a["internet_facing"] and sum(f.severity in ("critical", "high") for f in a["findings"]) >= 3),
]


def toxic() -> list[dict]:
    ctx = _ctx()
    hits = []
    for rule in RULES:
        for a in ctx.values():
            if rule["pred"](a):
                hits.append({"rule": rule["id"], "title": rule["title"], "asset": a["id"], "name": a["name"],
                             "linked_findings": len(a["findings"])})
    return hits


def toxic_counts() -> dict[str, int]:
    out = {r["id"]: 0 for r in RULES}
    for h in toxic():
        out[h["rule"]] += 1
    return out
