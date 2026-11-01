import json

import pytest

from secprog import cve_rank, data, findings
from secprog.findings import Finding

ALL = findings.all_findings()
CVES = data.cves()


def test_all_findings_count():
    assert len(ALL) == 73


@pytest.mark.parametrize("f", ALL, ids=lambda f: f.fingerprint)
def test_finding_valid(f):
    assert f.severity in findings.SEVERITIES
    assert f.sources and f.fingerprint and len(f.fingerprint) == 16


def test_fingerprints_unique_after_dedupe():
    assert len({f.fingerprint for f in ALL}) == len(ALL)


def test_dedupe_merges_sources_and_keeps_worst():
    a = Finding("sarif", "A-001", "r1", "t", "medium", "x.py:1")
    b = Finding("dast", "A-001", "r1", "t", "high", "x.py:1")
    out = findings.dedupe([a, b])
    assert len(out) == 1 and out[0].severity == "high" and out[0].sources == ["dast", "sarif"]


def test_dedupe_keeps_distinct():
    a = Finding("sarif", "A-001", "r1", "t", "medium", "x.py:1")
    b = Finding("sarif", "A-001", "r1", "t", "medium", "x.py:2")
    assert len(findings.dedupe([a, b])) == 2


@pytest.mark.parametrize("sev", ["urgent", "", "CRITICAL", "none"])
def test_bad_severity(sev):
    with pytest.raises(ValueError):
        Finding("s", "A", "r", "t", sev)


def test_sarif_import():
    fs = findings.import_sarif(findings.sample_sarif())
    assert fs and all(f.source == "code" for f in fs)


def test_secrets_import_redacted():
    fs = findings.import_secrets(findings.sample_secrets())
    assert fs and all(f.severity in ("critical", "high") for f in fs)


def test_secrets_import_rejects_raw_secret():
    raw = json.loads(findings.sample_secrets())
    raw[0]["Secret"] = "AKIA-not-redacted"
    with pytest.raises(ValueError):
        findings.import_secrets(json.dumps(raw))


def test_zap_import_maps_owasp():
    fs = findings.import_zap(findings.sample_zap())
    assert fs and all("owasp" in f.extra for f in fs)


def test_dependency_import_one_per_cve():
    assert len(findings.import_dependencies()) == len(CVES)


def test_pentest_status():
    s = findings.pentest_status()
    assert s["retest_coverage_pct"] == 75.0 and s["total"] == 4


def test_findings_evidence():
    e = findings.as_evidence(ALL)
    assert "RA-5" in e.control_hints


# ----- CVE ranking -----

EV = cve_rank.evaluate()


def test_v2_beats_baselines():
    assert EV["threat_v2"]["coverage_pct"] > EV["epss_only"]["coverage_pct"] > EV["cvss_only"]["coverage_pct"]
    assert EV["threat_v2"]["efficiency_pct"] >= EV["kev_epss_v1"]["efficiency_pct"]


@pytest.mark.parametrize("method", ["threat_v2", "epss_only", "cvss_only", "kev_epss_v1"])
def test_same_workload(method):
    assert EV[method]["workload_pct"] == 20.0 and EV[method]["k"] == 12


def test_evaluation_note_is_honest():
    assert "synthetic" in EV["note"] and "not a real-world" in EV["note"]


@pytest.mark.parametrize("k", [1, 5, 12, 20, 60])
def test_metrics_bounds(k):
    m = cve_rank.metrics(cve_rank.rank_v2(), k)
    assert 0 <= m["coverage_pct"] <= 100 and 0 <= m["efficiency_pct"] <= 100


@pytest.mark.parametrize("c", CVES, ids=lambda c: c["id"])
def test_every_cve_explainable(c):
    e = cve_rank.explain(c["id"])
    assert e["id"] == c["id"] if "id" in e else True
    assert 0 <= cve_rank.threat(c) <= 1
    assert cve_rank.reason(c)


def test_rank_v2_sorted():
    r = cve_rank.rank_v2()
    assert [x["score"] for x in r] == sorted((x["score"] for x in r), reverse=True)


def test_kev_cves_rank_high():
    top = {x["id"] for x in cve_rank.rank_v2()[:20]}
    kev = {c["id"] for c in CVES if c["kev"]}
    assert len(kev & top) >= 4


def test_rank_cvss_sorted():
    r = cve_rank.rank_cvss()
    assert r[0]["cvss"] == max(c["cvss"] for c in CVES)
