import re

import pytest

from secprog import DOMAIN, ORG, data

ASSETS = data.assets()
CVES = data.cves()
DEVICES = data.devices()
ACCOUNTS = data.accounts()
VENDORS = data.vendors()
CLIENTS = data.clients()


def test_org_is_fictional():
    assert ORG == "Brightwater Ledger" and DOMAIN.endswith(".example")


def test_data_is_deterministic():
    assert data.assets() == ASSETS and data.cves() == CVES and data.devices() == DEVICES


def test_counts():
    assert (len(ASSETS), len(CVES), len(DEVICES), len(ACCOUNTS), len(VENDORS), len(CLIENTS)) == (40, 60, 30, 26, 10, 8)


@pytest.mark.parametrize("a", ASSETS, ids=lambda a: a["id"])
def test_asset_shape(a):
    assert re.fullmatch(r"A-\d{3}", a["id"])
    assert a["bu"] in data.BUSINESS_UNITS
    assert a["kind"] in data.KINDS
    assert a["data_class"] in data.DATA_CLASSES
    assert isinstance(a["owner"], str)


def test_some_assets_have_no_owner_on_purpose():
    assert 1 <= sum(not a["owner"] for a in ASSETS) <= 8


@pytest.mark.parametrize("c", CVES, ids=lambda c: c["id"])
def test_cve_shape(c):
    assert c["id"].startswith("CVE-SYN-2026-")
    assert 0 <= c["cvss"] <= 10 and 0 <= c["epss"] <= 1
    assert c["maturity"] in data.MATURITY
    assert c["asset"] in {a["id"] for a in ASSETS}


def test_cve_labels():
    assert sum(c["exploited_later"] for c in CVES) == 19
    assert sum(c["kev"] for c in CVES) == 6


@pytest.mark.parametrize("d", DEVICES, ids=lambda d: d["id"])
def test_device_shape(d):
    assert d["os"] in ("windows", "macos", "linux")
    assert isinstance(d["open_ports"], list)


@pytest.mark.parametrize("a", ACCOUNTS, ids=lambda a: a["id"])
def test_account_shape(a):
    assert a["email"].endswith("@" + DOMAIN)
    assert a["role"] in data.ROLES


@pytest.mark.parametrize("v", VENDORS, ids=lambda v: v["id"])
def test_vendor_shape(v):
    assert v["tier"] in ("critical", "high", "medium", "low")
    assert (v["ai_provider"] is None) == (not v["ai_features"])


@pytest.mark.parametrize("c", CLIENTS, ids=lambda c: c["id"])
def test_client_shape(c):
    assert c["tier"] in ("essential", "advanced", "regulated")
    assert c["secret_canary"].startswith(f"canary-{c['id']}-")
    assert 0 < c["readiness_pct"] < 100


def test_day_offsets():
    assert data.day(0) == "2026-10-31" and data.day(-1) == "2026-10-30"
