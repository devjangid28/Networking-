"""Target Intelligence Bundle: endpoint auth, scope handling, bundle shape,
confirmed-vs-inferred counts, applicable guardrails and validation-history
isolation across demo / scan / agent model windows."""
import time
import uuid

import pytest
from starlette.testclient import TestClient

from main import app

TEST_ADMIN_PASS = "admin-test-pass-2026"

BUNDLE_KEYS = {"target", "status", "scope", "identity", "discovery_detail",
               "confirmed_vs_inferred", "applicable_guardrails",
               "validation_history", "suggested_actions"}


@pytest.fixture(scope="module")
def session():
    with TestClient(app, raise_server_exceptions=False) as cli:
        r = cli.post("/api/login", json={"username": "admin", "password": TEST_ADMIN_PASS})
        assert r.status_code == 200
        yield cli


@pytest.fixture(scope="module")
def anon():
    with TestClient(app, raise_server_exceptions=False) as cli:
        yield cli


@pytest.fixture(scope="module")
def account(session):
    """Fresh org + agent report pointing its model window at 192.168.50.0/24."""
    stamp = f"{int(time.time() * 1000) % 1000000}-{uuid.uuid4().hex[:4]}"
    org = session.post("/api/orgs", json={"name": f"TestOrg-Intel-{stamp}"}).json()["org"]
    payload = {
        "scan": {"target": "192.168.50.1", "network": "192.168.50.0/24", "devices": [
            {"ip": "192.168.50.1", "hostname": "gw", "is_target": True, "type_guess": "router", "vendor": "Acme", "services": []},
            {"ip": "192.168.50.10", "hostname": "web", "type_guess": "server", "vendor": "Acme",
             "services": [{"port": 80, "service": "http"}]},
        ], "notes": []},
        "config": {"192.168.50.1": {
            "filters": [{"name": "lan-in", "rules": [
                {"action": "permit", "src": "any", "dst": "any", "proto": "tcp", "dport": 443}]}],
            "routes": [{"network": "0.0.0.0/0", "next_hop": "203.0.113.1"}],
        }},
        "agent_version": "0.1.0", "consent": True,
    }
    r = session.post("/api/agent/report", json=payload,
                     headers={"X-NetProof-Key": org["api_key"]})
    assert r.status_code == 200 and r.json().get("ok")
    yield org["id"]
    # leave cleanup to the module teardown below via /api/orgs (no DELETE route uses TestOrg-)


# --------------------------------------------------------------------------- #
# demo mode                                                                    #
# --------------------------------------------------------------------------- #

def test_bundle_shape_and_status(anon):
    r = anon.get("/api/target/10.0.20.10/intelligence?mode=demo")
    assert r.status_code == 200
    b = r.json()
    assert set(b) == BUNDLE_KEYS
    assert b["status"] == "found"
    assert b["scope"]["mode"] == "demo"
    assert b["identity"]["ip"] == "10.0.20.10"
    assert b["identity"]["identity_source"] in ("scan", "snmp", "model", "none")
    assert isinstance(b["applicable_guardrails"], list)
    assert isinstance(b["validation_history"], list)
    assert isinstance(b["suggested_actions"], list)


def test_confirmed_vs_inferred_counts(anon):
    b = anon.get("/api/target/10.0.20.10/intelligence?mode=demo").json()
    c = b["confirmed_vs_inferred"]
    for grp in ("rules", "routes"):
        assert c[grp]["confirmed"] >= 0 and c[grp]["inferred"] >= 0
    assert "entries" in c


def test_not_in_scope_suggests_investigate(anon):
    b = anon.get("/api/target/192.168.200.99/intelligence?mode=demo").json()
    assert b["status"] == "not_in_scope"
    assert any(a["action"] == "investigate" for a in b["suggested_actions"])
    assert "validation_history" in b


def test_export_attachment_header(anon):
    r = anon.get("/api/target/10.0.20.10/intelligence/export?mode=demo")
    assert r.status_code == 200
    cd = r.headers.get("content-disposition", "")
    assert cd.startswith("attachment;") and "netproof-intel-10.0.20.10.json" in cd
    b = r.json()
    assert b["target"] == "10.0.20.10" and set(b) == BUNDLE_KEYS


# --------------------------------------------------------------------------- #
# scan mode                                                                    #
# --------------------------------------------------------------------------- #

def test_scan_mode_requires_session(anon):
    assert anon.get("/api/target/10.0.20.10/intelligence?mode=scan").status_code == 401


def test_scan_mode_with_no_scan_yet(session):
    # CI has no live scan; the guard order is session first, then scan presence.
    r = session.get("/api/target/10.0.20.10/intelligence?mode=scan")
    assert r.status_code in (200, 400)


# --------------------------------------------------------------------------- #
# agent mode                                                                   #
# --------------------------------------------------------------------------- #

def test_agent_mode_requires_session_or_org_scope(anon):
    assert anon.get("/api/target/192.168.50.10/intelligence?mode=agent").status_code == 401


def test_agent_bundle_scoped_to_report(account, session):
    url = f"/api/target/192.168.50.10/intelligence?mode=agent&org={account}"
    r = session.get(url)
    assert r.status_code == 200
    b = r.json()
    assert b["status"] == "found"
    assert b["identity"]["hostname"] == "web"
    assert b["identity"]["identity_source"] == "scan"
    svcs = {s["port"] for s in b["discovery_detail"]["services"]}
    assert 80 in svcs
    assert b["scope"]["subnet"] == "192.168.50.0/24"


def test_agent_guardrails_fire_on_default_route(account, session):
    b = session.get(f"/api/target/192.168.50.1/intelligence?mode=agent&org={account}").json()
    assert b["status"] == "found"
    assert len(b["applicable_guardrails"]) > 0
    reasons = {r["id"] for r in b["applicable_guardrails"]}
    assert any("default" in (r or "").lower() for r in reasons)


def test_agent_history_is_org_scoped(account, session):
    r = session.post("/api/validate", json={
        "change": {"type": "add_filter_rule", "filter": "router-lan-in",
                   "rule": {"action": "deny", "src": "192.168.50.10", "dst": "any",
                            "proto": "tcp", "dport": 8080}},
        "mode": "agent", "account": account,
    })
    assert r.status_code == 200
    b = session.get(f"/api/target/192.168.50.10/intelligence?mode=agent&org={account}").json()
    assert len(b["validation_history"]) >= 1
    assert all(v.get("org_id") == account for v in b["validation_history"])