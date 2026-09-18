"""End-to-end backward-compatibility + agent endpoint tests.

Migrated from the legacy ``test_new.py`` (46 checks) into real pytest tests so
the suite is CI-friendly: no bare print-based pass/fail, failures are attributed
to a named test.
"""
import time
import uuid

import pytest
from starlette.testclient import TestClient

import ratelimit
from engine import tenant as _tenant
from engine.validate import ALL_PRESETS
from main import app

TEST_ADMIN_PASS = "admin-test-pass-2026"


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
def accounts(session):
    """Create a fresh org + a second org, clean up prior TestOrg-* rows."""
    conn = _tenant._conn()
    for _r in conn.execute("SELECT id FROM orgs WHERE name LIKE 'TestOrg-%'").fetchall():
        conn.execute("DELETE FROM agent_reports WHERE org_id=?", (_r["id"],))
        conn.execute("DELETE FROM orgs WHERE id=?", (_r["id"],))
    conn.commit()

    stamp = f"{int(time.time() * 1000) % 1000000}-{uuid.uuid4().hex[:4]}"
    org = session.post("/api/orgs", json={"name": f"TestOrg-{stamp}"}).json()["org"]
    beta = session.post("/api/orgs", json={"name": f"TestOrg-Beta-{stamp}"}).json()["org"]
    yield {"org_id": org["id"], "org_key": org["api_key"], "beta_id": beta["id"],
           "dup_name": f"TestOrg-{stamp}"}

    conn = _tenant._conn()
    conn.execute("DELETE FROM agent_reports WHERE org_id IN (?,?)", (org["id"], beta["id"]))
    conn.execute("DELETE FROM orgs WHERE id IN (?,?)", (org["id"], beta["id"]))
    conn.commit()


# --------------------------------------------------------------------------- #
# Phase 0: dashboard session auth                                             #
# --------------------------------------------------------------------------- #

def test_orgs_401_without_session(anon):
    assert anon.get("/api/orgs").status_code == 401


def test_login_wrong_password_401(session):
    r = session.post("/api/login", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 401


def test_session_authenticated(session):
    r = session.get("/api/session")
    assert r.json().get("authenticated") is True


def test_orgs_200_with_session(session):
    assert session.get("/api/orgs").status_code == 200


# --------------------------------------------------------------------------- #
# Phases 1-5: backward compat                                                  #
# --------------------------------------------------------------------------- #

def test_all_presets_validate(session):
    for p in ALL_PRESETS:
        r = session.post("/api/validate", json={"change": p["change"]})
        assert r.status_code == 200, f"preset {p['id']} HTTP {r.status_code}"
        assert r.json()["summary"]["verdict"] is not None


def test_guardrail_vlan_4095_hard_block(session):
    r = session.post("/api/guardrails", json={
        "change": {"type": "add_vlan_assignment", "device": "switch", "iface": "Gi0/3",
                   "vlan_id": 4095, "name": "bad"},
        "mode": "demo",
    })
    assert r.json().get("hard_block")


def test_intent_bgp_parse(session):
    r = session.post("/api/intent", json={"text": "bgp 203.0.113.1 as 65000"})
    assert r.json().get("ok")
    assert r.json()["change"]["type"] == "add_bgp_peer"


def test_replay_deterministic_and_export(session):
    change = {"type": "add_filter_rule", "filter": "fw-inside-in",
              "rule": {"action": "permit", "src": "10.0.20.0/24", "dst": "any", "proto": "any"},
              "at_index": 0}
    r = session.post("/api/validate", json={"change": change})
    vid = r.json()["audit"]["verdict_id"]
    replay = session.post(f"/api/verdicts/{vid}/replay").json()
    assert replay.get("deterministic")
    assert session.get(f"/api/verdicts/{vid}/export").status_code == 200


def test_provenance_has_audit_id(session):
    change = {"type": "add_filter_rule", "filter": "fw-inside-in",
              "rule": {"action": "permit", "src": "10.0.20.0/24", "dst": "any", "proto": "any"},
              "at_index": 0}
    r = session.post("/api/validate", json={"change": change, "org": "test"})
    assert "audit" in r.json()


# --------------------------------------------------------------------------- #
# New: org + agent report endpoints                                           #
# --------------------------------------------------------------------------- #

SCAN_PAYLOAD = {
    "target": "192.168.50.1", "network": "192.168.50.0/24",
    "devices": [
        {"ip": "192.168.50.1", "hostname": "gw", "is_target": True, "type_guess": "router", "vendor": "Acme", "services": []},
        {"ip": "192.168.50.10", "hostname": "web", "type_guess": "server", "vendor": "Acme", "services": [{"port": 80, "service": "http"}]},
    ],
    "notes": [],
}
CONFIG_PAYLOAD = {
    "192.168.50.1": {
        "filters": [{"name": "router-lan-in", "rules": [
            {"action": "permit", "src": "any", "dst": "any", "proto": "tcp", "dport": 443},
            {"action": "permit", "src": "any", "dst": "any", "proto": "tcp", "dport": 80},
        ]}],
        "routes": [{"network": "0.0.0.0/0", "next_hop": "203.0.113.1"}],
    }
}


def test_create_org_returns_key(accounts):
    assert len(accounts["org_key"]) > 10


def test_duplicate_org_400(session, accounts):
    r = session.post("/api/orgs", json={"name": accounts["dup_name"]})
    assert r.status_code == 400


def test_list_orgs_has_ours(session, accounts):
    r = session.get("/api/orgs")
    assert len(r.json()["orgs"]) >= 2


def test_agent_report_no_auth_401(anon):
    r = anon.post("/api/agent/report", json={
        "scan": {"target": "1.2.3.4", "network": "1.2.3.0/24",
                 "devices": [{"ip": "1.2.3.1", "is_target": True, "type_guess": "router", "hostname": "r", "services": []}]},
        "consent": True,
    })
    assert r.status_code == 401


def test_agent_report_and_network(session, accounts):
    r = session.post("/api/agent/report",
                     json={"scan": SCAN_PAYLOAD, "config": CONFIG_PAYLOAD,
                           "agent_version": "0.1.0", "source_host": "laptop", "consent": True},
                     headers={"X-NetProof-Key": accounts["org_key"]})
    assert r.status_code == 200 and r.json().get("ok")

    status = session.get(f"/api/agent/status?org={accounts['org_id']}").json()
    assert status["has_report"] and status["network"] == "192.168.50.0/24"

    data = session.get(f"/api/network?org={accounts['org_id']}").json()
    assert data.get("source") == "agent" and data.get("mode") == "agent"
    assert data["confirmations"]["rules"]["confirmed"] > 0
    assert len(data["devices"]) >= 2
    assert "presets" in data and "reported_at" in data


def test_network_onboarding_no_report(session, accounts):
    data = session.get(f"/api/network?org={accounts['beta_id']}").json()
    assert data.get("onboarding") is True and data.get("source") == "none"


def test_network_demo_default(session):
    data = session.get("/api/network").json()
    assert data.get("source") == "demo" and "presets" in data


def test_validate_agent_mode(session, accounts):
    r = session.post("/api/validate", json={
        "change": {"type": "add_filter_rule", "filter": "router-lan-in",
                   "rule": {"action": "deny", "proto": "tcp", "dport": 22}},
        "mode": "agent", "account": accounts["org_id"],
    })
    assert r.json()["summary"]["verdict"] in ("pass", "warn", "block")
    assert r.json()["provenance"]["model_source"]["mode"] == "agent"


def test_republish_invalidates_cache(session, accounts):
    session.post("/api/agent/report",
                 json={"scan": SCAN_PAYLOAD, "config": {}, "agent_version": "0.1.0", "consent": True},
                 headers={"X-NetProof-Key": accounts["org_key"]})
    data = session.get(f"/api/network?org={accounts['org_id']}").json()
    assert data["confirmations"]["rules"]["confirmed"] == 0


def test_model_agent_200(session, accounts):
    r = session.get(f"/api/model?mode=agent&org={accounts['org_id']}")
    assert r.status_code == 200 and r.json().get("source") == "agent"


def test_model_agent_no_report_400(session, accounts):
    r = session.get(f"/api/model?mode=agent&org={accounts['beta_id']}")
    assert r.status_code == 400


def test_dev_scan_endpoint(session):
    assert session.get("/api/scan").status_code == 200


def test_intent_agent_mode(session, accounts):
    r = session.post("/api/intent", json={"text": "block ssh from any to web",
                                          "mode": "agent", "account": accounts["org_id"]})
    assert r.json().get("ok")
    assert r.json()["change"]["type"] == "add_filter_rule"