"""P2: the referee never scans or accepts a report without the owner's explicit
consent, and every consequential action leaves an append-only audit row."""
import pytest
import uuid

import json
from engine.events import _conn, init_events, list_events
from engine.validate import PRESETS
from main import app
from fastapi.testclient import TestClient

TEST_ADMIN_PASS = "admin-test-pass-2026"


@pytest.fixture(scope="module")
def client():
    init_events()
    return TestClient(app)


@pytest.fixture()
def session(client):
    r = client.post("/api/login", json={"username": "admin", "password": TEST_ADMIN_PASS})
    assert r.status_code == 200
    return client


@pytest.fixture()
def org_key(session):
    r = session.post("/api/orgs", json={"name": f"ConsentTest-{uuid.uuid4().hex[:6]}"})
    assert r.status_code == 200
    return r.json()["org"]["api_key"]


def test_scan_without_consent_403(session):
    r = session.post("/api/scan", json={"target": "192.0.2.5", "ping": False, "consent": False})
    assert r.status_code == 403
    assert "consent" in r.json()["detail"]


def test_scan_with_consent_ok(session):
    r = session.post("/api/scan", json={"target": "127.0.0.1", "ping": False, "consent": True})
    assert r.status_code == 200
    assert r.json().get("devices")
    # an attributable scan.run audit row was recorded for THIS scan (rows are
    # append-only; the newest inserted scan.run row is ours)
    row = _conn().execute(
        "SELECT detail FROM audit_events WHERE action = 'scan.run' ORDER BY rowid DESC LIMIT 1"
    ).fetchone()
    assert row is not None and json.loads(row["detail"]).get("devices") == len(r.json().get("devices"))


def test_agent_report_without_consent_403(session, org_key):
    r = session.post("/api/agent/report", json={
        "scan": {"target": "198.51.100.9", "network": "198.51.100.0/24",
                 "devices": [{"ip": "198.51.100.1", "is_target": True, "type_guess": "router", "services": []}]},
        "consent": False,
    }, headers={"X-NetProof-Key": org_key})
    assert r.status_code == 403


def test_agent_report_with_consent_ok(session, org_key):
    r = session.post("/api/agent/report", json={
        "scan": {"target": "198.51.100.9", "network": "198.51.100.0/24",
                 "devices": [{"ip": "198.51.100.1", "is_target": True, "type_guess": "router", "services": []}]},
        "consent": True,
    }, headers={"X-NetProof-Key": org_key})
    assert r.status_code == 200


def test_audit_trail_records_actions(session, org_key):
    """A validation and an agent report each append an audit row. Self-contained:
    this test performs its OWN actions instead of depending on which other tests
    ran before it in the session."""
    r = session.post("/api/validate", json={"mode": "demo", "change": PRESETS[0]["change"]})
    assert r.status_code == 200
    session.post("/api/agent/report", json={
        "scan": {"target": "203.0.113.9", "network": "203.0.113.0/24",
                 "devices": [{"ip": "203.0.113.1", "is_target": True, "type_guess": "router", "services": []}]},
        "consent": True,
    }, headers={"X-NetProof-Key": org_key})

    events = list_events(500)
    actions = {e["action"] for e in events}
    assert {"login", "agent.report", "validate"} <= actions
    for e in events:
        for key in ("id", "at", "actor", "action", "detail"):
            assert e.get(key) is not None, f"event field missing: {key}"


def test_audit_endpoint_gated():
    c = TestClient(app)
    assert c.get("/api/audit").status_code == 401