"""Phases 4 + 5: drift endpoint and the diagnostic bundle export.

/api/drift reports current-vs-baseline posture independent of a specific
change; /api/verdicts/{vid}/bundle bundles the whole diagnostic story of one
validation into a single machine-readable file.
"""
import pytest
from starlette.testclient import TestClient

from main import app

TEST_ADMIN_PASS = "admin-test-pass-2026"

BUNDLE_KEYS = {
    "bundle_spec", "exported_at", "verdict_id", "provenance", "environment",
    "change", "proposed_diff", "verdict", "checklist", "trace",
    "pipeline_layers", "drift", "findings", "matrix", "requirements",
    "flow_summary", "control_plane", "guardrails", "inventory",
}


@pytest.fixture(scope="module")
def session():
    with TestClient(app, raise_server_exceptions=False) as cli:
        r = cli.post("/api/login", json={"username": "admin", "password": TEST_ADMIN_PASS})
        assert r.status_code == 200
        yield cli


def test_drift_endpoint_has_baseline_and_risk_shape(session):
    r = session.get("/api/drift?mode=demo")
    assert r.status_code == 200
    j = r.json()
    for key in ("network", "baseline_exists", "baseline_at", "drift_count",
                "risk_level", "suggested_action", "results"):
        assert key in j, key
    assert j["network"]
    assert isinstance(j["results"], list)


def test_drift_endpoint_results_have_actionable_fields(session):
    r = session.get("/api/drift?mode=demo")
    assert r.status_code == 200
    for res in r.json()["results"]:
        assert {"drift_type", "details", "affected_flows", "suggested_action"} <= set(res)


def test_bundle_export_contains_every_diagnostic_section(session):
    body = {"mode": "demo", "change": {"type": "add_filter_rule", "filter": "fw-inside-in",
                                       "at_index": 0, "rule": {"action": "deny", "src": "10.0.10.0/24",
                                                               "dst": "any", "proto": "any"}}}
    v = session.post("/api/validate", json=body)
    assert v.status_code == 200
    vid = v.json()["audit"]["verdict_id"]
    b = session.get(f"/api/verdicts/{vid}/bundle")
    assert b.status_code == 200
    assert "attachment; filename=" in b.headers.get("content-disposition", "")
    j = b.json()
    assert BUNDLE_KEYS <= set(j)
    assert j["verdict_id"] == vid
    assert j["verdict"]["verdict"] in ("block", "warn", "pass")
    assert j["pipeline_layers"], "blocked verdict must keep its pipeline layer story"
    assert j["checklist"]
    assert j["proposed_diff"] is not None
    assert j["inventory"]["devices"]
    assert j["inventory"]["filters"]


def test_bundle_export_rejects_unknown_verdict(session):
    r = session.get("/api/verdicts/nope/bundle")
    assert r.status_code == 404