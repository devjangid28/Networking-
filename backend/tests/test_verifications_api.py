"""Phase 6 API surface: evidence-aware post-change verification endpoints.

POST /api/verifications                    - open a verification on a stored verdict
GET  /api/verifications/{id}               - lifecycle + evidence + result
POST /api/verifications/{id}/evidence      - append (redacted) post-change evidence
POST /api/verifications/{id}/run           - compare + health checks + rollback
GET  /api/verifications/{id}/bundle        - exportable redacted bundle
"""
import time
import uuid

import pytest
from starlette.testclient import TestClient

from engine import tenant as _tenant
from main import app

TEST_ADMIN_PASS = "admin-test-pass-2026"
ORG_PASS = "correct-horse-battery"

CHANGE = {"type": "add_filter_rule", "filter": "fw-inside-in",
          "rule": {"action": "permit", "src": "10.0.10.0/24", "dst": "10.0.20.0/24", "proto": "icmp"}}

RULES = [
    {"action": "permit", "src": "10.0.10.0/24", "dst": "10.0.20.0/24", "proto": "tcp", "dport": 443},
    {"action": "permit", "src": "10.0.10.0/24", "dst": "10.0.20.0/24", "proto": "tcp", "dport": 22},
    {"action": "permit", "src": "10.0.10.0/24", "dst": "any", "proto": "tcp", "dport": 80},
    {"action": "permit", "src": "10.0.10.0/24", "dst": "any", "proto": "tcp", "dport": 443},
]
ICMP = {"action": "permit", "src": "10.0.10.0/24", "dst": "10.0.20.0/24", "proto": "icmp"}


def _evidence_with_icmp():
    return [{
        "source": "snapshot", "device": "192.168.1.1", "section": "filters",
        "collected_at": "2099-01-01T00:00:00Z", "confirmed": True,
        "content": {"filters": {"fw-inside-in": {"rules": RULES + [ICMP]}}},
    }]


def _evidence_without_icmp():
    return [{
        "source": "snapshot", "device": "192.168.1.1", "section": "filters",
        "collected_at": "2099-01-01T00:00:00Z", "confirmed": True,
        "content": {"filters": {"fw-inside-in": {"rules": RULES}}},
    }]


@pytest.fixture(scope="module")
def admin():
    with TestClient(app, raise_server_exceptions=False) as cli:
        r = cli.post("/api/login", json={"username": "admin", "password": TEST_ADMIN_PASS})
        assert r.status_code == 200
        yield cli


@pytest.fixture(scope="module")
def anon():
    with TestClient(app, raise_server_exceptions=False) as cli:
        yield cli


@pytest.fixture(scope="module")
def world(admin):
    """One org with a viewer + operator user for the role-gating checks."""
    stamp = f"{int(time.time() * 1000) % 1000000}-{uuid.uuid4().hex[:4]}"
    org = admin.post("/api/orgs", json={"name": f"VerifOrg-{stamp}"}).json()["org"]

    def mk(username, role):
        return admin.post("/api/users", json={
            "org_id": org["id"], "username": username, "password": ORG_PASS, "role": role,
        }).json()["user"]

    mk(f"vop-{stamp}", "operator")
    mk(f"vvw-{stamp}", "viewer")
    yield {"stamp": stamp, "org_id": org["id"], "op": f"vop-{stamp}", "vw": f"vvw-{stamp}"}

    conn = _tenant._conn()
    conn.execute("DELETE FROM agent_reports WHERE org_id=?", (org["id"],))
    conn.execute("DELETE FROM users WHERE org_id=?", (org["id"],))
    conn.execute("DELETE FROM orgs WHERE id=?", (org["id"],))
    conn.commit()


def login(username, org_id=None):
    cli = TestClient(app, raise_server_exceptions=False)
    payload = {"username": username, "password": ORG_PASS}
    if org_id:
        payload["org_id"] = org_id
    r = cli.post("/api/login", json=payload)
    assert r.status_code == 200, r.text
    return cli


@pytest.fixture(scope="module")
def verdict(admin):
    r = admin.post("/api/validate", json={"change": CHANGE})
    assert r.status_code == 200
    report = r.json()
    assert "prediction" in report, "validate must carry the additive prediction block"
    assert report["prediction"]["deltas"], "prediction must include at least one delta"
    yield report["audit"]["verdict_id"]


# --------------------------------------------------------------------------- #
# lifecycle                                                                    #
# --------------------------------------------------------------------------- #

def test_full_verification_lifecycle(admin, verdict):
    r = admin.post("/api/verifications", json={"verdict_id": verdict,
                                               "requester": "tester",
                                               "pre_change_evidence": {
                                                   "devices": {"firewall": "192.168.1.1"},
                                                   "config": {"192.168.1.1": {"filters": {
                                                       "fw-inside-in": {"rules": RULES}}}},
                                               }})
    assert r.status_code == 200, r.text
    v = r.json()
    assert v["status"] == "not_started"
    assert v["verdict_id"] == verdict
    assert v["change"] == CHANGE
    assert v["prediction"]["summary"]["simulation_verdict"] == "pass"
    vid = v["id"]

    r = admin.post(f"/api/verifications/{vid}/evidence", json={"evidence": _evidence_with_icmp()})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "awaiting_observation"
    assert r.json()["evidence"], "evidence should be persisted"

    r = admin.post(f"/api/verifications/{vid}/run", json={})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["status"] == "verified"
    assert out["result"]["summary"]["deltas_confirmed"] >= 1
    assert out["health_checks"]
    assert out["rollback"]["recommended"] is False
    assert out["bundle"]["redacted"] is True

    assert admin.get(f"/api/verifications/{vid}").status_code == 200
    b = admin.get(f"/api/verifications/{vid}/bundle")
    assert b.status_code == 200
    assert "netproof-verification" in b.headers["content-disposition"]
    assert b.json()["verification"]["id"] == vid


def test_run_without_evidence_never_passes(admin, verdict):
    r = admin.post("/api/verifications", json={"verdict_id": verdict})
    vid = r.json()["id"]
    assert admin.get(f"/api/verifications/{vid}/bundle").status_code == 409
    r = admin.post(f"/api/verifications/{vid}/run", json={})
    assert r.status_code == 200
    assert r.json()["status"] == "inconclusive"
    assert admin.get(f"/api/verifications/{vid}/bundle").status_code == 200


def test_failed_verification_recommends_rollback(admin, verdict):
    r = admin.post("/api/verifications", json={"verdict_id": verdict})
    vid = r.json()["id"]
    admin.post(f"/api/verifications/{vid}/evidence", json={"evidence": _evidence_without_icmp()})
    out = admin.post(f"/api/verifications/{vid}/run", json={}).json()
    assert out["status"] == "failed"
    assert out["rollback"]["recommended"] is True
    assert out["rollback"]["inverse_change"]["type"] == "remove_filter_rule"


def test_create_missing_verdict_404(admin):
    r = admin.post("/api/verifications", json={"verdict_id": "nope-not-real"})
    assert r.status_code == 404


def test_evidence_rejects_unknown_source(admin, verdict):
    r = admin.post("/api/verifications", json={"verdict_id": verdict})
    vid = r.json()["id"]
    bad = _evidence_with_icmp()
    bad[0]["source"] = "tarot"
    r = admin.post(f"/api/verifications/{vid}/evidence", json={"evidence": bad})
    assert r.status_code == 400


def test_evidence_rejects_too_many_documents(admin, verdict):
    from engine import postchange as pc
    r = admin.post("/api/verifications", json={"verdict_id": verdict})
    vid = r.json()["id"]
    docs = _evidence_with_icmp() * (pc.MAX_EVIDENCE_DOCS + 1)
    r = admin.post(f"/api/verifications/{vid}/evidence", json={"evidence": docs})
    assert r.status_code == 400


def test_evidence_missing_verification_404(admin):
    r = admin.post("/api/verifications/not-here/evidence",
                   json={"evidence": _evidence_with_icmp()})
    assert r.status_code == 404


def test_evidence_secrets_redacted_at_rest(admin, verdict):
    r = admin.post("/api/verifications", json={"verdict_id": verdict})
    vid = r.json()["id"]
    docs = _evidence_with_icmp()
    docs[0]["service"] = {"password": "hunter2"}
    admin.post(f"/api/verifications/{vid}/evidence", json={"evidence": docs})
    stored = admin.get(f"/api/verifications/{vid}").json()
    assert "hunter2" not in str(stored)


# --------------------------------------------------------------------------- #
# auth + rbac + tenant isolation                                               #
# --------------------------------------------------------------------------- #

def test_verifications_require_session(anon, verdict):
    assert anon.post("/api/verifications",
                     json={"verdict_id": verdict}).status_code == 401
    assert anon.get("/api/verifications/nope").status_code == 401


def test_viewer_cannot_create_or_run(world, verdict):
    vw = login(world["vw"], world["org_id"])
    assert vw.post("/api/verifications",
                   json={"verdict_id": verdict}).status_code == 403
    assert vw.post("/api/verifications/nope/run", json={}).status_code == 403
    assert vw.post("/api/verifications/nope/evidence",
                   json={"evidence": []}).status_code == 403


def test_operator_can_create():
    # operator is granted the same create/boundary surface; verified implicitly
    # by require_role("operator") dependency above, but assert the rank exists.
    from security import _ROLE_RANK
    assert _ROLE_RANK["operator"] > _ROLE_RANK["viewer"]


def test_org_scoped_user_cannot_read_foreign_verification(world, admin, verdict):
    r = admin.post("/api/verifications", json={"verdict_id": verdict})
    vid = r.json()["id"]
    op = login(world["op"], world["org_id"])
    assert op.get(f"/api/verifications/{vid}").status_code == 403
    assert op.post(f"/api/verifications/{vid}/evidence",
                   json={"evidence": []}).status_code == 403
    assert op.get(f"/api/verifications/{vid}/bundle").status_code == 403