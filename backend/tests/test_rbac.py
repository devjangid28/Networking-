"""P?? RBAC: multi-user dashboards with admin/operator/viewer roles.

The global env-admin stays role "admin" and sees every account. Additional
org-scoped users:
  - admin    == full control of their org (same endpoints as global admin)
  - operator == read everything in their org, but cannot create accounts,
                rotate keys, manage users, or read the cross-org audit trail
  - viewer   == read-only: cannot create accounts or read the audit trail
Org-scoped users only ever see their OWN account (tenant isolation); usernames
are unique per account, and logins are org-scoped so two accounts may both have
an "admin"/"shared" user without any cross-account login bypass.
"""
import time
import uuid

import pytest
from starlette.testclient import TestClient

from engine import tenant as _tenant
from main import app

TEST_ADMIN_PASS = "admin-test-pass-2026"
ORG_PASS = "correct-horse-battery"


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
    """One org + one user per role + a second org for the isolation checks."""
    stamp = f"{int(time.time() * 1000) % 1000000}-{uuid.uuid4().hex[:4]}"
    org = admin.post("/api/orgs", json={"name": f"RBACOrg-{stamp}"}).json()["org"]
    other = admin.post("/api/orgs", json={"name": f"RBACOther-{stamp}"}).json()["org"]

    def mk(username, role):
        return admin.post("/api/users", json={
            "org_id": org["id"], "username": username, "password": ORG_PASS, "role": role,
        }).json()["user"]

    mk(f"op-{stamp}", "operator")
    mk(f"vw-{stamp}", "viewer")
    mk(f"ad-{stamp}", "admin")

    yield {
        "stamp": stamp,
        "org_id": org["id"],
        "other_id": other["id"],
        "op": f"op-{stamp}",
        "vw": f"vw-{stamp}",
        "ad": f"ad-{stamp}",
    }

    conn = _tenant._conn()
    conn.execute("DELETE FROM agent_reports WHERE org_id IN (?,?)", (org["id"], other["id"]))
    conn.execute("DELETE FROM users WHERE org_id IN (?,?)", (org["id"], other["id"]))
    conn.execute("DELETE FROM orgs WHERE id IN (?,?)", (org["id"], other["id"]))
    conn.commit()


def login(world, username, org_id=None, password=ORG_PASS):
    cli = TestClient(app, raise_server_exceptions=False)
    payload = {"username": username, "password": password}
    if org_id:
        payload["org_id"] = org_id
    r = cli.post("/api/login", json=payload)
    assert r.status_code == 200, r.text
    return cli


def test_login_returns_role(world, admin):
    r = admin.get("/api/session")
    assert r.json()["role"] == "admin"
    op = login(world, world["op"], world["org_id"])
    sess = op.get("/api/session")
    assert sess.json()["role"] == "operator"
    assert sess.json()["org_id"] == world["org_id"]
    vw = login(world, world["vw"], world["org_id"])
    assert vw.get("/api/session").json()["role"] == "viewer"


def test_org_scoped_listing(world):
    # org-bound users see ONLY their own account in /api/orgs
    op = login(world, world["op"], world["org_id"])
    orgs = op.get("/api/orgs").json()["orgs"]
    assert [o["id"] for o in orgs] == [world["org_id"]]


def test_operator_cannot_create_org(world):
    op = login(world, world["op"], world["org_id"])
    r = op.post("/api/orgs", json={"name": "should-not-exist"})
    assert r.status_code == 403


def test_viewer_cannot_rotate_key(world):
    vw = login(world, world["vw"], world["org_id"])
    r = vw.post(f"/api/orgs/{world['org_id']}/rotate-key")
    assert r.status_code == 403
    op = login(world, world["op"], world["org_id"])
    assert op.post(f"/api/orgs/{world['org_id']}/rotate-key").status_code == 403


def test_admin_can_rotate_key(world, admin):
    r = admin.post(f"/api/orgs/{world['org_id']}/rotate-key")
    assert r.status_code == 200
    assert "api_key" in r.json()


def test_org_scope_blocks_other_account(world):
    op = login(world, world["op"], world["org_id"])
    r = op.get(f"/api/agent/status?org={world['other_id']}")
    assert r.status_code == 403
    # their own org stays reachable
    assert op.get(f"/api/agent/status?org={world['org_id']}").status_code == 200


def test_audit_is_admin_only(world):
    op = login(world, world["op"], world["org_id"])
    assert op.get("/api/audit").status_code == 403
    vw = login(world, world["vw"], world["org_id"])
    assert vw.get("/api/audit").status_code == 403


def test_viewer_reads_own_org(world):
    vw = login(world, world["vw"], world["org_id"])
    assert vw.get(f"/api/agent/status?org={world['org_id']}").status_code == 200


def test_only_admin_manages_users(world, admin):
    op = login(world, world["op"], world["org_id"])
    assert op.get("/api/users").status_code == 403
    assert op.post("/api/users", json={
        "org_id": world["org_id"], "username": "nope", "password": "aaaaaaaaaa", "role": "viewer",
    }).status_code == 403
    assert admin.get("/api/users").status_code == 200


def test_user_validation(world, admin):
    # short password -> pydantic rejects it at the edge (422)
    assert admin.post("/api/users", json={
        "org_id": world["org_id"], "username": "shortpw", "password": "short", "role": "viewer",
    }).status_code == 422
    # bad role
    assert admin.post("/api/users", json={
        "org_id": world["org_id"], "username": "boss", "password": ORG_PASS, "role": "superuser",
    }).status_code == 400
    # duplicate WITHIN the same account is still blocked (per-org uniqueness)
    assert admin.post("/api/users", json={
        "org_id": world["org_id"], "username": world["op"], "password": ORG_PASS, "role": "viewer",
    }).status_code == 400
    # the SAME username in a DIFFERENT account is allowed (usernames are
    # account-scoped, and logins are org-scoped, so there is no ambiguity)
    assert admin.post("/api/users", json={
        "org_id": world["other_id"], "username": world["op"], "password": ORG_PASS, "role": "viewer",
    }).status_code == 200


def test_same_username_two_accounts_no_cross_login(world, admin):
    """Two accounts share the username 'shared' with DIFFERENT passwords.

    Each account's login may only succeed with ITS OWN password; passing the
    other account's password must fail, and the session org_id must be the
    account that OWNS the password used.
    """
    for oid, pwd in ((world["org_id"], "aaa-org-one-pass"), (world["other_id"], "bbb-org-two-pass")):
        r = admin.post("/api/users", json={
            "org_id": oid, "username": "shared", "password": pwd, "role": "operator",
        })
        assert r.status_code == 200, r.text

    a = TestClient(app, raise_server_exceptions=False)
    assert a.post("/api/login", json={
        "username": "shared", "password": "aaa-org-one-pass", "org_id": world["org_id"],
    }).status_code == 200
    assert a.get("/api/session").json()["org_id"] == world["org_id"]

    b = TestClient(app, raise_server_exceptions=False)
    assert b.post("/api/login", json={
        "username": "shared", "password": "bbb-org-two-pass", "org_id": world["other_id"],
    }).status_code == 200
    assert b.get("/api/session").json()["org_id"] == world["other_id"]

    # the other account's password must NEVER authenticate here — a cross-org
    # bypass would be a credential leak between tenants
    c = TestClient(app, raise_server_exceptions=False)
    assert c.post("/api/login", json={
        "username": "shared", "password": "bbb-org-two-pass", "org_id": world["org_id"],
    }).status_code == 401
    d = TestClient(app, raise_server_exceptions=False)
    assert d.post("/api/login", json={
        "username": "shared", "password": "aaa-org-one-pass", "org_id": world["other_id"],
    }).status_code == 401


def test_delete_user_revokes_access(world, admin):
    name = f"gone-{world['stamp']}"
    admin.post("/api/users", json={
        "org_id": world["org_id"], "username": name, "password": ORG_PASS, "role": "operator",
    })

    # log the user in FIRST so we hold a live, working session to prove we kill it
    cli = TestClient(app, raise_server_exceptions=False)
    r = cli.post("/api/login", json={
        "username": name, "password": ORG_PASS, "org_id": world["org_id"],
    })
    assert r.status_code == 200
    assert cli.get("/api/session").json()["authenticated"] is True

    # deleting the user must revoke that live session AND the account
    assert admin.delete(f"/api/users/{world['org_id']}/{name}").status_code == 200
    assert cli.get("/api/session").json()["authenticated"] is False
    assert cli.get("/api/orgs").status_code == 401

    # and a fresh login is refused too
    gone = TestClient(app, raise_server_exceptions=False)
    assert gone.post("/api/login", json={
        "username": name, "password": ORG_PASS, "org_id": world["org_id"],
    }).status_code == 401


def test_anon_still_401(world, anon):
    assert anon.get("/api/orgs").status_code == 401
    assert anon.get("/api/users").status_code == 401
    assert anon.get("/api/verdicts").status_code == 401