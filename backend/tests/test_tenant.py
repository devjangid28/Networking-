"""Security tests for the org/agent API-key store.

Covers: plaintext keys are never persisted, never returned by list/get, legacy
plaintext rows auto-migrate (old key keeps working), and rotation invalidates
the old key immediately.
"""
import os
import sqlite3

import pytest

from engine import tenant
from engine.tenant import (
    create_org, create_user, delete_user, get_org, get_org_by_api_key,
    init_tenant, list_orgs, login_org_user, rotate_api_key,
)


@pytest.fixture()
def db(tmp_path):
    return str(tmp_path / "test_tenants.db")


def test_create_org_returns_key_once_but_never_persists_it(db):
    init_tenant(db)
    org = create_org("Alpha", db=db)
    assert org["api_key"]
    assert tenant.get_org(org["id"], db=db)["id"] == org["id"]
    stored = sqlite3.connect(db).execute("SELECT key_digest, key_salt FROM orgs WHERE id = ?", (org["id"],)).fetchone()
    digest, salt = stored
    assert digest and salt
    assert org["api_key"] not in (digest, salt)
    # the raw API key never appears in the on-disk database bytes at all
    raw = open(db, "rb").read()
    assert org["api_key"].encode("utf-8") not in raw


def test_list_and_get_never_leak_key_material(db):
    init_tenant(db)
    create_org("Bravo", db=db)
    for o in list_orgs(db=db):
        assert "api_key" not in o and "key_digest" not in o and "key_salt" not in o
    assert "api_key" not in get_org(list_orgs(db=db)[0]["id"], db=db)


def test_get_org_by_api_key_rejects_wrong_key(db):
    init_tenant(db)
    org = create_org("Charlie", db=db)
    assert get_org_by_api_key(org["api_key"], db=db)["id"] == org["id"]
    assert get_org_by_api_key("nope-not-a-key", db=db) is None
    assert get_org_by_api_key("", db=db) is None


def test_rotation_invalidates_old_key_immediately(db):
    init_tenant(db)
    org = create_org("Delta", db=db)
    old = org["api_key"]
    rotated = rotate_api_key(org["id"], db=db)
    assert rotated["api_key"] != old
    assert get_org_by_api_key(old, db=db) is None
    assert get_org_by_api_key(rotated["api_key"], db=db)["id"] == org["id"]


def test_legacy_plaintext_store_migrates_and_key_survives(db):
    legacy = sqlite3.connect(db)
    legacy.executescript(
        """
        CREATE TABLE orgs (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL UNIQUE,
            api_key     TEXT NOT NULL UNIQUE,
            created_at  TEXT NOT NULL
        );
        INSERT INTO orgs VALUES ('legacy1','OldCo','plaintext-key-abc123','2026-01-01T00:00:00');
        CREATE TABLE agent_reports (
            id TEXT PRIMARY KEY, org_id TEXT NOT NULL, received_at TEXT NOT NULL,
            network TEXT, devices INTEGER, raw TEXT NOT NULL, meta TEXT NOT NULL
        );
        """
    )
    legacy.commit()
    legacy.close()

    init_tenant(db)
    cols = {r[1] for r in sqlite3.connect(db).execute("PRAGMA table_info(orgs)").fetchall()}
    assert "api_key" not in cols
    assert "key_digest" in cols and "key_salt" in cols
    assert get_org_by_api_key("plaintext-key-abc123", db=db)["id"] == "legacy1"
    assert get_org_by_api_key("wrong", db=db) is None
    assert sqlite3.connect(db).execute("SELECT COUNT(*) FROM orgs").fetchone()[0] == 1


# --------------------------------------------------------------------------- #
# Org-scoped login + session-safe user deletion                               #
# --------------------------------------------------------------------------- #

def _mk_world(db):
    """Two accounts, each with a user named 'shared' but DIFFERENT passwords."""
    init_tenant(db)
    a = create_org("One", db=db)
    b = create_org("Two", db=db)
    ua = create_user(a["id"], "shared", "aaa-org-one-pass", "operator", db=db)
    ub = create_user(b["id"], "shared", "bbb-org-two-pass", "operator", db=db)
    return a, b, ua, ub


def test_same_username_two_orgs_login_is_org_scoped(db):
    a, b, _, _ = _mk_world(db)
    # each org's OWN password authenticates its own user ...
    assert login_org_user(a["id"], "shared", "aaa-org-one-pass", db=db)["org_id"] == a["id"]
    assert login_org_user(b["id"], "shared", "bbb-org-two-pass", db=db)["org_id"] == b["id"]
    # ... and the OTHER org's password never authenticates here (no cross-org
    # credential leak, even when usernames collide)
    assert login_org_user(a["id"], "shared", "bbb-org-two-pass", db=db) is None
    assert login_org_user(b["id"], "shared", "aaa-org-one-pass", db=db) is None
    # wrong password / unknown org fail cleanly
    assert login_org_user(a["id"], "shared", "wrong-pass-123", db=db) is None
    assert login_org_user("no-such-org", "shared", "aaa-org-one-pass", db=db) is None
    # without an org_id the collision is REFUSED rather than silently picking one
    assert login_org_user("", "shared", "aaa-org-one-pass", db=db) is None


def test_two_orgs_may_each_create_admin_same_username(db):
    a, b, _, _ = _mk_world(db)
    # creating a duplicate username in the SAME org is rejected ...
    with pytest.raises(ValueError):
        create_user(a["id"], "shared", "aaa-org-one-pass", "viewer", db=db)
    # ... but the same username in the OTHER org is allowed
    c = create_user(b["id"], "shared2", "ccc-org-two-pass", "viewer", db=db)
    assert c["username"] == "shared2"


def test_delete_user_without_sessions_table_is_safe(db):
    """delete_user lives in the tenant store, but the `sessions` table is owned
    by backend/security.py. Deleting a user against a tenant-only database must
    not crash on the missing table."""
    a, _, ua, _ = _mk_world(db)
    tables = {r[0] for r in sqlite3.connect(db).execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "sessions" not in tables  # tenant-only DB, sessions owned by security.py
    delete_user(a["id"], ua["username"], db=db, actor="test")
    assert login_org_user(a["id"], ua["username"], "aaa-org-one-pass", db=db) is None
    # legacy global-unique index must not have been recreated by this store
    idx = sqlite3.connect(db).execute("SELECT name FROM sqlite_master WHERE name='idx_users_username'").fetchone()
    assert idx is None