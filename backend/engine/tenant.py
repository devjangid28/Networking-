"""Multi-tenant accounts + outbound agent reports.

NetProof is a neutral referee — it never walks into a customer network. A local
`agent/` binary runs INSIDE the customer network, discovers it, and posts the
result OUTBOUND to this server under an API key bound to an org/account. The
dashboard then renders whatever the account's latest report says; the server
itself never performs a live scan against the customer LAN.

Tables live in the same SQLite store as the audit trail (default netproof.db):
    orgs           id, name, key_digest + key_salt (salted PBKDF2 of the key),
                   created_at
    agent_reports  id, org_id, received_at, network, devices, raw, meta
    users          id, org_id, username, pass_hash + pass_salt (salted PBKDF2
                   of the password), role (admin/operator/viewer), created_at

The raw API key is NEVER persisted. It is returned exactly once at creation
(or rotation) and only its salted digest is stored, so a leaked database does
not leak agent credentials. User passwords are stored the same way (never in
plaintext).

Roles: admin (full control of the org + user/invite management), operator
(can run scans, validations and see everything within their org), viewer
(read-only).
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Optional

from .audit import DEFAULT_DB
from .events import log_event

ROLES = ("admin", "operator", "viewer")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS orgs (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    key_digest  TEXT NOT NULL,
    key_salt    TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_reports (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL,
    received_at TEXT NOT NULL,
    network     TEXT,
    devices     INTEGER,
    raw         TEXT NOT NULL,
    meta        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_org ON agent_reports (org_id, received_at DESC);
CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL,
    username    TEXT NOT NULL,
    pass_hash   TEXT NOT NULL,
    pass_salt   TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'viewer',
    created_at  TEXT NOT NULL,
    UNIQUE (org_id, username)
);
CREATE INDEX IF NOT EXISTS idx_users_org ON users (org_id);
"""

_conns: dict[str, sqlite3.Connection] = {}
_lock = threading.RLock()

_PBKDF2_ITERATIONS = 120_000


def _conn(db: str = DEFAULT_DB) -> sqlite3.Connection:
    with _lock:
        conn = _conns.get(db)
        if conn is None:
            Path(db).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(db, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.executescript(_SCHEMA)
            conn.commit()
            _conns[db] = conn
        return conn


def _hash(api_key: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", api_key.encode("utf-8"), salt.encode("ascii"), _PBKDF2_ITERATIONS
    ).hex()


def _migrate_legacy(db: str) -> None:
    """Rebuild a legacy orgs table that stored plaintext keys in `api_key`.

    The existing plaintext is digested in place so the same raw key keeps
    working after migration; nothing is lost and no plaintext survives.
    """
    with _lock:
        conn = _conn(db)
        conn.execute("ALTER TABLE orgs RENAME TO orgs_legacy")
        conn.executescript(_SCHEMA)
        for row in conn.execute("SELECT id, name, api_key, created_at FROM orgs_legacy").fetchall():
            salt = uuid.uuid4().hex[:16]
            conn.execute(
                "INSERT INTO orgs (id, name, key_digest, key_salt, created_at) VALUES (?,?,?,?,?)",
                (row["id"], row["name"], _hash(str(row["api_key"] or ""), salt), salt, row["created_at"]),
            )
        conn.execute("DROP TABLE orgs_legacy")
        conn.commit()


def init_tenant(db: str = DEFAULT_DB) -> None:
    """Create tables on startup and migrate any plaintext-key legacy store. Idempotent."""
    with _lock:
        conn = _conn(db)
        # Drop the legacy GLOBALLY-unique username index. Usernames are unique
        # per organisation (the table constraint), never across orgs; logins are
        # org-scoped. The old index would have silently blocked two orgs from
        # both having an "admin" dashboard user.
        conn.execute("DROP INDEX IF EXISTS idx_users_username")
        cols = {r[1] for r in conn.execute("PRAGMA table_info(orgs)").fetchall()}
    if "api_key" in cols:
        _migrate_legacy(db)


def new_api_key() -> str:
    return secrets.token_urlsafe(24)


def _org_row(row) -> Optional[dict]:
    """Public projection of an org — never leaks key material."""
    if row is None:
        return None
    return {"id": row["id"], "name": row["name"], "created_at": row["created_at"]}


def create_org(name: str, db: str = DEFAULT_DB, actor: str = "system") -> dict:
    name = (name or "").strip()
    if not name:
        raise ValueError("org name is required")
    with _lock:
        conn = _conn(db)
        if conn.execute("SELECT 1 FROM orgs WHERE name = ?", (name,)).fetchone():
            raise ValueError(f"an account named '{name}' already exists")
        oid = uuid.uuid4().hex[:8]
        key = new_api_key()
        salt = uuid.uuid4().hex[:16]
        conn.execute(
            "INSERT INTO orgs (id, name, key_digest, key_salt, created_at) VALUES (?,?,?,?,?)",
            (oid, name, _hash(key, salt), salt, datetime.datetime.now().isoformat(timespec="seconds")),
        )
        conn.commit()
        log_event("org.create", actor=actor, target=oid, detail={"name": name})
        org = _org_row(conn.execute("SELECT * FROM orgs WHERE id = ?", (oid,)).fetchone())
        org["api_key"] = key
        return org


def list_orgs(db: str = DEFAULT_DB) -> list[dict]:
    with _lock:
        conn = _conn(db)
        rows = conn.execute("SELECT * FROM orgs ORDER BY created_at ASC").fetchall()
        orgs = []
        for r in rows:
            o = _org_row(r)
            last = conn.execute(
                "SELECT received_at FROM agent_reports WHERE org_id = ? ORDER BY received_at DESC, rowid DESC LIMIT 1",
                (o["id"],),
            ).fetchone()
            o["has_report"] = last is not None
            o["last_report_at"] = last["received_at"] if last else None
            orgs.append(o)
        return orgs


def count_active_agents(db: str = DEFAULT_DB, days: int = 7) -> int:
    """How many accounts had an agent report in the last `days` days."""
    cutoff = (datetime.datetime.now() - datetime.timedelta(days=days)).isoformat(timespec="seconds")
    with _lock:
        return int(_conn(db).execute(
            "SELECT COUNT(DISTINCT org_id) FROM agent_reports WHERE received_at >= ?",
            (cutoff,),
        ).fetchone()[0])


def get_org(org_id: str, db: str = DEFAULT_DB) -> Optional[dict]:
    with _lock:
        return _org_row(_conn(db).execute("SELECT * FROM orgs WHERE id = ?", (org_id,)).fetchone())


def get_org_by_api_key(key: str, db: str = DEFAULT_DB) -> Optional[dict]:
    if not key:
        return None
    with _lock:
        for row in _conn(db).execute("SELECT * FROM orgs").fetchall():
            if secrets.compare_digest(_hash(key, row["key_salt"]), row["key_digest"]):
                return _org_row(row)
    return None


def rotate_api_key(org_id: str, db: str = DEFAULT_DB, actor: str = "system") -> dict:
    """Rotate an org's agent key. Returns the fresh key exactly once; the old
    key stops authenticating immediately."""
    with _lock:
        conn = _conn(db)
        if conn.execute("SELECT 1 FROM orgs WHERE id = ?", (org_id,)).fetchone() is None:
            raise LookupError(f"no account '{org_id}'")
        key = new_api_key()
        salt = uuid.uuid4().hex[:16]
        conn.execute(
            "UPDATE orgs SET key_digest = ?, key_salt = ? WHERE id = ?",
            (_hash(key, salt), salt, org_id),
        )
        conn.commit()
        log_event("org.rotate_key", actor=actor, target=org_id, detail={"outcome": "old key revoked"})
        return {"org_id": org_id, "api_key": key, "note": "returned once; the previous key stops working immediately"}


def save_agent_report(org_id: str, payload: dict, db: str = DEFAULT_DB) -> dict:
    """Store an agent's outbound report. Returns the stored report dict."""
    with _lock:
        conn = _conn(db)
        if conn.execute("SELECT 1 FROM orgs WHERE id = ?", (org_id,)).fetchone() is None:
            raise LookupError(f"no account '{org_id}'")
        rid = uuid.uuid4().hex[:16]
        scan = payload.get("scan") or {}
        meta = payload.get("meta") or {}
        conn.execute(
            """INSERT INTO agent_reports (id, org_id, received_at, network, devices, raw, meta)
               VALUES (?,?,?,?,?,?,?)""",
            (
                rid,
                org_id,
                datetime.datetime.now().isoformat(timespec="seconds"),
                scan.get("network") or meta.get("subnet"),
                len(scan.get("devices") or []),
                json.dumps(payload, default=str),
                json.dumps(meta),
            ),
        )
        conn.commit()
        log_event("agent.report", actor=org_id, target=rid, detail={
            "devices": len(scan.get("devices") or []),
            "network": scan.get("network"),
        })
        return _report_dict(conn.execute("SELECT * FROM agent_reports WHERE id = ?", (rid,)).fetchone())


def latest_agent_report(org_id: str, db: str = DEFAULT_DB) -> Optional[dict]:
    with _lock:
        row = _conn(db).execute(
            "SELECT * FROM agent_reports WHERE org_id = ? ORDER BY received_at DESC, rowid DESC LIMIT 1",
            (org_id,),
        ).fetchone()
    return _report_dict(row)


def _report_dict(row) -> Optional[dict]:
    if row is None:
        return None
    return {
        "id": row["id"],
        "org_id": row["org_id"],
        "received_at": row["received_at"],
        "network": row["network"],
        "devices": row["devices"],
        "raw": json.loads(row["raw"]),
        "meta": json.loads(row["meta"]),
    }


# --------------------------------------------------------------------------- #
# Dashboard users (RBAC)                                                      #
# --------------------------------------------------------------------------- #

def _pass_hash(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", (password or "").encode("utf-8"), salt.encode("ascii"), _PBKDF2_ITERATIONS
    ).hex()


def _user_row(row) -> dict:
    return {
        "id": row["id"],
        "org_id": row["org_id"],
        "username": row["username"],
        "role": row["role"],
        "created_at": row["created_at"],
    }


def create_user(org_id: str, username: str, password: str, role: str,
                db: str = DEFAULT_DB, actor: str = "system") -> dict:
    """Create a dashboard login scoped to an org. Raises ValueError on bad input."""
    org_id = (org_id or "").strip()
    username = (username or "").strip()
    if not org_id:
        raise ValueError("org_id is required")
    if not username:
        raise ValueError("username is required")
    if role not in ROLES:
        raise ValueError(f"role must be one of {', '.join(ROLES)}")
    if len(password or "") < 10:
        raise ValueError("password must be at least 10 characters long")
    with _lock:
        conn = _conn(db)
        if conn.execute("SELECT 1 FROM orgs WHERE id = ?", (org_id,)).fetchone() is None:
            raise LookupError(f"no account '{org_id}'")
        # Usernames are unique PER ORGANISATION (two orgs may each have an
        # "admin"); login is always scoped by org_id so there is no ambiguity.
        if conn.execute("SELECT 1 FROM users WHERE org_id = ? AND username = ?", (org_id, username)).fetchone():
            raise ValueError(f"a user '{username}' already exists in account '{org_id}'")
        uid = uuid.uuid4().hex[:12]
        salt = uuid.uuid4().hex[:16]
        conn.execute(
            "INSERT INTO users (id, org_id, username, pass_hash, pass_salt, role, created_at) VALUES (?,?,?,?,?,?,?)",
            (uid, org_id, username, _pass_hash(password, salt), salt, role,
             datetime.datetime.now().isoformat(timespec="seconds")),
        )
        conn.commit()
        log_event("user.create", actor=actor, target=uid, detail={"org_id": org_id, "username": username, "role": role})
        return _user_row(conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone())


def list_users(db: str = DEFAULT_DB, org_id: Optional[str] = None) -> list[dict]:
    with _lock:
        conn = _conn(db)
        if org_id:
            rows = conn.execute("SELECT * FROM users WHERE org_id = ? ORDER BY created_at ASC", (org_id,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM users ORDER BY org_id, created_at ASC").fetchall()
        return [_user_row(r) for r in rows]


def get_user_by_username(org_id: str, username: str, db: str = DEFAULT_DB) -> Optional[dict]:
    with _lock:
        row = _conn(db).execute(
            "SELECT * FROM users WHERE org_id = ? AND username = ?", (org_id, username),
        ).fetchone()
    return _user_row(row) if row else None


def delete_user(org_id: str, username: str, db: str = DEFAULT_DB, actor: str = "system") -> None:
    org_id = (org_id or "").strip()
    username = (username or "").strip()
    with _lock:
        conn = _conn(db)
        row = conn.execute("SELECT * FROM users WHERE org_id = ? AND username = ?", (org_id, username)).fetchone()
        if row is None:
            raise LookupError(f"no user '{username}' in account '{org_id}'")
        conn.execute("DELETE FROM users WHERE id = ?", (row["id"],))
        # Sessions live in a table owned by backend/security.py. In this
        # process it always exists (main.py calls init_sessions()), but
        # tenant.py is also used standalone by unit tests against a
        # tenant-only database — never assume the table exists.
        tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()}
        if "sessions" in tables:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (row["id"],))
            conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
        conn.commit()
        log_event("user.delete", actor=actor, detail={"org_id": org_id, "username": username, "role": row["role"]})


def login_org_user(org_id: str, username: str, password: str, db: str = DEFAULT_DB) -> Optional[dict]:
    """Validate an org-scoped dashboard user's password. Returns the user row or None.

    Logins are ALWAYS scoped to an organisation: the lookup never crosses org
    boundaries, so two orgs can share a username without any cross-org bypass.
    When `org_id` is empty (the legacy call shape), the lookup only succeeds if
    the username is unambiguous across all orgs; multiple matches are refused.
    """
    org_id = (org_id or "").strip()
    username = (username or "").strip()
    if not username or not password:
        return None
    with _lock:
        conn = _conn(db)
        if org_id:
            rows = conn.execute(
                "SELECT * FROM users WHERE org_id = ? AND username = ?", (org_id, username),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchall()
            if len(rows) > 1:
                return None  # ambiguous: the same username exists in several accounts
    for row in rows:
        if secrets.compare_digest(_pass_hash(password, row["pass_salt"]), row["pass_hash"]):
            return _user_row(row)
    return None