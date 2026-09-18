"""HTTP session auth for the NetProof dashboard.

The demo/landing endpoints stay public. Human-facing dashboard operations
(org management, agent-mode reads) require a login session carried in an
httponly cookie.

Credentials:
- The global admin account comes from the environment
  (NETPROOF_ADMIN_USER / NETPROOF_ADMIN_PASS). It is always role "admin" and
  sees every org.
- Additional dashboard users are org-scoped rows in the `users` table
  (engine.tenant) with roles admin/operator/viewer. Their passwords are
  salted PBKDF2 digests, never plaintext.

Sessions are stored in SQLite so they survive restarts.
"""
from __future__ import annotations

import datetime
import os
import secrets
import sqlite3
import threading
from pathlib import Path
from typing import Optional

from fastapi import HTTPException, Request

from engine.audit import DEFAULT_DB
from engine import tenant as tenant_store

SESSION_COOKIE = "netproof_session"
_SESSION_LIFE = datetime.timedelta(days=7)

_ROLE_RANK = {"viewer": 1, "operator": 2, "admin": 3}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    user_id    TEXT,
    role       TEXT NOT NULL,
    org_id     TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
"""

_conns: dict[str, sqlite3.Connection] = {}
_lock = threading.RLock()


def _ensure_columns(conn: sqlite3.Connection) -> None:
    """Migrate legacy sessions rows (pre-RBAC) so old cookies keep validating."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(sessions)").fetchall()}
    if "role" not in cols:
        conn.execute("ALTER TABLE sessions ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'")
    if "org_id" not in cols:
        conn.execute("ALTER TABLE sessions ADD COLUMN org_id TEXT NOT NULL DEFAULT ''")
    if "user_id" not in cols:
        conn.execute("ALTER TABLE sessions ADD COLUMN user_id TEXT")
    conn.commit()


def _conn(db: str = DEFAULT_DB) -> sqlite3.Connection:
    with _lock:
        conn = _conns.get(db)
        if conn is None:
            Path(db).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(db, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.executescript(_SCHEMA)
            _ensure_columns(conn)
            _conns[db] = conn
        return conn


def init_sessions(db: str = DEFAULT_DB) -> None:
    # Startup validation: the admin password must be configured. Called by the
    # app entrypoint so an unconfigured server fails loudly at boot, not when
    # someone first tries to log in.
    admin_credentials()
    _conn(db)


def admin_credentials() -> tuple[str, str]:
    """Global admin credentials come ONLY from the environment.

    There is deliberately no fallback default: running with a known
    admin/admin password is a remote-code-execution-by-default. If the password
    is not configured the process refuses to start instead of silently
    accepting the credentials everyone knows.
    """
    user = os.environ.get("NETPROOF_ADMIN_USER") or "admin"
    pwd = os.environ.get("NETPROOF_ADMIN_PASS") or ""
    if not pwd:
        raise RuntimeError(
            "NETPROOF_ADMIN_PASS is not set. Refusing to start with an empty admin "
            "password — configure it explicitly (docker-compose .env / the shell)."
        )
    return user, pwd


def _create_session(username: str, role: str, org_id: str, db: str, user_id: Optional[str] = None) -> str:
    token = secrets.token_urlsafe(32)
    now = datetime.datetime.now()
    with _lock:
        conn = _conn(db)
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now.isoformat(timespec="seconds"),))
        conn.execute(
            "INSERT INTO sessions (token, username, user_id, role, org_id, created_at, expires_at) VALUES (?,?,?,?,?,?,?)",
            (token, username, user_id, role, org_id, now.isoformat(timespec="seconds"),
             (now + _SESSION_LIFE).isoformat(timespec="seconds")),
        )
        conn.commit()
    return token


def login(username: str, password: str, org_id: str = "", db: str = DEFAULT_DB) -> Optional[dict]:
    """Validate credentials; on success create a session.

    Returns {token, username, role, org_id} or None. The global admin (env
    credentials) wins; otherwise an org-scoped dashboard user is tried, scoped
    to the organisation being logged into (`org_id`).
    """
    user, pwd = admin_credentials()
    if secrets.compare_digest(str(username or ""), user) and secrets.compare_digest(str(password or ""), pwd):
        token = _create_session(user, "admin", "", db)
        return {"token": token, "username": user, "role": "admin", "org_id": ""}

    row = tenant_store.login_org_user(org_id or "", username or "", password or "", db=db)
    if row is None:
        return None
    token = _create_session(row["username"], row["role"], row["org_id"], db, user_id=row["id"])
    return {"token": token, "username": row["username"], "role": row["role"], "org_id": row["org_id"]}


def user_for_token(token, db: str = DEFAULT_DB) -> Optional[dict]:
    if not token:
        return None
    with _lock:
        conn = _conn(db)
        row = conn.execute("SELECT username, role, org_id, expires_at FROM sessions WHERE token = ?", (token,)).fetchone()
    if row is None:
        return None
    if row["expires_at"] <= datetime.datetime.now().isoformat(timespec="seconds"):
        return None
    return {"username": row["username"], "role": row["role"], "org_id": row["org_id"]}


def logout(token, db: str = DEFAULT_DB) -> None:
    if not token:
        return
    with _lock:
        conn = _conn(db)
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()


def require_session(request: Request) -> dict:
    """FastAPI dependency: 401 unless a valid session cookie is present.

    Returns the session info dict {username, role, org_id}.
    """
    info = user_for_token(request.cookies.get(SESSION_COOKIE))
    if info is None:
        raise HTTPException(status_code=401, detail="authentication required")
    return info


def require_role(request: Request, minimum: str = "operator") -> dict:
    """FastAPI dependency factory: session + minimum role rank.

    admin > operator > viewer. Raises 403 when the session's role is below
    `minimum`, 401 when unauthenticated.
    """
    info = require_session(request)
    if _ROLE_RANK.get(info["role"], 0) < _ROLE_RANK.get(minimum, 0):
        raise HTTPException(status_code=403, detail=f"role '{minimum}' or higher required")
    return info


def require_admin(request: Request) -> dict:
    return require_role(request, "admin")