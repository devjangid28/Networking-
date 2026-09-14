"""Multi-tenant accounts + outbound agent reports.

NetProof is a neutral referee — it never walks into a customer network. A local
`agent/` binary runs INSIDE the customer network, discovers it, and posts the
result OUTBOUND to this server under an API key bound to an org/account. The
dashboard then renders whatever the account's latest report says; the server
itself never performs a live scan against the customer LAN.

Tables live in the same SQLite store as the audit trail (default netproof.db):
    orgs           id, name, api_key, created_at
    agent_reports  id, org_id, received_at, network, devices, raw, meta
"""
from __future__ import annotations

import datetime
import json
import os
import secrets
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Optional

from .audit import DEFAULT_DB

_SCHEMA = """
CREATE TABLE IF NOT EXISTS orgs (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    api_key     TEXT NOT NULL UNIQUE,
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
"""

_conns: dict[str, sqlite3.Connection] = {}
_lock = threading.RLock()


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


def init_tenant() -> None:
    """Create tables on startup. Idempotent."""
    _conn()


def new_api_key() -> str:
    return secrets.token_urlsafe(24)


def _org_row(row) -> Optional[dict]:
    if row is None:
        return None
    return {"id": row["id"], "name": row["name"], "api_key": row["api_key"], "created_at": row["created_at"]}


def create_org(name: str, db: str = DEFAULT_DB) -> dict:
    name = (name or "").strip()
    if not name:
        raise ValueError("org name is required")
    with _lock:
        conn = _conn(db)
        if conn.execute("SELECT 1 FROM orgs WHERE name = ?", (name,)).fetchone():
            raise ValueError(f"an account named '{name}' already exists")
        oid = uuid.uuid4().hex[:8]
        key = new_api_key()
        conn.execute(
            "INSERT INTO orgs (id, name, api_key, created_at) VALUES (?,?,?,?)",
            (oid, name, key, datetime.datetime.now().isoformat(timespec="seconds")),
        )
        conn.commit()
        return _org_row(conn.execute("SELECT * FROM orgs WHERE id = ?", (oid,)).fetchone())


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


def get_org(org_id: str, db: str = DEFAULT_DB) -> Optional[dict]:
    with _lock:
        return _org_row(_conn(db).execute("SELECT * FROM orgs WHERE id = ?", (org_id,)).fetchone())


def get_org_by_api_key(key: str, db: str = DEFAULT_DB) -> Optional[dict]:
    with _lock:
        return _org_row(_conn(db).execute("SELECT * FROM orgs WHERE api_key = ?", (key,)).fetchone())


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