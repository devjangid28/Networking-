"""Append-only audit-event log.

One row per meaningful action (login/logout, org created / key rotated, agent
report accepted, scan performed, validation run). This is the "who did what,
when, against what" record the dashboard can show to prove the referee never
acted without a trace.
"""
from __future__ import annotations

import datetime
import json
import sqlite3
import threading
import uuid
from pathlib import Path

from .audit import DEFAULT_DB

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    id        TEXT PRIMARY KEY,
    at        TEXT NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    target    TEXT,
    detail    TEXT NOT NULL,
    ip        TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_at ON audit_events (at DESC);
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


def init_events(db: str = DEFAULT_DB) -> None:
    _conn(db)


def log_event(action: str, actor: str = "?", target: str | None = None,
              detail: str | dict | None = None, ip: str | None = None,
              db: str = DEFAULT_DB) -> str:
    if isinstance(detail, dict):
        detail = json.dumps(detail, default=str)[:4000]
    else:
        detail = str(detail or "")[:4000]
    eid = uuid.uuid4().hex[:12]
    with _lock:
        conn = _conn(db)
        conn.execute(
            "INSERT INTO audit_events (id, at, actor, action, target, detail, ip) VALUES (?,?,?,?,?,?,?)",
            (eid, datetime.datetime.now().isoformat(timespec="seconds"),
             str(actor or "?")[:120], str(action or "")[:120], str(target or "")[:4000], detail, str(ip or "")[:64]),
        )
        conn.commit()
    return eid


def list_events(limit: int = 60, db: str = DEFAULT_DB) -> list[dict]:
    with _lock:
        rows = _conn(db).execute(
            "SELECT * FROM audit_events ORDER BY at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]