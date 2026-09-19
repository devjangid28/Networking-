"""Phase A5: global request-body size bound."""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json  # noqa: E402

import pytest  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

import limits as limits_mod  # noqa: E402
import main as main_mod  # noqa: E402

app = main_mod.app
LIMIT = 2048


@pytest.fixture(autouse=True)
def _small_limit(monkeypatch):
    monkeypatch.setenv("NETPROOF_MAX_BODY_BYTES", str(LIMIT))


def _payload(n: int) -> dict:
    return {"change": {"type": "add_filter_rule", "filter": "fw-inside-in",
                       "rule": {"action": "permit", "src": "10.0.20.0/24", "dst": "any", "proto": "any"}},
            "meta": "x" * n}


def _wire_len(n: int) -> int:
    # httpx's json= serialises compactly; mirror the true wire byte count.
    return len(json.dumps(_payload(n), separators=(",", ":")).encode("utf-8"))


def test_body_under_limit_passes():
    with TestClient(app, raise_server_exceptions=False) as cli:
        assert cli.post("/api/validate", json=_payload(10)).status_code == 200


def test_oversized_content_length_is_rejected_413():
    with TestClient(app, raise_server_exceptions=False) as cli:
        r = cli.post("/api/validate", json=_payload(LIMIT * 2))
        assert r.status_code == 413
        assert r.json()["detail"]


def test_exactly_at_limit_passes():
    assert _wire_len(0) < LIMIT
    n = LIMIT - _wire_len(0)
    with TestClient(app, raise_server_exceptions=False) as cli:
        r = cli.post("/api/validate", json=_payload(n))
        assert _wire_len(n) == LIMIT
        assert r.status_code == 200


def test_one_byte_over_limit_is_rejected():
    n = LIMIT - _wire_len(0) + 1
    with TestClient(app, raise_server_exceptions=False) as cli:
        r = cli.post("/api/validate", json=_payload(n))
        assert _wire_len(n) == LIMIT + 1
        assert r.status_code == 413


def test_chunked_body_without_content_length_is_streamed_and_capped():
    with TestClient(app, raise_server_exceptions=False) as cli:
        r = cli.post("/api/validate",
                     content=(chunk for chunk in (b'{"a": "' + b"x" * 1800, b"y" * LIMIT + b'"}')),
                     headers={"Content-Type": "application/json"})
        assert r.status_code == 413


def test_default_limit_documented():
    os.environ.pop("NETPROOF_MAX_BODY_BYTES", None)
    assert limits_mod.DEFAULT_MAX_BODY_BYTES == 8 * 1024 * 1024
    assert limits_mod.max_body_bytes() == limits_mod.DEFAULT_MAX_BODY_BYTES


def test_env_override_takes_effect():
    assert limits_mod.max_body_bytes() == LIMIT


def test_get_requests_unaffected():
    with TestClient(app, raise_server_exceptions=False) as cli:
        assert cli.get("/api/network").status_code == 200


def test_413_response_carries_security_headers():
    with TestClient(app, raise_server_exceptions=False) as cli:
        r = cli.post("/api/validate", json=_payload(LIMIT * 2))
        assert r.status_code == 413
        assert r.headers["content-security-policy"]
        assert r.headers["x-netproof-request-id"]
