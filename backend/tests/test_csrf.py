"""Phase A3: CSRF origin enforcement for cookie-authenticated state changes."""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from starlette.testclient import TestClient  # noqa: E402

import main as main_mod  # noqa: E402

app = main_mod.app
ADMIN_PASS = os.environ["NETPROOF_ADMIN_PASS"]
EVIL = "https://evil.example"


def login(client: TestClient) -> None:
    r = client.post("/api/login", json={"username": "admin", "password": ADMIN_PASS})
    assert r.status_code == 200


def create_org(client: TestClient, origin: str | None = None, referer: str | None = None) -> None:
    headers = {}
    if origin is not None:
        headers["Origin"] = origin
    if referer is not None:
        headers["Referer"] = referer
    return client.post("/api/orgs", json={"name": f"CsrfOrg-{os.urandom(3).hex()}"}, headers=headers)


def test_nobrowser_no_origin_request_is_allowed():
    with TestClient(app, raise_server_exceptions=False) as cli:
        login(cli)
        r = create_org(cli)
        assert r.status_code == 200


def test_same_origin_is_allowed():
    with TestClient(app, raise_server_exceptions=False) as cli:
        login(cli)
        r = create_org(cli, origin=str(cli.base_url))
        assert r.status_code == 200


def test_cross_origin_is_rejected():
    with TestClient(app, raise_server_exceptions=False) as cli:
        login(cli)
        r = create_org(cli, origin=EVIL)
        assert r.status_code == 403
        assert r.json()["detail"]


def test_null_origin_is_rejected():
    with TestClient(app, raise_server_exceptions=False) as cli:
        login(cli)
        r = create_org(cli, origin="null")
        assert r.status_code == 403


def test_cross_origin_without_cookie_is_allowed():
    with TestClient(app, raise_server_exceptions=False) as cli:
        r = create_org(cli, origin=EVIL)
        assert r.status_code == 401  # reaches the endpoint, fails at auth — not CSRF


def test_login_is_exempt_from_origin_check():
    with TestClient(app, raise_server_exceptions=False) as cli:
        r = cli.post("/api/login", json={"username": "admin", "password": ADMIN_PASS}, headers={"Origin": EVIL})
        assert r.status_code == 200


def test_evil_referer_is_rejected_when_origin_missing():
    with TestClient(app, raise_server_exceptions=False) as cli:
        login(cli)
        r = create_org(cli, referer=f"{EVIL}/malicious")
        assert r.status_code == 403


def test_good_referer_allows_when_origin_missing():
    with TestClient(app, raise_server_exceptions=False) as cli:
        login(cli)
        r = create_org(cli, referer=f"{cli.base_url}/dashboard")
        assert r.status_code == 200


def test_get_request_not_affected():
    with TestClient(app, raise_server_exceptions=False) as cli:
        login(cli)
        assert cli.get("/api/orgs", headers={"Origin": EVIL}).status_code == 200


def test_rejected_response_still_carries_security_headers():
    with TestClient(app, raise_server_exceptions=False) as cli:
        login(cli)
        r = create_org(cli, origin=EVIL)
        assert r.headers["content-security-policy"]
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-netproof-request-id"]
