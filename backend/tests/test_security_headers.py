"""Phase A4: strict security response headers + request correlation id."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from starlette.testclient import TestClient  # noqa: E402

import main as main_mod  # noqa: E402
import security_headers as sh  # noqa: E402

app = main_mod.app
REQ_ID = sh.REQUEST_ID_HEADER


def test_every_api_response_carries_the_security_headers():
    with TestClient(app) as client:
        for path in ["/health", "/api/session", "/api/network", "/metrics", "/openapi.json"]:
            r = client.get(path)
            assert r.status_code < 500, path
            assert r.headers["content-security-policy"], path
            assert r.headers["x-content-type-options"] == "nosniff", path
            assert r.headers["x-frame-options"].lower() == "deny", path
            assert r.headers["referrer-policy"], path
            assert r.headers["permissions-policy"], path
            assert r.headers[REQ_ID], path


def test_csp_is_strict_and_self_contained():
    with TestClient(app) as client:
        csp = client.get("/api/session").headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "unsafe-inline" not in csp.replace("style-src 'self' 'unsafe-inline'", "")
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp


def test_request_id_is_echoed_when_caller_supplies_a_sane_token():
    with TestClient(app) as client:
        r = client.get("/api/session", headers={REQ_ID: "agent-abc-123"})
        assert r.headers[REQ_ID] == "agent-abc-123"


def test_malicious_request_id_is_replaced_with_a_fresh_one():
    with TestClient(app) as client:
        r = client.get("/api/session", headers={REQ_ID: "good\r\nX-Injected: 1"})
        fresh = r.headers[REQ_ID]
        assert fresh != "good"
        assert "X-Injected" not in r.headers
        assert len(fresh) == 32


def test_request_id_is_generated_when_absent():
    with TestClient(app) as client:
        r = client.get("/api/session")
        rid = r.headers[REQ_ID]
        assert len(rid) == 32 and all(c in "0123456789abcdef" for c in rid)


def test_op8_extension_appends_to_csp(monkeypatch):
    monkeypatch.setenv("NETPROOF_CSP_SRC", "connect-src https://grafana.internal")
    with TestClient(app) as client:
        csp = client.get("/api/session").headers["content-security-policy"]
    assert "connect-src https://grafana.internal" in csp


def test_static_assets_also_get_security_headers():
    with TestClient(app) as client:
        r = client.get("/static/app.js")
        assert r.status_code == 200
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers[REQ_ID]


def test_tls_bump_response_carries_headers(monkeypatch):
    monkeypatch.setattr(main_mod, "_TLS_DOMAIN", "net.example")
    with TestClient(app) as client:
        r = client.get("/api/network", headers={"host": "net.example", "x-forwarded-proto": "http"},
                       follow_redirects=False)
    assert r.status_code == 307
    assert r.headers[REQ_ID]
    assert r.headers["content-security-policy"]
