"""Rate limiting trusts real client IPs only when the app is behind a trusted
proxy.

Without a proxy: X-Forwarded-For / X-Real-IP are IGNORED, so a direct client
cannot forge headers to open endless fresh buckets for itself.

Behind a proxy (NETPROOF_TRUST_PROXY=1 or NETPROOF_DOMAIN set): the real
client IP is the RIGHT-MOST X-Forwarded-For value — the hop the trusted proxy
itself appended — so all customers share one bucket each instead of all
funnelling through the proxy's IP.
"""
import pytest
from fastapi.testclient import TestClient

import ratelimit
from main import app


class _FakeRequest:
    def __init__(self, host, headers):
        self.client = type("C", (), {"host": host})()
        self.headers = headers


def _cli():
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def _no_proxy_env(monkeypatch):
    monkeypatch.delenv("NETPROOF_TRUST_PROXY", raising=False)
    monkeypatch.delenv("NETPROOF_DOMAIN", raising=False)


def test_forwarded_headers_ignored_when_untrusted(monkeypatch):
    """A direct client sending spoofed X-Forwarded-For / X-Real-IP headers
    must NOT get extra buckets — the spoof is ignored, one bucket per real IP."""
    monkeypatch.delenv("NETPROOF_TRUST_PROXY", raising=False)
    monkeypatch.delenv("NETPROOF_DOMAIN", raising=False)
    ratelimit.reset("*", "*")

    req = _FakeRequest("1.2.3.4", {
        "x-forwarded-for": "9.9.9.9",
        "x-real-ip": "8.8.8.8",
    })
    for _ in range(3):
        assert ratelimit.allow(req, "spoof", limit=3, window=60.0) is True
    # still the same 1.2.3.4 bucket: the forged IPs bought nothing
    assert ratelimit.allow(req, "spoof", limit=3, window=60.0) is False

    ratelimit.reset("*", "*")


def test_trusted_proxy_uses_rightmost_forwarded_client(monkeypatch):
    monkeypatch.setenv("NETPROOF_TRUST_PROXY", "1")
    ratelimit.reset("*", "*")

    # request arrives via proxy 10.0.0.2; the value the proxy APPENDED is the
    # right-most entry — the client-injected head is ignored
    a = _FakeRequest("10.0.0.2", {"x-forwarded-for": "9.9.9.9, 1.2.3.4"})
    b = _FakeRequest("10.0.0.2", {"x-forwarded-for": "9.9.9.9, 1.2.3.5"})

    for _ in range(3):
        assert ratelimit.allow(a, "proxied", limit=3) is True
    assert ratelimit.allow(a, "proxied", limit=3) is False  # 1.2.3.4 bucket full
    # the OTHER real client behind the same proxy has its OWN bucket
    for _ in range(3):
        assert ratelimit.allow(b, "proxied", limit=3) is True
    assert ratelimit.allow(b, "proxied", limit=3) is False

    ratelimit.reset("*", "*")


def test_proxy_mode_falls_back_to_real_ip_when_no_forwarded_header(monkeypatch):
    monkeypatch.setenv("NETPROOF_TRUST_PROXY", "1")
    ratelimit.reset("*", "*")
    req = _FakeRequest("127.0.0.9", {"x-real-ip": "5.5.5.5"})
    for _ in range(2):
        assert ratelimit.allow(req, "xreal", limit=2) is True
    assert ratelimit.allow(req, "xreal", limit=2) is False
    ratelimit.reset("*", "*")


def test_login_gets_its_own_proxy_client_bucket_and_spoof_cannot_escape(monkeypatch):
    """App-level proof through /api/login: NOT behind a proxy, a spoofed
    X-Forwarded-For must not dodge the 5/min per-IP limit."""
    monkeypatch.delenv("NETPROOF_TRUST_PROXY", raising=False)
    monkeypatch.delenv("NETPROOF_DOMAIN", raising=False)
    cli = _cli()
    for i in range(5):
        r = cli.post("/api/login", json={
            "username": "admin", "password": "admin-test-pass-2026",
        }, headers={"X-Forwarded-For": f"6.6.6.{i}"})  # spoof a fresh IP each call
        assert r.status_code == 200, i
    r = cli.post("/api/login", json={
        "username": "admin", "password": "admin-test-pass-2026",
    }, headers={"X-Forwarded-For": "6.6.6.99"})
    assert r.status_code == 429


def test_all_proxy_clients_share_one_login_bucket_not_the_proxy_ip(monkeypatch):
    """Behind a trusted proxy, two real clients behind the SAME proxy IP still
    get independent buckets (no global lockout and no shared blowout)."""
    monkeypatch.setenv("NETPROOF_TRUST_PROXY", "1")
    cli = _cli()
    for _ in range(5):
        assert cli.post("/api/login", json={
            "username": "admin", "password": "admin-test-pass-2026",
        }, headers={"X-Forwarded-For": "203.0.113.7"}).status_code == 200
    assert cli.post("/api/login", json={
        "username": "admin", "password": "admin-test-pass-2026",
    }, headers={"X-Forwarded-For": "203.0.113.7"}).status_code == 429
    # a different customer behind the same proxy keeps its own allowance
    assert cli.post("/api/login", json={
        "username": "admin", "password": "admin-test-pass-2026",
    }, headers={"X-Forwarded-For": "203.0.113.8"}).status_code == 200