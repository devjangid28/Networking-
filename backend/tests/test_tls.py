"""TLS terminal enforcement: when the app is served behind a TLS reverse proxy
(NETPROOF_DOMAIN set), plain-HTTP requests coming through the proxy get bumped
to HTTPS, HTTPS responses carry HSTS, and internal (header-less) health checks
are left untouched."""
import pytest
from starlette.testclient import TestClient

import main


@pytest.fixture(autouse=True)
def _restore_tls_domain():
    """These tests mutate the module-level global ``main._TLS_DOMAIN``. Restore
    its imported value afterwards so the pollution never leaks into tests that
    run later in the session."""
    before = getattr(main, "_TLS_DOMAIN", "")
    yield
    main._TLS_DOMAIN = before


def _client():
    return TestClient(main.app, raise_server_exceptions=False, follow_redirects=False)


def test_no_tls_mode_no_redirect_no_hsts():
    main._TLS_DOMAIN = ""
    with _client() as cli:
        r = cli.get("/health", headers={"X-Forwarded-Proto": "http"})
        assert r.status_code == 200
        assert "Strict-Transport-Security" not in r.headers


def test_plain_http_bumps_to_https_307():
    main._TLS_DOMAIN = "netproof.example.com"
    with _client() as cli:
        r = cli.get("/api/orgs", headers={"X-Forwarded-Proto": "http", "Host": "netproof.example.com"})
        assert r.status_code == 307
        assert r.headers["location"].startswith("https://netproof.example.com/api/orgs")

        r2 = cli.get("/health", headers={"X-Forwarded-Proto": "http", "Host": "netproof.example.com"})
        assert r2.status_code == 307  # even health via public proto gets bumped


def test_https_gets_hsts():
    main._TLS_DOMAIN = "netproof.example.com"
    with _client() as cli:
        r = cli.get("/health", headers={"X-Forwarded-Proto": "https", "Host": "netproof.example.com"})
        assert r.status_code == 200
        assert r.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"


def test_headerless_internal_health_untouched():
    main._TLS_DOMAIN = "netproof.example.com"
    with _client() as cli:
        r = cli.get("/health")  # Docker/healthcheck hits :8000 directly, no proto header
        assert r.status_code == 200
        assert "Strict-Transport-Security" not in r.headers


def test_query_string_preserved_on_redirect():
    main._TLS_DOMAIN = "netproof.example.com"
    with _client() as cli:
        r = cli.get("/api/orgs?x=1&y=abc", headers={"X-Forwarded-Proto": "http", "Host": "netproof.example.com"})
        assert r.status_code == 307
        assert r.headers["location"] == "https://netproof.example.com/api/orgs?x=1&y=abc"