"""Phase A2: adversary-style security probes against the Phase A hardening.

Everything that reaches the wire must hold under abuse: header injection into
the correlation id, error responses staying hardened, CSRF evasions (origin
spoofing / port confusion / reference smuggling), body-size bypasses (lying or
malformed Content-Length, chunked floods), rate-limit behaviour with a revoked
ors flooded session, TLS proxy-header spoofing, and the redaction gaps the
evidence surface could leak through.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main as main_mod  # noqa: E402
import security_headers as sh  # noqa: E402
from engine import postchange as pc  # noqa: E402

app = main_mod.app
ADMIN_PASS = os.environ.get("NETPROOF_ADMIN_PASS", "admin-test-pass-2026")
EVIL = "https://evil.example"
HOST = "testserver"
REQ_ID = sh.REQUEST_ID_HEADER
ID_PATTERN = re.compile(r"^[A-Za-z0-9._:/-]{1,128}$")


def login(client: TestClient) -> None:
    r = client.post("/api/login", json={"username": "admin", "password": ADMIN_PASS})
    assert r.status_code == 200, r.text


def create_org(client: TestClient, **headers) -> TestClient:
    return client.post("/api/orgs", json={"name": f"Advo-{os.urandom(3).hex()}"}, headers=headers)


STRICT_HEADERS = ("content-security-policy", "x-content-type-options",
                  "x-frame-options", "referrer-policy", "permissions-policy")


@pytest.mark.parametrize("candidate", [
    "abc\r\nX-Injected: 1",
    "</script><script>alert(1)</script>",
    "a" * 128 + "!",
    "snowman \u00e2\u0098\u0083 injection",
    "",
    None,
])
def test_request_id_never_reflects_hostile_input(candidate):
    resolved = sh.resolve_request_id(candidate)
    assert ID_PATTERN.match(resolved)
    assert resolved != candidate


def test_hostile_request_id_over_the_wire():
    injected = "</script><script>alert(1)</script>"
    with TestClient(app, raise_server_exceptions=False) as cli:
        r = cli.get("/health", headers={REQ_ID: injected})
        got = r.headers.get(REQ_ID)
        assert got != injected
        assert ID_PATTERN.match(got)
        assert "\r" not in got and "\n" not in got


# --------------------------------------------------------------------------- #
# hardened error responses                                                     #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("method, path, kwargs", [
    ("post", "/api/login", {"json": {"username": "admin", "password": "wrong-wrong-wrong"}}),
    ("get", "/api/verifications/nope", {}),
    ("get", "/api/orgs/nope", {}),
], ids=["401-unauthorized", "404-verification", "404-org"])
def test_error_responses_carry_strict_headers_and_request_id(method, path, kwargs):
    with TestClient(app, raise_server_exceptions=False) as cli:
        r = getattr(cli, method)(path, **kwargs)
    assert r.status_code in (401, 404)
    for header in STRICT_HEADERS:
        assert r.headers.get(header), header
    assert r.headers.get(REQ_ID)


def test_csrf_403_still_has_fingerprinting_deterministic_request_id():
    with TestClient(app, raise_server_exceptions=False) as cli:
        login(cli)
        r = create_org(cli, Origin=EVIL)
        assert r.status_code == 403
        assert r.headers.get("x-frame-options") == "DENY"
        assert r.headers.get("x-content-type-options") == "nosniff"
        assert r.headers.get(REQ_ID)


# --------------------------------------------------------------------------- #
# CSRF evasion                                                                #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("origin", [
    "NULL",
    " null ",
    "nullcircumstance",
    "https://testserver:1337",
    "https://testserver.evil.example",
    "https://evil.example.testserver",
    "http://evil.example",
    "https://evil.example,testserver",
    "not-a-url",
    "///evil.example/x",
], ids=["upper-null", "padded-null", "nullish", "cross-port", "suffix-host",
        "prefix-host", "cross-origin", "comma-merged", "not-a-url", "triple-slash"])
def test_cross_site_origin_variants_rejected(origin):
    with TestClient(app, raise_server_exceptions=False) as cli:
        login(cli)
        r = create_org(cli, Origin=origin)
        assert r.status_code == 403
        assert r.json()["detail"]


def test_same_host_origin_with_uppercase_and_trailing_slash_allowed():
    with TestClient(app, raise_server_exceptions=False) as cli:
        login(cli)
        r = create_org(cli, Origin=f"https://{HOST}/")
        assert r.status_code == 200
        r = create_org(cli, Origin=f"HTTPS://{HOST.upper()}")
        assert r.status_code == 200


def test_same_host_but_cross_port_rejected():
    with TestClient(app, raise_server_exceptions=False) as cli:
        login(cli)
        assert create_org(cli, Origin="https://testserver:9999").status_code == 403


@pytest.mark.parametrize("referer", [
    f"{EVIL}/orgs/create",
    "//evil.example/orgs",
    "null",
    "https://testserver:9999/orgs",
    "https://evil.example@testserver/orgs",
], ids=["evil-path", "scheme-relative", "null-string", "cross-port", "userinfo-swap"])
def test_referer_variants_rejected_when_origin_missing(referer):
    with TestClient(app, raise_server_exceptions=False) as cli:
        login(cli)
        r = create_org(cli, Referer=referer)
        assert r.status_code == 403


def test_duplicate_origin_headers_first_wins():
    with TestClient(app, raise_server_exceptions=False) as cli:
        login(cli)
        r = cli.post("/api/orgs", json={"name": f"Advo-{os.urandom(3).hex()}"},
                     headers=[("Origin", EVIL), ("Origin", f"http://{HOST}")])
        assert r.status_code == 403


# --------------------------------------------------------------------------- #
# body-size bypass                                                             #
# --------------------------------------------------------------------------- #

LIMIT = 2048


@pytest.fixture(autouse=True)
def _cap_body(monkeypatch):
    monkeypatch.setenv("NETPROOF_MAX_BODY_BYTES", str(LIMIT))
    yield


def _big_json(extra: int) -> bytes:
    import json as _j
    payload = {"change": {"type": "add_filter_rule", "filter": "fw-inside-in",
                          "rule": {"action": "permit", "src": "10.0.20.0/24", "dst": "any", "proto": "any"}},
               "meta": "y" * extra}
    return _j.dumps(payload, separators=(",", ":")).encode("utf-8")


def test_lying_content_length_small_header_big_body_rejected():
    body = _big_json(LIMIT * 2)
    with TestClient(app, raise_server_exceptions=False) as cli:
        r = cli.post("/api/validate", content=body,
                     headers={"Content-Type": "application/json", "Content-Length": "3"})
        assert r.status_code == 413


def test_malformed_content_length_still_capped_by_stream_guard():
    body = _big_json(LIMIT * 2)
    with TestClient(app, raise_server_exceptions=False) as cli:
        r = cli.post("/api/validate", content=body,
                     headers={"Content-Type": "application/json", "Content-Length": "banana"})
        assert r.status_code == 413


def test_negative_content_length_still_capped_by_stream_guard():
    body = _big_json(LIMIT * 2)
    with TestClient(app, raise_server_exceptions=False) as cli:
        r = cli.post("/api/validate", content=body,
                     headers={"Content-Type": "application/json", "Content-Length": "-5"})
        assert r.status_code == 413


def test_chunked_flood_of_many_small_chunks_capped():
    def flood():
        for _ in range(300):
            yield b"z" * 10
    with TestClient(app, raise_server_exceptions=False) as cli:
        r = cli.post("/api/validate", content=flood(),
                     headers={"Content-Type": "application/json"})
        assert r.status_code == 413


# --------------------------------------------------------------------------- #
# rate limit + session replay                                                  #
# --------------------------------------------------------------------------- #

def test_rate_limit_429_still_hardened(monkeypatch):
    monkeypatch.setattr(main_mod.ratelimit, "allow", lambda *a, **k: False)
    with TestClient(app, raise_server_exceptions=False) as cli:
        r = cli.post("/api/login", json={"username": "admin", "password": ADMIN_PASS})
        assert r.status_code == 429
        for header in STRICT_HEADERS:
            assert r.headers.get(header), header
        assert r.headers.get(REQ_ID)


def test_revoked_session_cookie_no_longer_authenticates():
    with TestClient(app, raise_server_exceptions=False) as cli:
        assert cli.post("/api/login", json={"username": "admin", "password": ADMIN_PASS}).status_code == 200
        stale = dict(cli.cookies)
        assert cli.post("/api/logout").status_code == 200
        replay = TestClient(app, raise_server_exceptions=False)
        replay.cookies.update(stale)
        sess = replay.get("/api/session").json()
        assert sess["authenticated"] is False
        assert replay.post("/api/orgs", json={"name": "Stale-Org"}).status_code == 401


# --------------------------------------------------------------------------- #
# TLS proxy-header spoofing (domain-not-set default)                           #
# --------------------------------------------------------------------------- #

def test_forged_forwarded_proto_gets_no_hsts_when_domain_unset():
    with TestClient(app, raise_server_exceptions=False) as cli:
        for proto in ("https", "http", "https:evil"):
            r = cli.get("/health", headers={"X-Forwarded-Proto": proto, "Host": "victim.example"})
            assert r.status_code == 200
            assert "strict-transport-security" not in r.headers


def test_forged_forwarded_https_does_not_upgrade_when_domain_unset():
    with TestClient(app, raise_server_exceptions=False) as cli:
        r = cli.post("/api/login", json={"username": "admin", "password": ADMIN_PASS},
                     headers={"X-Forwarded-Proto": "https", "Host": "victim.example"})
        assert r.status_code == 200
        assert "location" not in r.headers  # no proxy-induced redirect on a forged header


# --------------------------------------------------------------------------- #
# redaction gaps                                                               #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("key", [
    "ADMIN_PASS", "DB_PASS", "root_pass", "app_pass", "master_pass",
    "login_pass", "passcode", "netproof_admin_pass",
])
def test_env_style_credential_keys_redacted(key):
    assert pc.redact_secrets({key: "hunter2"})[key] == "[REDACTED]"
    assert pc.sensitives_present({key: "hunter2"}) is True
    assert pc.sensitives_present(pc.redact_secrets({key: "hunter2"})) is False


def test_stringified_json_credentials_still_caught():
    blob = '{"connection": {"host":"db.internal","password":"behind-the-json","user":"app"}}'
    out = pc.redact_secrets({"memo": blob})["memo"]
    assert "behind-the-json" not in out


@pytest.mark.parametrize("benign", ["bypass", "passenger", "bypass_dmz", "compass_heading"])
def test_no_false_positive_on_pass_containing_keys(benign):
    doc = {benign: "meaningful value", "inner": {"enabled": "yes"}, "x": 1}
    assert pc.redact_secrets(doc) == doc
    assert pc.sensitives_present(doc) is False


def test_redaction_leaves_no_raw_secret_in_exported_wire():
    doc = {"wifi": {"wpa_passphrase": "psk", "preSharedKey": "alt"},
           "notes": "Authorization: Bearer tok.eyJhbGciOiJIUzI1NiJ9.xyz"}
    dumped = str(pc.redact_secrets(doc))
    for leak in ("psk", "tok.eyJhbGciOiJIUzI1NiJ9.xyz", "\\\"alt\\\""):
        assert leak not in dumped
