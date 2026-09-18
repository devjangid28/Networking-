"""Agent transport security: the agent must refuse to ship the API key over
plain HTTP to any non-loopback backend, must accept HTTPS, and must actually
verify the server certificate (no silent downgrade to unverified TLS)."""
import http.server
import ipaddress
import os
import ssl
import sys
import threading

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)

from agent import agent as agent_mod  # noqa: E402


def test_plain_http_to_lan_rejected():
    with pytest.raises(ValueError, match="refusing to send the API key over plain HTTP"):
        agent_mod.validate_backend("http://192.168.1.5:8000")


def test_plain_http_to_hostname_rejected():
    with pytest.raises(ValueError, match="plain HTTP"):
        agent_mod.validate_backend("http://netproof.example.com")


def test_https_accepted():
    assert agent_mod.validate_backend("https://netproof.example.com") == "https://netproof.example.com"


def test_loopback_http_allowed_for_local_dev():
    assert agent_mod.validate_backend("http://127.0.0.1:8000") == "http://127.0.0.1:8000"
    assert agent_mod.validate_backend("http://localhost:8000") == "http://localhost:8000"


def test_allow_http_override(monkeypatch):
    monkeypatch.setenv("NETPROOF_ALLOW_HTTP", "1")
    assert agent_mod.validate_backend("http://netproof.example.com") == "http://netproof.example.com"


def test_bad_scheme_rejected():
    with pytest.raises(ValueError, match="http"):
        agent_mod.validate_backend("ftp://netproof.example.com")
    with pytest.raises(ValueError, match="required"):
        agent_mod.validate_backend("")


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *args):  # silence test output
        pass


def test_report_over_https_verifies_server_certificate():
    """Point the agent's _post at a local HTTPS endpoint whose cert is NOT
    trusted. The default verification must refuse it (status 0, TLS/SSL error),
    proving we never silently accept unverified certificates."""
    import datetime
    import tempfile

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                       critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with tempfile.TemporaryDirectory() as tmp:
        cert_file = os.path.join(tmp, "cert.pem")
        key_file = os.path.join(tmp, "key.pem")
        with open(cert_file, "wb") as f:
            f.write(cert_pem)
        with open(key_file, "wb") as f:
            f.write(key_pem)

        srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_file, key_file)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        port = srv.server_address[1]

        def serve():
            try:
                srv.handle_request()
            except Exception:
                pass  # client aborts the handshake when verification fails

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        try:
            res = agent_mod._post(f"https://127.0.0.1:{port}", "KEY123", {"x": 1})
            assert res["ok"] is False
            assert res["status"] == 0
            assert res["body"]  # non-empty error detail, no ssl-context overrides
        finally:
            srv.server_close()