"""Default security response headers and per-request correlation ids (Phase A4).

Every response (static + API) gets a strict Content-Security-Policy and the
defensive headers below. The CSP is deliberately strict: the dashboard wires
every handler through addEventListener and styles come from styles.css / Google
Fonts, so no inline script or style-tag allowance is needed for ``script-src``;
``style-src 'unsafe-inline'`` is required because app.js injects ``style=``
attributes via innerHTML templates.

Operators may append extra allowlisted sources (e.g. an embedded Grafana) with
``NETPROOF_CSP_SRC`` (space-separated directives appended to the CSP), e.g.
``NETPROOF_CSP_SRC="connect-src https://grafana.example"``.

Note: FastAPI's /docs (Swagger UI) and /redoc load their JS from public CDNs, so
they are blocked by this policy. This is intentional; API docs should be read
from the OpenAPI JSON at /openapi.json or served behind the TLS entry point.
"""
from __future__ import annotations

import os
import re
import uuid

REQUEST_ID_HEADER = "x-netproof-request-id"
_INCOMING_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:/-]{1,128}$")

_BASE_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


def csp_policy() -> str:
    """The shipped CSP, optionally extended with NETPROOF_CSP_SRC directives."""
    extra = (os.environ.get("NETPROOF_CSP_SRC") or "").strip()
    if not extra:
        return _BASE_CSP
    return f"{_BASE_CSP}; {extra}"


def default_headers() -> dict[str, str]:
    """Headers for every response that bypasses TLS (HSTS is added by the
    TLS middleware when the request actually arrived over HTTPS)."""
    return {
        "content-security-policy": csp_policy(),
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()",
    }


def resolve_request_id(incoming: str | None) -> str:
    """Honour a caller-supplied id (agent correlation) only if it is a sane,
    short token; otherwise mint a fresh one. Prevents header injection."""
    if incoming and _INCOMING_REQUEST_ID.match(incoming):
        return incoming
    return uuid.uuid4().hex


def apply_to(response, request_id: str) -> None:
    """Stamp the security headers (and the correlation id) onto a response."""
    for name, value in default_headers().items():
        response.headers[name] = value
    response.headers[REQUEST_ID_HEADER] = request_id
