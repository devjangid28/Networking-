"""Same-site origin enforcement for cookie-authenticated state changes (Phase A3).

Session cookies alone are not armour: a cross-site form POST to e.g.
``/api/users`` would carry the victim's cookie. ``samesite=lax`` already blocks
most of that, but this middleware is the explicit defence-in-depth layer:

- Browsers always send an ``Origin`` header on POST/PUT/PATCH/DELETE, regardless
  of same- or cross-site. Servers with no Origin and no Referer are non-browser
  clients (curl, agents, the jsdom harness), which are allowed.
- A cross-site Origin is rejected with 403 unless the request has no session
  cookie (nothing for an attacker to ride) or the path is exempt (``/api/login``
  — a login CSRF can only log the victim into attacker-chosen credentials).
- The configured ``NETPROOF_ALLOWED_ORIGINS`` list (the same one the CORS
  middleware trusts) is also honoured, so a deliberately integrated foreign
  dashboard keeps working.

Order-of-application: this middleware sits *under* the security-header
middleware, so its 403 responses still carry the strict headers + request id.
"""
from __future__ import annotations

import os
from urllib.parse import urlparse

from fastapi import Request
from fastapi.responses import JSONResponse

from security import SESSION_COOKIE

STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
CSRF_EXEMPT_PATHS = frozenset({"/api/login"})


def _allowed_domains() -> set[str]:
    return {o.strip().lower() for o in os.environ.get("NETPROOF_ALLOWED_ORIGINS", "").split(",") if o.strip()}


def origin_allowed(request: Request) -> bool:
    """True when the request can safely act on a cookie-authenticated session."""
    origin = request.headers.get("origin")
    if origin is not None:
        if origin == "null":
            return False
        return _is_same_host(origin, request)
    referer = request.headers.get("referer")
    if referer:
        try:
            ref_origin = f"{urlparse(referer).scheme}://{urlparse(referer).netloc}"
        except ValueError:
            return False
        return _is_same_host(ref_origin, request)
    return True


def _is_same_host(origin: str, request: Request) -> bool:
    clean = origin.strip().lower()
    if clean in _allowed_domains():
        return True
    parsed = urlparse(clean)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    host = (request.headers.get("host") or "").lower()
    if not host:
        return False
    if parsed.hostname.lower() != host.split(":", 1)[0].lower():
        return False
    origin_port = parsed.port
    host_port = None
    if ":" in host:
        try:
            host_port = int(host.rsplit(":", 1)[1])
        except ValueError:
            host_port = None
    expected = host_port if host_port is not None else (443 if parsed.scheme == "https" else 80)
    return origin_port is None or origin_port == expected


def is_targeted_check(request: Request) -> bool:
    """Cookie-authenticated state-changing path needing the origin check?"""
    if request.method not in STATE_CHANGING_METHODS:
        return False
    if not request.cookies.get(SESSION_COOKIE):
        return False
    return request.url.path not in CSRF_EXEMPT_PATHS


async def csrf_middleware(request: Request, call_next):
    if is_targeted_check(request) and not origin_allowed(request):
        return JSONResponse(status_code=403, content={"detail": "cross-origin state change rejected"})
    return await call_next(request)
