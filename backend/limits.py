"""Global request-body size bound (Phase A5).

Bounding the body bounds the memory a single request can force the server to
commit, closing the unbounded-body DoS hole. Configured by
``NETPROOF_MAX_BODY_BYTES`` (default 8 MiB). Three coordinated pieces:

1. ``DEFAULT_MAX_BODY_BYTES`` — the shipped skeleton; ``NETPROOF_MAX_BODY_BYTES``
   overrides it (per request, so tests can flip it without a restart).
2. ``body_size_middleware`` (function middleware, inside the security-header
   layer so its 413 carries the strict headers) — the cheap ``Content-Length``
   pre-check that rejects oversized announcements before a byte is read.
3. ``BodySizeLimitMiddleware`` — an innermost ASGI guard that wraps the receive
   channel, so *actual* bytes are counted even with chunked / unannounced
   bodies, raising mid-stream. FastAPI swallows that body-read error into a 400,
   so the guard's ``send`` wrapper rewrites the response to 413 the moment the
   overflow flag is set. Either way the body is never buffered past the cap.

The engine's per-artefact caps (2 MiB / 64 evidence docs) are tighter and
unchanged; this is the outer safety net for every endpoint and body type.
"""
from __future__ import annotations

import os

from fastapi import Request
from fastapi.responses import JSONResponse

DEFAULT_MAX_BODY_BYTES = 8 * 1024 * 1024
STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def max_body_bytes() -> int:
    raw = os.environ.get("NETPROOF_MAX_BODY_BYTES", "")
    if not raw:
        return DEFAULT_MAX_BODY_BYTES
    try:
        return int(raw)
    except ValueError:
        return DEFAULT_MAX_BODY_BYTES


class BodyTooLarge(Exception):
    pass


async def body_size_middleware(request: Request, call_next):
    """Content-Length pre-check; runs inside the security-header layer."""
    limit = max_body_bytes()
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > limit:
                return JSONResponse(status_code=413, content={"detail": "request body too large"})
        except ValueError:
            pass
    return await call_next(request)


class _OverflowGuard:
    def __init__(self, limit: int, receive) -> None:
        self.limit = limit
        self._receive = receive
        self.count = 0
        self.overflow = False

    async def __call__(self):
        message = await self._receive()
        if message["type"] == "http.request":
            self.count += len(message.get("body", b""))
            if self.count > self.limit:
                self.overflow = True
                raise BodyTooLarge()
        return message


class BodySizeLimitMiddleware:
    """Innermost ASGI guard for chunked / unannounced bodies."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        method = scope.get("method")
        guard = None
        if scope.get("type") == "http" and method in STATE_CHANGING_METHODS:
            guard = _OverflowGuard(max_body_bytes(), receive)
            receive = guard

        started = {"flipped": False}

        async def guarded_send(message) -> None:
            if guard is not None and guard.overflow and message["type"] == "http.response.start":
                headers = [(b"content-type", b"application/json")]
                for name, value in message.get("headers", []):
                    if name.lower() not in (b"content-type", b"content-length"):
                        headers.append((name, value))
                message = dict(message, status=413, headers=headers)
                started["flipped"] = True
            await send(message)

        try:
            await self.app(scope, receive, send if guard is None else guarded_send)
        except BodyTooLarge:
            if not started["flipped"]:
                await JSONResponse(status_code=413, content={"detail": "request body too large"})(scope, receive, send)
