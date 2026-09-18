"""Per-client-IP in-memory rate limiting.

Every endpoint that does real work (scan, validate, login, ...) calls
``allow(request, scope, limit, window)``.  The function uses a bounded
deque of timestamps per (ip, scope) key so the memory footprint is
proportional to the number of distinct active clients, not total requests.

Proxy awareness: when deployed behind the Caddy/TLS reverse proxy
(NETPROOF_DOMAIN set, or NETPROOF_TRUST_PROXY=1), ``request.client.host`` is
the *proxy's* IP and every real client would share one rate-limit bucket. In
that mode the real client IP is read from X-Forwarded-For (the right-most hop,
added by the trusted proxy itself) or X-Real-IP. When neither switch is on the
proxy headers are IGNORED entirely, so a direct client cannot spoof a foreign
IP to dodge its own bucket.
"""
from __future__ import annotations

import os
import time
import threading
from collections import defaultdict, deque

_lock = threading.RLock()
_buckets: dict[tuple[str, str], deque] = defaultdict(deque)


def allow(request, scope: str, limit: int, window: float = 60.0) -> bool:
    """Return True if the request is within the rate limit, False if it
    should be rejected (HTTP 429 by the caller)."""
    ip = _client_ip(request)
    key = (ip, scope)
    now = time.monotonic()
    cutoff = now - window
    with _lock:
        dq = _buckets[key]
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= limit:
            return False
        dq.append(now)
        return True


def reset(ip: str = "*", scope: str = "") -> None:
    """Flush buckets for testing."""
    with _lock:
        if ip == "*" and scope == "*":
            _buckets.clear()
        else:
            keys = [k for k in _buckets if (ip == "*" or k[0] == ip) and (scope == "*" or k[1] == scope)]
            for k in keys:
                del _buckets[k]


def _trusted_proxy() -> bool:
    """True when the app sits behind a reverse proxy we trust to set the
    X-Forwarded-For / X-Real-IP headers. Explicit opt-in, or automatic for the
    Caddy TLS profile (which must set NETPROOF_DOMAIN)."""
    if os.environ.get("NETPROOF_TRUST_PROXY", "").strip().lower() in ("1", "true", "yes", "on"):
        return True
    return bool((os.environ.get("NETPROOF_DOMAIN") or "").strip())


def _client_ip(request) -> str:
    try:
        direct = request.client.host
    except Exception:
        direct = "unknown"
    if not _trusted_proxy():
        return direct
    # The right-most X-Forwarded-For hop is the proxy itself; the value it
    # appended is the real client. The left-most entries could have been
    # injected by the client, but because we only trust the header from a
    # configured proxy, the right-most value is the one the proxy saw.
    fwd = request.headers.get("x-forwarded-for", "") or ""
    if fwd:
        last = fwd.split(",")[-1].strip()
        if last and " " not in last:
            return last
    real = (request.headers.get("x-real-ip", "") or "").strip()
    if real and " " not in real:
        return real
    return direct
