"""Shared pytest fixtures.

Admin credentials: ``security.admin_credentials`` reads them ONLY from the
environment (there is deliberately no baked-in default), and ``main`` calls
``init_sessions()`` at import time. Those env vars must therefore exist before
any test module imports ``main`` — set them at the top of this file, which
pytest always imports first.

Rate limits are per-(client-ip, scope) buckets in process memory. TestClient
reports every request as the same client IP, so without a reset the limits
(scan 2/min, login 5/min, validate 60/min, ...) would be shared across tests
and modules and cause flaky 429s. Reset before every test.
"""
import os

os.environ.setdefault("NETPROOF_ADMIN_USER", "admin")
os.environ.setdefault("NETPROOF_ADMIN_PASS", "admin-test-pass-2026")

import pytest
import ratelimit


@pytest.fixture(autouse=True)
def _clear_ratelimits():
    ratelimit.reset("*", "*")
    yield
    ratelimit.reset("*", "*")