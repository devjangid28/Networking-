"""Observability: /metrics exposes Prometheus text-format counters and the
HTTP middleware records requests (with dynamic segments collapsed to {id}).
Assertions are delta-based because counters live in process-wide memory shared
by the whole test session."""
import re

import pytest
from starlette.testclient import TestClient

import main
from main import app
from engine.validate import PRESETS

TEST_ADMIN_PASS = "admin-test-pass-2026"


def _counter(body: str, name: str, label_filter: str | None = None) -> int:
    if label_filter:
        pattern = re.escape(name) + r"\{" + re.escape(label_filter) + r"\} (\d+)"
    else:
        pattern = re.escape(name) + r"(?:\{[^}]*\})? (\d+)"
    for m in re.finditer(pattern, body):
        return int(m.group(1))
    return 0


def test_metrics_content_type_and_shape():
    with TestClient(app, raise_server_exceptions=False) as cli:
        assert cli.get("/health").status_code == 200
        m = cli.get("/metrics")
        assert m.status_code == 200
        assert m.headers["content-type"].startswith("text/plain")
        body = m.text
        assert "# TYPE netproof_http_requests_total counter" in body
        assert "netproof_http_requests_total{route=\"/health\",method=\"GET\",status=\"200\"}" in body
        assert "netproof_uptime_seconds" in body
        assert "netproof_scans_total " in body
        assert "netproof_scan_failures_total " in body
        assert "# HELP netproof_validation_verdicts_total" in body
        assert "# TYPE netproof_validation_verdicts_total counter" in body
        assert "netproof_active_agents " in body


def test_metrics_route_grouping_collapses_ids():
    with TestClient(app, raise_server_exceptions=False) as cli:
        cli.post("/api/login", json={"username": "admin", "password": TEST_ADMIN_PASS})
        r = cli.post("/api/metrics-probe", json={})  # unknown route -> grouped as-is
        assert r.status_code == 404
        # known dynamic route still shows its template, not the concrete id
        _probe = cli.get("/api/orgs/aaaa1234/rotate-key")
        assert _probe.status_code in (401, 403, 404, 405)  # unauthenticated path
        m = cli.get("/metrics")
        assert "route=\"/api/orgs/{id}/rotate-key\"" in m.text


def test_metrics_validation_verdict_and_scan_failure_recorded(monkeypatch):
    """A failed scan bumps the failure counter (not success); a validation
    bumps the verdict counter for its outcome."""

    def boom(target, community, ping):
        raise Exception("boom")  # simulates a discovery failure

    monkeypatch.setattr(main, "_run_scan_with_timeout", boom)

    with TestClient(app, raise_server_exceptions=False) as cli:
        before_fail = _counter(cli.get("/metrics").text, "netproof_scan_failures_total")
        before_scans = _counter(cli.get("/metrics").text, "netproof_scans_total")

        # /api/scan now requires a session — log in first, then provoke a failure
        assert cli.post("/api/login", json={"username": "admin", "password": TEST_ADMIN_PASS}).status_code == 200
        r = cli.post("/api/scan", json={"target": "192.168.200.1", "consent": True})
        assert r.status_code in (400, 500)

        after = cli.get("/metrics").text
        assert _counter(after, "netproof_scan_failures_total") == before_fail + 1
        assert _counter(after, "netproof_scans_total") == before_scans

        r = cli.post("/api/validate", json={
            "mode": "demo",
            "change": PRESETS[0]["change"],
        })
        assert r.status_code == 200
        verdict = r.json()["summary"]["verdict"]
        assert verdict in ("pass", "warn", "block")

        before_verdict = _counter(after, "netproof_validation_verdicts_total", label_filter=f"verdict=\"{verdict}\"")
        m2 = cli.get("/metrics").text
        assert _counter(m2, "netproof_validation_verdicts_total", label_filter=f"verdict=\"{verdict}\"") == before_verdict + 1