"""Dependency-free Prometheus-style metrics for the NetProof process.

Exported at GET /metrics in Prometheus text format:

    netproof_http_requests_total{route,method,status}  - request counter
    netproof_http_request_duration_seconds{route}      - todate count/sum
    netproof_scans_total                               - completed scan count
    netproof_scan_duration_seconds                     - todate count/sum
    netproof_scan_failures_total                       - failed/errored scans
    netproof_validation_verdicts_total{verdict}        - pass/warn/block
    netproof_active_agents                             - orgs w/ report in 7d
    netproof_uptime_seconds                            - process uptime

Counters live in process memory (no external dependency). Scrape the internal
port only; the endpoint is deliberately unauthenticated like /health so the
Prometheus collector needs no credentials.
"""
from __future__ import annotations

import threading
import time

_lock = threading.Lock()
_requests: dict[tuple[str, str, int], int] = {}          # (route, method, status) -> count
_latency: dict[tuple[str, str], list[float]] = {}        # (route, method) -> sample list
_scans: dict[str, float] = {"count": 0.0, "sum": 0.0}
_scan_failures = 0
_verdicts: dict[str, int] = {}
_START = time.time()

VALID_VERDICTS = ("pass", "warn", "block")

MAX_LATENCY_SAMPLES = 400  # cap per route to bound memory


def note_request(method: str, route: str, status: int, seconds: float) -> None:
    with _lock:
        key = (route, method, int(status // 100) * 100)
        _requests[key] = _requests.get(key, 0) + 1
        lkey = (route, method)
        samples = _latency.setdefault(lkey, [])
        if len(samples) >= MAX_LATENCY_SAMPLES:
            samples.pop(0)
        samples.append(seconds)


def note_scan(seconds: float, ok: bool = True) -> None:
    with _lock:
        if ok:
            _scans["count"] += 1
            _scans["sum"] += seconds
        else:
            _scans["fail"] = _scans.get("fail", 0) + 1


def note_verdict(verdict: str) -> None:
    verdict = (verdict or "unknown").lower()
    with _lock:
        _verdicts[verdict] = _verdicts.get(verdict, 0) + 1


def render(active_agents: int = 0) -> str:
    now = time.time()
    uptime = now - _START
    with _lock:
        lines = [
            "# HELP netproof_http_requests_total HTTP requests by route/method/status-class.",
            "# TYPE netproof_http_requests_total counter",
        ]
        for (route, method, status), n in sorted(_requests.items()):
            lines.append(f"netproof_http_requests_total{{route=\"{route}\",method=\"{method}\",status=\"{status}\"}} {n}")

        lines += [
            "# HELP netproof_http_request_duration_seconds HTTP request latency (seconds) by route/method.",
            "# TYPE netproof_http_request_duration_seconds summary",
        ]
        for (route, method), samples in sorted(_latency.items()):
            if samples:
                cnt = len(samples)
                tot = sum(samples)
                lines.append(f"netproof_http_request_duration_seconds_count{{route=\"{route}\",method=\"{method}\"}} {cnt}")
                lines.append(f"netproof_http_request_duration_seconds_sum{{route=\"{route}\",method=\"{method}\"}} {tot:.6f}")

        lines += [
            "# HELP netproof_scans_total Completed live scans.",
            "# TYPE netproof_scans_total counter",
            f"netproof_scans_total {_scans['count']:.0f}",
            "# HELP netproof_scan_duration_seconds Live scan duration.",
            "# TYPE netproof_scan_duration_seconds summary",
            f"netproof_scan_duration_seconds_count {_scans['count']:.0f}",
            f"netproof_scan_duration_seconds_sum {_scans['sum']:.3f}",
            "# HELP netproof_scan_failures_total Live scans that errored or timed out.",
            "# TYPE netproof_scan_failures_total counter",
            f"netproof_scan_failures_total {_scans.get('fail', 0):.0f}",
            "# HELP netproof_validation_verdicts_total Validation verdicts by outcome.",
            "# TYPE netproof_validation_verdicts_total counter",
        ]
        for verdict in sorted(_verdicts):
            lines.append(f"netproof_validation_verdicts_total{{verdict=\"{verdict}\"}} {_verdicts[verdict]}")
        lines += [
            "# HELP netproof_active_agents Accounts with an agent report received in the last 7 days.",
            "# TYPE netproof_active_agents gauge",
            f"netproof_active_agents {int(active_agents)}",
            "# HELP netproof_uptime_seconds Process uptime in seconds.",
            "# TYPE netproof_uptime_seconds gauge",
            f"netproof_uptime_seconds {uptime:.1f}",
        ]
    return "\n".join(lines) + "\n"