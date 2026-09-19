"""NetProof - neutral network-change validation for agents and engineers.

Serves the web UI and a tiny public API:
    GET  /api/network              - demo topology + zones + requirements + presets
    POST /api/scan                 - discover systems live on the segment of a target IP
    GET  /api/model?mode=scan      - the discovered network as a model
    POST /api/validate             - run a proposed change through the engine (demo or scan)
    POST /api/intent               - parse a plain-English change into change dicts
    POST /api/guardrails           - organisational pre-flight checks on a change

This is the neutral referee layer designs of the future: any agent or any
human proposes a change, NetProof answers "safe / unsafe, and here's proof".
"""
from __future__ import annotations

import datetime
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from engine import tenant as tenant_store
from security import (
    SESSION_COOKIE,
    init_sessions,
    login as auth_login,
    logout as auth_logout,
    require_admin,
    require_role,
    require_session,
    user_for_token,
)
import security_headers as security_headers_mod
import csrf
from engine.audit import (
    change_fingerprint,
    get_snapshot,
    get_verdict,
    list_verdicts,
    model_hash,
    replay_verdict,
    save_verdict,
    unified_diff,
)
from engine.buildnet import build_net
from engine.confirm import counts as confirm_counts, ingest_config, merge_configs, mark_confirmed
from engine.discover import scan as run_scan
from engine.guardrails import check_change, guardrail_blocked, load_guardrails
from engine.intent import parse_intent
from engine.intel import target_intelligence
from engine.model import load_net, Net
from engine.events import init_events, log_event, list_events
from engine.reach import apply_change
from engine.validate import ALL_PRESETS, ENGINE_VERSION, PRESETS, validate_change
from engine.validate_pipeline import run_validation_pipeline
from engine.drift import baseline_meta, detect_drift
import ratelimit
from logfmt import setup_logging
from metrics import note_request as metrics_note_request, note_scan as metrics_note_scan, note_verdict as metrics_note_verdict, render as render_metrics

setup_logging()

_STARTED_AT = time.time()

BASE = Path(__file__).resolve().parent
NET_PATH = BASE / "data" / "acme_office.yaml"
WEB_DIR = BASE.parent / "web"

app = FastAPI(title="NetProof", description="Neutral network-change validation", version=ENGINE_VERSION)

# CORS: same-origin by default. Adding a foreign origin requires the operator
# to opt in explicitly via $NETPROOF_ALLOWED_ORIGINS (comma-separated).
_origins = [o.strip() for o in os.environ.get("NETPROOF_ALLOWED_ORIGINS", "").split(",") if o.strip()]
if _origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "X-NetProof-Key"],
    )

NET = load_net(str(NET_PATH))

tenant_store.init_tenant()
init_sessions()
init_events()

app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")


def _route_group(path: str) -> str:
    """Collapse dynamic path segments (hex ids, numbers) to {id} so metric
    labels don't explode cardinality."""
    parts = []
    for seg in path.split("/"):
        if seg and (seg.isdigit() or (len(seg) >= 6 and all(c in "0123456789abcdef" for c in seg.lower()))):
            parts.append("{id}")
        else:
            parts.append(seg)
    return "/".join(parts) or "/"


@app.middleware("http")
async def record_metrics(request: Request, call_next):
    started = time.time()
    try:
        response = await call_next(request)
    except Exception:
        metrics_note_request(request.method, _route_group(request.url.path), 500, time.time() - started)
        raise
    metrics_note_request(request.method, _route_group(request.url.path), response.status_code, time.time() - started)
    return response


# Terminal-TLS enforcement: when the app is served through a TLS reverse proxy
# (NETPROOF_DOMAIN set), the proxy marks every off-box request with
# X-Forwarded-Proto. Requests that reached the proxy in plain HTTP get bumped to
# HTTPS (307); HTTPS requests get HSTS. Requests WITHOUT the header (the Docker
# healthcheck, or anything inside the trusted network hitting :8000 directly)
# are left alone so the container can still self-check.
_TLS_DOMAIN = (os.environ.get("NETPROOF_DOMAIN") or "").strip()


@app.middleware("http")
async def enforce_https(request: Request, call_next):
    if not _TLS_DOMAIN:
        return await call_next(request)
    forwarded = request.headers.get("x-forwarded-proto")
    if forwarded == "http":
        host = request.headers.get("host") or _TLS_DOMAIN
        target = f"https://{host}{request.url.path}"
        if request.url.query:
            target = f"{target}?{request.url.query}"
        return RedirectResponse(target, status_code=307)
    response = await call_next(request)
    if forwarded == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# Phase A3: CSRF origin enforcement for cookie-authenticated state changes.
# Declared under security_headers so the 403 it returns still gets the strict
# headers + request id. (Server middleware runs in reverse declaration order.)
@app.middleware("http")
async def csrf_guard(request: Request, call_next):
    return await csrf.csrf_middleware(request, call_next)


# Phase A4: strict default security headers + request correlation id. Declared
# after the other two middlewares so it runs outermost and stamps every response
# (including the 307 TLS bump above). FastAPI's user-middleware stack runs the
# LAST-added middleware first.
@app.middleware("http")
async def security_headers(request: Request, call_next):
    request.state.request_id = security_headers_mod.resolve_request_id(
        request.headers.get(security_headers_mod.REQUEST_ID_HEADER)
    )
    response = await call_next(request)
    security_headers_mod.apply_to(response, request.state.request_id)
    return response


@app.get("/metrics", response_class=PlainTextResponse)
def metrics() -> PlainTextResponse:
    """Prometheus text-format metrics for scraping (internal port)."""
    try:
        active_agents = tenant_store.count_active_agents()
    except Exception:
        active_agents = 0
    return PlainTextResponse(render_metrics(active_agents=active_agents),
                             media_type="text/plain; version=0.0.4; charset=utf-8")

# --------------------------------------------------------------------------- #
# Live scan state                                                           #
# --------------------------------------------------------------------------- #

_SCAN_LOCK = threading.Lock()
_SCAN_RESULT = None   # raw discovery dict
_SCAN_NET = None      # built model
_SCAN_META = {}
_SCAN_AT = 0
_SCAN_CONFIG_SOURCES: list[str] = []  # how rules got onto the live-scan model
_SCAN_CONFIG = None  # merged config snapshot retained for re-renders

SCAN_TIMEOUT_S = 30


def _run_with_timeout(fn, timeout_s: float):
    """Run ``fn`` on a daemon thread; return its result or None on timeout."""
    box: dict = {}
    def _run():
        try:
            box["result"] = fn()
        except Exception as e:  # surface any failure as the result
            box["error"] = e
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=timeout_s)
    if t.is_alive():
        return None
    if "error" in box:
        raise box["error"]
    return box.get("result")


_PULL_MODULE = None


def _pull_module():
    """Load ``agent/pull.py`` by file path so the server can reuse its config
    parsing + SSH pull. A plain ``import`` would be ambiguous with the
    ``agent/`` folder when uvicorn runs from the backend directory."""
    global _PULL_MODULE
    if _PULL_MODULE is None:
        import importlib.util
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent", "pull.py")
        if not os.path.exists(path):
            raise RuntimeError("agent/pull.py not found at " + path)
        spec = importlib.util.spec_from_file_location("netproof_pull", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _PULL_MODULE = mod
    return _PULL_MODULE


def _attach_scan_config(net, req) -> tuple[list[str], dict | None]:
    """Option A (``config_file`` text) + Option B (``ssh`` login) -> ONE merged
    config applied to the freshly scanned model as confirmed rules. Non-fatal:
    a failed login/file merge must never kill an otherwise-good discovery.

    Returns ``(sources, merged_config)`` so callers can retain the merged
    config for later re-renders (e.g. the "tick what to protect" rebuild)."""
    sources: list = []
    merged = None
    if (req.config_file or "").strip():
        try:
            data = json.loads(req.config_file)
            if not isinstance(data, dict):
                raise ValueError("top level must be a JSON object of {ip: {filters, routes}}")
            merged = data
            sources.append("config-file")
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"config file invalid: {exc}")
    if req.ssh:
        host = (req.ssh.get("host") or req.target or "").strip().split("/")[0]
        if not host:
            host = req.target or ""
        try:
            port = int(req.ssh.get("port") or 22)
        except Exception:
            port = 22
        pulled = _run_with_timeout(
            lambda: _pull_module().via_ssh(
                host=host,
                username=req.ssh.get("user") or "",
                password=req.ssh.get("password") or "",
                key_file=req.ssh.get("key") or "",
                port=port,
                config_path=req.ssh.get("config_path") or "/config/run.cfg",
                known_hosts=req.ssh.get("known_hosts") or "",
            ),
            30,
        )
        if pulled and pulled.get("config"):
            content = {host: pulled["config"]}
            merged = merge_configs(merged, content)
            sources.append("ssh")
    if merged:
        try:
            ingest_config(net, merged)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"could not apply router rules: {exc}")
    return sources, merged


def _run_scan_with_timeout(target: str, community: str, do_ping: bool) -> dict:
    """Run discover.scan on a daemon thread, failing fast if it hangs."""
    box: dict = {}
    def _run():
        try:
            box["result"] = run_scan(target, community=community, do_ping=do_ping)
        except Exception as e:  # surface any scan error as the result
            box["error"] = e
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=SCAN_TIMEOUT_S)
    if t.is_alive():
        raise HTTPException(status_code=503, detail=f"scan timed out after {SCAN_TIMEOUT_S}s; the segment may be unresponsive (retry with ping disabled)")
    if "error" in box:
        raise HTTPException(status_code=400, detail=f"scan failed: {box['error']}")
    return box.get("result") or {}

# Agent-mode models, keyed by account id. Rebuilt lazily from the account's
# latest agent report and invalidated whenever a new report is stored.
_AGENT_LOCK = threading.Lock()
_AGENT_CACHE: dict[str, dict] = {}


class ScanRequest(BaseModel):
    target: str = Field(..., description="Router/server IP to scan, or CIDR, e.g. 192.168.1.1 or 192.168.1.0/24")
    community: str = Field("public", description="SNMP community for optional device details")
    ping: bool = Field(True, description="Run an ICMP sweep (slower but finds more devices)")
    consent: bool = Field(False, description="Owner's explicit consent to scan this segment")
    protect: list[str] | None = Field(None, description=(
        "Opt-in set of ``ip:port`` service keys the owner wants guarded after "
        "this scan (tick to protect). When None every discovered service becomes "
        "a requirement (backward-compatible with the demo/test flows). When an "
        "explicit list is given ONLY those services are protected â€” anything else "
        "stays 'discovered but open' until the owner ticks it. Pass [] to reveal "
        "the network with nothing guarded yet."))
    config_file: str | None = Field(None, description=(
        "Option A: the text of a device-config JSON snapshot "
        "{ip: {filters: [{name, rules}], routes: []}} to import as CONFIRMED "
        "rules on the scanned model."))
    ssh: dict | None = Field(None, description=(
        "Option B: SSH login to pull the router config live, e.g. "
        "{host, user, password, key, port, config_path, known_hosts}. Requires "
        "the optional 'paramiko' dependency to be installed."))


class AgentReportRequest(BaseModel):
    """Payload a customer-side agent posts OUTBOUND. The server never scans the LAN."""
    scan: dict = Field(..., description="Discovery result from the local agent (same shape /api/scan returns)")
    config: dict | None = Field(None, description="Optional pulled device config: rules/routes the agent READ from the box, marked confirmed")
    config_sources: list[str] | None = Field(None, description="How config was obtained: 'config-file', 'ssh', or both")
    agent_version: str | None = Field(None, description="agent/agent.py version that rendered the report")
    source_host: str | None = Field(None, description="Hostname of the machine the agent ran on")
    scan_at: str | None = Field(None, description="When the agent performed the discovery")
    consent: bool = Field(False, description="Agent runs with the network owner's explicit consent (agent --consent)")


class ChangeRequest(BaseModel):
    change: dict = Field(..., description="Proposed change object, e.g. {type: add_filter_rule, filter:..., rule:...}")
    mode: str = Field("demo", description="'demo' = sample network, 'scan' = dev/single-machine scan, 'agent' = an account's latest agent report")
    org: str = Field("default", description="Organisation guardrail set to pre-flight against")
    account: str | None = Field(None, description="Account id used when mode='agent'")
    requester: str | None = Field(None, description="Who (agent name / human id) is proposing this change")


class IntentRequest(BaseModel):
    text: str = Field(..., description="Plain-English change description, e.g. 'block ssh from user-pc to app-server'")
    mode: str = Field("demo", description="'demo' uses the sample network, 'scan' uses the last live discovery, 'agent' uses an account report")
    account: str | None = Field(None, description="Account id used when mode='agent'")


class GuardrailRequest(BaseModel):
    change: dict = Field(..., description="Change object to pre-flight against organisational policy")
    mode: str = Field("demo", description="'demo' uses the sample network, 'scan' uses the last live discovery, 'agent' uses an account report")
    org: str = Field("default", description="Organisation guardrail set to use")
    account: str | None = Field(None, description="Account id used when mode='agent'")


class OrgRequest(BaseModel):
    name: str = Field(..., description="Account display name used on the dashboard")


class UserRequest(BaseModel):
    org_id: str = Field(..., description="Account the user belongs to")
    username: str = Field(..., description="Dashboard login name (unique per account)")
    password: str = Field(..., min_length=10, description="Password (min 10 chars) â€” stored as a salted PBKDF2 digest only")
    role: str = Field("viewer", description="Role: admin | operator | viewer")


class LoginRequest(BaseModel):
    username: str = Field("", description="Dashboard username ($NETPROOF_ADMIN_USER, or an org user)")
    password: str = Field("", description="Dashboard password ($NETPROOF_ADMIN_PASS, or the org user's password)")
    org_id: str = Field("", description="Account to log into when this is an org-scoped user. Empty for the global admin.")


class VerificationCreateRequest(BaseModel):
    """Open a post-change verification against a stored verdict."""
    verdict_id: str = Field(..., description="A stored verdict id from the audit trail to verify against")
    requester: str | None = Field(None, description="Who is driving this verification (human or agent name)")
    source_precedence: list[str] | None = Field(
        None, description="Evidence-source tie-break order, e.g. [\"snapshot\",\"agent_report\",\"probe\",\"manual\"]")
    pre_change_evidence: dict | None = Field(
        None, description="Optional pre-change snapshot for before-values and device mapping: "
                          "{devices: {name: ip-or-[ips]}, config: {ip: {filters,routes,dst_nat,bgp,ospf,dns,vlan_assignment}}}")


class VerificationRunRequest(BaseModel):
    """Run the comparison, health checks and rollback in one call."""
    source_precedence: list[str] | None = Field(None, description="Optional evidence-source tie-break order")


class EvidenceAddRequest(BaseModel):
    """Post-change evidence documents collected from the live network."""
    evidence: list[dict] = Field(
        ..., description="Evidence documents: "
                         "{source, device, section, content, collected_at, confirmed, errors?, unsupported?}")


def _require_org_scope(request: Request, org: str) -> dict:
    """Authenticated session + the right to view the given account.

    The global admin (org_id '') may see any account; an org-scoped user may
    only ever see their own account â€” the tenant-isolation half of RBAC.
    """
    info = require_session(request)
    if info.get("org_id") and org and org != info["org_id"]:
        raise HTTPException(status_code=403, detail="access to this account is not allowed for your role")
    return info


def _agent_net(org: str) -> dict | None:
    """Build/cache the Net for an account from its latest agent report."""
    report = tenant_store.latest_agent_report(org)
    if report is None:
        return None
    with _AGENT_LOCK:
        cached = _AGENT_CACHE.get(org)
        if cached is not None and cached["report_id"] == report["id"]:
            return cached
    net, meta = build_net(report["raw"].get("scan") or {})
    changes = mark_confirmed(net, report["raw"].get("config"))
    entry = {
        "net": net,
        "report_id": report["id"],
        "at": report["received_at"],
        "changes": changes,
        "scan": report["raw"].get("scan") or {},
        "config_sources": report["raw"].get("config_sources") or [],
    }
    with _AGENT_LOCK:
        _AGENT_CACHE[org] = entry
    return entry


def _model_for_mode(mode: str, account: str | None = None) -> Net:
    if mode == "scan":
        with _SCAN_LOCK:
            if _SCAN_NET is None:
                raise HTTPException(status_code=400, detail="No live scan yet - run a scan from the 'Scan a network' panel first.")
            return _SCAN_NET
    if mode == "agent":
        entry = _agent_net(account or "")
        if entry is None:
            raise HTTPException(status_code=400, detail="No agent report yet for this account - install the agent and paste this account's API key.")
        return entry["net"]
    return NET


@app.get("/")
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.get("/health")
def health(request: Request) -> dict:
    """Liveness probe for orchestrators / load balancers. Not auth-gated on
    purpose: it must not leak anything and must work from a naive GET."""
    db_ok = True
    try:
        from engine.audit import _conn
        _conn()
    except Exception:
        db_ok = False
    return {
        "status": "ok" if db_ok else "degraded",
        "version": ENGINE_VERSION,
        "uptime_s": round(time.time() - _STARTED_AT, 1),
        "db": "reachable" if db_ok else "unreachable",
        "ip": request.client.host if request.client else None,
        "time": datetime.datetime.now().isoformat(timespec="seconds"),
    }


@app.get("/api/gateway")
def default_gateway(request: Request) -> dict:
    """Suggest the current default gateway (the router IP of the network this
    backend is on). Read-only, public: it only reveals the gateway of the host
    serving the app to users already on that same network/AUI. Returns an empty
    list when the gateway cannot be determined (VPNs, containers, edge cases).
    """
    candidates = _detect_default_gateways()
    return {"gateways": candidates, "client_ip": request.client.host if request.client else None}


def _detect_default_gateways() -> list[str]:
    """Best-effort cross-platform default-gateway detection. Order matters: the
    first entry is the strongest candidate (lowest route metric)."""
    got: list[str] = []
    try:
        if os.name == "nt":
            out = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True, text=True, timeout=10,
            ).stdout
            # IPv4 "0.0.0.0 ... 0.0.0.0 <gateway> <iface> <metric>" rows.
            # Route & metric columns are fixed-width in the v4 table; lowest
            # metric wins. The interface column may be "Default" or an IP.
            rows = []
            for line in out.splitlines():
                m = re.match(
                    r"\s*0\.0\.0\.0\s{4,}0\.0\.0\.0\s{4,}(\S+)\s+(?:\S+)\s+(\d+)\s*$", line
                )
                if m:
                    rows.append((int(m.group(2)), m.group(1)))
            seen = set()
            for _, gw in sorted(rows):
                if gw not in seen:
                    seen.add(gw)
                    got.append(gw)
        else:
            with open("/proc/net/route", "r", encoding="utf-8") as fh:
                for line in fh.read().splitlines()[1:]:
                    row = line.strip().split()
                    if row and _hex_ip(row[1]) == 0 and _hex_ip(row[2]) == 0:
                        gw = str(ipaddress.IPv4Address(int(row[2], 16)))
                        if gw not in got:
                            got.append(gw)
    except Exception:
        return []
    # Fall back to the connection's local source IP only if we found nothing.
    if not got:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
            got = [str(net.network_address + 1)]
        except Exception:
            pass
    return got


def _hex_ip(value: str) -> int:
    return int(value, 16)


@app.post("/api/scan")
def scan_endpoint(req: ScanRequest, request: Request, info: dict = Depends(require_session)) -> dict:
    """Discover systems on the segment of `target`, then build a model from it.

    Session required — a live scan is an invasive, consent-gated action that
    must be attributable to a logged-in operator, never to an anonymous caller.
    """
    if not ratelimit.allow(request, "scan", 2, 60):
        raise HTTPException(status_code=429, detail="scan rate limit: 2 per minute")
    global _SCAN_RESULT, _SCAN_NET, _SCAN_META, _SCAN_AT, _SCAN_CONFIG_SOURCES, _SCAN_CONFIG
    if not req.target.strip():
        raise HTTPException(status_code=400, detail="target is required (router/server IP, or CIDR)")
    if not req.consent:
        raise HTTPException(status_code=403, detail="scan consent required - the request must explicitly confirm the owner authorizes discovery of this segment")
    started = time.time()
    ok = False
    try:
        result = _run_scan_with_timeout(req.target, req.community, req.ping)
        if not result.get("devices"):
            raise HTTPException(status_code=400, detail=("No devices discovered. " + " ".join(result.get("notes", [])) or "Check the IP and that you are on the same network."))
        try:
            # Protect is the OPT-IN set ("ip:port" service keys) the owner ticked to
            # guard. None means "guard everything this scan finds" (the demo/agent
            # flows stay fully governed - their model is a complete policy). A list -
            # even empty - means ONLY the listed services become policy requirements;
            # everything else stays "discovered but open" until the owner ticks it.
            net, meta = build_net(result, protect=set(req.protect) if req.protect is not None else None)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        config_sources, _merged_config = _attach_scan_config(net, req)
        ok = True
    finally:
        metrics_note_scan(time.time() - started, ok=ok)

    with _SCAN_LOCK:
        _SCAN_RESULT = result
        _SCAN_NET = net
        _SCAN_META = meta
        _SCAN_AT = time.time()
        _SCAN_CONFIG_SOURCES = config_sources
        _SCAN_CONFIG = _merged_config
    log_event("scan.run", actor="session", target=req.target, detail={"devices": len(result.get("devices") or [])},
              ip=(request.client.host if request and request.client else None))
    result["model"] = meta
    result["seconds"] = round(time.time() - started, 1)
    result["config_sources"] = config_sources
    return result


@app.get("/api/scan")
def scan_status() -> dict:
    with _SCAN_LOCK:
        if _SCAN_RESULT is None:
            return {"scanned": False}
        return {
            "scanned": True,
            "at": _SCAN_AT,
            "summary": {
                "subnet": _SCAN_RESULT.get("network"),
                "target": _SCAN_RESULT.get("target"),
                "devices": len(_SCAN_RESULT.get("devices", [])),
            },
            "meta": _SCAN_META,
        }


# --------------------------------------------------------------------------- #
# Accounts + outbound agent reports                                           #
# --------------------------------------------------------------------------- #
# The dashboard does NOT sweep the LAN. A tiny `agent/` binary runs inside the
# customer network, discovers it, and posts the result here under the account's
# API key. The dashboard renders whatever the latest report says.

@app.post("/api/orgs")
def create_org(req: OrgRequest, info: dict = Depends(require_admin), request: Request = None) -> dict:
    """Create an account (admin only). Returns the raw agent API key once."""
    if ratelimit.allow(request, "orgs", 20, 60) is False:
        raise HTTPException(status_code=429, detail="org creation rate limit")
    try:
        org = tenant_store.create_org(req.name, actor="admin:" + info["username"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"org": org, "note": "The API key is returned once at creation â€” store it in the agent config on the customer machine."}


@app.get("/api/orgs")
def list_orgs(info: dict = Depends(require_session)) -> dict:
    """List accounts. The global admin sees every account; an org-scoped user
    only ever sees their own account (tenant isolation by role)."""
    orgs = tenant_store.list_orgs()
    if info.get("org_id"):
        orgs = [o for o in orgs if o["id"] == info["org_id"]]
    return {"orgs": orgs}


@app.post("/api/orgs/{org_id}/rotate-key")
def rotate_org_key(org_id: str, info: dict = Depends(require_admin)) -> dict:
    """Rotate an account's agent API key. Admin only. Old key stops working immediately."""
    try:
        return tenant_store.rotate_api_key(org_id, actor="admin:" + info["username"])
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# --------------------------------------------------------------------------- #
# Dashboard users (RBAC)                                                      #
# --------------------------------------------------------------------------- #

@app.get("/api/users")
def list_users_api(info: dict = Depends(require_admin)) -> dict:
    """All dashboard users across accounts (admin only)."""
    return {"users": tenant_store.list_users()}


@app.post("/api/users")
def create_user_api(req: UserRequest, info: dict = Depends(require_admin)) -> dict:
    """Create an org-scoped dashboard user (admin only). Roles: admin, operator, viewer."""
    try:
        user = tenant_store.create_user(
            req.org_id, req.username, req.password, req.role, actor="admin:" + info["username"],
        )
    except (ValueError, LookupError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"user": user}


@app.delete("/api/users/{org_id}/{username}")
def delete_user_api(org_id: str, username: str, info: dict = Depends(require_admin)) -> dict:
    """Delete an org-scoped dashboard user and their live sessions (admin only)."""
    try:
        tenant_store.delete_user(org_id, username, actor="admin:" + info["username"])
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"ok": True}


@app.post("/api/login")
def do_login(req: LoginRequest, response: Response, request: Request) -> dict:
    """Create a dashboard session. Rate-limited per client IP (see /api/login)."""
    if not ratelimit.allow(request, "login", 5, 60):
        raise HTTPException(status_code=429, detail="login rate limit: 5 per minute")
    sess = auth_login(req.username, req.password, req.org_id or "")
    if sess is None:
        log_event("login.failed", actor=req.username or "?", ip=(request.client.host if request.client else None))
        raise HTTPException(status_code=401, detail="invalid credentials")
    # Mark the session cookie Secure when served over TLS (via the Caddy
    # reverse proxy) or when a production domain is configured, so the token
    # is never replayed over plain HTTP.
    behind_tls = request.headers.get("x-forwarded-proto") == "https" or bool(os.environ.get("NETPROOF_DOMAIN"))
    response.set_cookie(SESSION_COOKIE, sess["token"], httponly=True, samesite="lax", max_age=604800, secure=behind_tls)
    log_event("login", actor=sess["username"], ip=(request.client.host if request.client else None),
              detail={"role": sess["role"]})
    return {"ok": True, "username": sess["username"], "role": sess["role"], "org_id": sess["org_id"]}


@app.post("/api/logout")
def do_logout(request: Request, response: Response) -> dict:
    auth_logout(request.cookies.get(SESSION_COOKIE))
    log_event("logout", actor="session", ip=(request.client.host if request.client else None))
    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True}


@app.get("/api/session")
def session_info(request: Request) -> dict:
    info = user_for_token(request.cookies.get(SESSION_COOKIE))
    if info is None:
        return {"authenticated": False, "username": None, "role": None, "org_id": None}
    return {"authenticated": True, **info}


@app.post("/api/agent/report")
def agent_report(req: AgentReportRequest, api_key: str | None = Header(default=None, alias="X-NetProof-Key"), request: Request = None) -> dict:
    """Accept an agent's outbound discovery report (API-key authenticated)."""
    if request and not ratelimit.allow(request, "agent_report", 60, 60):
        raise HTTPException(status_code=429, detail="agent report rate limit: 60 per minute")
    if not req.consent:
        raise HTTPException(status_code=403, detail="agent consent required â€” the agent must be run with explicit owner consent (agent.py --consent)")
    org = tenant_store.get_org_by_api_key(api_key or "")
    if org is None:
        raise HTTPException(status_code=401, detail="invalid or missing X-NetProof-Key")
    payload = {
        "scan": req.scan,
        "config": req.config or {},
        "config_sources": req.config_sources or [],
        "agent_version": req.agent_version,
        "source_host": req.source_host,
        "scan_at": req.scan_at,
    }
    try:
        stored = tenant_store.save_agent_report(org["id"], payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    with _AGENT_LOCK:
        _AGENT_CACHE.pop(org["id"], None)
    return {
        "ok": True,
        "org": org["name"],
        "org_id": org["id"],
        "report_id": stored["id"],
        "received_at": stored["received_at"],
        "network": stored["network"],
        "devices": stored["devices"],
    }


@app.get("/api/agent/status")
def agent_status(org: str = "", info: dict = Depends(require_session)) -> dict:
    if not org:
        raise HTTPException(status_code=400, detail="org query param required")
    if info.get("org_id") and org != info["org_id"]:
        raise HTTPException(status_code=403, detail="access to this account is not allowed for your role")
    o = tenant_store.get_org(org)
    if o is None:
        raise HTTPException(status_code=404, detail="unknown account")
    report = tenant_store.latest_agent_report(org)
    base = {"org": o["name"], "org_id": o["id"], "has_report": report is not None}
    if report is not None:
        base.update({
            "last_report_at": report["received_at"],
            "network": report["network"],
            "devices": report["devices"],
        })
    return base


def _network_info(net: Net, name: str) -> dict:
    zones = []
    for zname, z in net.zones.items():
        zones.append({
            "name": zname,
            "prefix": z.prefix.text if z.prefix else None,
            "sample_dst": f"{z.sample_dst}" if z.sample_dst else None,
            "gateway": z.gateway,
            "source": z.is_source,
            "dest": z.is_dest,
        })
    devices = []
    for dev in net.devices.values():
        devices.append({
            "name": dev.name,
            "type": dev.dtype,
            "x": dev.x,
            "y": dev.y,
            "interfaces": [
                {
                    "name": i.name,
                    "ip": i.ip,
                    "network": i.network,
                    "label": i.label,
                    "filters": i.filters,
                    "connected_to": i.connected_to,
                    "prefix": i.prefix.text if i.prefix else None,
                }
                for i in dev.interfaces
            ],
            "routes": [{"network": r.network, "next_hop": r.next_hop, "source": r.source} for r in dev.routes],
            "dst_nat": [
                {"public_ip": r.public_ip, "public_port": r.public_port, "private_ip": r.private_ip,
                 "private_port": r.private_port, "proto": r.proto}
                for r in (dev.dst_nat or [])
            ],
            "bgp": [
                {"neighbor": p.neighbor, "local_as": p.local_as, "remote_as": p.remote_as,
                 "export_prefixes": p.export_prefixes, "active": p.active}
                for p in (dev.bgp or [])
            ],
            "ospf": [
                {"area_id": a.area_id, "networks": a.networks, "auth_type": a.auth_type}
                for a in (dev.ospf or [])
            ],
            "dns": [
                {"zone": r.zone, "fqdn": r.fqdn, "type": r.rtype, "value": r.value, "ttl": r.ttl}
                for r in (dev.dns or [])
            ],
            "vlans": [
                {"iface": v.iface, "vlan_id": v.vlan_id, "name": v.name, "tagged": v.tagged}
                for v in (dev.vlans or [])
            ],
        })
    filters = [
        {
            "name": f.name,
            "default": f.default,
            "rules": [
                {"action": r.action, "src": r.src, "dst": r.dst, "proto": r.proto, "dport": r.dport, "source": r.source}
                for r in f.rules
            ],
        }
        for f in net.filters.values()
    ]
    requirements = [
        {
            "name": r.name,
            "src": r.src,
            "dst": r.dst,
            "proto": r.proto,
            "dport": r.dport,
            "expect": r.expect,
        }
        for r in net.requirements
    ]
    links = [{"a_dev": l.dev_a, "a_iface": l.iface_a, "b_dev": l.dev_b, "b_iface": l.iface_b} for l in net.links]
    return {
        "name": name,
        "zones": zones,
        "devices": devices,
        "filters": filters,
        "requirements": requirements,
        "links": links,
    }


@app.get("/api/network")
def network_info(org: str = "", request: Request = None) -> dict:
    """The dashboard's network. With `org` = an account's LATEST AGENT REPORT
    (the dashboard never scans on its own). Without `org` = the demo baseline."""
    if org:
        _require_org_scope(request, org)
        entry = _agent_net(org)
        if entry is None:
            return {
                "source": "none",
                "mode": "agent",
                "org": org,
                "onboarding": True,
                "description": "No agent report yet. Install the NetProof agent inside the network and paste this account's API key â€” the dashboard never scans on its own.",
            }
        info = _network_info(entry["net"], entry["net"].name)
        info["description"] = entry["net"].description
        info["presets"] = ALL_PRESETS
        info["source"] = "agent"
        info["mode"] = "agent"
        info["reported_at"] = entry["at"]
        info["confirmations"] = confirm_counts(entry["net"])
        info["agent_changes"] = entry["changes"]
        info["config_sources"] = entry.get("config_sources") or []
        info["scan_devices"] = entry["scan"].get("devices") or []
        info["scan_summary"] = {
            "subnet": entry["scan"].get("network"),
            "target": entry["scan"].get("target"),
            "devices": len(entry["scan"].get("devices") or []),
        }
        return info
    info = _network_info(NET, NET.name)
    info["description"] = NET.description
    info["presets"] = ALL_PRESETS
    info["source"] = "demo"
    info["mode"] = "demo"
    return info


@app.get("/api/org/network")
def org_network_by_key(api_key: str | None = Header(default=None, alias="X-NetProof-Key"), request: Request = None) -> dict:
    """Fetch an account's network using ONLY its API key (no session needed).
    Returns the same payload the dashboard uses, so pasting an account key in
    the Agent tab renders that managed network directly."""
    if request and not ratelimit.allow(request, "org_network", 120, 60):
        raise HTTPException(status_code=429, detail="rate limit: 120 per minute")
    org = tenant_store.get_org_by_api_key(api_key or "")
    if org is None:
        raise HTTPException(status_code=401, detail="invalid or missing X-NetProof-Key")
    entry = _agent_net(org["id"])
    if entry is None:
        return {
            "source": "none",
            "mode": "agent",
            "org": org["id"],
            "org_name": org["name"],
            "onboarding": True,
            "description": "No agent report yet. Install the NetProof agent inside the network and run it with this account's API key — the dashboard never scans on its own.",
        }
    info = _network_info(entry["net"], entry["net"].name)
    info["description"] = entry["net"].description
    info["presets"] = ALL_PRESETS
    info["source"] = "agent"
    info["mode"] = "agent"
    info["org"] = org["id"]
    info["org_name"] = org["name"]
    info["reported_at"] = entry["at"]
    info["confirmations"] = confirm_counts(entry["net"])
    info["agent_changes"] = entry["changes"]
    info["config_sources"] = entry.get("config_sources") or []
    info["scan_devices"] = entry["scan"].get("devices") or []
    info["scan_summary"] = {
        "subnet": entry["scan"].get("network"),
        "target": entry["scan"].get("target"),
        "devices": len(entry["scan"].get("devices") or []),
    }
    return info


@app.get("/api/model")
def model_info(mode: str = "demo", org: str = "", protect: str = "", request: Request = None) -> dict:
    if mode == "agent":
        if org:
            _require_org_scope(request, org)
        else:
            require_session(request)
    global _SCAN_NET, _SCAN_META
    if mode == "scan" and protect:
        # Owner ticked services on the last live scan: rebuild the policy from the
        # RETAINED discovery result with THAT opt-in set â€” no rescan needed. Empty
        # or absent protect is a plain render. parse the JSON list of "ip:port".
        try:
            wanted = set(json.loads(protect))
        except Exception:
            raise HTTPException(status_code=400, detail="protect must be a JSON array of 'ip:port' service keys, e.g. [\"192.168.1.5:445\"]")
        with _SCAN_LOCK:
            if _SCAN_RESULT is None:
                raise HTTPException(status_code=400, detail="No live scan yet - run a scan from the 'Scan a network' panel first.")
            net, _meta = build_net(_SCAN_RESULT, protect=wanted)
            if _SCAN_CONFIG:
                ingest_config(net, _SCAN_CONFIG)
            _SCAN_NET = net
            _SCAN_META = _meta
        net = _model_for_mode("scan")
        info = _network_info(net, net.name)
        info["description"] = net.description
        info["scan_at"] = _SCAN_AT
        info["scan_summary"] = {"subnet": _SCAN_RESULT.get("network"), "target": _SCAN_RESULT.get("target"), "models": _SCAN_META}
        info["opt_in"] = "protect"
        info["confirmations"] = confirm_counts(net)
        info["config_sources"] = list(_SCAN_CONFIG_SOURCES)
        return info
    net = _model_for_mode(mode, org or None)
    info = _network_info(net, net.name)
    info["description"] = net.description
    if mode == "scan":
        with _SCAN_LOCK:
            info["scan_at"] = _SCAN_AT
            info["scan_summary"] = {"subnet": _SCAN_RESULT.get("network"), "target": _SCAN_RESULT.get("target"), "models": _SCAN_META}
            info["confirmations"] = confirm_counts(net)
            info["config_sources"] = list(_SCAN_CONFIG_SOURCES)
    if mode == "agent":
        entry = _agent_net(org)
        if entry is None:
            raise HTTPException(status_code=400, detail="No agent report yet for this account.")
        info["source"] = "agent"
        info["reported_at"] = entry["at"]
        info["confirmations"] = confirm_counts(entry["net"])
        info["config_sources"] = entry.get("config_sources") or []
    return info


def _intel_bundle(ip: str, mode: str, org: str, request: Request) -> dict:
    """Assemble the target-intelligence bundle for `ip`, scoped to the same
    model window the dashboard is showing (active scan / agent report / demo).
    Session scope mirrors /api/model: scans and agent reports are attributable
    actions, an agent account requires org scope, the demo baseline is public."""
    if mode == "agent":
        if org:
            _require_org_scope(request, org)
        else:
            require_session(request)
    elif mode == "scan":
        require_session(request)
    scan = None
    scope: dict = {"mode": mode, "org": org or "default"}
    if mode == "scan":
        with _SCAN_LOCK:
            if _SCAN_NET is None:
                raise HTTPException(status_code=400, detail="No live scan yet - run a scan from the 'Scan a network' panel first.")
            net = _SCAN_NET
            scan = _SCAN_RESULT or {}
            scope.update({
                "subnet": scan.get("network"),
                "scan_target": scan.get("target"),
                "at": datetime.datetime.fromtimestamp(_SCAN_AT).isoformat() if _SCAN_AT else None,
                "config_sources": list(_SCAN_CONFIG_SOURCES),
            })
    elif mode == "agent":
        entry = _agent_net(org)
        if entry is None:
            raise HTTPException(status_code=400, detail="No agent report yet for this account.")
        net = entry["net"]
        scan = entry["scan"] or {}
        scope.update({
            "subnet": scan.get("network"),
            "scan_target": scan.get("target"),
            "at": entry["at"],
            "config_sources": entry.get("config_sources") or [],
        })
    else:
        net = NET
        scope["model"] = str(NET_PATH)
    return target_intelligence(ip, net, scan=scan, scope=scope, org=org or "default")


@app.get("/api/target/{ip}/intelligence")
def target_intelligence_endpoint(ip: str, mode: str = "demo", org: str = "", request: Request = None) -> dict:
    """A per-device dossier: identity, discovery detail, confirmed-vs-inferred,
    the guardrails that would fire on THIS device, past validations touching it,
    and evidence-based suggested actions. Scoped to the active model window."""
    return _intel_bundle(ip, mode, org, request)


@app.get("/api/target/{ip}/intelligence/export")
def target_intelligence_export(ip: str, mode: str = "demo", org: str = "", request: Request = None):
    """Machine-readable JSON export of the target-intelligence bundle
    (consistent with the verdict export surface)."""
    bundle = _intel_bundle(ip, mode, org, request)
    fname = f"netproof-intel-{ip}.json"
    return JSONResponse(
        content=bundle,
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.post("/api/validate")
def validate(req: ChangeRequest, request: Request = None) -> dict:
    if request and not ratelimit.allow(request, "validate", 60, 60):
        raise HTTPException(status_code=429, detail="validate rate limit: 60 per minute")
    if req.mode == "agent":
        if req.account:
            _require_org_scope(request, req.account)
        else:
            require_session(request)
    net = _model_for_mode(req.mode, req.account)
    try:
        report = run_validation_pipeline(req.change, net,
                                         org_id=(req.account if req.mode == "agent" else ""))["report"]
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    prov = _provenance(req.mode, net, req.change, requester=req.requester)
    report["provenance"] = prov

    # org pre-flight (guardrails) â€” a distinct layer, rendered separately from
    # the engine's trust score. A critical trip hard-blocks regardless.
    cfg = load_guardrails(org=req.org)
    guardrails = check_change(req.change, net=net, org=req.org)
    report["guardrails"] = {
        "org": cfg["org"],
        "source": cfg["source"],
        "pass": not guardrail_blocked(guardrails),
        "checks": guardrails,
    }
    report["summary"]["engine_verdict"] = report["summary"]["verdict"]
    report["summary"]["engine_score"] = report["summary"]["trust_score"]
    if guardrail_blocked(guardrails):
        report["summary"] = {**report["summary"], "verdict": "block", "guardrail_block": True}
    metrics_note_verdict(report["summary"].get("verdict"))

    try:
        net_after = apply_change(net, req.change)
        report["proposed_diff"] = unified_diff(net, net_after)
    except ValueError:
        report["proposed_diff"] = ""

    vid = save_verdict(net, report, req.change, model_source=prov["model_source"], requester=req.requester,
                      guardrails=guardrails, org_id=(req.account if req.mode == "agent" else ""))
    log_event("validate", actor=(req.requester or "session"), target=vid,
              detail={"mode": req.mode, "verdict": report["summary"].get("verdict"), "change": req.change.get("type")},
              ip=(request.client.host if request and request.client else None))
    report["audit"] = {
        "verdict_id": vid,
        "model_hash": model_hash(net),
        "change_fingerprint": prov["change_fingerprint"],
        "replay_endpoint": f"/api/verdicts/{vid}/replay",
        "export_endpoint": f"/api/verdicts/{vid}/export",
        "verification_endpoint": "/api/verifications",
        "replayed_deterministic": True,
    }

    try:
        from engine import postchange as _postchange
        report["prediction"] = _postchange.build_prediction(report, None)
    except Exception as _exc:  # additive; must never break validation
        report["prediction"] = {"available": False, "reason": str(_exc)}
    return report


@app.post("/api/intent")
def intent(req: IntentRequest, request: Request = None) -> dict:
    if req.mode == "agent":
        if req.account:
            _require_org_scope(request, req.account)
        else:
            require_session(request)
    """Turn plain English into a referee-compatible change."""
    net = _model_for_mode(req.mode, req.account)
    parsed = parse_intent(req.text, net)
    if not parsed.get("ok"):
        raise HTTPException(status_code=400, detail=(parsed.get("errors") or ["couldn't parse"])[0])
    return parsed


@app.get("/api/guardrails")
def guardrails_config(org: str = "default", request: Request = None) -> dict:
    """The org's loaded guardrail rule set (source + every rule)."""
    if org != "default":
        _require_org_scope(request, org)
    cfg = load_guardrails(org=org)
    return {"org": cfg["org"], "source": cfg["source"], "rules": cfg["rules"]}


@app.post("/api/guardrails")
def guardrails(req: GuardrailRequest, request: Request = None) -> dict:
    """Organisational pre-flight checks on a proposed change."""
    if req.mode == "agent":
        if req.account:
            _require_org_scope(request, req.account)
        else:
            require_session(request)
    net = _model_for_mode(req.mode, req.account)
    checks = check_change(req.change, net=net, org=req.org)
    return {"org": req.org, "pass": not guardrail_blocked(checks), "hard_block": guardrail_blocked(checks), "checks": checks}


@app.get("/api/drift")
def drift_status(mode: str = "demo", org: str = "", request: Request = None) -> dict:
    """Current model vs. the last approved baseline for this network (Phase 4).

    Independently of any specific change, this tells an engineer whether the
    running model quietly drifted off what was last signed off - and how risky
    each moved section is.
    """
    if request and mode != "demo":
        if org:
            _require_org_scope(request, org)
        else:
            require_session(request)
    net = _model_for_mode(mode, org)
    org_id = org or None
    baseline, baseline_at = baseline_meta(net, org_id)
    results = detect_drift(net, baseline, org_id)
    lead = results[0] if results else None
    return {
        "network": net.name,
        "baseline_exists": baseline is not None,
        "baseline_at": baseline_at,
        "drift_count": len(results) - 1 if results else 0,
        "risk_level": (lead.details.get("risk_level") or "none") if lead else "none",
        "suggested_action": lead.suggested_action if lead else None,
        "results": [
            {"drift_type": r.drift_type, "details": r.details,
             "affected_flows": r.affected_flows, "suggested_action": r.suggested_action}
            for r in results
        ],
    }


# --------------------------------------------------------------------------- #
# Provenance / audit                                                          #
# --------------------------------------------------------------------------- #

@app.get("/api/audit")
def audit_events(limit: int = Query(60, ge=1, le=500), _user: dict = Depends(require_admin)) -> dict:
    """Append-only audit trail: logins, org/key operations, scans, agent reports, validations.
    Admin-only â€” it spans every account."""
    return {"events": list_events(limit)}


def _net_for_hash(wanted: str):
    """Return the model whose snapshot hash matches `wanted`.
    Priority: in-memory baselines, then the persisted verdicts snapshot (so
    replay stays deterministic even after a server restart)."""
    with _SCAN_LOCK:
        for net in (NET, _SCAN_NET):
            if net is not None and model_hash(net) == wanted:
                return net
    with _AGENT_LOCK:
        for entry in _AGENT_CACHE.values():
            if entry is not None and model_hash(entry["net"]) == wanted:
                return entry["net"]
    for verdict in list_verdicts(200):
        net = get_snapshot(verdict["id"])
        if net is not None and model_hash(net) == wanted:
            return net
    return None


@app.get("/api/verdicts")
def verdicts(limit: int = Query(20, ge=1, le=100), info: dict = Depends(require_session)) -> dict:
    """Validation history. Requires a session; an org-scoped user only ever sees
    their own account's verdicts (tenant isolation), the global admin sees all."""
    org_id = info.get("org_id") or None
    return {"verdicts": list_verdicts(limit, org_id=org_id)}


def _verdict_visible(info: dict, stored: dict) -> None:
    """Raise 403 when an org-scoped session tries to read a verdict that belongs
    to a different account. Global admin (no org) sees everything."""
    if info.get("org_id") and stored.get("org_id") != info.get("org_id"):
        raise HTTPException(status_code=403, detail="access to this verdict is not allowed for your account")


@app.get("/api/verdicts/{vid}")
def verdict(vid: str, info: dict = Depends(require_session)) -> dict:
    stored = get_verdict(vid)
    if stored is None:
        raise HTTPException(status_code=404, detail=f"no verdict '{vid}' in the audit trail")
    _verdict_visible(info, stored)
    return stored


@app.post("/api/verdicts/{vid}/replay")
def verdict_replay(vid: str, info: dict = Depends(require_session)) -> dict:
    """Re-run the stored change against the same snapshot — proves determinism."""
    stored = get_verdict(vid)
    if stored is None:
        raise HTTPException(status_code=404, detail=f"no verdict '{vid}' in the audit trail")
    _verdict_visible(info, stored)
    net = _net_for_hash(stored["model_hash"])
    if net is None:
        return {"verdict_id": vid, "deterministic": False,
                "reason": "the baseline snapshot for this verdict is not loaded in this process",
                "stored_model_hash": stored["model_hash"]}
    return replay_verdict(vid, net)


@app.get("/api/verdicts/{vid}/export")
def verdict_export(vid: str, info: dict = Depends(require_session)):
    """Machine-readable JSON export: diff + before/after summary + per-rule pass/fail + risk."""
    stored = get_verdict(vid)
    if stored is None:
        raise HTTPException(status_code=404, detail=f"no verdict '{vid}' in the audit trail")
    _verdict_visible(info, stored)
    net = _net_for_hash(stored["model_hash"])
    if net is None:
        raise HTTPException(status_code=409, detail="the baseline snapshot for this verdict is not loaded")
    net_after = apply_change(net, stored["raw_change"])
    report = stored["report"]
    artifact = {
        "exported_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "app": "NetProof",
        "verdict_id": vid,
        "provenance": {
            "engine": "netproof",
            "engine_version": stored["engine_version"],
            "network": stored["model_name"],
            "model_hash": stored["model_hash"],
            "requester": stored["requester"],
            "created_at": stored["created_at"],
            "change_fingerprint": stored["change_fingerprint"],
        },
        "change": stored["raw_change"],
        "proposed_diff": unified_diff(net, net_after),
        "verdict": report.get("summary"),
        "findings": report.get("findings"),
        "matrix": report.get("matrix"),
        "requirements": report.get("requirements"),
        "flow_summary": {"before": report.get("before"), "after": report.get("after")},
        "control_plane": report.get("control_plane"),
        "guardrails": stored.get("guardrails"),
    }
    fname = f"netproof-verdict-{vid}.json"
    return JSONResponse(
        content=artifact,
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.get("/api/verdicts/{vid}/bundle")
def verdict_bundle(vid: str, info: dict = Depends(require_session)):
    """Full diagnostic bundle (Phase 5): everything a support engineer needs in
    one file - verdict, findings, hop-by-hop traces, checklist, pipeline layers,
    drift, diff, guardrails, and the model inventory at validation time."""
    stored = get_verdict(vid)
    if stored is None:
        raise HTTPException(status_code=404, detail=f"no verdict '{vid}' in the audit trail")
    _verdict_visible(info, stored)
    net = _net_for_hash(stored["model_hash"])
    if net is None:
        raise HTTPException(status_code=409, detail="the baseline snapshot for this verdict is not loaded")
    try:
        net_after = apply_change(net, stored["raw_change"])
        proposed_diff = unified_diff(net, net_after)
    except ValueError:
        proposed_diff = ""
    report = stored["report"]
    bundle = {
        "bundle_spec": "netproof/diagnostic/v1",
        "exported_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "app": "NetProof",
        "verdict_id": vid,
        "provenance": {
            "engine": "netproof",
            "engine_version": stored["engine_version"],
            "network": stored["model_name"],
            "model_hash": stored["model_hash"],
            "requester": stored["requester"],
            "created_at": stored["created_at"],
            "change_fingerprint": stored["change_fingerprint"],
        },
        "environment": {
            "model_source": stored.get("model_source") or "unknown",
            "python": sys.version.split()[0],
            "platform": sys.platform,
        },
        "change": json.loads(stored["raw_change"]) if isinstance(stored["raw_change"], str) else stored["raw_change"],
        "proposed_diff": proposed_diff,
        "verdict": report.get("summary"),
        "checklist": report.get("checklist") or [],
        "trace": report.get("trace") or [],
        "pipeline_layers": (report.get("pipeline") or {}).get("layers") or [],
        "drift": report.get("drift"),
        "findings": report.get("findings") or [],
        "matrix": report.get("matrix"),
        "requirements": report.get("requirements") or [],
        "flow_summary": {"before": report.get("before"), "after": report.get("after")},
        "control_plane": report.get("control_plane"),
        "guardrails": stored.get("guardrails"),
        "inventory": {
            "devices": sorted(({
                "name": d.name, "type": d.dtype,
                "interfaces": sorted(i.name for i in d.interfaces),
                "routes": [{"network": r.network, "next_hop": r.next_hop} for r in d.routes],
            } for d in net.devices.values()), key=lambda x: x["name"]),
            "filters": sorted(({
                "name": f.name, "default": f.default, "stateful": f.stateful,
                "rules": [{"action": r.action, "src": r.src, "dst": r.dst,
                           "proto": r.proto, "dport": str(r.dport)} for r in f.rules],
            } for f in net.filters.values()), key=lambda x: x["name"]),
        },
    }
    fname = f"netproof-bundle-{vid}.json"
    return JSONResponse(
        content=bundle,
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@app.get("/api/verdicts/{vid}/diff")
def verdict_diff(vid: str, info: dict = Depends(require_session)) -> PlainTextResponse:
    """Unified-diff of the proposed config change (rendered from the model)."""
    stored = get_verdict(vid)
    if stored is None:
        raise HTTPException(status_code=404, detail=f"no verdict '{vid}' in the audit trail")
    _verdict_visible(info, stored)
    net = _net_for_hash(stored["model_hash"])
    if net is None:
        raise HTTPException(status_code=409, detail="the baseline snapshot for this verdict is not loaded")
    net_after = apply_change(net, stored["raw_change"])
    return PlainTextResponse(unified_diff(net, net_after), media_type="text/plain")


def _verification_visible(info: dict, stored: dict) -> None:
    """403 for an org-scoped session trying to reach another account's verification."""
    if info.get("org_id") and stored.get("org_id") != info.get("org_id"):
        raise HTTPException(status_code=403, detail="access to this verification is not allowed for your account")


@app.post("/api/verifications")
def create_verification(req: VerificationCreateRequest, request: Request = None,
                        info: dict = Depends(require_role)) -> dict:
    """Open a post-change verification for a stored verdict (Phase 6).

    Builds the evidence-aware prediction from the persisted report (never from a
    live simulation) and stores the verification in the ``not_started`` state.
    """
    if request and not ratelimit.allow(request, "verifications", 60, 60):
        raise HTTPException(status_code=429, detail="verifications rate limit: 60 per minute")
    stored = get_verdict(req.verdict_id)
    if stored is None or not (stored.get("report") or {}):
        raise HTTPException(status_code=404, detail=f"no verdict '{req.verdict_id}' with a stored report in the audit trail")
    _verdict_visible(info, stored)

    from engine import postchange as _postchange
    prediction = _postchange.build_prediction(
        stored["report"], req.pre_change_evidence)
    org_id = info.get("org_id") or stored.get("org_id") or "default"
    verification = _postchange.create_verification(
        verdict_id=req.verdict_id,
        org_id=org_id,
        requester=req.requester or info.get("username"),
        change=(stored.get("raw_change") if isinstance(stored.get("raw_change"), dict)
                else json.loads(stored.get("raw_change") or "{}")),
        source_precedence=req.source_precedence,
        prediction=prediction,
    )
    log_event("verification", actor=info.get("username"), target=verification["id"],
              detail={"action": "create", "verdict_id": req.verdict_id,
                      "status": verification["status"], "change": (verification.get("change") or {}).get("type")},
              ip=(request.client.host if request and request.client else None))
    return verification


@app.get("/api/verifications/{vid}")
def verification(vid: str, info: dict = Depends(require_session)) -> dict:
    from engine import postchange as _postchange
    stored = _postchange.get_verification(vid)
    if stored is None:
        raise HTTPException(status_code=404, detail=f"no verification '{vid}'")
    _verification_visible(info, stored)
    return stored


@app.post("/api/verifications/{vid}/evidence")
def verification_evidence(vid: str, req: EvidenceAddRequest, request: Request = None,
                          info: dict = Depends(require_role)) -> dict:
    """Append post-change evidence documents (redacted at rest) to a verification."""
    if request and not ratelimit.allow(request, "verifications", 120, 60):
        raise HTTPException(status_code=429, detail="verifications rate limit: 120 per minute")
    from engine import postchange as _postchange
    stored = _postchange.get_verification(vid)
    if stored is None:
        raise HTTPException(status_code=404, detail=f"no verification '{vid}'")
    _verification_visible(info, stored)
    try:
        updated = _postchange.add_evidence(vid, req.evidence)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    log_event("verification", actor=info.get("username"), target=vid,
              detail={"action": "add_evidence", "documents": len(req.evidence),
                      "status": updated["status"]},
              ip=(request.client.host if request and request.client else None))
    return updated


@app.post("/api/verifications/{vid}/run")
def verification_run(vid: str, req: VerificationRunRequest = None, request: Request = None,
                     info: dict = Depends(require_role)) -> dict:
    """Run comparison + read-only health checks + rollback recommendation."""
    if request and not ratelimit.allow(request, "verifications", 30, 60):
        raise HTTPException(status_code=429, detail="verifications rate limit: 30 per minute")
    from engine import postchange as _postchange
    stored = _postchange.get_verification(vid)
    if stored is None:
        raise HTTPException(status_code=404, detail=f"no verification '{vid}'")
    _verification_visible(info, stored)
    precedence = list((req or VerificationRunRequest()).source_precedence or [])
    if not precedence and stored.get("source_precedence"):
        precedence = list(stored["source_precedence"] or [])
    try:
        out = _postchange.run_verification(vid, source_precedence=precedence or None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    log_event("verification", actor=info.get("username"), target=vid,
              detail={"action": "run", "status": out["status"],
                      "mismatches": len((out.get("result") or {}).get("mismatches") or [])},
              ip=(request.client.host if request and request.client else None))
    return out


@app.get("/api/verifications/{vid}/bundle")
def verification_bundle(vid: str, info: dict = Depends(require_session)):
    """Exportable verification bundle: prediction, evidence, result, health
    checks, rollback and the source verdict summary (secrets always redacted)."""
    from engine import postchange as _postchange
    stored = _postchange.get_verification(vid)
    if stored is None:
        raise HTTPException(status_code=404, detail=f"no verification '{vid}'")
    _verification_visible(info, stored)
    bundle = stored.get("bundle")
    if bundle is None:
        raise HTTPException(status_code=409, detail="run the verification before exporting its bundle")
    fname = f"netproof-verification-{vid}.json"
    return JSONResponse(
        content=bundle,
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


def _provenance(mode: str, net: Net, change: dict, requester: str | None = None) -> dict:
    import hashlib
    if mode == "scan":
        with _SCAN_LOCK:
            source = {
                "mode": "scan",
                "subnet": _SCAN_RESULT.get("network"),
                "target": _SCAN_RESULT.get("target"),
                "discovered_at": datetime.datetime.fromtimestamp(_SCAN_AT).isoformat() if _SCAN_AT else None,
            }
    elif mode == "agent":
        with _AGENT_LOCK:
            for entry in _AGENT_CACHE.values():
                if entry is not None and entry["net"] is net:
                    source = {
                        "mode": "agent",
                        "subnet": entry["scan"].get("network"),
                        "target": entry["scan"].get("target"),
                        "reported_at": entry["at"],
                        "report_id": entry["report_id"],
                    }
                    break
            else:
                source = {"mode": "agent"}
    else:
        source = {
            "mode": "demo",
            "model": str(NET_PATH),
            "loaded_at": datetime.datetime.fromtimestamp(os.path.getmtime(str(NET_PATH))).isoformat(timespec="seconds"),
        }
    fp = hashlib.sha256(repr(change).encode("utf-8")).hexdigest()[:16]
    return {
        "engine": "netproof",
        "engine_version": ENGINE_VERSION,
        "network": net.name,
        "model_source": source,
        "change_fingerprint": change_fingerprint(change),
        "model_hash": model_hash(net),
        "requester": requester,
        "validated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "dry_run": True,
        "note": "Dry run. The baseline model is deep-copied for the test; the real network was never touched.",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
