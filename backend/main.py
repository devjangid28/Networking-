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
import os
import threading
import time
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from engine import tenant as tenant_store
from engine.audit import (
    change_fingerprint,
    get_verdict,
    list_verdicts,
    model_hash,
    replay_verdict,
    save_verdict,
    unified_diff,
)
from engine.buildnet import build_net
from engine.confirm import counts as confirm_counts, mark_confirmed
from engine.discover import scan as run_scan
from engine.guardrails import check_change, guardrail_blocked, load_guardrails
from engine.intent import parse_intent
from engine.model import load_net, Net
from engine.reach import apply_change
from engine.validate import ALL_PRESETS, ENGINE_VERSION, PRESETS, validate_change

BASE = Path(__file__).resolve().parent
NET_PATH = BASE / "data" / "acme_office.yaml"
WEB_DIR = BASE.parent / "web"

app = FastAPI(title="NetProof", description="Neutral network-change validation", version=ENGINE_VERSION)

NET = load_net(str(NET_PATH))

tenant_store.init_tenant()

app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

# --------------------------------------------------------------------------- #
# Live scan state                                                           #
# --------------------------------------------------------------------------- #

_SCAN_LOCK = threading.Lock()
_SCAN_RESULT = None   # raw discovery dict
_SCAN_NET = None      # built model
_SCAN_META = {}
_SCAN_AT = 0

# Agent-mode models, keyed by account id. Rebuilt lazily from the account's
# latest agent report and invalidated whenever a new report is stored.
_AGENT_LOCK = threading.Lock()
_AGENT_CACHE: dict[str, dict] = {}


class ScanRequest(BaseModel):
    target: str = Field(..., description="Router/server IP to scan, or CIDR, e.g. 192.168.1.1 or 192.168.1.0/24")
    community: str = Field("public", description="SNMP community for optional device details")
    ping: bool = Field(True, description="Run an ICMP sweep (slower but finds more devices)")
    protect: list[str] | None = Field(None, description=(
        "Opt-in set of ``ip:port`` service keys the owner wants guarded after "
        "this scan (tick to protect). When None every discovered service becomes "
        "a requirement (backward-compatible with the demo/test flows). When an "
        "explicit list is given ONLY those services are protected — anything else "
        "stays 'discovered but open' until the owner ticks it. Pass [] to reveal "
        "the network with nothing guarded yet."))


class AgentReportRequest(BaseModel):
    """Payload a customer-side agent posts OUTBOUND. The server never scans the LAN."""
    scan: dict = Field(..., description="Discovery result from the local agent (same shape /api/scan returns)")
    config: dict | None = Field(None, description="Optional pulled device config: rules/routes the agent READ from the box, marked confirmed")
    agent_version: str | None = Field(None, description="agent/agent.py version that rendered the report")
    source_host: str | None = Field(None, description="Hostname of the machine the agent ran on")
    scan_at: str | None = Field(None, description="When the agent performed the discovery")


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


@app.post("/api/scan")
def scan_endpoint(req: ScanRequest) -> dict:
    """Discover systems on the segment of `target`, then build a model from it."""
    global _SCAN_RESULT, _SCAN_NET, _SCAN_META, _SCAN_AT
    if not req.target.strip():
        raise HTTPException(status_code=400, detail="target is required (router/server IP, or CIDR)")
    started = time.time()
    result = run_scan(req.target, community=req.community, do_ping=req.ping)
    if not result.get("devices"):
        raise HTTPException(status_code=400, detail=("No devices discovered. " + " ".join(result.get("notes", [])) or "Check the IP and that you are on the same network."))
    try:
        # Protect is the OPT-IN set ("ip:port" service keys) the owner ticked to
        # guard. None means "guard everything this scan finds" (the demo/agent
        # flows stay fully governed — their model is a complete policy). A list —
        # even empty — means ONLY the listed services become policy requirements;
        # everything else stays "discovered but open" until the owner ticks it.
        net, meta = build_net(result, protect=set(req.protect) if req.protect is not None else None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    with _SCAN_LOCK:
        _SCAN_RESULT = result
        _SCAN_NET = net
        _SCAN_META = meta
        _SCAN_AT = time.time()
    result["model"] = meta
    result["seconds"] = round(time.time() - started, 1)
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
def create_org(req: OrgRequest) -> dict:
    try:
        org = tenant_store.create_org(req.name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"org": org, "note": "The API key is returned once at creation — store it in the agent config on the customer machine."}


@app.get("/api/orgs")
def list_orgs() -> dict:
    return {"orgs": tenant_store.list_orgs()}


@app.post("/api/agent/report")
def agent_report(req: AgentReportRequest, api_key: str | None = Header(default=None, alias="X-NetProof-Key")) -> dict:
    """Accept an agent's outbound discovery report (API-key authenticated)."""
    org = tenant_store.get_org_by_api_key(api_key or "")
    if org is None:
        raise HTTPException(status_code=401, detail="invalid or missing X-NetProof-Key")
    payload = {
        "scan": req.scan,
        "config": req.config or {},
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
def agent_status(org: str = "") -> dict:
    if not org:
        raise HTTPException(status_code=400, detail="org query param required")
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
def network_info(org: str = "") -> dict:
    """The dashboard's network. With `org` = an account's LATEST AGENT REPORT
    (the dashboard never scans on its own). Without `org` = the demo baseline."""
    if org:
        entry = _agent_net(org)
        if entry is None:
            return {
                "source": "none",
                "mode": "agent",
                "org": org,
                "onboarding": True,
                "description": "No agent report yet. Install the NetProof agent inside the network and paste this account's API key — the dashboard never scans on its own.",
            }
        info = _network_info(entry["net"], entry["net"].name)
        info["description"] = entry["net"].description
        info["presets"] = ALL_PRESETS
        info["source"] = "agent"
        info["mode"] = "agent"
        info["reported_at"] = entry["at"]
        info["confirmations"] = confirm_counts(entry["net"])
        info["agent_changes"] = entry["changes"]
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


@app.get("/api/model")
def model_info(mode: str = "demo", org: str = "", protect: str = "") -> dict:
    if mode == "scan" and protect:
        # Owner ticked services on the last live scan: rebuild the policy from the
        # RETAINED discovery result with THAT opt-in set — no rescan needed. Empty
        # or absent protect is a plain render. parse the JSON list of "ip:port".
        try:
            wanted = set(json.loads(protect))
        except Exception:
            raise HTTPException(status_code=400, detail="protect must be a JSON array of 'ip:port' service keys, e.g. [\"192.168.1.5:445\"]")
        with _SCAN_LOCK:
            if _SCAN_RESULT is None:
                raise HTTPException(status_code=400, detail="No live scan yet - run a scan from the 'Scan a network' panel first.")
            net, _meta = build_net(_SCAN_RESULT, protect=wanted)
            _SCAN_NET = net
            _SCAN_META = _meta
        net = _model_for_mode("scan")
        info = _network_info(net, net.name)
        info["description"] = net.description
        info["scan_at"] = _SCAN_AT
        info["scan_summary"] = {"subnet": _SCAN_RESULT.get("network"), "target": _SCAN_RESULT.get("target"), "models": _SCAN_META}
        info["opt_in"] = "protect"
        return info
    net = _model_for_mode(mode, org or None)
    info = _network_info(net, net.name)
    info["description"] = net.description
    if mode == "scan":
        with _SCAN_LOCK:
            info["scan_at"] = _SCAN_AT
            info["scan_summary"] = {"subnet": _SCAN_RESULT.get("network"), "target": _SCAN_RESULT.get("target"), "models": _SCAN_META}
    if mode == "agent":
        entry = _agent_net(org)
        if entry is None:
            raise HTTPException(status_code=400, detail="No agent report yet for this account.")
        info["source"] = "agent"
        info["reported_at"] = entry["at"]
        info["confirmations"] = confirm_counts(entry["net"])
    return info


@app.post("/api/validate")
def validate(req: ChangeRequest) -> dict:
    net = _model_for_mode(req.mode, req.account)
    try:
        report = validate_change(net, req.change)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    prov = _provenance(req.mode, net, req.change, requester=req.requester)
    report["provenance"] = prov

    # org pre-flight (guardrails) — a distinct layer, rendered separately from
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

    try:
        net_after = apply_change(net, req.change)
        report["proposed_diff"] = unified_diff(net, net_after)
    except ValueError:
        report["proposed_diff"] = ""

    vid = save_verdict(net, report, req.change, model_source=prov["model_source"], requester=req.requester, guardrails=guardrails)
    report["audit"] = {
        "verdict_id": vid,
        "model_hash": model_hash(net),
        "change_fingerprint": prov["change_fingerprint"],
        "replay_endpoint": f"/api/verdicts/{vid}/replay",
        "export_endpoint": f"/api/verdicts/{vid}/export",
        "replayed_deterministic": True,
    }
    return report


@app.post("/api/intent")
def intent(req: IntentRequest) -> dict:
    """Turn plain English into a referee-compatible change."""
    net = _model_for_mode(req.mode, req.account)
    parsed = parse_intent(req.text, net)
    if not parsed.get("ok"):
        raise HTTPException(status_code=400, detail=(parsed.get("errors") or ["couldn't parse"])[0])
    return parsed


@app.get("/api/guardrails")
def guardrails_config(org: str = "default") -> dict:
    """The org's loaded guardrail rule set (source + every rule)."""
    cfg = load_guardrails(org=org)
    return {"org": cfg["org"], "source": cfg["source"], "rules": cfg["rules"]}


@app.post("/api/guardrails")
def guardrails(req: GuardrailRequest) -> dict:
    """Organisational pre-flight checks on a proposed change."""
    net = _model_for_mode(req.mode, req.account)
    checks = check_change(req.change, net=net, org=req.org)
    return {"org": req.org, "pass": not guardrail_blocked(checks), "hard_block": guardrail_blocked(checks), "checks": checks}


# --------------------------------------------------------------------------- #
# Provenance / audit                                                          #
# --------------------------------------------------------------------------- #

def _net_for_hash(wanted: str):
    """Return the in-memory baseline whose snapshot hash matches `wanted`."""
    with _SCAN_LOCK:
        for net in (NET, _SCAN_NET):
            if net is not None and model_hash(net) == wanted:
                return net
    with _AGENT_LOCK:
        for entry in _AGENT_CACHE.values():
            if entry is not None and model_hash(entry["net"]) == wanted:
                return entry["net"]
    return None


@app.get("/api/verdicts")
def verdicts(limit: int = Query(20, ge=1, le=100)) -> dict:
    return {"verdicts": list_verdicts(limit)}


@app.get("/api/verdicts/{vid}")
def verdict(vid: str) -> dict:
    stored = get_verdict(vid)
    if stored is None:
        raise HTTPException(status_code=404, detail=f"no verdict '{vid}' in the audit trail")
    return stored


@app.post("/api/verdicts/{vid}/replay")
def verdict_replay(vid: str) -> dict:
    """Re-run the stored change against the same snapshot — proves determinism."""
    stored = get_verdict(vid)
    if stored is None:
        raise HTTPException(status_code=404, detail=f"no verdict '{vid}' in the audit trail")
    net = _net_for_hash(stored["model_hash"])
    if net is None:
        return {"verdict_id": vid, "deterministic": False,
                "reason": "the baseline snapshot for this verdict is not loaded in this process",
                "stored_model_hash": stored["model_hash"]}
    return replay_verdict(vid, net)


@app.get("/api/verdicts/{vid}/export")
def verdict_export(vid: str):
    """Machine-readable JSON export: diff + before/after summary + per-rule pass/fail + risk."""
    stored = get_verdict(vid)
    if stored is None:
        raise HTTPException(status_code=404, detail=f"no verdict '{vid}' in the audit trail")
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


@app.get("/api/verdicts/{vid}/diff")
def verdict_diff(vid: str) -> PlainTextResponse:
    """Unified-diff of the proposed config change (rendered from the model)."""
    stored = get_verdict(vid)
    if stored is None:
        raise HTTPException(status_code=404, detail=f"no verdict '{vid}' in the audit trail")
    net = _net_for_hash(stored["model_hash"])
    if net is None:
        raise HTTPException(status_code=409, detail="the baseline snapshot for this verdict is not loaded")
    net_after = apply_change(net, stored["raw_change"])
    return PlainTextResponse(unified_diff(net, net_after), media_type="text/plain")


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