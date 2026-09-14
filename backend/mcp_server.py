"""NetProof MCP server (official Python `mcp` SDK, FastMCP decorators).

Exposes NetProof to agents over Model Context Protocol. Two transports:

    python backend/mcp_server.py               # stdio (default, for Claude/etc.)
    python backend/mcp_server.py --http        # Streamable HTTP on 127.0.0.1:8100

Tools:
    validate_change         - sentence + differentially validate a change (with guardrails + audit)
    get_verdict             - read a persisted verdict from the audit trail
    list_network_inventory  - devices, interfaces, routes, filters, zones, requirements
    parse_intent            - plain-English -> IR change (+ confirmation)
    get_guardrails          - per-org pre-flight policy check
    list_presets            - example change schema

Every tool is read-only against the real network: the baseline model is
deep-copied for validation and the result is persisted to the audit DB.
"""
from __future__ import annotations

import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from engine.audit import get_verdict as _get_verdict, save_verdict  # noqa: E402
from engine.guardrails import check_change, guardrail_blocked, load_guardrails  # noqa: E402
from engine.intent import parse_intent as _parse_intent  # noqa: E402
from engine.model import load_net, Net  # noqa: E402
from engine.validate import ALL_PRESETS, ENGINE_VERSION  # noqa: E402
from engine import validate as _validate  # noqa: E402


def _model() -> Net:
    return load_net(str(BACKEND / "data" / "acme_office.yaml"))


def _net_for(args: dict) -> Net:
    path = (args or {}).get("model") or ""
    if not path:
        return _model()
    cand = Path(path)
    if cand.exists():
        return load_net(str(cand))
    for f in (BACKEND / "data").glob("*.yaml"):
        if f.stem == path or f.name == path:
            return load_net(str(f))
    return _model()


def _inventory(net: Net) -> dict:
    return {
        "name": net.name,
        "presets": ALL_PRESETS,
        "zones": [
            {"name": z.name, "prefix": z.prefix.text if z.prefix else None,
             "gateway": z.gateway, "source": z.is_source, "dest": z.is_dest}
            for z in net.zones.values()
        ],
        "devices": [
            {
                "name": dev.name, "type": dev.dtype,
                "interfaces": [
                    {"name": i.name, "ip": i.ip, "network": i.network, "filters": i.filters,
                     "connected_to": i.connected_to}
                    for i in dev.interfaces
                ],
                "routes": [{"network": r.network, "next_hop": r.next_hop} for r in dev.routes],
                "dst_nat": [
                    {"public_ip": r.public_ip, "public_port": r.public_port,
                     "private_ip": r.private_ip, "private_port": r.private_port, "proto": r.proto}
                    for r in (dev.dst_nat or [])
                ],
                "bgp": [
                    {"neighbor": p.neighbor, "local_as": p.local_as, "remote_as": p.remote_as,
                     "export_prefixes": p.export_prefixes}
                    for p in (dev.bgp or [])
                ],
                "ospf": [
                    {"area_id": a.area_id, "networks": a.networks}
                    for a in (dev.ospf or [])
                ],
                "dns": [
                    {"zone": r.zone, "fqdn": r.fqdn, "type": r.rtype, "value": r.value, "ttl": r.ttl}
                    for r in (dev.dns or [])
                ],
                "vlans": [
                    {"iface": v.iface, "vlan_id": v.vlan_id, "name": v.name}
                    for v in (dev.vlans or [])
                ],
            }
            for dev in net.devices.values()
        ],
        "filters": [
            {"name": f.name, "default": f.default,
             "rules": [{"action": r.action, "src": r.src, "dst": r.dst, "proto": r.proto, "dport": r.dport}
                       for r in f.rules]}
            for f in net.filters.values()
        ],
        "requirements": [
            {"name": r.name, "src": r.src, "dst": r.dst, "proto": r.proto, "dport": r.dport, "expect": r.expect}
            for r in net.requirements
        ],
    }


def _run() -> "FastMCP":
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:  # pragma: no cover - the pip package mcp is required
        sys.stderr.write("The 'mcp' python package is required. Run: pip install mcp>=1.2\n")
        sys.exit(2)

    mcp = FastMCP(
        "netproof",
        host="127.0.0.1",
        port=8100,
        instructions=(
            "NetProof validates proposed network changes before they touch the network. "
            "Use validate_change to sentence + check a change; parse_intent turns plain text into the "
            "change schema. Replay verdicts to prove determinism and read inventory for context."
        ),
    )

    @mcp.tool()
    def validate_change(
        change_request: str,
        model: str = "",
        org: str = "default",
        requester: str = "",
    ) -> dict:
        """Differentially validate a proposed network change before applying it anywhere.

        Pass `change_request` as a JSON string of the change object, e.g.
        '{"type":"add_filter_rule","filter":"fw-inside-in","at_index":0,"rule":'
        '{"action":"deny","src":"any","dst":"10.0.20.0/24","proto":"tcp","dport":22}}'.
        Returns a verdict (pass/warn/block), trust score, guardrail section, findings with
        evidence, a zone-reachability matrix, a unified config diff, and an audit verdict id.
        Never touches a real network: the baseline model is deep-copied for the test.
        """
        import json
        try:
            change = json.loads(change_request)
        except (TypeError, ValueError):
            raise ValueError("change_request must be a JSON string of a change object")
        if not isinstance(change, dict):
            raise ValueError("change_request must decode to a JSON object")

        net = _net_for({"model": model})
        report = _validate.validate_change(net, change)

        cfg = load_guardrails(org=org)
        checks = check_change(change, net=net, org=org)
        report["guardrails"] = {
            "org": cfg["org"], "source": cfg["source"],
            "pass": not guardrail_blocked(checks), "checks": checks,
        }
        report["summary"]["engine_verdict"] = report["summary"]["verdict"]
        report["summary"]["engine_score"] = report["summary"]["trust_score"]
        if guardrail_blocked(checks):
            report["summary"] = {**report["summary"], "verdict": "block", "guardrail_block": True}
        report["audit"] = {"verdict_id": save_verdict(net, report, change, requester=requester or None, guardrails=checks)}
        return report

    @mcp.tool()
    def get_verdict(verdict_id: str) -> dict:
        """Read a persisted validation verdict from the audit trail (provenance & audit)."""
        stored = _get_verdict(verdict_id)
        if stored is None:
            raise ValueError(f"no verdict '{verdict_id}' in the audit trail")
        return stored

    @mcp.tool()
    def list_network_inventory(model: str = "") -> dict:
        """Return the full inventory NetProof reasons over: devices, interfaces, routes,
        filters/ACLs, NAT, BGP, OSPF, DNS, VLANs, zones and policy requirements."""
        return _inventory(_net_for({"model": model}))

    @mcp.tool()
    def parse_intent(text: str, model: str = "") -> dict:
        """Translate a plain-English network change into the machine change dict the validator
        consumes, with the resolved entities and a confirmation string. Stage 1 resolves every
        name against the inventory; stage 2 emits the IR change."""
        net = _net_for({"model": model})
        parsed = _parse_intent(text, net)
        if not parsed.get("ok"):
            raise ValueError((parsed.get("errors") or ["could not parse intent"])[0])
        return parsed

    @mcp.tool()
    def get_guardrails(change_request: str, org: str = "default", model: str = "") -> dict:
        """Per-org pre-flight policy check on a proposed change (before the main validator).
        Critical failures hard-block the change regardless of the validator's score."""
        import json
        try:
            change = json.loads(change_request)
        except (TypeError, ValueError):
            raise ValueError("change_request must be a JSON string of a change object")
        net = _net_for({"model": model})
        checks = check_change(change, net=net, org=org)
        return {"org": org, "pass": not guardrail_blocked(checks), "hard_block": guardrail_blocked(checks), "checks": checks}

    @mcp.tool()
    def list_presets() -> dict:
        """List the example change presets bundled with NetProof (learn the change schema,
        including the BGP / OSPF / DNS / VLAN change language)."""
        return {"presets": ALL_PRESETS}

    return mcp


if __name__ == "__main__":
    mcp = _run()
    transport = "streamable-http" if "--http" in sys.argv else "stdio"
    mcp.run(transport=transport)