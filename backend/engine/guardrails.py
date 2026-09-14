"""NetProof organisational guardrails.

A per-org, data-driven policy layer that runs BEFORE the data-plane referee.
Rules live in YAML (backend/data/orgs/<org>.yaml); each rule carries a `when`
matcher (change type + field conditions) and a severity. A severity of
`critical` hard-blocks the change regardless of the main validator's score.

Kept deliberately transparent: the built-in rules ship as YAML too, so every
policy an org runs is visible and editable without touching code.
"""
from __future__ import annotations

import os
from pathlib import Path

import yaml

from .model import Net

ORG_DIR = Path(os.environ.get("NETPROOF_ORG_DIR", str(Path(__file__).resolve().parent.parent / "data" / "orgs")))

BUILTIN_RULES: list[dict] = [
    {
        "id": "allow_all_rule",
        "severity": "warning",
        "title": "Allow-all firewall rule",
        "message": "A permit any → any rule makes the policy point meaningless for every flow. Prefer scoped src/dst/proto.",
        "when": {"change_type_in": ["add_filter_rule", "replace_filter_rule"], "rule_action": "permit", "rule_src": "any", "rule_dst": "any", "rule_proto": "any"},
    },
    {
        "id": "deny_all_rule",
        "severity": "warning",
        "title": "Deny-all firewall rule",
        "message": "A deny any → any rule at the top blocks everything behind that policy point.",
        "when": {"change_type_in": ["add_filter_rule", "replace_filter_rule"], "rule_action": "deny", "rule_src": "any", "rule_dst": "any", "rule_proto": "any"},
    },
    {
        "id": "expose_ssh",
        "severity": "warning",
        "title": "SSH exposed broadly",
        "message": "Permitting tcp/22 anywhere (dst=any) is a common escalation path. Confirm the blast radius.",
        "when": {"change_type_in": ["add_filter_rule", "replace_filter_rule"], "rule_action": "permit", "rule_proto": "tcp", "rule_dport_in": [22]},
    },
    {
        "id": "expose_rdp",
        "severity": "warning",
        "title": "RDP exposed broadly",
        "message": "Permitting tcp/3389 to dst=any hands out a remote-desktop foothold. Check scope.",
        "when": {"change_type_in": ["add_filter_rule", "replace_filter_rule"], "rule_action": "permit", "rule_proto": "tcp", "rule_dport_in": [3389]},
    },
    {
        "id": "remove_default_route",
        "severity": "critical",
        "title": "Default route removed",
        "message": "Removing the 0.0.0.0/0 route on a border device kills Internet egress for the whole branch.",
        "when": {"change_type": "remove_route", "route_network": "0.0.0.0/0"},
    },
    {
        "id": "add_default_route",
        "severity": "info",
        "title": "Default route added",
        "message": "A new default route re-pins egress; ensure it is the intended upstream (dual-WAN, DR).",
        "when": {"change_type": "add_route", "route_network": "0.0.0.0/0"},
    },
    {
        "id": "forward_ssh",
        "severity": "critical",
        "title": "SSH port-forward to the Internet",
        "message": "Publishing tcp/22 to the WAN exposes a shell to the world. Exclude or restrict source, and rotate creds first.",
        "when": {"change_type": "add_dst_nat", "dst_nat_port_in": [22]},
    },
    {
        "id": "forward_rdp",
        "severity": "critical",
        "title": "RDP port-forward to the Internet",
        "message": "Publishing tcp/3389 to the WAN is a ransomware-grade exposure. Use a VPN or previewing access.",
        "when": {"change_type": "add_dst_nat", "dst_nat_port_in": [3389]},
    },
    {
        "id": "forward_wide",
        "severity": "warning",
        "title": "Port-forward to a desktop",
        "message": "Forwarding to a workstation-class host (not a server) is unusual - double-check the target deserves public inbound.",
        "when": {"change_type": "add_dst_nat", "dst_nat_to_host": True},
    },
    {
        "id": "bgp_export_default",
        "severity": "warning",
        "title": "BGP exporting the default route",
        "message": "Advertising 0.0.0.0/0 over BGP is a route-leak risk toward transit peers. Verify the peering is a controlled edge.",
        "when": {"change_type": "add_bgp_peer", "bgp_export_default": True},
    },
    {
        "id": "bgp_neighbor_unreachable",
        "severity": "critical",
        "title": "BGP peer not in inventory",
        "message": "The BGP neighbor is not an address any modelled device owns - the session cannot come up and the config is inert at best, a blackhole at worst.",
        "when": {"change_type": "add_bgp_peer", "bgp_neighbor_unreachable": True},
    },
    {
        "id": "ospf_wan_advertise",
        "severity": "warning",
        "title": "OSPF across a WAN link",
        "message": "Advertising a WAN/Internet-facing subnet into OSPF leaks interior topology toward the provider.",
        "when": {"change_type": "add_ospf_network", "ospf_advertise_wan": True},
    },
    {
        "id": "dns_unmanaged_target",
        "severity": "warning",
        "title": "DNS pointing outside managed inventory",
        "message": "The record target is not an address any managed device owns. Names will resolve into a silent blackhole.",
        "when": {"change_type": "add_dns_record", "dns_unmanaged_target": True},
    },
    {
        "id": "vlan_reserved",
        "severity": "critical",
        "title": "Reserved VLAN id",
        "message": "VLAN ids below 1 or above 4094 are reserved for platform use and will be rejected by the switch.",
        "when": {"change_type": "add_vlan_assignment", "vlan_id_lt": 1},
    },
    {
        "id": "vlan_4094",
        "severity": "critical",
        "title": "VLAN id beyond the legal range",
        "message": "VLAN ids above 4094 cannot exist in 802.1Q; the switch will reject the assignment.",
        "when": {"change_type": "add_vlan_assignment", "vlan_id_gt": 4094},
    },
    {
        "id": "vlan_native_one",
        "severity": "warning",
        "title": "Assignment into the native VLAN",
        "message": "Placing a port in VLAN 1 reuses the native/default segment. Use a named segment for access ports.",
        "when": {"change_type": "add_vlan_assignment", "vlan_id_lt": 2},
    },
    {
        "id": "vlan_segment_move",
        "severity": "warning",
        "title": "Switchport segments change",
        "message": "Reassigning a live access port moves everything behind it onto a new L2 segment.",
        "when": {"change_type": "add_vlan_assignment", "vlan_segment_move": True},
    },
    {
        "id": "vlan_on_host",
        "severity": "critical",
        "title": "VLAN assigned to a host",
        "message": "VLAN assignments only apply to switch/router ports. Assigning one to a workstation is a category error.",
        "when": {"change_type": "add_vlan_assignment", "vlan_on_host": True},
    },
]


def load_guardrails(path: str | None = None, org: str = "default") -> dict:
    """Load org guardrails: the org YAML file, merged over the built-ins.

    A rule in the file with the same `id` as a built-in replaces it entirely.
    """
    merged: dict[str, dict] = {r["id"]: dict(r) for r in BUILTIN_RULES}
    source = "built-in rules"
    org_name = org or "default"
    if path:
        p = Path(path)
    else:
        p = Path(ORG_DIR) / f"{org_name}.yaml"
    if p.exists():
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        org_name = data.get("org", org_name)
        for rule in data.get("rules") or []:
            if not isinstance(rule.get("when"), dict):
                rule["when"] = {}
            merged[str(rule["id"])] = rule
        source = str(p)
    return {"org": org_name, "rules": list(merged.values()), "source": source}


# --------------------------------------------------------------------------- #
# rule evaluation                                                             #
# --------------------------------------------------------------------------- #

def _device_owning_ip(net: Net, addr: str):
    if not net or not addr:
        return None
    try:
        want = _ip_int(addr)
    except (ValueError, TypeError):
        return None
    for dev in net.devices.values():
        if want in dev.own_ips():
            return dev
    return None


def _ip_int(s: str) -> int:
    parts = s.strip().split(".")
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])


def _canonical(p) -> str:
    return f"{_ip_str(p.lo)}/{p.plen}"


def _ip_str(n: int) -> str:
    return f"{n >> 24 & 255}.{n >> 16 & 255}.{n >> 8 & 255}.{n & 255}"


def match_one(key: str, value, change: dict, net: Net | None) -> bool:
    ctype = change.get("type")
    rule = change.get("rule") or {}
    if key == "change_type":
        return ctype == value
    if key == "change_type_in":
        return ctype in value
    if key == "rule_action":
        return (rule.get("action") or "").lower() == str(value).lower()
    if key == "rule_proto":
        return (rule.get("proto") or "any").lower() == str(value).lower()
    if key == "rule_src":
        return (rule.get("src") or "any") == value
    if key == "rule_dst":
        return (rule.get("dst") or "any") == value
    if key == "rule_dport_in":
        return int(rule.get("dport") or 0) in [int(x) for x in (value if isinstance(value, list) else [value])]
    if key == "route_network":
        return (change.get("route") or {}).get("network") == value
    if key == "dst_nat_port_in":
        return int((change.get("dst_nat") or {}).get("public_port") or 0) in [int(x) for x in (value if isinstance(value, list) else [value])]
    if key == "dst_nat_to_host":
        dev = net.devices.get(change.get("device")) if net else None
        if not dev:
            return False
        priv = (change.get("dst_nat") or {}).get("private_ip")
        owner = _device_owning_ip(net, priv) if priv else None
        return bool(value) == bool(owner is not None and owner.dtype == "host")
    if key == "bgp_export_default":
        exports = [str(p) for p in ((change.get("peer") or {}).get("export_prefixes") or [])]
        has_default = any(p in ("0.0.0.0/0", "default") for p in exports)
        return bool(value) == has_default
    if key == "bgp_neighbor_unreachable":
        neighbor = (change.get("peer") or {}).get("neighbor")
        owner = _device_owning_ip(net, neighbor) if net and neighbor else None
        return bool(value) == (owner is None and bool(neighbor))
    if key == "ospf_advertise_wan":
        dev = net.devices.get(change.get("device")) if net else None
        if not dev:
            return False
        network = change.get("network")
        wan = False
        for i in dev.interfaces:
            if not i.prefix or not network:
                continue
            if _canonical(i.prefix) == network and str(i.label or "").lower() in ("isp", "wan", "outside", "upstream", "internet"):
                wan = True
                break
        return bool(value) == wan
    if key == "dns_type_in":
        rtype = str((change.get("record") or {}).get("type") or "").upper()
        return rtype in [str(x).upper() for x in (value if isinstance(value, list) else [value])]
    if key == "dns_unmanaged_target":
        rec = change.get("record") or {}
        owner = _device_owning_ip(net, rec.get("value")) if net and rec.get("value") else None
        return bool(value) == (owner is None and bool(rec.get("value")))
    if key in ("vlan_id_lt", "vlan_id_gt"):
        vid = int((change.get("vlan") or {}).get("vlan_id") or 0)
        return vid < int(value) if key == "vlan_id_lt" else vid > int(value)
    if key == "vlan_on_host":
        dev = net.devices.get(change.get("device")) if net else None
        return bool(value) == bool(dev is not None and dev.dtype == "host")
    if key == "vlan_segment_move":
        dev = net.devices.get(change.get("device")) if net else None
        if not dev:
            return False
        iface = (change.get("vlan") or {}).get("iface")
        prev = next((a for a in (dev.vlans or []) if a.iface == iface), None)
        new_vid = int((change.get("vlan") or {}).get("vlan_id") or 0)
        moved = bool(prev and prev.vlan_id != new_vid)
        return bool(value) == moved
    return True  # unknown matcher keys are ignored, never block


def _rule_matches(rule: dict, change: dict, net: Net | None) -> bool:
    when = rule.get("when") or {}
    if not isinstance(when, dict):
        return False
    for k, v in when.items():
        if not match_one(k, v, change, net):
            return False
    return True


# --------------------------------------------------------------------------- #
# public API                                                                 #
# --------------------------------------------------------------------------- #

def check_change(change: dict, net: Net | None = None, org: str = "default", guardrail_path: str | None = None) -> list[dict]:
    """Score `change` against an org's guardrail set. Returns fired checks."""
    cfg = load_guardrails(guardrail_path, org)
    hits = [dict(r) for r in cfg["rules"] if _rule_matches(r, change, net)]
    # structural default-route removal (index-based changes carry no network text)
    if change.get("type") == "remove_route":
        hits.extend(check_default_route_removal(net, change))
    dedup: list[dict] = []
    seen: set[str] = set()
    for c in hits:
        if c["id"] in seen:
            continue
        seen.add(c["id"])
        dedup.append(c)
    return dedup


def guardrail_blocked(checks: list[dict]) -> bool:
    """A guardrail failure hard-blocks regardless of the validator's score."""
    return any(c.get("severity") == "critical" for c in checks)


def check_default_route_removal(net: Net | None, change: dict) -> list[dict]:
    """Structural check needing the model: was a 0.0.0.0/0 route deleted?"""
    if change.get("type") != "remove_route" or net is None:
        return []
    dev = net.devices.get(change.get("device"))
    if dev is None:
        return []
    routes = dev.routes
    idx = int(change.get("index", -1))
    if 0 <= idx < len(routes) and routes[idx].network in ("0.0.0.0/0", "default"):
        return [{
            "id": "remove_default_route",
            "severity": "critical",
            "title": "Default route removed",
            "message": "Removing the 0.0.0.0/0 route on a border device kills Internet egress for the whole branch.",
        }]
    return []