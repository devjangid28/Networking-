"""NetProof target intelligence bundle.

A per-device dossier assembled purely from what the active context already
knows about a target (the current model + a live scan or agent report + the
org's guardrails + the persisted audit trail):

    target                   the IP being interrogated
    scope                    where the picture comes from (scan / agent report /
                             demo) and the org
    identity                 who/what the device is (hostname, MAC, vendor,
                             type) and how confident we are (SNMP > scan > model)
    discovery_detail         raw discovery: SNMP fields, open services, LLDP/CDP
                             neighbours, model interfaces + links
    confirmed_vs_inferred    per-entry ground-truth accounting (rules/routes)
    applicable_guardrails    the org rules that could fire for a change on THIS
                             device, annotated with why they are relevant
    validation_history       every past verdict whose change mentioned the device
    suggested_actions        evidence-based, provable next steps (no guesses)

Everything here is read-only and derived from data already in-band; the bundle
never scans, never queries the network, and never fabricates a fact it cannot
point at.
"""
from __future__ import annotations

from typing import Optional

from .audit import list_verdicts_for_target
from .guardrails import load_guardrails
from .model import Net, Device, ip_int, ip_str


# --------------------------------------------------------------------------- #
# locating the device                                                          #
# --------------------------------------------------------------------------- #

def device_for_ip(net: Net | None, ip: str) -> Optional[Device]:
    """The model device that owns `ip` (via its interface addresses)."""
    if net is None or not ip:
        return None
    try:
        want = ip_int(ip)
    except (ValueError, TypeError):
        return None
    for dev in net.devices.values():
        if want in dev.own_ips():
            return dev
    return None


def scan_device_for_ip(scan: dict | None, ip: str) -> Optional[dict]:
    if not scan:
        return None
    for d in scan.get("devices") or []:
        if d.get("ip") == ip:
            return d
    return None


def _zone_for_ip(net: Net | None, ip: str) -> Optional[str]:
    """A zone whose name is the IP, or whose prefix contains it."""
    if net is None or not ip:
        return None
    try:
        want = ip_int(ip)
    except (ValueError, TypeError):
        return None
    for zone in net.zones.values():
        if zone.name == ip or (zone.prefix and zone.prefix.contains(want)):
            return zone.name
    return None


def _device_needles(dev: Device | None, ip: str, net: Net | None) -> list[str]:
    """Every text an audit change could plausibly use for this device."""
    needles = [ip]
    if dev is not None:
        needles.append(dev.name)
        needles.extend(ip_str(own) for own in dev.own_ips())
    zone = _zone_for_ip(net, ip)
    if zone and zone != ip:
        needles.append(zone)
    return [n for n in dict.fromkeys(needles) if n]


# --------------------------------------------------------------------------- #
# confirmed vs inferred                                                        #
# --------------------------------------------------------------------------- #

def _confirmed_counts(dev: Device | None, net: Net | None) -> dict:
    rules = {"confirmed": 0, "inferred": 0}
    routes = {"confirmed": 0, "inferred": 0}
    entries: list[dict] = []
    if dev is not None and net is not None:
        for iface in dev.interfaces:
            for fname in iface.filters:
                f = net.filters.get(fname)
                if not f:
                    continue
                for r in f.rules:
                    source = r.source if r.source == "confirmed" else "inferred"
                    rules[source] += 1
                    entries.append({
                        "kind": "rule", "iface": iface.name, "filter": fname,
                        "label": r.describe(), "source": source,
                    })
        for r in dev.routes:
            source = r.source if r.source == "confirmed" else "inferred"
            routes[source] += 1
            entries.append({
                "kind": "route", "label": f"{r.network} via {r.next_hop}", "source": source,
            })
    return {"rules": rules, "routes": routes, "entries": entries}


# --------------------------------------------------------------------------- #
# guardrail applicability                                                      #
# --------------------------------------------------------------------------- #

_CHANGE_TYPES_BY_FEATURE = {
    "filter": {"add_filter_rule", "remove_filter_rule", "replace_filter_rule"},
    "route": {"add_route", "remove_route"},
    "dst_nat": {"add_dst_nat", "remove_dst_nat"},
    "bgp": {"add_bgp_peer", "remove_bgp_peer"},
    "ospf": {"add_ospf_network", "remove_ospf_network"},
    "dns": {"add_dns_record", "remove_dns_record"},
    "vlan": {"add_vlan_assignment", "remove_vlan_assignment"},
}


def _rule_change_types(when: dict) -> set[str]:
    types: set[str] = set()
    for key, value in (when or {}).items():
        if key == "change_type" and isinstance(value, str):
            types.add(value)
        elif key == "change_type_in" and isinstance(value, list):
            types.update(value)
    return types


def _device_feature_evidence(dev: Device | None, net: Net | None, when: dict) -> list[str]:
    """Facts on THIS device that make a rule applicable (empty = not applicable
    unless the rule is global to a change class)."""
    if dev is None:
        return []
    evidence: list[str] = []
    types = _rule_change_types(when)
    has_route = bool(dev.routes)
    has_dst_nat = bool(dev.dst_nat or dev.nat)
    has_bgp = bool(dev.bgp)
    has_ospf = bool(dev.ospf)
    has_dns = bool(dev.dns)
    has_vlan = bool(dev.vlans) or dev.dtype == "switch"
    is_policy_point = dev.dtype in ("router", "firewall", "switch") or any(i.filters for i in dev.interfaces)

    if types & _CHANGE_TYPES_BY_FEATURE["route"]:
        default_route = next((r for r in dev.routes if r.network in ("0.0.0.0/0", "default")), None)
        if default_route is not None:
            evidence.append("this device holds the default route 0.0.0.0/0 — removing or re-pointing it is the guardrailed action")
        elif has_route:
            evidence.append("this device carries static routes")
    if types & _CHANGE_TYPES_BY_FEATURE["dst_nat"]:
        if dev.dst_nat:
            evidence.append(f"this device publishes {len(dev.dst_nat)} port-forward(s) to the Internet/inbound")
        elif dev.nat:
            evidence.append("this device performs source/destination NAT")
    if types & _CHANGE_TYPES_BY_FEATURE["bgp"]:
        if has_bgp:
            evidence.append(f"this device runs {len(dev.bgp)} BGP peer(s)")
    if types & _CHANGE_TYPES_BY_FEATURE["ospf"]:
        if has_ospf:
            evidence.append(f"this device advertises {len(dev.ospf)} OSPF area(s)")
        elif any(str(i.label or "").lower() in ("isp", "wan", "outside", "upstream", "internet") for i in dev.interfaces):
            evidence.append("this device carries a WAN-facing interface")
    if types & _CHANGE_TYPES_BY_FEATURE["dns"]:
        if has_dns:
            evidence.append(f"this device is authoritative for {len(dev.dns)} DNS record(s)")
    if types & _CHANGE_TYPES_BY_FEATURE["vlan"]:
        if has_vlan:
            evidence.append("this device is a switchport owner (VLAN assignments apply)")
    if types & _CHANGE_TYPES_BY_FEATURE["filter"]:
        if is_policy_point:
            evidence.append("this device enforces filter policy (rule changes land here)")
    return evidence


def applicable_guardrails(org: str, net: Net | None, dev: Device | None) -> list[dict]:
    """The org guardrail rules that could fire for a change ON THIS DEVICE, with
    the observed device facts that make them relevant."""
    cfg = load_guardrails(org=org)
    out: list[dict] = []
    for rule in cfg["rules"]:
        when = rule.get("when") or {}
        evidence = _device_feature_evidence(dev, net, when)
        if not evidence:
            continue
        out.append({
            "id": rule.get("id"),
            "severity": rule.get("severity", "info"),
            "title": rule.get("title"),
            "message": rule.get("message"),
            "relevance": "; ".join(evidence),
            "change_types": sorted(_rule_change_types(when)),
        })
    return out


# --------------------------------------------------------------------------- #
# suggested actions                                                            #
# --------------------------------------------------------------------------- #

def suggested_actions(ip: str, dev: Device | None, scan: dict | None, net: Net | None,
                      org: str) -> list[dict]:
    actions: list[dict] = []
    sc = scan_device_for_ip(scan, ip)

    if dev is None:
        if sc is not None:
            actions.append({
                "action": "onboard",
                "severity": "info",
                "why": "this device was discovered on the live scan but is not yet in the modelled network",
                "note": "flip the 'protect' switches for the services you care about, or re-scan, to bring it into policy.",
            })
        else:
            actions.append({
                "action": "investigate",
                "severity": "info",
                "why": "this address appears in no modelled device, zone or live scan result",
                "note": "confirm the address is in the scanned subnet before expecting the referee to reason over it.",
            })
        if sc is None:
            return actions

    dev = dev or Device(name=ip, dtype=sc.get("type_guess") or "host")  # type: ignore[arg-type]

    # -- services: guarded vs merely open -------------------------------------
    services = [s for s in (sc or {}).get("services") or [] if s.get("port")]
    if services:
        req = {r.dst: r for r in (net.requirements if net else [])}
        covered = [s for s in services if req.get(ip) and req[ip].dport == int(s.get("port"))]
        open_uncovered = [s for s in services if not (req.get(ip) and req[ip].dport == int(s.get("port")))]
        if covered:
            ports = ", ".join(f"{s.get('port')}/{s.get('service')}" for s in covered[:4])
            actions.append({
                "action": "validate",
                "severity": "info",
                "why": f"{len(covered)} open service(s) ({ports}) are already enforced as policy requirements",
                "note": "run /api/validate before any change that touches this reachability.",
            })
        if open_uncovered:
            ports = ", ".join(f"{s.get('port')}/{s.get('service')}" for s in open_uncovered[:4])
            actions.append({
                "action": "guard",
                "severity": "info",
                "why": f"{len(open_uncovered)} open service(s) ({ports}) are discovered but not protected as requirements",
                "note": "tick them in the protect list so the referee enforces them, or confirm they are intentionally open.",
            })

    # -- egress: default route is a footgun -----------------------------------
    default = next((r for r in dev.routes if r.network in ("0.0.0.0/0", "default")), None)
    if default is not None:
        actions.append({
            "action": "review",
            "severity": "warning",
            "why": "this device holds the 0.0.0.0/0 route; the remove_default_route guardrail hard-blocks removing it",
            "note": "dry-run a re-point instead: post \"add route 0.0.0.0/0 via <new next-hop> on <device>\".",
        })

    # -- inbound: published port forwards --------------------------------------
    if dev.dst_nat:
        spans = ", ".join(f"{r.public_port}->{r.private_ip}" for r in dev.dst_nat[:4])
        actions.append({
            "action": "review",
            "severity": "warning",
            "why": f"this device publishes {len(dev.dst_nat)} inbound forward(s) ({spans})",
            "note": "port-forwards only work when policy also permits the inbound path; validate before changing either side.",
        })

    # -- policy point: guardrail surface ---------------------------------------
    if dev.dtype in ("router", "firewall", "switch") or any(i.filters for i in dev.interfaces):
        actions.append({
            "action": "review",
            "severity": "info",
            "why": "every rule change on this device is pre-flighted by guardrails (allow-all / broad SSH / RDP exposure)",
            "note": "the applicable_guardrails section lists the exact rules with their evidence.",
        })

    return actions


# --------------------------------------------------------------------------- #
# validation history on this target                                            #
# --------------------------------------------------------------------------- #

def validation_history(ip: str, dev: Device | None, net: Net | None, org: str,
                       limit: int = 20, org_id: str | None = None) -> list[dict]:
    needles = _device_needles(dev, ip, net)
    seen: dict[str, dict] = {}
    for needle in needles:
        for row in list_verdicts_for_target(needle, limit=limit, org_id=org_id):
            vid = row.get("id")
            if vid in seen:
                continue
            # only keep rows that really concern this address, not substring hits
            # on an unrelated long name
            seen[vid] = {
                "verdict_id": vid,
                "created_at": row.get("created_at"),
                "verdict": row.get("verdict_final"),
                "trust_score": row.get("trust_score"),
                "requester": row.get("requester"),
                "change": row.get("change") or {},
                "org_id": row.get("org_id"),
                "link": f"/api/verdicts/{vid}",
            }
    return list(reversed(sorted(seen.values(), key=lambda v: v["created_at"] or "")))[:limit]


# --------------------------------------------------------------------------- #
# the bundle                                                                   #
# --------------------------------------------------------------------------- #

def target_intelligence(ip: str, net: Net | None, *, scan: dict | None = None,
                        scope: dict | None = None, org: str = "default") -> dict:
    ip = str(ip or "").strip()
    dev = device_for_ip(net, ip)
    sc = scan_device_for_ip(scan, ip)

    # identity ---------------------------------------------------------------
    identity: dict = {"ip": ip}
    hostname = sc and (sc.get("hostname") or sc.get("snmp", {}).get("sysName")) or (dev.name if dev and dev.name != ip else "")
    identity["device"] = dev.name if dev else None
    identity["device_type"] = dev.dtype if dev else None
    identity["type_guess"] = sc.get("type_guess") if sc else None
    identity["hostname"] = hostname or None
    identity["mac"] = sc.get("mac") if sc else None
    identity["vendor"] = sc.get("vendor") if sc else None
    identity["is_target"] = bool(sc and sc.get("is_target"))
    if sc and (sc.get("snmp", {}).get("sysName") or sc.get("snmp", {}).get("sysDescr")):
        identity["identity_source"] = "snmp"
    elif sc and (sc.get("hostname") or sc.get("mac") or sc.get("vendor")):
        identity["identity_source"] = "scan"
    elif dev is not None:
        identity["identity_source"] = "model"
    else:
        identity["identity_source"] = "none"

    # discovery detail ---------------------------------------------------------
    discovery: dict = {}
    snmp_fields = ["sysName", "sysDescr", "sysObjectID", "sysLocation"]
    if sc and any((sc.get("snmp") or {}).get(k) for k in snmp_fields):
        discovery["snmp"] = {k: (sc.get("snmp") or {}).get(k) for k in snmp_fields}
    if sc and sc.get("services"):
        discovery["services"] = sc.get("services")
    if scan and scan.get("neighbors"):
        discovery["neighbors"] = scan.get("neighbors")
    if dev is not None:
        discovery["interfaces"] = [
            {
                "name": i.name, "ip": i.ip, "network": i.network, "label": i.label,
                "connected_to": i.connected_to, "filters": i.filters,
            }
            for i in dev.interfaces
        ]
        if net is not None:
            discovery["links"] = [
                {"device": l.dev_a, "iface": l.iface_a, "peer": l.dev_b, "peer_iface": l.iface_b}
                for l in net.links if l.dev_a == dev.name or l.dev_b == dev.name
            ]

    confirmed = _confirmed_counts(dev, net)

    guardrails = applicable_guardrails(org=org, net=net, dev=dev)
    hist_org = org if (scope or {}).get("mode") == "agent" else None
    history = validation_history(ip, dev, net, org, org_id=hist_org)
    actions = suggested_actions(ip, dev, scan, net, org)

    found = dev is not None or sc is not None or _zone_for_ip(net, ip) is not None

    return {
        "target": ip,
        "status": "found" if found else "not_in_scope",
        "scope": {
            "mode": (scope or {}).get("mode", "demo"),
            "org": org,
            "subnet": (scope or {}).get("subnet"),
            "scan_target": (scope or {}).get("scan_target"),
            "at": (scope or {}).get("at"),
            "config_sources": (scope or {}).get("config_sources") or [],
        },
        "identity": identity,
        "discovery_detail": discovery,
        "confirmed_vs_inferred": confirmed,
        "applicable_guardrails": guardrails,
        "validation_history": history,
        "suggested_actions": actions,
    }