"""NetProof differential validator.

Compares reachability of the baseline network vs. the network with the
proposed change applied, then produces a verdict (pass / warn / block), a
trust score, structured findings with evidence, and requirement results.
"""
from __future__ import annotations

from .model import MAX_IP, Net, Prefix, Requirement, parse_host_or_prefix, ip_int, ip_str
from .reach import apply_change, resolve_flow

ENGINE_VERSION = "0.3.0"

# Example change presets surfaced in the UI for an instant, honest demo.
PRESETS: list[dict] = [
    {
        "id": "allow_server_internet",
        "label": "Allow outbound Internet from servers",
        "description": "Inserts a permit any/any rule for 10.0.20.0/24 at the top of the inside firewall policy.",
        "expect": "blocked",
        "change": {
            "type": "add_filter_rule",
            "filter": "fw-inside-in",
            "at_index": 0,
            "rule": {"action": "permit", "src": "10.0.20.0/24", "dst": "any", "proto": "any"},
        },
    },
    {
        "id": "block_ssh_to_servers",
        "label": "Block SSH to app servers at the switch",
        "description": "Denies tcp/22 toward 10.0.20.0/24 on the access-switch ACL (the *actual* enforcement point for LAN traffic).",
        "expect": "blocked",
        "change": {
            "type": "add_filter_rule",
            "filter": "core-user-in",
            "at_index": 0,
            "rule": {"action": "deny", "src": "any", "dst": "10.0.20.0/24", "proto": "tcp", "dport": 22},
        },
    },
    {
        "id": "remove_web_rule",
        "label": "Remove outbound HTTPS permit",
        "description": "Deletes the permit tcp/443 rule from the inside firewall policy (LAN to Internet).",
        "expect": "blocked",
        "change": {"type": "remove_filter_rule", "filter": "fw-inside-in", "index": 3},
    },
    {
        "id": "add_icmp_ping",
        "label": "Allow ICMP ping to the firewall",
        "description": "Adds a harmless diagnostic permit for ICMP from the LAN to the firewall. Should be a clean pass.",
        "expect": "pass",
        "change": {
            "type": "add_filter_rule",
            "filter": "fw-inside-in",
            "at_index": 4,
            "rule": {"action": "permit", "src": "10.0.10.0/24", "dst": "203.0.113.2", "proto": "icmp"},
        },
    },
    {
        "id": "redirect_default_route",
        "label": "Delete the firewall's default route",
        "description": "Removes the default route on the firewall. Internet egress silently dies - the classic silent outage.",
        "expect": "blocked",
        "change": {"type": "remove_route", "device": "firewall", "index": 1},
    },
    {
        "id": "add_web_port_forward",
        "label": "Publish web to the Internet (port-forward 8080 → app-server)",
        "description": "Adds DST NAT on the firewall (outside 203.0.113.2:8080 → 10.0.20.10:80). Note the outside-in firewall policy still blocks tcp/8080, so the forward is added yet unreachable — the referee catches both sides of a change.",
        "expect": "warning",
        "change": {
            "type": "add_dst_nat",
            "device": "firewall",
            "dst_nat": {"public_ip": "", "public_port": 8080, "private_ip": "10.0.20.10", "private_port": 80, "proto": "tcp"},
        },
    },
    {
        "id": "block_user_internet",
        "label": "Block the user zone from the Internet",
        "description": "Denies all traffic from the user LAN (10.0.10.0/24) toward the Internet on the inside firewall policy. Hard, immediate egress lockdown - the referee proves before/after paths and shows every collapsed flow.",
        "expect": "blocked",
        "change": {
            "type": "add_filter_rule",
            "filter": "fw-inside-in",
            "at_index": 0,
            "rule": {"action": "deny", "src": "10.0.10.0/24", "dst": "any", "proto": "any"},
        },
    },
]

# Wider change language: BGP / OSPF / DNS / VLAN presets. Each carries its own
# "safe / hard-block / warning" story so the wider DSL is demoable immediately.
CONTROL_PLANE_PRESETS: list[dict] = [
    {
        "id": "peer_with_isp",
        "label": "Peer with the ISP via BGP (firewall ↔ isp-router)",
        "description": "Stands up a BGP peering on the firewall to the ISP handoff 203.0.113.1 (AS 65000), advertising 10.0.0.0/16 as AS 64512. The neighbor is attached and the exported prefix is routable, so this should pass cleanly.",
        "expect": "pass",
        "change": {
            "type": "add_bgp_peer",
            "device": "firewall",
            "peer": {"neighbor": "203.0.113.1", "local_as": 64512, "remote_as": 65000, "export_prefixes": ["10.0.0.0/16"]},
        },
    },
    {
        "id": "ospf_on_wan",
        "label": "Run OSPF area 0 across the WAN link",
        "description": "Adds 203.0.113.0/29 into OSPF area 0 on the firewall. It is a connected subnet, so it forms, but advertising toward the ISP WAN is a warning - the provider's loopback range should not learn your interior topology.",
        "expect": "warning",
        "change": {
            "type": "add_ospf_network",
            "device": "firewall",
            "area_id": 0,
            "network": "203.0.113.0/29",
        },
    },
    {
        "id": "add_dns_record",
        "label": "Add DNS record status.internal → 10.0.20.10",
        "description": "Adds an A record for a host that exists in the inventory on the DNS server. The name stays inside the zone and the target is a managed device - a clean pass.",
        "expect": "pass",
        "change": {
            "type": "add_dns_record",
            "device": "dns-server",
            "record": {"zone": "internal", "fqdn": "status.internal", "type": "A", "value": "10.0.20.10", "ttl": 300},
        },
    },
    {
        "id": "add_dangling_dns",
        "label": "Add DNS record to an unmanaged IP (10.0.99.99)",
        "description": "Adds an A record pointing at an address no managed device owns. The name resolves, but traffic to it will land nowhere - a dangling record is a silent outage waiting to happen.",
        "expect": "warning",
        "change": {
            "type": "add_dns_record",
            "device": "dns-server",
            "record": {"zone": "internal", "fqdn": "scan.internal", "type": "A", "value": "10.0.99.99", "ttl": 300},
        },
    },
    {
        "id": "move_dns_to_guest",
        "label": "Rehome the DNS port into guest vlan 30",
        "description": "Moves the DNS access port (Gi0/3, currently vlan 20) to guest vlan 30. The L2 segment of the DNS server silently changes - a warning that isolation just moved.",
        "expect": "warning",
        "change": {
            "type": "add_vlan_assignment",
            "device": "core-switch",
            "vlan": {"iface": "Gi0/3", "vlan_id": 30, "name": "guest"},
        },
    },
    {
        "id": "invalid_vlan",
        "label": "Assign a switchport to vlan 4095 (reserved)",
        "description": "VLAN 4095 is outside the legal 1-4094 range. The engine hard-blocks this regardless of any reachability math.",
        "expect": "blocked",
        "change": {
            "type": "add_vlan_assignment",
            "device": "core-switch",
            "vlan": {"iface": "Gi0/4", "vlan_id": 4095},
        },
    },
]

ALL_PRESETS: list[dict] = PRESETS + CONTROL_PLANE_PRESETS


# --------------------------------------------------------------------------- #
# Flows to analyze                                                           #
# --------------------------------------------------------------------------- #

def _zone_flow(net: Net, sname: str, dname: str) -> dict:
    s = net.zones[sname]
    d = net.zones[dname]
    dst_ip = d.prefix.lo if d.prefix is not None else d.sample_dst
    dst_zone = d.name
    return {
        "kind": "zone",
        "key": f"{s.name} -> {d.name}",
        "label": f"{s.name} -> {d.name}",
        "src_rep": s.prefix.lo,
        "src_origin": s.gateway,
        "dst_ip": dst_ip,
        "proto": "any",
        "dport": None,
        "src_zone": s.name,
        "dst_zone": dst_zone,
    }


def _requirement_flow(net: Net, r: Requirement) -> dict:
    origin, rep, _ = parse_host_or_prefix(net, r.src)
    if r.dst in (None, "", "any"):
        dst_ip = None
        dst_prefix = None
    elif "/" in r.dst:
        dst_prefix = r.dst
        dst_ip = Prefix.parse(r.dst).lo
    else:
        dst_prefix = f"{r.dst}/32"
        dst_ip = ip_int(r.dst)
    return {
        "kind": "requirement",
        "key": r.name,
        "label": f"{r.src} -> {r.dst}" + (f" /{r.dport}" if r.dport else ""),
        "src_rep": rep,
        "src_origin": origin,
        "dst_ip": dst_ip,
        "proto": r.proto,
        "dport": r.dport,
        "expect": r.expect,
    }


def _collect_flows(net: Net) -> list[dict]:
    flows: list[dict] = []
    for sname, s in net.zones.items():
        if not s.is_source:
            continue
        for dname, d in net.zones.items():
            if not d.is_dest or dname == sname:
                continue
            flows.append(_zone_flow(net, sname, dname))
    for r in net.requirements:
        flows.append(_requirement_flow(net, r))
    flows.extend(_dstnat_flows(net))
    return flows


def _internet_gateway(net: Net) -> str:
    """A device name the packet can start from when it comes from the Internet."""
    iz = net.zones.get("internet")
    if iz is not None:
        gw = iz.gateway
        if gw in net.devices and net.devices[gw].dtype != "cloud":
            return gw
        owning = _device_owning_ip(net, gw)
        if owning is not None:
            return owning.name
    for name, dev in net.devices.items():
        if dev.dtype == "cloud":
            for (nbr, _loc, _rem) in net.adjacency.get(name, []):
                if net.devices[nbr].dtype != "cloud":
                    return nbr
    for name, dev in net.devices.items():
        if dev.dtype in ("firewall", "router"):
            return name
    return ""


def _device_owning_ip(net: Net, addr: str):
    try:
        want = ip_int(addr)
    except (ValueError, TypeError):
        return None
    for dev in net.devices.values():
        if want in dev.own_ips():
            return dev
    return None


def _dstnat_flows(net: Net) -> list[dict]:
    """One analyzed flow per port-forward rule on every device.

    Surfaces silently broken forwards (policy blocks them) and removed
    forwards (service reachability dies) as findings.
    """
    flows: list[dict] = []
    from .reach import _wan_ip
    for dev in net.devices.values():
        for i, rule in enumerate(dev.dst_nat or []):
            pub = rule.public_ip or _wan_ip(dev) or ""
            label = f"{pub or 'wan'}:{rule.public_port} → {rule.private_ip}:{rule.private_port} ({rule.proto})"
            flows.append({
                "kind": "dstnat",
                "key": f"dnat|{dev.name}|{pub}|{rule.public_port}|{rule.proto}|{rule.private_ip}|{rule.private_port}",
                "label": f"port-forward {label}",
                "src_rep": 8 * 2 ** 24 + 8 * 2 ** 16 + 8 * 2 ** 8 + 8,  # 8.8.8.8 client
                "src_origin": _internet_gateway(net),
                "dst_ip": ip_int(pub) if pub else 0,
                "proto": rule.proto,
                "dport": rule.public_port,
                "expect": "reachable",
                "rule": {
                    "device": dev.name,
                    "index": i,
                    "public_ip": pub,
                    "public_port": rule.public_port,
                    "private_ip": rule.private_ip,
                    "private_port": rule.private_port,
                    "proto": rule.proto,
                },
            })
    return flows


def _net_has_dstnat(net: Net, f: dict) -> bool:
    r = f.get("rule") or {}
    dev = net.devices.get(r.get("device"))
    if dev is None:
        return False
    for x in dev.dst_nat:
        if x.public_port != r.get("public_port"):
            continue
        if x.private_ip != r.get("private_ip"):
            continue
        if x.private_port != r.get("private_port"):
            continue
        if x.proto != r.get("proto"):
            continue
        return True
    return False


def _run(net: Net, flows: list[dict]) -> dict:
    results: dict[str, dict] = {}
    for f in flows:
        if f["kind"] == "dstnat":
            has = _net_has_dstnat(net, f)
            if not has:
                results[f["key"]] = {
                    "label": f["label"],
                    "kind": f["kind"],
                    "reachable": False,
                    "status": "no_forward",
                    "path": [],
                    "steps": [],
                    "drop": {"device": f["rule"]["device"], "detail": "port-forward rule not present on this network"},
                    "nat": None,
                    "src_zone": None,
                    "dst_zone": None,
                    "proto": f["proto"],
                    "dport": f["dport"],
                    "expect": f.get("expect"),
                    "forward_present": has,
                }
                continue
        res = resolve_flow(net, f["src_rep"], f["src_origin"], f["dst_ip"], f["proto"], f["dport"])
        results[f["key"]] = {
            "label": f["label"],
            "kind": f["kind"],
            "reachable": res["reachable"],
            "status": res["status"],
            "path": res["path"],
            "steps": res["steps"],
            "drop": res["drop"],
            "nat": res["nat"],
            "trace": res.get("trace") or [],
            "src_zone": f.get("src_zone"),
            "dst_zone": f.get("dst_zone"),
            "proto": f["proto"],
            "dport": f["dport"],
            "expect": f.get("expect"),
            "forward_present": f["kind"] == "dstnat",
        }
    return results


def _zone_prefix(net: Net, name: str) -> Prefix | None:
    z = net.zones.get(name)
    return z.prefix if z else None


def _requirement_covers(net: Net, f: dict, r: Requirement) -> bool:
    """Does requirement r govern the same zonal (src, dst) pair as matrix flow f?"""
    if f.get("kind") != "zone":
        return False
    s, d = f.get("src_zone"), f.get("dst_zone")
    if s is None or d is None:
        return False
    rs = Prefix.parse(r.src)
    zs = _zone_prefix(net, s)
    if zs is None or not (rs.lo <= zs.hi and rs.hi >= zs.lo):
        return False
    rd = Prefix.parse(r.dst)
    if d == "internet":
        return True  # any requirement toward a public address governs the Internet zone
    zd = _zone_prefix(net, d)
    if zd is None:
        return False
    return rd.lo <= zd.hi and rd.hi >= zd.lo


# --------------------------------------------------------------------------- #
# Control-plane validation (BGP / OSPF / DNS / VLAN)                          #
# --------------------------------------------------------------------------- #

def _cp_inventory(net: Net) -> dict:
    """Per-change-family inventory summary (before/after) for the audit trail."""
    return {
        "bgp_peers": sum(len(d.bgp or []) for d in net.devices.values()),
        "ospf_areas": sum(len(d.ospf or []) for d in net.devices.values()),
        "dns_records": sum(len(d.dns or []) for d in net.devices.values()),
        "vlan_assignments": sum(len(d.vlans or []) for d in net.devices.values()),
    }


def _canonical(p: Prefix) -> str:
    """Canonical network text of a prefix, e.g. 203.0.113.2/29 -> 203.0.113.0/29."""
    return f"{ip_str(p.lo)}/{p.plen}"


def _iface_subnets(dev) -> set[str]:
    """Canonical subnet texts of every interface on a device."""
    return {_canonical(p) for i in dev.interfaces if (p := i.prefix) is not None}


def _subnet_of(net: Net, ip_str_addr: str) -> str | None:
    """The most specific interface subnet that contains an IP, or None."""
    try:
        want = ip_int(ip_str_addr)
    except (ValueError, TypeError):
        return None
    best: Prefix | None = None
    for dev in net.devices.values():
        for i in dev.interfaces:
            if i.prefix and i.prefix.contains(want) and (best is None or i.prefix.plen > best.plen):
                best = i.prefix
    return _canonical(best) if best else None


def _has_route_or_connected(net: Net, dev, prefix_text: str) -> bool:
    """Can this device actually forward packets to `prefix_text` (static route,
    connected segment, or default)?"""
    p = Prefix.parse(prefix_text)
    for i in dev.interfaces:
        if i.prefix and i.prefix.contains(p.lo):
            return True
    for r in dev.routes:
        if r.prefix.contains(p.lo):
            return True
    return bool(dev.routes and any(r.prefix.plen == 0 for r in dev.routes)) or _is_border(dev)


def _is_border(dev) -> bool:
    return dev.dtype in ("firewall", "router", "switch") and any(i.ip for i in dev.interfaces)


def _cp_finding(sev, ftype, title, detail, before=None, after=None) -> dict:
    return {"severity": sev, "type": ftype, "title": title, "detail": detail, "before": before, "after": after}


def _check_bgp(net: Net, after: Net, change: dict) -> list[dict]:
    dev_name = change.get("device")
    dev = after.devices.get(dev_name)
    if dev is None:
        return []
    bdev = net.devices.get(dev_name)
    out: list[dict] = []
    if change.get("type") == "add_bgp_peer":
        peer = change.get("peer") or {}
        neighbor = peer.get("neighbor")
        local_as = int(peer.get("local_as") or 0)
        remote_as = int(peer.get("remote_as") or 0)
        exports = [str(p) for p in (peer.get("export_prefixes") or [])]
        bf = {"peer": None, "reachable": False}
        af = {"peer": neighbor, "local_as": local_as, "remote_as": remote_as, "export_prefixes": exports}

        if not (1 <= local_as <= 65535):
            out.append(_cp_finding("critical", "bgp", "Invalid local ASN",
                                   f"AS {local_as} is out of range on '{dev_name}'. BGP will not even begin.", bf, af))
        if not (1 <= remote_as <= 65535):
            out.append(_cp_finding("critical", "bgp", "Invalid remote ASN",
                                   f"AS {remote_as} is reserved/invalid for {neighbor}.", bf, af))
        owner = _device_owning_ip(net, neighbor)
        if owner is None:
            out.append(_cp_finding("critical", "bgp", "BGP neighbor unreachable",
                                   f"{neighbor} is not an address any modelled device owns. The session would never come up.", bf, af))
        else:
            subnet = _subnet_of(net, neighbor)
            bf = {"peer": neighbor, "reachable": True, "owner": owner.name, "subnet": subnet}
            af["owner"] = owner.name
        for pref in exports:
            prefix = Prefix.parse(pref)
            if prefix.plen == 0:
                out.append(_cp_finding("warning", "bgp", "BGP exporting the default route",
                                       f"Advertising 0.0.0.0/0 to {neighbor} is a route-leak risk for transit peers.", bf, af))
            elif not _has_route_or_connected(after, dev, pref):
                out.append(_cp_finding("critical", "bgp", "Prefix advertisement would blackhole",
                                       f"'{dev_name}' has no route for {pref} yet advertises it to {neighbor}. Traffic attracted into a dead end.", bf, af))
        if not out:
            out.append(_cp_finding("info", "bgp", "BGP peering is sound",
                                   f"Neighbor {neighbor} (AS {remote_as}) is reachable and exports are routable.", bf, af))
    else:  # remove_bgp_peer
        removed = (change.get("peer") or {}).get("neighbor") or change.get("neighbor") or ""
        bdev = net.devices.get(dev_name)
        bcount = len(bdev.bgp or []) if bdev else 0
        acount = len(dev.bgp or [])
        default_route = any(r.network in ("0.0.0.0/0", "default") for r in dev.routes)
        if bcount and not acount and not default_route and dev.dtype in ("firewall", "router"):
            out.append(_cp_finding("warning", "bgp", "Possibly last upstream removed",
                                   f"'{dev_name}' keeps no BGP sessions and no default route - egress may depend on a static default that is not present. Verify another upstream exists."))
        elif bcount and not acount:
            out.append(_cp_finding("info", "bgp", "BGP session removed",
                                   f"No more peers remain on '{dev_name}', but static routing still provides reachability."))
        else:
            out.append(_cp_finding("info", "bgp", "BGP peer removed",
                                   f"Peering to {removed} has been torn down."))
    return out


def _check_ospf(net: Net, after: Net, change: dict) -> list[dict]:
    dev_name = change.get("device")
    dev = after.devices.get(dev_name)
    if dev is None:
        return []
    area_id = int(change.get("area_id", change.get("area", 0)))
    network = str(change.get("network") or "")
    out: list[dict] = []
    for pre in net.devices.values():
        for area in pre.ospf or []:
            for nw in area.networks:
                if nw != network:
                    continue
                if area.area_id != area_id and change.get("type") == "add_ospf_network":
                    # same subnet already in a different area somewhere -> split-area
                    if pre.name == dev_name:
                        out.append(_cp_finding("critical", "ospf", "Network in multiple areas",
                                               f"{network} is already advertised in area {area.area_id} on '{dev_name}'. Re-adding it into area {area_id} splits the segment."))
                    else:
                        out.append(_cp_finding("critical", "ospf", "Area mismatch on shared link",
                                               f"{network} is advertised in area {area.area_id} on '{pre.name}' but '{dev_name}' is now announcing it in area {area_id}. The adjacency will not form."))
    if not (0 <= area_id <= 0xFFFFFFFF):
        out.append(_cp_finding("critical", "ospf", "Invalid OSPF area id",
                               f"Area {area_id} is outside the valid 32-bit range."))
    subnets = _iface_subnets(after.devices.get(dev_name))
    if change.get("type") == "add_ospf_network":
        if network not in subnets:
            out.append(_cp_finding("critical", "ospf", "OSPF advertisement for a foreign prefix",
                                   f"'{dev_name}' has no interface in {network}. OSPF can only advertise directly attached networks."))
        else:
            wan_iface = any(i.prefix and _canonical(i.prefix) == network and (i.label or "").lower() in ("isp", "wan", "outside", "upstream") for i in dev.interfaces)
            nbr_nets = set()
            for k, nbr in net.devices.items():
                if k == dev_name:
                    continue
                for i in nbr.interfaces:
                    if i.prefix and i.prefix.contains(Prefix.parse(network).lo) and nbr.dtype in ("router", "firewall", "switch"):
                        nbr_nets.add(k)
            link_partners = [k for k in nbr_nets]
            if wan_iface or any(p.lower().startswith("wan") for p in [net.zones.get("internet") and ""]):
                out.append(_cp_finding("warning", "ospf", "OSPF on a WAN-facing link",
                                       f"Advertising the Internet-facing subnet {network} into OSPF leaks interior topology toward the provider."))
            if link_partners:
                out.append(_cp_finding("info", "ospf", "OSPF adjacency expected",
                                       f"{network} connects to {', '.join(sorted(link_partners))} - area {area_id} will peer with them if they run OSPF on the same segment."))
    else:  # remove_ospf_network
        still = [a for a in after.devices[dev_name].ospf or [] if a.area_id == area_id and network in a.networks]
        if not still and any(a.area_id == area_id for a in (net.devices[dev_name].ospf or [])):
            out.append(_cp_finding("info", "ospf", "OSPF network withdrawn",
                                   f"{network} no longer advertises on '{dev_name}'. Routes learned from it will age out."))
    if not out:
        out.append(_cp_finding("info", "ospf", "OSPF change valid",
                               f"{network} area {area_id} on '{dev_name}' is a connected subnet with consistent areas."))
    return out


def _check_dns(net: Net, after: Net, change: dict) -> list[dict]:
    dev_name = change.get("device")
    dev = after.devices.get(dev_name)
    if dev is None:
        return []
    rec = change.get("record") or {}
    fqdn = str(rec.get("fqdn") or "").rstrip(".")
    rtype = str(rec.get("type") or rec.get("rtype") or "A").upper()
    value = str(rec.get("value") or "")
    zone = str(rec.get("zone") or "")
    ttl = int(rec.get("ttl") or 300)
    out: list[dict] = []
    if rtype not in ("A", "AAAA", "CNAME", "MX", "TXT", "PTR", "SRV"):
        out.append(_cp_finding("critical", "dns", "Unsupported record type",
                               f"'{rtype}' is not a supported RR type. The record cannot be served."))
    if not zone or not (fqdn == zone or fqdn.endswith("." + zone)):
        out.append(_cp_finding("critical", "dns", "Name outside the authoritative zone",
                               f"{fqdn} is not inside zone '{zone}'. The server is not authoritative for it."))
    if ttl < 0:
        out.append(_cp_finding("critical", "dns", "Negative TTL",
                               f"TTL {ttl} is invalid. Negative TTLs are not permitted."))
    elif ttl > 86400:
        out.append(_cp_finding("warning", "dns", "Very long TTL",
                               f"TTL {ttl}s (>{86400}s) pins stale answers for over a day. Longer caches delay rollover."))
    if rtype in ("A", "AAAA"):
        try:
            x = ip_int(value)
        except (ValueError, TypeError):
            x = None
        if x is None:
            out.append(_cp_finding("critical", "dns", "Unparsable address",
                                   f"A/AAAA record '{value}' is not an IP address."))
        elif x in (0, MAX_IP):
            out.append(_cp_finding("critical", "dns", "Reserved address in record",
                                   f"{value} is the any/broadcast address - not a routable answer."))
        elif _device_owning_ip(net, value) is None:
            out.append(_cp_finding("warning", "dns", "Record points outside managed inventory",
                                   f"{fqdn} now resolves to {value}, which no modelled device owns. Traffic would land on an unmanaged target."))
    if rtype == "CNAME":
        known = {r.fqdn for d in after.devices.values() for z in [d] for r in (d.dns or [])}
        known.add(zone)
        if value.rstrip(".").lower() not in {k.lower() for k in known}:
            out.append(_cp_finding("warning", "dns", "Dangling CNAME target",
                                   f"CNAME {fqdn} points at {value}, which has no record in this zone."))
    if change.get("type") == "remove_dns_record":
        same_fqdn_left = [r for d in after.devices.values() for r in (d.dns or []) if r.fqdn == fqdn]
        if not same_fqdn_left:
            out.append(_cp_finding("warning", "dns", "Last record for the name removed",
                                   f"{fqdn} now has zero records on '{dev_name}'. Anything referencing the name will stop resolving."))
    if not out:
        out.append(_cp_finding("info", "dns", "DNS record is consistent",
                               f"{fqdn} {rtype} {value} is inside zone '{zone}' and its target is a managed device."))
    return out


def _check_vlan(net: Net, after: Net, change: dict) -> list[dict]:
    dev_name = change.get("device")
    dev = after.devices.get(dev_name)
    if dev is None:
        return []
    v = change.get("vlan") or change
    iface = str(v.get("iface") or v.get("interface") or "")
    vlan_id = int(v.get("vlan_id", v.get("vlan", 0)))
    out: list[dict] = []
    if dev.dtype == "host":
        out.append(_cp_finding("critical", "vlan", "VLAN on a host device",
                               f"'{dev_name}' is a host, not a switch. Switchport assignment is meaningless here."))
    if not (1 <= vlan_id <= 4094):
        out.append(_cp_finding("critical", "vlan", "VLAN id out of legal range",
                               f"VLAN {vlan_id} is outside 1-4094. Switch hardware will reject this."))
        if not out:
            out.append(_cp_finding("critical", "vlan", "Reserved VLAN id",
                                   f"VLAN {vlan_id} is reserved for internal/platform use."))
    prev = next((a for a in (net.devices[dev_name].vlans or []) if a.iface == iface), None)
    if vlan_id == 1:
        out.append(_cp_finding("warning", "vlan", "Assignment to the default VLAN",
                               f"{iface} is placed in native vlan 1. Prefer an explicit segment name for access ports."))
    if prev is not None and prev.vlan_id != vlan_id:
        label = prev.name or f"vlan {prev.vlan_id}"
        attached = [h.name for h in net.devices.values() if h.dtype in ("host", "server") and any(i.connected_to and i.connected_to.split(" ")[0] == dev_name and i.connected_to.split(" ")[1] == iface for i in h.interfaces)]
        who = ", ".join(attached) or "the port's device"
        out.append(_cp_finding("warning", "vlan", "L2 segment change",
                               f"{iface} moves out of {label} into vlan {vlan_id}. {who} silently changes segments - verify isolation is intended."))
    if change.get("type") == "remove_vlan_assignment" and prev is not None:
        out.append(_cp_finding("info", "vlan", "Switchport leaves the segment",
                               f"{iface} on '{dev_name}' is no longer assigned to vlan {prev.vlan_id}."))
    if not out:
        out.append(_cp_finding("info", "vlan", "VLAN assignment is clean",
                               f"{iface} on '{dev_name}' into vlan {vlan_id} is within range on an L2-capable device."))
    return out


def _control_plane_findings(net: Net, after: Net, change: dict) -> list[dict]:
    ctype = change.get("type")
    if ctype in ("add_bgp_peer", "remove_bgp_peer"):
        return _check_bgp(net, after, change)
    if ctype in ("add_ospf_network", "remove_ospf_network"):
        return _check_ospf(net, after, change)
    if ctype in ("add_dns_record", "remove_dns_record"):
        return _check_dns(net, after, change)
    if ctype in ("add_vlan_assignment", "remove_vlan_assignment"):
        return _check_vlan(net, after, change)
    return []


# --------------------------------------------------------------------------- #
# Validation                                                                 #
# --------------------------------------------------------------------------- #

def validate_change(net: Net, change: dict) -> dict:
    net_after = apply_change(net, change)

    keyed: dict[str, dict] = {}
    for f in _collect_flows(net):
        keyed.setdefault(f["key"], f)
    for f in _collect_flows(net_after):
        keyed.setdefault(f["key"], f)
    flows = list(keyed.values())

    before = _run(net, flows)
    after = _run(net_after, flows)

    findings: list[dict] = []
    matrix: dict[tuple, dict] = {}

    for f in flows:
        key = f["key"]
        b, a = before[key], after[key]

        if f["kind"] == "requirement":
            ok = (b["reachable"] == a["reachable"]) and (a["reachable"] == (f["expect"] == "reachable"))
            if not ok:
                sev = "critical"
                if b["reachable"] == a["reachable"] and a["reachable"] != (f["expect"] == "reachable"):
                    sev = "critical"
                findings.append({
                    "severity": sev,
                    "type": "requirement",
                    "title": f"Requirement '{f['key']}' violated",
                    "detail": _requirement_summary(b, a, f),
                    "before": b,
                    "after": a,
                    "requirement": f["key"],
                })
            continue

        if f["kind"] == "dstnat":
            bf, af = b["forward_present"], a["forward_present"]
            if not bf and af:
                if a["reachable"]:
                    findings.append({
                        "severity": "info",
                        "type": "port_forward",
                        "title": f"Port-forward live: {f['label']}",
                        "detail": "The Internet can now reach the forwarded service through the new rule.",
                        "before": b,
                        "after": a,
                        "port_forward": f["label"],
                    })
                else:
                    findings.append({
                        "severity": "warning",
                        "type": "port_forward",
                        "title": f"Port-forward added but unreachable: {f['label']}",
                        "detail": "The forward exists but traffic is stopped before the host. " + _reason_text(a),
                        "before": b,
                        "after": a,
                        "port_forward": f["label"],
                    })
            elif bf and not af:
                findings.append({
                    "severity": "critical",
                    "type": "connectivity_loss",
                    "title": f"Port-forward removed — service behind it no longer reachable: {f['label']}",
                    "detail": "Traffic from the Internet now stops instead of reaching the forwarded host.",
                    "before": b,
                    "after": a,
                    "port_forward": f["label"],
                })
            elif bf and af:
                if b["reachable"] and not a["reachable"]:
                    findings.append({
                        "severity": "critical",
                        "type": "connectivity_loss",
                        "title": f"Port-forward broken: {f['label']}",
                        "detail": _reason_text(a),
                        "before": b,
                        "after": a,
                        "port_forward": f["label"],
                    })
                elif not b["reachable"] and a["reachable"]:
                    findings.append({
                        "severity": "info",
                        "type": "port_forward",
                        "title": f"Port-forward now reachable: {f['label']}",
                        "detail": "Previously stopped by policy, now reaching the forwarded host.",
                        "before": b,
                        "after": a,
                        "port_forward": f["label"],
                    })
            continue

    zone_flows = [f for f in flows if f["kind"] == "zone"]
    for f in zone_flows:
        key = f["key"]
        b, a = before[key], after[key]
        pair = (f["src_zone"], f["dst_zone"])
        matrix[pair] = {"label": f["label"], "before": _cell(b), "after": _cell(a)}

        if b["reachable"] == a["reachable"]:
            if b["reachable"] and b["path"] != a["path"]:
                findings.append({
                    "severity": "info",
                    "type": "path_change",
                    "title": f"Path changed: {f['label']}",
                    "detail": "Still reachable, but the forwarding path is different.",
                    "before": b,
                    "after": a,
                })
            continue

        covered = any(_requirement_covers(net, f, r) for r in net.requirements if r.expect == "denied")
        if b["reachable"] and not a["reachable"]:
            findings.append({
                "severity": "critical",
                "type": "connectivity_loss",
                "title": f"Connectivity lost: {f['label']}",
                "detail": _reason_text(a),
                "before": b,
                "after": a,
            })
        elif not b["reachable"] and a["reachable"]:
            if covered:
                continue
            findings.append({
                "severity": "warning",
                "type": "new_exposure",
                "title": f"New access opened: {f['label']}",
                "detail": "Previously blocked traffic can now get through. Verify this is intended.",
                "before": b,
                "after": a,
            })

    ncrit = sum(1 for f in findings if f["severity"] == "critical")
    nwarn = sum(1 for f in findings if f["severity"] == "warning")
    ninfo = sum(1 for f in findings if f["severity"] == "info")

    findings.extend(_control_plane_findings(net, net_after, change))
    ncrit = sum(1 for f in findings if f["severity"] == "critical")
    nwarn = sum(1 for f in findings if f["severity"] == "warning")
    ninfo = sum(1 for f in findings if f["severity"] == "info")

    verdict = "block" if ncrit else ("warn" if nwarn else "pass")
    score = 100 - ncrit * 65 - nwarn * 20 - ninfo * 3
    score = max(0, min(100, score))

    req_results = [
        {
            "name": f["key"],
            "label": before[f["key"]]["label"],
            "expect": f["expect"],
            "before": _status_word(before[f["key"]]),
            "after": _status_word(after[f["key"]]),
            "ok": (after[f["key"]]["reachable"] == (f["expect"] == "reachable")),
        }
        for f in flows
        if f["kind"] == "requirement"
    ]

    return {
        "network": net.name,
        "engine_version": ENGINE_VERSION,
        "change": change,
        "summary": {
            "verdict": verdict,
            "pass": verdict == "pass",
            "trust_score": score,
            "blocked": ncrit,
            "warnings": nwarn,
            "info": ninfo,
            "flows_checked": len(flows),
        },
        "findings": sorted(findings, key=lambda x: {"critical": 0, "warning": 1, "info": 2}[x["severity"]]),
        "matrix": {f"{k[0]} ~ {k[1]}": v for k, v in matrix.items()},
        "requirements": req_results,
        "before": _summary_of(before),
        "after": _summary_of(after),
        "control_plane": {
            "before": _cp_inventory(net),
            "after": _cp_inventory(net_after),
        },
    }


def _cell(r: dict) -> dict:
    return {
        "reachable": r["reachable"],
        "status": r["status"],
        "path": r["path"],
        "steps": r["steps"],
        "drop": r["drop"],
        "nat": r["nat"],
        "trace": r.get("trace") or [],
    }


def _status_word(r: dict) -> str:
    if r["reachable"]:
        return "reachable"
    if r["drop"] and r["drop"].get("filter"):
        return "blocked"
    return r["status"]


def _summary_of(results: dict) -> dict:
    return {
        "reachable": sum(1 for r in results.values() if r["reachable"]),
        "total": len(results),
    }


def _requirement_summary(b: dict, a: dict, f: dict) -> str:
    expect = f["expect"]
    if b["reachable"] and not a["reachable"]:
        return f"Was reachable, now {a['status']}. " + _reason_text(a)
    if not b["reachable"] and a["reachable"]:
        return "Expectation was 'denied' but this traffic can now get through."
    if b["reachable"] and a["reachable"]:
        return "Requirement expects it, and it remains reachable."
    return "Stays denied, as required."


def _reason_text(a: dict) -> str:
    drop = a["drop"] or {}
    if drop.get("filter"):
        rule = drop.get("rule") or f"default {drop.get('default')}"
        return f"Blocked by {drop['filter']} on {drop.get('device', '?')} (rule: {rule})."
    if drop.get("detail"):
        where = f" on {drop['device']}" if drop.get("device") else ""
        return f"Packet cannot be routed{where} ({drop['detail']})."
    return a["status"]