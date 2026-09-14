"""NetProof verification engine.

Derives the "data plane" (where packets actually go) from the model's
control-plane configuration (routes, filters, NAT), then answers reachability
queries for flows - the same core idea as Batfish / ERA / Minesweeper, scoped
and transparent for an MVP.
"""
from __future__ import annotations

from copy import deepcopy

from .model import DstNatRule, Device, Filter, Net, Prefix, ip_int, ip_str

MAX_HOPS = 24


# --------------------------------------------------------------------------- #
# Change application (the proposed modification, applied to a deep copy)      #
# --------------------------------------------------------------------------- #

def _rule_from_change(rule: dict):
    from .model import Rule
    return Rule.from_dict(rule)


def apply_change(net: Net, change: dict) -> Net:
    """Return a NEW net (deep copy) with the proposed change applied.

    Never mutates the baseline - this is the isolation guarantee behind the
    'safe to run' promise.
    """
    net2 = deepcopy(net)
    ctype = change.get("type")
    if ctype == "add_filter_rule":
        filt = net2.filters.get(change["filter"])
        if filt is None:
            raise ValueError(f"unknown filter '{change['filter']}'")
        rule = _rule_from_change(change["rule"])
        idx = int(change.get("at_index", 0))
        idx = max(0, min(idx, len(filt.rules)))
        filt.rules.insert(idx, rule)
        return net2

    if ctype == "remove_filter_rule":
        filt = net2.filters.get(change["filter"])
        if filt is None:
            raise ValueError(f"unknown filter '{change['filter']}'")
        idx = int(change.get("at_index", change.get("index", 0)))
        if not (0 <= idx < len(filt.rules)):
            raise ValueError(f"rule index {idx} out of range for filter '{change['filter']}'")
        filt.rules.pop(idx)
        return net2

    if ctype == "replace_filter_rule":
        filt = net2.filters.get(change["filter"])
        if filt is None:
            raise ValueError(f"unknown filter '{change['filter']}'")
        idx = int(change.get("at_index", change.get("index", 0)))
        if not (0 <= idx < len(filt.rules)):
            raise ValueError(f"rule index {idx} out of range for filter '{change['filter']}'")
        filt.rules[idx] = _rule_from_change(change["rule"])
        return net2

    if ctype == "add_route":
        dev = net2.devices.get(change["device"])
        if dev is None:
            raise ValueError(f"unknown device '{change['device']}'")
        from .model import Route
        dev.routes.append(Route.from_dict(change["route"]))
        return net2

    if ctype == "remove_route":
        dev = net2.devices.get(change["device"])
        if dev is None:
            raise ValueError(f"unknown device '{change['device']}'")
        idx = int(change["index"])
        if not (0 <= idx < len(dev.routes)):
            raise ValueError(f"route index {idx} out of range on device '{change['device']}'")
        dev.routes.pop(idx)
        return net2

    if ctype == "add_dst_nat":
        dev = net2.devices.get(change.get("device") or "")
        if dev is None:
            raise ValueError(f"unknown device '{change.get('device')}'")
        rule = DstNatRule.from_dict(change["dst_nat"])
        if not rule.public_ip:
            rule.public_ip = _wan_ip(dev)
        index = int(change.get("at_index", change.get("index", len(dev.dst_nat))))
        dev.dst_nat.insert(index, rule)
        return net2

    if ctype == "remove_dst_nat":
        dev = net2.devices.get(change.get("device") or "")
        if dev is None:
            raise ValueError(f"unknown device '{change.get('device')}'")
        idx = int(change.get("index", change.get("at_index", 0)))
        if not (0 <= idx < len(dev.dst_nat)):
            raise ValueError(f"dst-nat index {idx} out of range on device '{change.get('device')}'")
        dev.dst_nat.pop(idx)
        return net2

    if ctype in ("add_bgp_peer", "remove_bgp_peer"):
        return _apply_bgp(net2, change, ctype == "remove_bgp_peer")

    if ctype in ("add_ospf_network", "remove_ospf_network"):
        return _apply_ospf(net2, change, ctype == "remove_ospf_network")

    if ctype in ("add_dns_record", "remove_dns_record"):
        return _apply_dns(net2, change, ctype == "remove_dns_record")

    if ctype in ("add_vlan_assignment", "remove_vlan_assignment"):
        return _apply_vlan(net2, change, ctype == "remove_vlan_assignment")

    raise ValueError(f"unknown change type '{ctype}'")


def _apply_bgp(net: Net, change: dict, removing: bool) -> Net:
    from .model import BgpPeer
    dev = net.devices.get(change.get("device") or "")
    if dev is None:
        raise ValueError(f"unknown device '{change.get('device')}'")
    if removing:
        idx = change.get("index")
        if idx is None:
            nbr = (change.get("peer") or {}).get("neighbor") or change.get("neighbor")
            for i, p in enumerate(dev.bgp):
                if p.neighbor == nbr:
                    idx = i
                    break
        if idx is None:
            raise ValueError(f"no BGP peer to remove on '{dev.name}'")
        idx = int(idx)
        if not (0 <= idx < len(dev.bgp)):
            raise ValueError(f"BGP peer index {idx} out of range on '{dev.name}'")
        dev.bgp.pop(idx)
        return net
    if any(p.neighbor == change.get("peer", {}).get("neighbor") for p in dev.bgp):
        raise ValueError(f"BGP peer {change['peer'].get('neighbor')} already configured on '{dev.name}'")
    dev.bgp.append(BgpPeer.from_dict(change.get("peer") or change))
    return net


def _apply_ospf(net: Net, change: dict, removing: bool) -> Net:
    from .model import OspfArea
    dev = net.devices.get(change.get("device") or "")
    if dev is None:
        raise ValueError(f"unknown device '{change.get('device')}'")
    area_id = int(change.get("area_id", change.get("area", 0)))
    network = str(change.get("network") or "")
    area = next((a for a in dev.ospf if a.area_id == area_id), None)
    if removing:
        if area is None or network not in area.networks:
            raise ValueError(f"OSPF network {network} not in area {area_id} on '{dev.name}'")
        area.networks.remove(network)
        if not area.networks:
            dev.ospf.remove(area)
        return net
    if area is None:
        area = OspfArea(area_id=area_id, networks=[network])
        dev.ospf.append(area)
    elif network not in area.networks:
        area.networks.append(network)
    else:
        raise ValueError(f"OSPF already advertises {network} in area {area_id} on '{dev.name}'")
    return net


def _apply_dns(net: Net, change: dict, removing: bool) -> Net:
    from .model import DnsRecord
    dev = net.devices.get(change.get("device") or "")
    if dev is None:
        raise ValueError(f"unknown device '{change.get('device')}'")
    rec = DnsRecord.from_dict(change.get("record") or {})
    for existing in dev.dns:
        if existing.fqdn == rec.fqdn and existing.rtype == rec.rtype and existing.value == rec.value and existing.zone == rec.zone:
            if removing:
                dev.dns.remove(existing)
                return net
            raise ValueError(f"DNS record already present: {rec.describe()}")
    if removing:
        raise ValueError(f"no DNS record {rec.describe()} on '{dev.name}'")
    dev.dns.append(rec)
    return net


def _apply_vlan(net: Net, change: dict, removing: bool) -> Net:
    from .model import VlanAssignment
    dev = net.devices.get(change.get("device") or "")
    if dev is None:
        raise ValueError(f"unknown device '{change.get('device')}'")
    v = VlanAssignment.from_dict(change.get("vlan") or change)
    if not v.iface:
        raise ValueError("vlan assignment needs an interface")
    if dev.iface(v.iface) is None:
        raise ValueError(f"no interface '{v.iface}' on '{dev.name}'")
    existing = next((a for a in dev.vlans if a.iface == v.iface), None)
    if removing:
        if existing is None or int(change.get("vlan_id", existing.vlan_id)) != existing.vlan_id:
            raise ValueError(f"no vlan assignment to remove for '{v.iface}' on '{dev.name}'")
        dev.vlans.remove(existing)
        return net
    if existing is not None and existing.vlan_id == v.vlan_id:
        raise ValueError(f"'{dev.name}'/{v.iface} already in vlan {v.vlan_id}")
    if "-" in v.iface:
        raise ValueError("vlan assignment targets a single switchport; use add_vlan_assignment per port")
    dev.vlans.append(v)
    return net


def _wan_ip(dev: Device) -> str:
    """Best-guess public / outside address for a device (for dst-nat auto-fill)."""
    for i in dev.interfaces:
        if dev.nat is not None and i.name == dev.nat.outside_interface and i.ip:
            return i.ip.rsplit("/", 1)[0]
    ips = sorted(dev.own_ips())
    return ip_str(ips[0]) if ips else ""


def _device_owning_ip(net: Net, addr: str) -> Device | None:
    """The device that has addr as one of its interface addresses."""
    addr = str(addr or "").strip()
    if not addr:
        return None
    try:
        want = ip_int(addr)
    except ValueError:
        return None
    for dev in net.devices.values():
        if want in dev.own_ips():
            return dev
    return None


# --------------------------------------------------------------------------- #
# Reachability                                                            #
# --------------------------------------------------------------------------- #

def check_filters(filters: list[Filter], src_ip: int, dst_ip: int, proto: str, dport) -> tuple[bool, dict]:
    """Apply a chain of ACL/firewall filters to a flow.

    Returns (allowed, detail). Conservative semantics:
      - a rule matching a specific protocol/port does NOT apply to 'any'
        protocol flows (we cannot prove the match), so generic reachability is
        judged against generic rules + the default action.

    The detail dict includes a ``trace`` list of per-rule evaluations (for
    line-by-line simulation on the frontend).
    """
    for filt in filters:
        checks = []
        for idx, rule in enumerate(filt.rules):
            matched = _rule_matches(rule, src_ip, dst_ip, proto, dport)
            entry = {
                "index": idx,
                "desc": rule.describe(),
                "action": rule.action,
                "matched": matched,
            }
            checks.append(entry)
            if matched:
                allowed = rule.action == "permit"
                return allowed, {
                    "device": None,
                    "filter": filt.name,
                    "rule_index": idx,
                    "rule": rule.describe(),
                    "by_default": False,
                    "trace": {
                        "filter": filt.name,
                        "default_action": filt.default,
                        "checks": checks,
                        "allowed": allowed,
                        "by_default": False,
                        "hit_rule": idx,
                    },
                }
        allowed = filt.default == "permit"
        checks.append({"index": None, "desc": None, "action": None, "matched": False})
        return allowed, {
            "device": None,
            "filter": filt.name,
            "rule": None,
            "rule_index": None,
            "by_default": True,
            "default": filt.default,
            "trace": {
                "filter": filt.name,
                "default_action": filt.default,
                "checks": checks,
                "allowed": allowed,
                "by_default": True,
                "hit_rule": None,
            },
        }
    return True, {"no_filter": True, "trace": None}


def _rule_matches(rule, src_ip: int, dst_ip: int, proto: str, dport) -> bool:
    if not Prefix.parse(rule.src).contains(src_ip):
        return False
    if not Prefix.parse(rule.dst).contains(dst_ip):
        return False
    rproto = rule.proto
    if rproto == "any":
        if rule.dport is not None:
            return False  # a port-specific rule cannot claim all traffic
        return True
    if proto == "any":
        return False  # protocol-specific rule does not constrain 'any' flow
    if rproto != proto:
        return False
    if rule.dport is not None:
        if dport is None:
            return False
        if dport != rule.dport:
            return False
    return True


def resolve_next_hop(net: Net, dev: Device, next_hop_ip: int):
    """Return (neighbor_device, local_iface_name, remote_iface_name)."""
    for (nbr, local_iface, remote_iface) in net.adjacency.get(dev.name, []):
        nbr_dev = net.devices[nbr]
        for ni in nbr_dev.interfaces:
            if ni.name != remote_iface:
                continue
            if ni.prefix is None:
                continue
            if ni.prefix.contains(next_hop_ip):
                return nbr, local_iface, remote_iface
    return None, None, None


def resolve_flow(net: Net, src_rep: int, src_origin: str, dst_ip: int, proto: str, dport) -> dict:
    """Walk the data plane from the source device to the destination.

    Returns a verdict dict with path, drop evidence, NAT info, and a per-rule
    filter trace (for line-by-line simulation).
    """
    cur = net.devices.get(src_origin)
    if cur is None and src_origin:
        cur = _device_owning_ip(net, src_origin)
    if cur is None and src_origin:
        cur = net.devices.get(net.zones["internet"].gateway) if "internet" in net.zones else None
    if cur is None and src_origin:
        cur = _device_owning_ip(net, net.zones["internet"].gateway) if "internet" in net.zones else None
    if cur is None:
        return _verdict("no_route", [], drop={"device": src_origin or "?", "detail": "source device not found"})

    src_ip = src_rep
    arrived_iface = None
    path: list[str] = []
    steps: list[dict] = []
    nat_applied: dict | None = None
    seen: set[tuple] = set()
    trace_all: list[dict] = []

    for _ in range(MAX_HOPS):
        if cur is None:
            return _verdict("no_route", path, drop={"detail": "packet left the model"}, trace=trace_all)
        state = (cur.name, src_ip, dst_ip)
        if state in seen:
            return _verdict("loop", path, drop={"device": cur.name, "detail": "forwarding loop detected"}, trace=trace_all)
        seen.add(state)

        # 1) ingress filters on the interface we arrived on
        if arrived_iface is not None:
            iface = _interface(cur, arrived_iface)
            if iface is not None and iface.filters:
                filters = [net.filters[f] for f in iface.filters if f in net.filters]
                allowed, detail = check_filters(filters, src_ip, dst_ip, proto, dport)
                if detail.get("trace"):
                    trace_all.append({"device": cur.name, "iface": arrived_iface, **detail["trace"]})
                if not allowed:
                    steps.append({"device": cur.name, "iface": arrived_iface, "note": f"blocked by {detail.get('filter')}"})
                    return _verdict("blocked", path, drop={**detail, "device": cur.name, "iface": arrived_iface}, steps=steps, trace=trace_all)

        # 2) cloud devices accept everything
        if cur.dtype == "cloud":
            path.append(cur.name)
            steps.append({"device": cur.name, "iface": arrived_iface, "note": "delivered (public outside world)"})
            return _verdict("reachable", path, steps=steps, nat=nat_applied, trace=trace_all)

        # 3) destination NAT: the packet's destination is THIS device's own
        #    IP but a port-forward matches -> rewrite the destination and keep
        #    walking toward the private host.
        if dst_ip in cur.own_ips() and cur.dst_nat:
            hit = _match_dstnat(cur, dst_ip, proto, dport)
            if hit is not None:
                old_dst = ip_str(dst_ip)
                old_dport = dport
                dst_ip = hit["new_dst"]
                dport = hit["new_dport"]
                nat_applied = {
                    "kind": "dst_nat",
                    "device": cur.name,
                    "iface": arrived_iface,
                    "old_dst": old_dst,
                    "old_dport": old_dport,
                    "new_dst": hit["new_dst_ip"],
                    "new_dport": dport,
                    "public_ip": old_dst,
                }
                steps.append({"device": cur.name, "iface": arrived_iface, "note": f"DST NAT {old_dst}:{old_dport} -> {hit['new_dst_ip']}:{dport}"})

        # 3b) the packet reached a device that hosts the destination
        if dst_ip in cur.own_ips():
            steps.append({"device": cur.name, "iface": arrived_iface, "note": "delivered (destined for this device)"})
            return _verdict("reachable", path, steps=steps, nat=nat_applied, trace=trace_all)

        # 4) connected route: the destination is on a directly attached
        #    segment. If another device OWNS that address (e.g. a shared
        #    transit subnet), deliver to it and keep walking; otherwise stop.
        on_connected = False
        for iface in cur.interfaces:
            if iface.prefix and iface.prefix.contains(dst_ip):
                on_connected = True
                break
        if on_connected:
            owner = _device_owning_ip(net, ip_str(dst_ip))
            if owner is not None and owner.name != cur.name:
                nbr, local_iface, remote_iface = resolve_next_hop(net, cur, dst_ip)
                if nbr is None:
                    steps.append({"device": cur.name, "iface": arrived_iface, "note": "connected segment, destination owner unreachable"})
                    return _verdict("no_route", path, drop={"device": cur.name, "detail": "destination owner not attached"}, steps=steps, trace=trace_all)
                path.append(cur.name)
                steps.append({"device": cur.name, "iface": arrived_iface, "note": f"forwarded via {local_iface} -> {nbr} (L2 to {ip_str(dst_ip)})"})
                cur = net.devices.get(nbr)
                arrived_iface = remote_iface
                continue
            steps.append({"device": cur.name, "iface": arrived_iface, "note": "delivered (connected segment)"})
            return _verdict("reachable", path, steps=steps, nat=nat_applied, trace=trace_all)

        # 5) longest-prefix-match route lookup
        best = None
        for r in cur.routes:
            if r.prefix.contains(dst_ip) and (best is None or r.prefix.plen > best.prefix.plen):
                best = r
        if best is None:
            steps.append({"device": cur.name, "iface": arrived_iface, "note": "no route to destination"})
            return _verdict("no_route", path, drop={"device": cur.name, "detail": "no route to destination"}, steps=steps, trace=trace_all)

        nbr, local_iface, remote_iface = resolve_next_hop(net, cur, ip_int(best.next_hop))
        if nbr is None:
            steps.append({"device": cur.name, "iface": arrived_iface, "note": f"next hop {best.next_hop} unreachable"})
            return _verdict("no_route", path, drop={"device": cur.name, "detail": f"next hop {best.next_hop} not in model"}, steps=steps, trace=trace_all)

        # 6) source NAT at the egress interface
        if cur.nat is not None:
            nat = cur.nat
            inside = [p for p in nat.inside_prefixes]
            if _interface(cur, local_iface) is not None and cur.nat.outside_interface == local_iface and not any(p.contains(dst_ip) for p in inside) and not any(p.contains(src_ip) for p in inside):
                nat_iface = _interface(cur, local_iface)
                if nat_iface and nat_iface.ip:
                    nat_applied = {"device": cur.name, "iface": local_iface, "new_src": ip_str(ip_int(nat_iface.ip.rsplit("/", 1)[0])), "old_src": ip_str(src_ip)}
                    src_ip = ip_int(nat_iface.ip.rsplit("/", 1)[0])
                    steps[-1 if steps else 0] = {**steps[-1], "note": steps[-1].get("note", "") + " [NAT applied]"}

        path.append(cur.name)
        steps.append({"device": cur.name, "iface": arrived_iface, "note": f"forwarded via {local_iface} -> {nbr}"})
        cur = net.devices.get(nbr)
        arrived_iface = remote_iface

    return _verdict("loop", path, drop={"detail": "hop limit exceeded"}, steps=steps, trace=trace_all)


def _interface(dev: Device, name: str):
    for i in dev.interfaces:
        if i.name == name:
            return i
    return None


def _match_dstnat(dev: Device, dst_ip: int, proto: str, dport) -> dict | None:
    """Return a rewrite ({new_dst, new_dst_ip, new_dport}) for the first
    port-forward rule on `dev` whose public side matches the packet."""
    for rule in dev.dst_nat:
        rp = rule.proto
        if rp != "any" and proto != "any" and rp != proto:
            continue
        if rule.public_port and dport is not None and rule.public_port != dport:
            continue
        if (proto == "any" or dport is None):
            if rule.public_port:
                continue
            if rp != "any":
                continue
        return {
            "new_dst": ip_int(rule.private_ip),
            "new_dst_ip": rule.private_ip,
            "new_dport": rule.private_port,
            "rule": rule,
        }
    return None


def _verdict(status: str, path: list[str], drop: dict | None = None, steps: list[dict] | None = None, nat: dict | None = None, trace: list[dict] | None = None) -> dict:
    return {
        "status": status,
        "reachable": status == "reachable",
        "path": path,
        "steps": steps or [],
        "drop": drop,
        "nat": nat,
        "trace": trace or [],
    }