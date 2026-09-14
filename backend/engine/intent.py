"""NetProof intent parser — turn plain English changes into machine changes.

The acceptance contract: single line in, structured change out (the same dict
shape the referee engine consumes). Deliberately transparent: if it cannot
prove a field it says so and lowers confidence, it never invents.
"""
from __future__ import annotations

import re

from .model import Net, Prefix, ip_int

ANY = "any"

SERVICES: dict[str, dict] = {
    "ssh": {"proto": "tcp", "port": 22},
    "telnet": {"proto": "tcp", "port": 23},
    "smtp": {"proto": "tcp", "port": 25},
    "dns": {"proto": "udp", "port": 53},
    "http": {"proto": "tcp", "port": 80},
    "https": {"proto": "tcp", "port": 443},
    "web": {"proto": "tcp", "port": 80},
    "rdp": {"proto": "tcp", "port": 3389},
    "ftp": {"proto": "tcp", "port": 21},
    "mysql": {"proto": "tcp", "port": 3306},
    "postgres": {"proto": "tcp", "port": 5432},
    "ntp": {"proto": "udp", "port": 123},
}

RE_IP = r"(?:\d{1,3}\.){3}\d{1,3}"
RE_CIDR = rf"{RE_IP}/\d{{1,2}}"


def parse_intent(text: str, net: Net) -> dict:
    """Two-stage intent resolution against model `net`.

    1. Resolver — bind every entity in the sentence to the live inventory
       (device/IP/zone/policy-point). Anything it cannot bind with evidence
       lowers confidence instead of guessing.
    2. IR builder — emit the constrained change dict (the same schema the
       referee engine consumes), plus a plain-English confirmation string so a
       human (or a guardrail gate) can approve it before it is validated.
    """
    t = (text or "").strip()
    if not t:
        return _err("no text to parse")
    low = t.lower()

    if "bgp" in low or re.search(r"\bpeer(?:ing)?\b", low):
        return _parse_bgp(t, net)
    if "ospf" in low or "advertise" in low:
        return _parse_ospf(t, net)
    if "dns" in low or re.search(r"\brecord", low):
        return _parse_dns(t, net)
    if "vlan" in low or "switchport" in low:
        return _parse_vlan(t, net)
    if any(k in low for k in ("port-forward", "port forward", "portforward", "publish ", "expose ")):
        return _parse_dstnat(t, net)
    if "route" in low or "reroute" in low:
        return _parse_route(t, net)
    if re.search(r"\b(remove|delete)\b.*\b(rule|acl|entry)\b", low):
        return _parse_remove_rule(t, net)
    if re.search(r"\b(allow|permit|block|deny|drop|firewall)\b", low):
        return _parse_policy(t, net)

    return _err("I could not understand that. Try: 'block ssh from user-pc to app-server', "
                "'allow http from any to app-server', 'port-forward 8080 to app-server:80', "
                "'add route 10.99.0.0/16 via 192.168.1.2 on firewall', "
                "'bgp peer 203.0.113.1 remote-as 65000 on firewall', "
                "'advertise 10.0.0.0/16 in ospf area 0 on core-switch', "
                "'add dns record status.internal A 10.0.20.10 on dns-server', "
                "'assign vlan 30 to Gi0/3 on core-switch'.")


def _ok(change: dict, description: str, confidence: float, resolved: dict | None = None) -> dict:
    resolved = resolved or {}
    return {
        "ok": True,
        "change": change,
        "description": description,
        "confirmation": _confirmation(description, resolved),
        "confidence": round(confidence, 2),
        "errors": [],
        "resolved": resolved,
    }


def _confirmation(description: str, resolved: dict) -> str:
    parts = []
    if resolved.get("source"):
        parts.append(f"source '{resolved['source']}'")
    if resolved.get("destination"):
        parts.append(f"destination '{resolved['destination']}'")
    if resolved.get("neighbor"):
        parts.append(f"peer {resolved['neighbor']}")
    if resolved.get("fqdn"):
        parts.append(f"name '{resolved['fqdn']}'")
    if resolved.get("value"):
        parts.append(f"points to '{resolved['value']}'")
    if resolved.get("iface"):
        parts.append(f"port '{resolved['iface']}'")
    if resolved.get("device"):
        parts.append(f"on '{resolved['device']}'")
    if resolved.get("filter"):
        parts.append(f"policy '{resolved['filter']}'")
    if resolved.get("next_hop"):
        parts.append(f"via {resolved['next_hop']}")
    if resolved.get("port"):
        parts.append(f"port {resolved['port']}")
    if resolved.get("name"):
        parts.append(f"'{resolved['name']}'")
    body = ", ".join(parts)
    return f"{description}. Confirmed with {body}." if body else f"{description}."


def _err(msg: str) -> dict:
    return {"ok": False, "change": None, "description": "", "confirmation": "", "confidence": 0.0, "errors": [msg], "resolved": {}}


# --------------------------------------------------------------------------- #
# resolution helpers                                                          #
# --------------------------------------------------------------------------- #

def _device_map(net: Net) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, dev in net.devices.items():
        out[name.lower()] = name
        for i in dev.interfaces:
            if i.ip:
                out[i.ip.rsplit("/", 1)[0]] = name
    return out


def _first_main_ip(net: Net, name: str) -> str:
    dev = net.devices.get(name)
    if not dev:
        return ""
    for i in dev.interfaces:
        if i.ip:
            return i.ip.rsplit("/", 1)[0]
    return ""


def _is_routerish(net: Net, name: str) -> bool:
    dev = net.devices.get(name)
    return bool(dev and dev.dtype in ("router", "firewall"))


def _resolve_addr(net: Net, token: str, aliases: dict[str, str]) -> str:
    """Turn a raw token (ip/cidr/device name/zone name) into an address string."""
    tok = (token or "").strip().rstrip(".,;")
    if not tok or tok == ANY:
        return ANY
    if "/" in tok:
        try:
            Prefix.parse(tok)
            return tok
        except (ValueError, TypeError):
            pass
    if re.fullmatch(RE_IP, tok):
        return tok
    # device name or alias
    hit = aliases.get(tok.lower())
    if hit:
        ip = _first_main_ip(net, hit)
        if ip:
            return ip
        return hit
    # zone name
    for zname, z in net.zones.items():
        if zname.lower() == tok.lower():
            if z.prefix:
                return z.prefix.text
            return z.sample_dst and f"{z.sample_dst}" or ANY
    try:
        ip_int(tok)
        return tok
    except (ValueError, TypeError):
        return ""


def _pick_filter(net: Net, tok: str | None) -> tuple[str, float]:
    if tok:
        for fname in net.filters:
            if fname.lower() == tok.strip().lower():
                return fname, 1.0
        # fuzzy: token containment
        for fname in net.filters:
            if tok.strip().lower() in fname.lower():
                return fname, 0.9
    # default: prefer firewall-style inside policies, else first filter
    for fname in net.filters:
        if "inside" in fname or "lan-in" in fname or "user-in" in fname:
            return fname, 0.6
    return next(iter(net.filters), ""), 0.5


def _pick_router(net: Net) -> str:
    for name, dev in net.devices.items():
        if dev.dtype == "firewall":
            return name
    for name, dev in net.devices.items():
        if dev.dtype == "router":
            return name
    return next(iter(net.devices), "")


def _capture(text: str, regex: str) -> str | None:
    m = re.search(regex, text, re.IGNORECASE)
    return m.group(0) if m else None


# --------------------------------------------------------------------------- #
# policy rules: allow / block <proto> from <src> to <dst> [on <filter>] [, port <p>]
# --------------------------------------------------------------------------- #

def _parse_policy(text: str, net: Net) -> dict:
    low = text.lower()
    action = "permit" if re.search(r"\b(allow|permit)\b", low) else "deny"

    aliases = _device_map(net)

    fromm = _capture(text, r"from\s+(" + RE_CIDR + r"|" + RE_IP + r"|[a-zA-Z0-9._-]+)")
    to = _capture(text, r"\bto\s+(" + RE_CIDR + r"|" + RE_IP + r"|[a-zA-Z0-9._-]+)")
    if fromm:
        fromm = fromm[5:].strip()
    if to:
        to = to[3:].strip()

    src = _resolve_addr(net, fromm or ANY, aliases)
    dst = _resolve_addr(net, to or ANY, aliases)
    if not src or not dst:
        return _err("couldn't resolve the source/destination address.")

    # protocol + port from service words
    proto = "any"
    dport = None
    conf = 1.0
    m1 = re.search(r"\b(tcp|udp|icmp|any)\b", low)
    if m1:
        proto = m1.group(1).lower()
    for word in low.split():
        clean = word.strip(".,:;'()")
        if clean in SERVICES:
            svc = SERVICES[clean]
            proto = svc["proto"]
            dport = svc["port"]
            break
    portm = re.search(r"port\s+(?:\d{1,5})", low)
    if portm:
        dport = int(re.search(r"\d{1,5}", portm.group(0)).group(0))
    if proto == "tcp" and dport is None:
        dport = None

    # filter choice + position
    onm = _capture(text, r"(?:on|at)\s+([a-zA-Z0-9_.-]+)")
    onm = onm[3:].strip() if onm else None
    fname, fconf = _pick_filter(net, onm)
    if not fname:
        return _err("the model has no policy points (filters) defined.")
    at = 0
    idxm = re.search(r"(?:index|position|rule number)\s+(\d+)", low)
    if idxm:
        at = int(idxm.group(1))

    if src == ANY and dst == ANY:
        conf = min(conf, 0.55)
    if not (fromm or to):
        conf = min(conf, 0.4)
    conf = min(conf, fconf)

    change = {
        "type": "add_filter_rule",
        "filter": fname,
        "at_index": at,
        "rule": {"action": action, "src": src, "dst": dst, "proto": proto},
    }
    if dport:
        change["rule"]["dport"] = dport
    desc = f"{action} {proto + ('/' + str(dport) if dport else '')} {src} → {dst} on {fname}"
    return _ok(change, desc, conf, {"source": src, "destination": dst, "filter": fname, "device": _device_for_filter(net, fname)})


# --------------------------------------------------------------------------- #
# routes                                                                      #
# --------------------------------------------------------------------------- #

def _parse_route(text: str, net: Net) -> dict:
    low = text.lower()
    removing = bool(re.search(r"\b(remove|delete)\b", low))

    aliases = _device_map(net)
    dev = _pick_router(net)
    onm = _capture(text, r"(?:on|at)\s+([a-zA-Z0-9_.-]+)")
    if onm:
        onm = onm[3:].strip()
        hit = aliases.get(onm.lower())
        if hit and (_is_routerish(net, hit) or True):
            dev = hit

    if removing:
        return _remove_route(text, net, dev)
    return _add_route(text, net, dev, aliases)


def _add_route(text: str, net: Net, dev: str, aliases: dict[str, str]) -> dict:
    low = text.lower()
    network = _capture(text, RE_CIDR) or _capture(text, RE_IP)
    if "default" in low:
        network = "0.0.0.0/0"
    if not network:
        return _err("no network found. e.g. 'add route 10.99.0.0/16 via 192.168.1.2 on firewall'")
    nh = None
    vm = re.search(r"via\s+(" + RE_IP + r"|" + RE_CIDR + r"|[a-zA-Z0-9._-]+)", text, re.IGNORECASE)
    if vm:
        token = vm.group(1)
        nh = token if re.fullmatch(RE_IP, token) else _resolve_addr(net, token, aliases)
        if nh == ANY or nh == "":
            nh = None
    if not nh:
        return _err("no next hop found. e.g. 'add route 10.99.0.0/16 via 192.168.1.2 on firewall'")
    if not network.endswith("/"):
        pass
    change = {"type": "add_route", "device": dev, "route": {"network": network, "next_hop": nh}}
    return _ok(change, f"add route {network} via {nh} on {dev}", 1.0, {"destination": network, "device": dev, "next_hop": nh})


def _remove_route(text: str, net: Net, dev: str) -> dict:
    low = text.lower()
    network = _capture(text, RE_CIDR) or _capture(text, RE_IP)
    if "default" in low:
        network = "0.0.0.0/0"
    device = net.devices.get(dev)
    if device is None:
        return _err(f"device '{dev}' not in model.")
    index = None
    idxm = re.search(r"(?:index|route number|#)\s*(\d+)", low)
    if idxm:
        index = int(idxm.group(1))
    elif network:
        for i, r in enumerate(device.routes):
            if r.network == network:
                index = i
                break
        if index is None:
            return _err(f"no route {network} found on {dev}.")
    return _ok({"type": "remove_route", "device": dev, "index": index or 0},
               f"remove route #{index or 0} ({network or '?'}) on {dev}", 0.95 if network else 0.6,
               {"device": dev, "destination": network or "?", "name": f"route #{index or 0}"})


# --------------------------------------------------------------------------- #
# port-forward / dst nat                                                      #
# --------------------------------------------------------------------------- #

def _parse_dstnat(text: str, net: Net) -> dict:
    low = text.lower()
    removing = bool(re.search(r"\b(remove|delete|take.?down)\b", low))
    if removing:
        return _err("removing a forward from plain words needs the forward index — use the builder for now.")

    # public port: "8080" around the forward keyword, or after 'port'
    pub_port = None
    m = re.search(r"(?:port\s*)?(\d{1,5})(?:\s*to\s*|\s*(?:->|→)\s*)", text)
    if m:
        pub_port = int(m.group(1))
    else:
        mm = re.search(r"port\s+(\d{1,5})", low)
        if mm:
            pub_port = int(mm.group(1))
    if pub_port is None:
        return _err("no public port found. e.g. 'port-forward 8080 to app-server:80'")

    # private target: keyword (to/->/→/at) + device[:port] or ip[:port]
    target = None
    priv_port = pub_port
    tm = re.search(r"(?:to|->|→|at)\s+(" + RE_IP + r"|[a-zA-Z0-9_.-]+)(?::(\d{1,5}))?", text)
    if tm and tm.group(1):
        name_or_ip = tm.group(1).strip().rstrip(",.;")
        if tm.group(2):
            priv_port = int(tm.group(2))
        target = _resolve_addr(net, name_or_ip, _device_map(net))
        if target and target != ANY:
            if not re.fullmatch(RE_IP, target):
                target = None
    if not target:
        return _err("couldn't resolve the destination host. e.g. 'port-forward 8080 to app-server:80'")

    proto = "tcp"
    for word in low.split():
        if word.strip(".,:") in SERVICES:
            proto = SERVICES[word.strip(".,:")]["proto"]
            break
    if "udp" in low:
        proto = "udp"

    dev = _pick_router(net)
    change = {
        "type": "add_dst_nat",
        "device": dev,
        "dst_nat": {"public_ip": "", "public_port": pub_port, "private_ip": target, "private_port": priv_port, "proto": proto},
    }
    desc = f"port-forward {proto}/{pub_port} → {target}:{priv_port} on {dev}"
    return _ok(change, desc, 0.95, {"device": dev, "destination": target, "port": f"{proto}/{pub_port}", "value": f"{target}:{priv_port}"})


# --------------------------------------------------------------------------- #
# remove a rule                                                               #
# --------------------------------------------------------------------------- #

def _parse_remove_rule(text: str, net: Net) -> dict:
    low = text.lower()
    fname, fconf = _pick_filter(net, None)
    onm = _capture(text, r"(?:on|at)\s+([a-zA-Z0-9_.-]+)")
    if onm:
        onm = onm[3:].strip()
        fname, fconf = _pick_filter(net, onm)
    if not fname:
        return _err("no policy point found for the rule removal.")
    idxm = re.search(r"(?:rule|#|index|entry)\s*#?\s*(\d+)", low)
    index = int(idxm.group(1)) if idxm else None
    if index is None:
        return _err("tell me which rule number, e.g. 'remove rule 2 on fw-inside-in'")
    return _ok({"type": "remove_filter_rule", "filter": fname, "at_index": index},
               f"remove rule #{index} on {fname}", 0.92, {"filter": fname, "destination": f"rule #{index}", "device": _device_for_filter(net, fname)})


def _device_for_filter(net: Net, fname: str) -> str:
    """A device that actually binds `fname` to one of its interfaces."""
    for dev in net.devices.values():
        for i in dev.interfaces:
            if fname in (i.filters or []):
                return dev.name
    return ""


# --------------------------------------------------------------------------- #
# BGP peering                                                                 #
# --------------------------------------------------------------------------- #

def _parse_bgp(text: str, net: Net) -> dict:
    low = text.lower()
    aliases = _device_map(net)
    removing = bool(re.search(r"\b(remove|delete|tear.?down|disable|drop)\b", low))

    dev = _pick_router(net)
    onm = _capture(text, r"(?:on|at)\s+([a-zA-Z0-9_.-]+)")
    if onm:
        hit = aliases.get(onm[3:].strip().lower())
        if hit:
            dev = hit
    device = net.devices.get(dev)
    if device is None:
        return _err(f"device '{dev}' not in model.")

    nb = _capture(text, RE_IP)
    if nb is None:
        nm = re.search(r"\bpeer(?:ing)?\s+(?:to\s+|with\s+)?([a-zA-Z0-9_.-]+)", text, re.IGNORECASE)
        if nm:
            nb = nm.group(1).strip().rstrip(".,;")
    if nb is None and removing and device.bgp:
        nb = device.bgp[0].neighbor
    if nb is None:
        return _err("which BGP peer? e.g. 'bgp peer 203.0.113.1 remote-as 65000 on firewall'")
    nbr_ip = nb if re.fullmatch(RE_IP, nb) else _resolve_addr(net, nb, aliases)
    if not nbr_ip or nbr_ip == ANY:
        return _err(f"couldn't resolve BGP neighbor '{nb}' to an address in the model.")

    local_as = 0
    remote_as = 0
    lam = re.search(r"local[- ]as\s+(\d+)", low)
    if lam:
        local_as = int(lam.group(1))
    ram = re.search(r"remote[- ]as\s+(\d+)", low)
    if ram:
        remote_as = int(ram.group(1))
    asm = re.search(r"(?:^|\s)as\s+(\d+)", low)
    if remote_as == 0 and asm:
        remote_as = int(asm.group(1))
    if remote_as == 0:
        return _err("need the neighbor ASN: 'remote-as 65000'")
    if local_as == 0:
        known = [p.local_as for p in (device.bgp or []) if p.local_as]
        if known:
            local_as = known[0]
    em = re.search(r"export(?:ing)?\s+(" + RE_CIDR + r")", low)
    exports = [em.group(1)] if em else []

    if removing:
        if not device.bgp:
            return _err(f"no BGP peers configured on '{dev}' to remove.")
        for i, p in enumerate(device.bgp):
            if p.neighbor == nbr_ip:
                return _ok({"type": "remove_bgp_peer", "device": dev, "index": i},
                           f"remove BGP peering with {nbr_ip} on {dev}", 0.95,
                           {"neighbor": nbr_ip, "device": dev})
        return _err(f"no BGP peer {nbr_ip} on '{dev}'.")

    change = {
        "type": "add_bgp_peer",
        "device": dev,
        "peer": {"neighbor": nbr_ip, "local_as": local_as, "remote_as": remote_as, "export_prefixes": exports},
    }
    desc = f"add BGP peering with {nbr_ip} (as {local_as} → as {remote_as})"
    if exports:
        desc += f" exporting {', '.join(exports)}"
    desc += f" on {dev}"
    return _ok(change, desc, 0.95, {"neighbor": nbr_ip, "device": dev, "name": f"as {remote_as}", "next_hop": nbr_ip})


# --------------------------------------------------------------------------- #
# OSPF                                                                        #
# --------------------------------------------------------------------------- #

def _parse_ospf(text: str, net: Net) -> dict:
    low = text.lower()
    aliases = _device_map(net)
    removing = bool(re.search(r"\b(remove|delete|withdraw|stop)\b", low))

    dev = _pick_router(net)
    onm = _capture(text, r"(?:on|at)\s+([a-zA-Z0-9_.-]+)")
    if onm:
        hit = aliases.get(onm[3:].strip().lower())
        if hit:
            dev = hit
    device = net.devices.get(dev)
    if device is None:
        return _err(f"device '{dev}' not in model.")

    area_id = 0
    am = re.search(r"area\s+(\d+)", low)
    if am:
        area_id = int(am.group(1))
    network = _capture(text, RE_CIDR)
    if not network:
        return _err("which network? e.g. 'advertise 10.0.0.0/16 in ospf area 0 on core-switch'")

    if removing:
        area = next((a for a in (device.ospf or []) if network in a.networks), None)
        if area is None:
            return _err(f"no OSPF advertisement for {network} on '{dev}' to withdraw.")
        change = {"type": "remove_ospf_network", "device": dev, "area_id": area.area_id, "network": network}
        return _ok(change, f"stop advertising {network} in OSPF area {area.area_id} on {dev}", 0.95,
                   {"device": dev, "destination": network, "name": f"area {area.area_id}"})

    change = {"type": "add_ospf_network", "device": dev, "area_id": area_id, "network": network}
    return _ok(change, f"advertise {network} in OSPF area {area_id} on {dev}", 0.95,
               {"device": dev, "destination": network, "name": f"area {area_id}"})


# --------------------------------------------------------------------------- #
# DNS records                                                                 #
# --------------------------------------------------------------------------- #

def _parse_dns(text: str, net: Net) -> dict:
    low = text.lower()
    aliases = _device_map(net)
    removing = bool(re.search(r"\b(remove|delete|drop)\b", low))

    dev = ""
    for name, d in net.devices.items():
        if d.dns:
            dev = name
            break
    onm = _capture(text, r"(?:on|at)\s+([a-zA-Z0-9_.-]+)")
    if onm:
        hit = aliases.get(onm[3:].strip().lower())
        if hit:
            dev = hit
    server = net.devices.get(dev)
    if server is None:
        return _err("no DNS server is modelled — add one first or name it explicitly under 'on <device>'.")
    authoritative = {r.zone for r in (server.dns or [])}

    fm = re.search(r"\b([a-zA-Z0-9][a-zA-Z0-9._-]*\.[a-zA-Z][a-zA-Z0-9._-]*)\b", text)
    fqdn = fm.group(1).rstrip(".,;").lower() if fm else None
    if not fqdn:
        return _err("which name? e.g. 'add dns record portal.internal A 10.0.20.10 on dns-server'")

    rtype = "A"
    rtm = re.search(r"\b(A|AAAA|CNAME|MX|TXT|PTR|SRV)\b", low.upper())
    if rtm:
        rtype = rtm.group(1).upper()

    value = ""
    if rtype in ("A", "AAAA"):
        value = _capture(text, RE_IP) or ""
    else:
        vm = re.search(r"(?:to|->|→|points?\s+(?:to\s+)?|targets?=?)\s+([a-zA-Z0-9.:-]+)", text, re.IGNORECASE)
        if vm:
            value = vm.group(1).strip().rstrip(".,;")
    if not value:
        return _err(f"need a target for the {rtype} record. e.g. 'add dns record status.internal {rtype} <ip-or-name> on dns-server'")

    zone = ""
    for z in authoritative:
        if fqdn == z or fqdn.endswith("." + z):
            zone = z
            break
    if not zone and "." in fqdn:
        zone = fqdn.split(".", 1)[1]
        confidence = 0.8
    else:
        confidence = 0.95
    if not zone:
        return _err("couldn't determine an authoritative zone for that name.")

    if removing:
        existing = next((r for r in (server.dns or []) if r.fqdn == fqdn and r.rtype == rtype), None)
        if existing is None:
            existing = next((r for r in (server.dns or []) if r.fqdn == fqdn), None)
        if existing is None:
            return _err(f"no DNS record for {fqdn} on '{dev}' to remove.")
        change = {"type": "remove_dns_record", "device": dev,
                  "record": {"zone": existing.zone, "fqdn": existing.fqdn, "type": existing.rtype, "value": existing.value, "ttl": existing.ttl}}
        return _ok(change, f"remove DNS record {existing.describe()} on {dev}", 0.95,
                   {"device": dev, "fqdn": existing.fqdn, "value": existing.value})

    change = {"type": "add_dns_record", "device": dev,
              "record": {"zone": zone, "fqdn": fqdn, "type": rtype, "value": value, "ttl": 300}}
    desc = f"add DNS record {fqdn} {rtype} {value} on {dev}"
    return _ok(change, desc, confidence, {"device": dev, "fqdn": fqdn, "value": value})


# --------------------------------------------------------------------------- #
# VLAN switchport assignment                                                  #
# --------------------------------------------------------------------------- #

def _parse_vlan(text: str, net: Net) -> dict:
    low = text.lower()
    aliases = _device_map(net)
    removing = bool(re.search(r"\b(remove|delete|clear)\b", low))

    im = re.search(r"\b([A-Za-z]{1,6}\d*(?:\.?\d+)(?:/\d+)(?:\.\d+)?)\b", text) or re.search(r"\b(eth\d+)\b", text)
    iface = im.group(1).strip().rstrip(".,;") if im else None
    if not iface:
        return _err("which switchport? e.g. 'assign vlan 30 to Gi0/3 on core-switch' or 'move Gi0/3 to vlan 30'")

    dev = ""
    onm = _capture(text, r"(?:on|at)\s+([a-zA-Z0-9_.-]+)")
    if onm:
        hit = aliases.get(onm[3:].strip().lower())
        if hit:
            dev = hit
    if not dev:
        for name, d in net.devices.items():
            if d.dtype in ("switch", "router") and (any(v.iface == iface for v in (d.vlans or [])) or d.iface(iface)):
                dev = name
                break
    device = net.devices.get(dev)
    if device is None:
        return _err(f"couldn't find switch '{dev or '?'}' with a port '{iface}' in the model.")
    if device.dtype == "host":
        return _err(f"'{dev}' is a host — switchports only exist on switches and routers.")

    vlan_id = 0
    vm = re.search(r"vlan\s+(\d+)", low)
    if vm:
        vlan_id = int(vm.group(1))

    if removing:
        existing = next((a for a in (device.vlans or []) if a.iface == iface), None)
        if existing is None:
            return _err(f"no vlan assignment for {iface} on '{dev}'.")
        change = {"type": "remove_vlan_assignment", "device": dev,
                  "vlan": {"iface": iface, "vlan_id": existing.vlan_id, "name": existing.name, "tagged": existing.tagged}}
        return _ok(change, f"remove {iface} from vlan {existing.vlan_id} on {dev}", 0.95,
                   {"device": dev, "iface": iface, "name": f"vlan {existing.vlan_id}"})

    if vlan_id == 0:
        return _err("which vlan id? e.g. 'assign vlan 30 to Gi0/3 on core-switch'")
    change = {"type": "add_vlan_assignment", "device": dev, "vlan": {"iface": iface, "vlan_id": vlan_id, "name": "guest" if vlan_id >= 30 else ""}}
    return _ok(change, f"assign {iface} to vlan {vlan_id} on {dev}", 0.95, {"device": dev, "iface": iface, "name": f"vlan {vlan_id}"})