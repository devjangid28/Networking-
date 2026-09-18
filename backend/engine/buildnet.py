"""Build an engine Net model from a live discovery scan.

The scan contains per-device facts but no physical link map, so we model the
segment as a router-centric star: every discovered system is connected up to
the target router, and the router owns the subnet + a default route toward an
(assumed) uplink. This is honest about what a sweep knows, and it lets every
policy/routing question the engine understands be asked against the real LAN.

Design notes
------------
- Each host interface is a /32 host route so same-subnet devices route via the
  router (L2 delivery would otherwise terminate flows at the source).
- One policy filter "router-lan-in" (default permit) hangs on the router's LAN
  side, so proposed deny/permit rules are actually enforceable and verified.
- Every device becomes its own zone, so the validation matrix is per-machine.
"""
from __future__ import annotations

import ipaddress
import math
import re

from . import model as M

UPLINK_GW = "203.0.113.1"
UPLINK_IP = "203.0.113.2"
CX, CY = 600, 340
# Base orbit radii — scaled up for large device counts so nodes never overlap
BASE_RX, BASE_RY = 340, 240

SERVICE_ICONS = {
    "ssh": "ssh", "telnet": "telnet", "http": "http", "https": "https",
    "smb": "smb", "rdp": "rdp", "vnc": "vnc", "raw-printer": "printer",
    "lpd": "printer", "ipp": "printer", "mssql": "db", "mysql": "db",
    "postgres": "db", "ftp": "ftp", "dns": "dns",
}


def _unique_name(base: str, used: set[str], ip: str) -> str:
    if base and base not in used:
        name = base
    elif ip:
        name = ip
    else:
        name = "device"
    s = name
    n = 1
    while s in used:
        s = f"{name}-{n}"
        n += 1
    used.add(s)
    return s


def _port_name(raw: str, fallback_idx: int, used: set[str]) -> str:
    """Sanitize a real LLDP/CDP port id into a safe, unique interface name."""
    s = re.sub(r"[^A-Za-z0-9./_-]", "_", str(raw or "")).strip()
    if not s or len(s) > 32:
        s = f"P{fallback_idx}"
    base, n = s, 1
    while s in used:
        s = f"{base}_{n}"
        n += 1
    used.add(s)
    return s


def build_net(scan: dict, protect: set[str] | None = None) -> tuple[M.Net, dict]:
    """Returns (net, meta). Raises ValueError on structurally bad scans.

    `protect` is the opt-in set of ``"ip:port"`` service keys that the owner
    explicitly wants guarded after a live scan. When None (demo/agent flows)
    every discovered service becomes a requirement — the demo/agent model is
    fully governed. When a set is given, ONLY those listed services become
    policy requirements; everything else stays "discovered but open" until the
    owner ticks it to protect. Empty set == nothing protected yet.
    """
    devices = scan.get("devices", [])
    if not devices:
        raise ValueError("no devices discovered - nothing to model")
    target_ip = scan.get("target", "").strip()
    subnet = scan.get("network")
    try:
        cidr = ipaddress.ip_network(subnet, strict=False)
    except Exception:
        cidr = ipaddress.ip_network("0.0.0.0/0", strict=False)

    used: set[str] = set()
    net = M.Net(name=f"Live {cidr.with_prefixlen}", description=f"Discovered segment {cidr.with_prefixlen} (via NetProof scan of {target_ip})")

    net.filters["router-lan-in"] = M.Filter(name="router-lan-in", default="permit")

    # -- router ----------------------------------------------------------------
    target = next((d for d in devices if d.get("is_target")), devices[0])
    # The raw target may be a CIDR (the UI invites "IP or CIDR"). Every use of
    # target_ip below expects a bare host address, so resolve the address the
    # scanner flagged as the target; a CIDR would otherwise yield "a.b.c.d/24/24"
    # and crash Prefix.parse.
    target_ip = target.get("ip") or target_ip.split("/")[0]
    router_name = _unique_name(target.get("hostname") or target_ip, used, target_ip)
    router = M.Device(name=router_name, dtype="router", x=CX, y=CY)
    router.routes.append(M.Route.from_dict({"network": "0.0.0.0/0", "next_hop": UPLINK_GW}))
    net.devices[router.name] = router

    # -- real physical link map from the LLDP/CDP tables on the target ---------
    # A sweep alone cannot see links, so this is best-effort ground truth: match
    # the target's reported neighbors to the scanned inventory (by sysName or
    # hostname). Matched devices get their REAL port names from the neighbor
    # tables; unmatched ones fall back to the synthetic star. When nothing
    # matches, the whole build stays the honest router-centric star.
    neighbors = scan.get("neighbors") or []
    by_name: dict[str, dict] = {}
    for _d in devices:
        sn = (_d.get("snmp") or {}).get("sysName") or ""
        hn = _d.get("hostname") or ""
        if sn:
            by_name.setdefault(sn.strip().lower(), _d)
        if hn:
            by_name.setdefault(hn.strip().lower(), _d)

    matched: dict[str, dict] = {}  # device ip -> neighbor entry
    for nb in neighbors:
        want = str(nb.get("remote_sysname") or nb.get("remote_device_id") or "").strip().lower()
        dev = by_name.get(want)
        if dev is None or dev.get("ip") == target_ip or dev.get("ip") in matched:
            continue
        matched[dev["ip"]] = nb
    real_links = bool(matched)

    # -- link-facing interfaces on the router (one per discovered system) ------
    lan_ifaces = []
    used_ports: set[str] = set()
    for idx, d in enumerate(devices):
        ip = d.get("ip")
        if not ip:
            continue
        nb = matched.get(ip)
        iface_name = _port_name(str(nb.get("local_port")), idx, used_ports) if nb else f"Eth{idx}"
        # ip carries the CIDR so Interface.from_dict derives a real /24 prefix
        # (a bare IP alone would silently become a /32 and break connected-route
        # delivery for same-subnet neighbours).
        lan = M.Interface.from_dict(iface_name, {"ip": f"{target_ip}/{cidr.prefixlen}", "network": cidr.with_prefixlen, "label": d.get("vendor", ""), "filters": ["router-lan-in"], "connected_to": "HOLD"})
        router.interfaces.append(lan)
        lan.connected_to = None  # fixed below after neighbor names resolve
        lan_ifaces.append((lan, ip, d, nb))

    # -- orbit geometry (needed before cloud placement) -------------------------
    others = [(lan, ip, d, nb) for (lan, ip, d, nb) in lan_ifaces if ip != target_ip]
    n_others = max(len(others), 1)
    min_arc = 110
    min_rx = int(n_others * min_arc / (2 * math.pi))
    RX = max(BASE_RX, min_rx)
    RY = max(BASE_RY, int(min_rx * 0.72))

    # -- uplink -----------------------------------------------------------------
    wan = M.Interface.from_dict("Wan", {"ip": UPLINK_IP, "network": "203.0.113.0/24", "label": "WAN (assumed)", "connected_to": "internet eth0"})
    router.interfaces.append(wan)
    cloud = M.Device(name="internet", dtype="cloud", x=CX + RX + 90, y=CY)
    cloud.interfaces.append(M.Interface.from_dict("eth0", {"ip": UPLINK_GW, "network": "203.0.113.0/24", "connected_to": f"{router.name} Wan"}))
    net.devices[cloud.name] = cloud

    # -- every other system -----------------------------------------------------
    for idx, (lan, ip, d, nb) in enumerate(others):
        base = d.get("hostname")
        dtype = d.get("type_guess")
        if dtype not in ("router", "switch", "host", "server", "printer", "camera", "mobile", "laptop", "phone"):
            dtype = "router" if d.get("is_target") else "host"
        if dtype == "router":
            dtype = "switch"
        angle = 2 * math.pi * idx / n_others
        dev = M.Device(name=_unique_name(base, used, ip), dtype=dtype,
                       x=CX + RX * math.cos(angle), y=CY + RY * math.sin(angle))
        remote_iface = _port_name(str((nb or {}).get("remote_port")), 0, set()) if nb else "Eth0"
        iface = M.Interface.from_dict(remote_iface, {"ip": ip, "network": f"{ip}/32", "label": d.get("vendor", "") or dtype})
        iface.connected_to = f"{router.name} {lan.name}"
        dev.interfaces.append(iface)
        dev.routes.append(M.Route.from_dict({"network": "0.0.0.0/0", "next_hop": target_ip}))
        net.devices[dev.name] = dev
        lan.connected_to = f"{dev.name} {remote_iface}"

    # -- zones ------------------------------------------------------------------
    for d in devices:
        ip = d.get("ip", "")
        if not ip:
            continue
        zname = ip
        net.zones[zname] = M.Zone(
            name=zname, prefix=M.Prefix.parse(f"{ip}/32"), sample_dst=M.ip_int(ip), gateway=ip,
            is_source=True, is_dest=True,
        )
    net.zones["internet"] = M.Zone(
        name="internet", prefix=None, sample_dst=M.ip_int("8.8.8.8"), gateway=UPLINK_GW,
        is_source=False, is_dest=True,
    )

    # -- service requirements ---------------------------------------------------
    # Every open port discovered on a scanned device becomes an expectation the
    # engine verifies: `Server X reachable on tcp/445`. Without this the flow
    # set is only proto-any zone pairs, so a port-specific rule (deny tcp/445)
    # would match nothing and pass silently - useless for a real network.
    # The source is a real LAN client (not the router) so the packet traverses
    # the router's LAN ingress filter and the rule is actually enforceable.
    lan_client = next((d.get("ip") for d in devices
                       if d.get("ip") and d.get("ip") != target_ip and not d.get("is_target")), target_ip)
    PROTO_BY_SERVICE = {"dns": "udp", "ntp": "udp", "dhcp": "udp", "snmp": "udp", "syslog": "udp"}
    req_names: set[str] = set()
    for d in devices:
        ip = d.get("ip")
        for svc in d.get("services") or []:
            port = int(svc.get("port") or 0)
            if not port:
                continue
            # opt-in gate: a service only becomes a policy requirement when the
            # owner explicitly ticks to protect THIS ip:port. In demo/agent flows
            # `protect` is None, so every discovered service is governed (the
            # sample/agent model is a full policy). After a live scan `protect`
            # is the set the owner ticked; anything else stays "discovered but
            # open" until ticked - no silent 10-rule wall, nothing auto-guarded.
            if protect is not None and f"{ip}:{port}" not in protect:
                continue
            hn = (d.get("hostname") or "").strip().lower()
            base = (hn.split(".")[0] if hn else str(ip))[:24]
            name = f"svc-{base}-{port}"
            n = 1
            while name in req_names:
                n += 1
                name = f"svc-{base}-{port}-{n}"
            req_names.add(name)
            proto = PROTO_BY_SERVICE.get(str(svc.get("service", "")).lower(), "tcp")
            net.requirements.append(M.Requirement(
                name=name,
                src=lan_client,         # a real LAN host stands in for any client
                dst=str(ip),
                proto=proto,
                dport=port,
                expect="reachable",
            ))
    del req_names

    net.build_adjacency()

    real_link_count = len(matched)
    if real_links:
        proto = next((nb.get("protocol", "lldp") for nb in matched.values() if nb.get("protocol")), "lldp")
        topology = f"{proto}-discovered"
    else:
        topology = "inferred-star"

    meta = {
        "subnet": cidr.with_prefixlen,
        "target": target_ip,
        "device_count": len(used),
        "topology": topology,
        "wan": "assumed",
        "links_discovered": real_link_count,
        "notes": [],
    }
    if real_links:
        meta["notes"].append(
            f"physical links ARE known on the target: {real_link_count} edge(s) grounded in real "
            "LLDP/CDP neighbor tables (port names from the device, not synthetic)"
        )
        net.description = (
            f"{net.description}. Topology is {topology}: {real_link_count} link(s) "
            "read from real LLDP/CDP neighbor tables on the target."
        )
    else:
        meta["notes"] += [
            "physical links are not known to a sweep: devices are modelled on a router-centric star",
            "the WAN/uplink (203.0.113.0/24, gateway 203.0.113.1) is assumed, not observed",
        ]
        net.description = f"{net.description}. Topology is inferred (router-centric star); uplink is assumed."
    return net, meta