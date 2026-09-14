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

from . import model as M

UPLINK_GW = "203.0.113.1"
UPLINK_IP = "203.0.113.2"
CX, CY, RX, RY = 600, 320, 300, 210

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
    router_name = _unique_name(target.get("hostname") or target_ip, used, target_ip)
    router = M.Device(name=router_name, dtype="router", x=CX, y=CY)
    router.routes.append(M.Route.from_dict({"network": "0.0.0.0/0", "next_hop": UPLINK_GW}))
    net.devices[router.name] = router

    # -- link-facing interfaces on the router (one per discovered system) ------
    lan_ifaces = []
    for idx, d in enumerate(devices):
        ip = d.get("ip")
        if not ip:
            continue
        iface_name = f"Eth{idx}"
        # ip carries the CIDR so Interface.from_dict derives a real /24 prefix
        # (a bare IP alone would silently become a /32 and break connected-route
        # delivery for same-subnet neighbours).
        lan = M.Interface.from_dict(iface_name, {"ip": f"{target_ip}/{cidr.prefixlen}", "network": cidr.with_prefixlen, "label": d.get("vendor", ""), "filters": ["router-lan-in"], "connected_to": "HOLD"})
        router.interfaces.append(lan)
        lan.connected_to = None  # fixed below after neighbor names resolve
        lan_ifaces.append((lan, ip, d))

    # -- uplink -----------------------------------------------------------------
    wan = M.Interface.from_dict("Wan", {"ip": UPLINK_IP, "network": "203.0.113.0/24", "label": "WAN (assumed)", "connected_to": "internet eth0"})
    router.interfaces.append(wan)
    cloud = M.Device(name="internet", dtype="cloud", x=CX + RX + 90, y=CY)
    cloud.interfaces.append(M.Interface.from_dict("eth0", {"ip": UPLINK_GW, "network": "203.0.113.0/24", "connected_to": f"{router.name} Wan"}))
    net.devices[cloud.name] = cloud

    # -- every other system -----------------------------------------------------
    others = [(lan, ip, d) for (lan, ip, d) in lan_ifaces if ip != target_ip]
    for idx, (lan, ip, d) in enumerate(others):
        base = d.get("hostname")
        dtype = d.get("type_guess")
        if dtype not in ("router", "switch", "host", "server", "printer"):
            dtype = "router" if d.get("is_target") else "host"
        if dtype == "router":
            dtype = "switch"
        angle = 2 * math.pi * idx / max(len(others), 1)
        dev = M.Device(name=_unique_name(base, used, ip), dtype=dtype,
                       x=CX + RX * math.cos(angle), y=CY + RY * math.sin(angle))
        iface = M.Interface.from_dict("Eth0", {"ip": ip, "network": f"{ip}/32", "label": d.get("vendor", "") or dtype})
        iface.connected_to = f"{router.name} {lan.name}"
        dev.interfaces.append(iface)
        dev.routes.append(M.Route.from_dict({"network": "0.0.0.0/0", "next_hop": target_ip}))
        net.devices[dev.name] = dev
        lan.connected_to = f"{dev.name} Eth0"

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
            base = (d.get("hostname") or str(ip)).split(".")[0].strip().lower()[:24]
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

    meta = {
        "subnet": cidr.with_prefixlen,
        "target": target_ip,
        "device_count": len(used),
    }
    return net, meta