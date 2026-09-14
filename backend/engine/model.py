"""NetProof engine - network model built from a declarative YAML definition.

The input format mirrors what real-world source-of-truth systems (NetBox /
Nautobot) + config repos provide: devices, interfaces, links, routes,
filters (ACLs), NAT and policy requirements. This is the vendor-neutral
"control plane" model that the verification engine reasons over.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import yaml

MAX_IP = 0xFFFFFFFF
ANY = "any"


def ip_int(s: str) -> int:
    parts = s.strip().split(".")
    if len(parts) != 4:
        raise ValueError(f"invalid IPv4 address: {s}")
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])


def ip_str(n: int) -> str:
    return f"{n >> 24 & 255}.{n >> 16 & 255}.{n >> 8 & 255}.{n & 255}"


@dataclass
class Prefix:
    text: str
    lo: int
    hi: int
    plen: int

    @staticmethod
    def parse(text: str) -> "Prefix":
        text = (text or ANY).strip()
        if text == ANY:
            return Prefix(ANY, 0, MAX_IP, 0)
        if "/" in text:
            network, plc = text.split("/")
            plen = int(plc)
        else:
            network, plen = text, 32
        base = ip_int(network)
        mask = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF if plen > 0 else 0
        lo = base & mask
        hi = lo | (MAX_IP ^ mask)
        return Prefix(text, lo, hi, plen)

    def contains(self, ip: int) -> bool:
        return self.lo <= ip <= self.hi

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"Prefix({self.text})"


@dataclass
class Rule:
    action: str
    src: str = ANY
    dst: str = ANY
    proto: str = ANY
    dport: Optional[int] = None
    source: str = "inferred"  # "confirmed" = read from device config, "inferred" = scanner guess

    @staticmethod
    def from_dict(d: dict) -> "Rule":
        proto = (d.get("proto") or ANY).lower()
        dport = d.get("dport")
        if dport in (None, "", ANY, "any"):
            dport = None
        else:
            dport = int(dport)
        return Rule(
            action=str(d.get("action", "permit")).lower(),
            src=str(d.get("src") or ANY),
            dst=str(d.get("dst") or ANY),
            proto=proto,
            dport=dport,
            source=str(d.get("source") or "inferred"),
        )

    def describe(self) -> str:
        return (
            f"{self.action} {self.src} -> {self.dst}"
            + (f" {self.proto}" if self.proto != ANY else "")
            + (f"/{self.dport}" if self.dport else "")
        )


@dataclass
class Filter:
    name: str
    default: str
    rules: list[Rule] = field(default_factory=list)


@dataclass
class Interface:
    name: str
    ip: Optional[str] = None
    prefix: Optional[Prefix] = None
    network: Optional[str] = None
    filters: list[str] = field(default_factory=list)
    connected_to: Optional[str] = None
    label: Optional[str] = None
    x: Optional[float] = None
    y: Optional[float] = None

    @staticmethod
    def from_dict(name: str, d: dict) -> "Interface":
        ip = d.get("ip")
        return Interface(
            name=name,
            ip=ip,
            prefix=Prefix.parse(ip) if ip else None,
            network=d.get("network"),
            filters=list(d.get("filters") or []),
            connected_to=d.get("connected_to"),
            label=d.get("label"),
            x=d.get("x"),
            y=d.get("y"),
        )


@dataclass
class Route:
    network: str
    prefix: Prefix
    next_hop: str
    source: str = "inferred"  # "confirmed" = read from device config, "inferred" = scanner guess

    @staticmethod
    def from_dict(d: dict) -> "Route":
        net = str(d["network"])
        return Route(net, Prefix.parse(net), str(d["next_hop"]), str(d.get("source") or "inferred"))


@dataclass
class Nat:
    outside_interface: str
    inside_prefixes: list[Prefix]

    @staticmethod
    def from_dict(d: dict) -> "Nat":
        return Nat(
            outside_interface=str(d["outside_interface"]),
            inside_prefixes=[Prefix.parse(p) for p in (d.get("inside_networks") or [])],
        )


@dataclass
class DstNatRule:
    """A destination-NAT / port-forward rule.

    public_ip may be empty -> the device's WAN (outside) address is used.
    """
    public_ip: str
    public_port: int
    private_ip: str
    private_port: int
    proto: str = "tcp"

    @staticmethod
    def from_dict(d: dict) -> "DstNatRule":
        proto = (d.get("proto") or "tcp").lower()
        return DstNatRule(
            public_ip=str(d.get("public_ip") or ""),
            public_port=int(d.get("public_port") or d.get("port") or 0),
            private_ip=str(d.get("private_ip") or d.get("dst") or ""),
            private_port=int(d.get("private_port") or d.get("dport") or 0),
            proto=proto,
        )

    def describe(self) -> str:
        return (
            f"{self.public_ip or 'wan'}:{self.public_port} -> "
            f"{self.private_ip}:{self.private_port} {self.proto}"
        )


@dataclass
class BgpPeer:
    """A BGP peering relationship on a device.

    `export_prefixes` are the networks this speaker advertises to the peer
    (empty = none). `active` marks whether the peering is configured.
    """
    neighbor: str
    local_as: int
    remote_as: int
    export_prefixes: list[str] = field(default_factory=list)
    active: bool = True

    @staticmethod
    def from_dict(d: dict) -> "BgpPeer":
        return BgpPeer(
            neighbor=str(d["neighbor"]),
            local_as=int(d.get("local_as", 0)),
            remote_as=int(d.get("remote_as", 0)),
            export_prefixes=[str(p) for p in (d.get("export_prefixes") or [])],
            active=bool(d.get("active", True)),
        )

    def describe(self) -> str:
        return (
            f"BGP peer {self.neighbor} (as {self.local_as} -> as {self.remote_as})"
            + (f" exporting {', '.join(self.export_prefixes)}" if self.export_prefixes else "")
        )


@dataclass
class OspfArea:
    """An OSPF area on a device: area id + the directly-attached networks
    participating in it (one per interface subnet)."""
    area_id: int
    networks: list[str] = field(default_factory=list)
    auth_type: str = "none"

    @staticmethod
    def from_dict(d: dict) -> "OspfArea":
        return OspfArea(
            area_id=int(d.get("area_id", d.get("area", 0))),
            networks=[str(n) for n in (d.get("networks") or [])],
            auth_type=str(d.get("auth_type", "none")).lower(),
        )


@dataclass
class DnsRecord:
    """A DNS resource record a DNS server is authoritative for."""
    zone: str
    fqdn: str
    rtype: str
    value: str
    ttl: int = 300

    @staticmethod
    def from_dict(d: dict) -> "DnsRecord":
        return DnsRecord(
            zone=str(d.get("zone") or ""),
            fqdn=str(d.get("fqdn") or d.get("name") or "").rstrip("."),
            rtype=str(d.get("type", d.get("rtype", "A"))).upper(),
            value=str(d.get("value") or d.get("target") or ""),
            ttl=int(d.get("ttl") or 300),
        )

    def describe(self) -> str:
        return f"{self.fqdn}. {self.rtype} {self.value} (ttl {self.ttl})"


@dataclass
class VlanAssignment:
    """L2 segment assignment for a switchport."""
    iface: str
    vlan_id: int
    name: str = ""
    tagged: bool = False

    @staticmethod
    def from_dict(d: dict) -> "VlanAssignment":
        return VlanAssignment(
            iface=str(d.get("iface") or d.get("interface") or ""),
            vlan_id=int(d.get("vlan_id", d.get("vlan", 0))),
            name=str(d.get("name") or ""),
            tagged=bool(d.get("tagged", False)),
        )

    def describe(self) -> str:
        kind = "trunk" if self.tagged else "access"
        return f"{self.iface} → vlan {self.vlan_id} ({kind}{': ' + self.name if self.name else ''})"


@dataclass
class Device:
    name: str
    dtype: str
    interfaces: list[Interface] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    nat: Optional[Nat] = None
    dst_nat: list[DstNatRule] = field(default_factory=list)
    bgp: list[BgpPeer] = field(default_factory=list)
    ospf: list[OspfArea] = field(default_factory=list)
    dns: list[DnsRecord] = field(default_factory=list)
    vlans: list[VlanAssignment] = field(default_factory=list)
    x: Optional[float] = None
    y: Optional[float] = None

    def has_ip(self) -> bool:
        return any(i.ip for i in self.interfaces)

    def own_ips(self) -> set[int]:
        return {ip_int(i.ip.rsplit("/", 1)[0]) for i in self.interfaces if i.ip}

    def iface(self, name: str) -> Optional["Interface"]:
        for i in self.interfaces:
            if i.name == name:
                return i
        return None


@dataclass
class Zone:
    name: str
    prefix: Optional[Prefix]
    gateway: str
    is_source: bool
    is_dest: bool
    sample_dst: Optional[int] = None


@dataclass
class Requirement:
    name: str
    src: str
    dst: str
    proto: str
    dport: Optional[int] = None
    expect: str = "reachable"

    @staticmethod
    def from_dict(d: dict) -> "Requirement":
        proto = (d.get("proto") or ANY).lower()
        dport = d.get("dport")
        if dport in (None, "", ANY, "any"):
            dport = None
        else:
            dport = int(dport)
        return Requirement(
            name=str(d.get("name")),
            src=str(d.get("src") or ANY),
            dst=str(d.get("dst") or ANY),
            proto=proto,
            dport=dport,
            expect=str(d.get("expect", "reachable")).lower(),
        )


@dataclass
class Link:
    dev_a: str
    iface_a: str
    dev_b: str
    iface_b: str


@dataclass
class Net:
    name: str
    description: str = ""
    devices: dict[str, Device] = field(default_factory=dict)
    filters: dict[str, Filter] = field(default_factory=dict)
    requirements: list[Requirement] = field(default_factory=list)
    zones: dict[str, Zone] = field(default_factory=dict)
    links: list[Link] = field(default_factory=list)
    adjacency: dict[str, list[tuple[str, str, str]]] = field(default_factory=dict)

    def build_adjacency(self) -> None:
        adj: dict[str, list[tuple[str, str, str]]] = {}
        seen: set[tuple] = set()
        for dev in self.devices.values():
            adj.setdefault(dev.name, [])
        for dev in self.devices.values():
            for iface in dev.interfaces:
                if not iface.connected_to:
                    continue
                target_dev, _, target_iface = iface.connected_to.partition(" ")
                tdev = self.devices.get(target_dev)
                if tdev is None:
                    continue
                if not any(i.name == target_iface for i in tdev.interfaces):
                    continue
                key = frozenset(((dev.name, iface.name), (target_dev, target_iface)))
                if key in seen:
                    continue
                seen.add(key)
                self.links.append(Link(dev.name, iface.name, target_dev, target_iface))
                adj.setdefault(dev.name, []).append((target_dev, iface.name, target_iface))
                adj.setdefault(target_dev, []).append((dev.name, target_iface, iface.name))
        self.adjacency = adj

    def gateway_for(self, ip: int) -> Optional[str]:
        """Find the non-host device whose interface subnet most specifically
        contains ip (used as the origin for subnet-level flows)."""
        candidates: list[tuple[int, str]] = []
        for dev in self.devices.values():
            if dev.dtype == "host":
                continue
            for iface in dev.interfaces:
                if iface.prefix and iface.prefix.plen > 0 and iface.prefix.contains(ip):
                    candidates.append((iface.prefix.plen, dev.name))
        if not candidates:
            return None
        candidates.sort(key=lambda c: c[0], reverse=True)
        return candidates[0][1]


def parse_host_or_prefix(net: Net, addr: str) -> tuple[str, int, Prefix]:
    """Resolve an address (host IP or prefix) to (origin device, representative IP, prefix)."""
    if addr in (ANY, "internet"):
        raise ValueError("internet is only valid as a destination")
    if "/" in addr:
        pref = Prefix.parse(addr)
        rep = pref.lo
        gw = net.gateway_for(rep)
        origin = gw or net.gateway_for(pref.hi)
        return origin or "", rep, pref
    ip = ip_int(addr)
    rep = ip
    for dev in net.devices.values():
        for i in dev.interfaces:
            if i.ip and ip_int(i.ip.rsplit("/", 1)[0]) == ip:
                return dev.name, rep, Prefix(f"{addr}/32", ip, ip, 32)
    gw = net.gateway_for(ip)
    return gw or "", rep, Prefix(f"{addr}/32", ip, ip, 32)


def load_net(path: str) -> Net:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    net = Net(name=data.get("name", "Network"), description=data.get("description", ""))

    for d in data.get("filters") or []:
        filt = Filter(name=str(d["name"]), default=str(d.get("default", "deny")).lower())
        filt.rules = [Rule.from_dict(r) for r in (d.get("rules") or [])]
        net.filters[filt.name] = filt

    for d in data.get("devices") or []:
        dev = Device(name=str(d["name"]), dtype=str(d.get("type", "router")), x=d.get("x"), y=d.get("y"))
        for iname, idict in (d.get("interfaces") or {}).items():
            iface = Interface.from_dict(iname, idict)
            if iface.x is None and dev.x is not None:
                pass
            dev.interfaces.append(iface)
        dev.routes = [Route.from_dict(r) for r in (d.get("routes") or [])]
        if d.get("nat"):
            dev.nat = Nat.from_dict(d["nat"])
        dev.dst_nat = [DstNatRule.from_dict(r) for r in (d.get("dst_nat") or [])]
        dev.bgp = [BgpPeer.from_dict(p) for p in (d.get("bgp") or [])]
        dev.ospf = [OspfArea.from_dict(a) for a in (d.get("ospf") or [])]
        dev.dns = [DnsRecord.from_dict(r) for r in (d.get("dns") or [])]
        dev.vlans = [VlanAssignment.from_dict(v) for v in (d.get("vlans") or [])]
        net.devices[dev.name] = dev

    net.build_adjacency()

    zones = data.get("zones") or {}
    for zname, zd in zones.items():
        sample = zd.get("sample_dst")
        net.zones[zname] = Zone(
            name=zname,
            prefix=Prefix.parse(zd["prefix"]) if zd.get("prefix") else None,
            gateway=zd.get("gateway", ""),
            is_source=bool(zd.get("source", False)),
            is_dest=bool(zd.get("dest", False)),
            sample_dst=ip_int(sample) if sample else None,
        )

    net.requirements = [Requirement.from_dict(r) for r in (data.get("requirements") or [])]
    return net