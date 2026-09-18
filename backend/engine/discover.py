"""Live network discovery for NetProof.

Given a target router/server IP (or CIDR), finds the systems reachable on the
same L2 segment and gathers real machine details:

  - ARP table (instant, authoritative for the local segment)
  - ICMP ping sweep (finds hosts that answer even if not in ARP yet)
  - TCP service probes (ssh, http, https, smb, rdp, printer ports, ...)
  - hostname: NetBIOS (nbtstat) + reverse DNS
  - hardware vendor from the MAC OUI
  - optional SNMPv2c sysDescr/sysName/sysObjectID (raw UDP, no external libs)

Everything is best-effort: failures are recorded per device, never fatal.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import struct
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

# --------------------------------------------------------------------------- #
# Targets / subnets                                                         #
# --------------------------------------------------------------------------- #

SERVICE_PORTS = [
    (22, "ssh"), (23, "telnet"), (21, "ftp"), (80, "http"), (443, "https"),
    (445, "smb"), (135, "rpc"), (139, "netbios"), (3389, "rdp"), (5900, "vnc"),
    (53, "dns"), (1433, "mssql"), (3306, "mysql"), (5432, "postgres"),
    (8080, "http-alt"), (8443, "https-alt"),
    (9100, "raw-printer"), (515, "lpd"), (631, "ipp"), (25, "smtp"),
    # cameras: RTSP streaming + the most common vendor SDK/ONVIF ports
    (554, "rtsp"), (8554, "rtsp-alt"), (8000, "hikvision-sdk"), (37777, "dahua-sdk"), (34567, "wisenet"),
]

# Small but useful MAC OUI -> vendor table. Prefixes are lowercase, colons removed.
OUI = {
    "005056": "VMware", "000c29": "VMware", "000569": "VMware",
    "3cd92b": "Cisco", "001c58": "Cisco", "0001c9": "Cisco", "00604d": "Cisco",
    "c87d50": "Cisco", "f0c74c": "Cisco", "8c64b8": "Cisco",
    "b827eb": "Raspberry Pi", "dca632": "Raspberry Pi", "e45f01": "Raspberry Pi",
    "3c22fb": "Apple", "acbc32": "Apple", "f01898": "Apple", "0017f2": "Apple",
    "006172": "Apple", "0003fa": "Intel", "001b21": "Intel", "3c970e": "Intel",
    "f875a4": "Intel", "705a0f": "Intel", "2866b9": "Intel",
    "b09134": "ASUS", "3c1e04": "Huawei", "f8c3c3": "Huawei", "00e0fc": "Huawei",
    "68b599": "HP", "3c5282": "HP", "001f29": "HP", "00b8a8": "HP", "b4b5af": "HP",
    "001422": "Dell", "1866da": "Dell", "248617": "Dell", "a4badb": "Dell",
    "001b42": "Brother", "100c6b": "Brother", "000749": "Brother",
    "000074": "Canon", "001e8f": "Canon", "00a0cc": "Canon",
    "0026ab": "Epson", "ac6f4f": "Epson", "00e029": "Epson",
    "0000b4": "Ricoh", "000097": "Xerox", "0090d0": "Lexmark",
    "58e876": "Samsung", "001fcc": "Samsung", "3c8bfe": "Lenovo", "fcaa14": "Lenovo",
    "14cc20": "TP-Link", "50fa84": "TP-Link", "5c2aef": "TP-Link", "a4c3f0": "TP-Link",
    "1c7ec5": "D-Link", "2001bf": "D-Link", "204e7f": "NETGEAR", "9c21b1": "NETGEAR",
    "98ded0": "Linksys", "00e0bd": "Linksys", "4074e0": "Hikvision", "9ce723": "Hikvision",
    "ecfaec": "MikroTik", "004b6b": "MikroTik", "8032e6": "MikroTik",
    # cameras (IP CCTV) — the big brands by MAC OUI
    "4419b6": "Hikvision", "ec2e4e": "Hikvision", "2857be": "Hikvision",
    "4c8eef": "Hikvision", "c872bc": "Hikvision", "dc6b73": "Hikvision",
    "3cef8c": "Dahua", "accc8e": "Dahua", "5c48ab": "Dahua", "9c1e95": "Dahua",
    "00408c": "Axis", "8c8caa": "Axis", "d4c9ef": "Reolink",
    "2c0100": "Amcrest", "685a5e": "Amcrest", "485d60": "Amcrest",
    "584466": "Uniview", "28f64d": "Uniview", "00d041": "Uniview",
    "000786": "Bosch", "001cb7": "Bosch", "0056cd": "Hanwha",
}


def target_to_network(target: str) -> (ipaddress.IPv4Network, str):
    """Interpret a target into a network to sweep. IP alone -> /24 or the
    local NIC netmask if the IP belongs to a local interface."""
    text = target.strip().strip('"')
    if "/" in text:
        net = ipaddress.ip_network(text, strict=False)
        return net, str(text)
    ip = ipaddress.ip_address(text)
    for net_ip, mask in local_interfaces():
        if ip in ipaddress.ip_network(f"{net_ip}/{mask}", strict=False):
            n = ipaddress.ip_network(f"{net_ip}/{mask}", strict=False)
            return n, str(n.with_prefixlen)
    net = ipaddress.ip_network(f"{ip}/{24}", strict=False)
    return net, str(net.with_prefixlen)


def local_interfaces() -> list[tuple[str, str]]:
    """List (ip, prefixlen) of this host's IPv4 interfaces. Cross-platform:
    Windows uses ipconfig, everything else uses `ip -4 addr` (fallback ifconfig)."""
    pairs: list[tuple[str, str]] = []
    if os.name == "nt":
        try:
            out = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            ).stdout
        except Exception:
            return pairs
        cur_ip = None
        for line in out.splitlines():
            m = re.search(r"IPv4 Address[^:]*:\s*([\d.]+)", line)
            if m:
                cur_ip = m.group(1)
            m = re.search(r"Subnet Mask[^:]*:\s*([\d.]+)", line)
            if m and cur_ip:
                mask = m.group(1)
                plen = 0
                for octet in mask.split("."):
                    plen += bin(int(octet)).count("1")
                pairs.append((cur_ip, plen))
                cur_ip = None
        return pairs

    # POSIX: `ip -4 addr show` (modern Linux / recent macOS replaced ifconfig)
    out = _run_hidden(["ip", "-4", "addr", "show"], timeout=5)
    if out:
        ip_now = None
        for line in out.splitlines():
            m = re.search(r"inet\s+([\d.]+)/(\d+)", line)
            if m:
                pairs.append((m.group(1), int(m.group(2))))
        if pairs:
            return pairs
    # last resort: ifconfig-style
    out = _run_hidden(["ifconfig", "-a"], timeout=5)
    for m in re.finditer(r"inet\s+(?:addr:)?([\d.]+).*?(?:netmask\s+(?:0x)?([\da-fA-F]+))?", out, re.DOTALL):
        raw = m.group(0)
        am = re.search(r"inet\s+(?:addr:)?([\d.]+)", raw)
        mm = re.search(r"netmask\s+(?:0x)?([\da-fA-F]+)", raw)
        if am:
            plen = 32 - bin(int(mm.group(1), 16)).count("1") if mm and mm.group(1).isdigit() and len(mm.group(1)) == 8 else 24
            pairs.append((am.group(1), plen))
    return pairs


def _fetch(cmd: list[str], timeout: float) -> str:
    try:
        res = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        return res.stdout or ""
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
# Basic probes                                                               #
# --------------------------------------------------------------------------- #

def mac_to_vendor(mac: str) -> str:
    if not mac:
        return "Unknown"
    key = mac.replace(":", "").replace("-", "").lower()[:6]
    return OUI.get(key, "Unknown")


def _run_hidden(cmd: list[str], timeout: float = 2.0) -> str:
    try:
        res = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return (res.stdout or "") + (res.stderr or "")
    except Exception:
        return ""


def arp_table() -> dict[str, str]:
    """ip -> mac from the OS ARP/neighbor cache. Cross-platform:
    Windows `arp -a`, Linux `ip neigh`, macOS/BSD `arp -an`."""
    if os.name == "nt":
        out = _run_hidden(["arp", "-a"], timeout=5)
        rows = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                try:
                    ip = str(ipaddress.ip_address(parts[0]))
                    mac = parts[1].replace("-", ":")
                except ValueError:
                    continue
                rows[ip] = mac
    else:
        rows = {}
        out = _run_hidden(["ip", "neigh"], timeout=5)
        if not out:
            out = _run_hidden(["arp", "-an"], timeout=5)
        for line in out.splitlines():
            # Linux: 192.168.1.5 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
            m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?lladdr\s+([0-9a-fA-F:]+)", line)
            # BSD/macOS: ? (192.168.1.5) at aa:bb:cc:dd:ee:ff on en0 [ethernet]
            if not m:
                m = re.search(r"\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)\s+at\s+([0-9a-fA-F:]+)", line)
            if not m:
                continue
            ip, mac = m.group(1), m.group(2)
            try:
                ip = str(ipaddress.ip_address(ip))
            except ValueError:
                continue
            rows[ip] = mac.replace("-", ":")
    return {
        ip: mac.replace("-", ":")
        for ip, mac in rows.items()
        if re.fullmatch(r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}", mac)
        and mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff")
    }


def ping_alive(ip: str) -> bool:
    if os.name == "nt":
        return _run_hidden(["ping", "-n", "1", "-w", "500", ip], timeout=3).find("TTL=") >= 0
    # POSIX: ping -c1 with a short deadline; success == host answered
    return _run_hidden(["ping", "-c", "1", "-W", "1", ip], timeout=3).find("1 packets received") >= 0 or _alive_by_returncode(ip)


def _alive_by_returncode(ip: str) -> bool:
    try:
        res = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return res.returncode == 0
    except Exception:
        return False


def ping_sweep(net: ipaddress.IPv4Network) -> set[str]:
    pill = [str(h) for h in net.hosts()]
    alive: set[str] = set()

    def _p(ip: str) -> None:
        if ping_alive(ip):
            alive.add(ip)

    with ThreadPoolExecutor(max_workers=64) as ex:
        list(ex.map(_p, pill))
    return alive


def probe_ports_many(items: list[tuple[str, tuple[int, str]]], max_open: int = 8) -> dict[str, list[dict]]:
    """Probe many (ip, port) pairs concurrently. Returns {ip: [open services]}."""
    open_map: dict[str, list[dict]] = {ip: [] for ip in {x[0] for x in items}}

    def _probe(pair):
        ip, (port, name) = pair
        if len(open_map[ip]) >= max_open:
            return
        try:
            with socket.create_connection((ip, port), timeout=0.35):
                open_map[ip].append({"port": port, "service": name})
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=96) as ex:
        list(ex.map(_probe, items))
    return open_map


def hostname_of(ip: str) -> str:
    nb = ""
    if os.name == "nt":
        nb = _run_hidden(["nbtstat", "-A", ip], timeout=1.5)
    else:
        nb = _run_hidden(["nmblookup", "-A", ip], timeout=1.5)
    m = re.search(r"<00>\s+UNIQUE\s+(\S+)", nb)
    if m:
        return m.group(1)
    return _rdns(ip)


def _rdns(ip: str) -> str:
    """Bounded reverse DNS. `socket.gethostbyaddr` has no deadline on Windows
    and can block for many seconds per IP, which alone blew the scan timeout on
    segments without a working PTR service - so always run it inside a worker
    thread and refuse to wait longer than _RDNS_TIMEOUT_S below."""
    deadline_s = getattr(_rdns, "_deadline", 1.2)
    box: dict = {}

    def _lookup():
        try:
            box["name"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            box["name"] = ""

    t = threading.Thread(target=_lookup, daemon=True)
    t.start()
    t.join(deadline_s)
    return box.get("name") or ""


# --------------------------------------------------------------------------- #
# Minimal SNMPv2c GET + WALK (raw UDP)                                       #
# --------------------------------------------------------------------------- #

def _snmp_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    buf = bytearray()
    while n:
        buf.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(buf)]) + bytes(buf)


def _snmp_tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _snmp_len(len(payload)) + payload


def _snmp_oid_bytes(oid: str) -> bytes:
    nums = [int(x) for x in oid.strip(".").split(".")]
    if len(nums) < 2:
        raise ValueError("bad oid")
    out = bytearray([40 * nums[0] + nums[1]])
    for n in nums[2:]:
        buf = bytearray([n & 0x7F])
        n >>= 7
        while n:
            buf.insert(0, 0x80 | (n & 0x7F))
            n >>= 7
        out += buf
    return bytes(out)


def _snmp_parse_int(data: bytes, off: int) -> tuple[int, int]:
    assert data[off] == 0x02
    ln = data[off + 1]
    off += 2
    val = int.from_bytes(data[off:off + ln], "big", signed=True)
    return val, off + ln


def _snmp_parse_oid(data: bytes, off: int) -> tuple[str, int]:
    assert data[off] == 0x06
    ln = data[off + 1]
    off += 2
    nums = [0]
    for byte in data[off:off + ln]:
        if byte & 0x80:
            nums[-1] = (nums[-1] << 7) | (byte & 0x7F)
        else:
            nums[-1] = (nums[-1] << 7) | byte
            nums.append(0)
    nums = nums[:-1]
    first = nums[0]
    oid = str(first // 40) + "." + str(first % 40)
    oid += "." + ".".join(str(x) for x in nums[1:])
    return oid, off + ln


def _snmp_decode_value(tag: int, data: bytes, off: int, base_off: int):
    ln = data[off]
    is_long = bool(ln & 0x80)
    if is_long:
        n = ln & 0x7F
        ln = int.from_bytes(data[off + 1:off + 1 + n], "big")
        off = off + 1 + n
    else:
        off += 1
    raw = data[off:off + ln]
    new_off = off + ln
    if tag in (0x02, 0x43):
        return int.from_bytes(raw, "big", signed=True), new_off
    if tag == 0x04:
        return raw.decode("utf-8", "replace"), new_off
    if tag == 0x06:
        return _snmp_parse_oid(data, base_off + 0)[0], new_off
    if tag == 0x05:
        return None, new_off
    return raw.hex(), new_off


def snmp_get(host: str, community: str, oids: list[str], timeout: float = 1.4) -> dict[str, str]:
    """Perform an SNMPv2c GET for each OID. Returns {oid: value}. No response
    (blocked / not running / wrong community) is reported as {}."""
    try:
        req_id = os.getpid() & 0xFFFF
        varbinds = b""
        for oid in oids:
            vb = _snmp_tlv(0x30, _snmp_tlv(0x06, _snmp_oid_bytes(oid)) + _snmp_tlv(0x05, b""))
            varbinds += vb
        pdu = _snmp_tlv(0x30, b"")  # placeholder, real body below
        body = (
            _snmp_tlv(0x02, b"\x01")                    # request-id
            + _snmp_tlv(0x02, b"\x00")                  # error-status
            + _snmp_tlv(0x02, b"\x00")                  # error-index
            + varbinds
        )
        pdu = _snmp_tlv(0xA0, body)
        msg = (
            _snmp_tlv(0x02, b"\x01")                    # version 2c
            + _snmp_tlv(0x04, community.encode("ascii", "replace"))
            + pdu
        )
        packet = _snmp_tlv(0x30, msg)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (host, 161))
        data, _ = sock.recvfrom(65535)
        sock.close()
    except Exception:
        return {}

    # walk outer sequence, find the inner 0x30 (scope/PDU) that has varbinds
    _, off = _snmp_parse_oid, 0
    return _snmp_walk_varbinds(data, oids)


def _snmp_walk_varbinds(data: bytes, want: list[str]) -> dict[str, str]:
    def seq_start(buf, off):
        if buf[off + 1] & 0x80:
            n = buf[off + 1] & 0x7F
            off += 1 + n
        else:
            off += 2
        return off

    results: dict[str, str] = {}
    try:
        if data[0] != 0x30:
            return {}
        off = seq_start(data, 0)          # version
        if data[off] != 0x02:
            return {}
        off = seq_start(data, off)        # community
        if data[off] != 0x04:
            return {}
        off = seq_start(data, off)        # pdu
        if data[off] not in (0xA0, 0xA2):
            return {}
        off = seq_start(data, off)        # request-id
        off = seq_start(data, off)        # error-status
        off = seq_start(data, off)        # error-index
        # varbind list
        if data[off] != 0x30:
            return {}
        off = seq_start(data, off)
        while off < len(data):
            if data[off] != 0x30:
                break
            off = seq_start(data, off)
            if data[off] != 0x06:
                break
            oid, off = _snmp_parse_oid(data, off)
            tag = data[off]
            val, off = _snmp_decode_value(tag, data, off + 1, off)
            results[oid] = val if val is not None else ""
    except Exception:
        return {}
    return results


def _snmp_getnext(host: str, community: str, oid: str, timeout: float = 1.4) -> dict[str, str]:
    """SNMPv2c GETNEXT for a single OID. Returns {returned_oid: value} or {}."""
    try:
        body = (
            _snmp_tlv(0x02, b"\x01")
            + _snmp_tlv(0x02, b"\x00")
            + _snmp_tlv(0x02, b"\x00")
            + _snmp_tlv(0x30, _snmp_tlv(0x06, _snmp_oid_bytes(oid)) + _snmp_tlv(0x05, b""))
        )
        pdu = _snmp_tlv(0xA1, body)
        msg = (
            _snmp_tlv(0x02, b"\x01")
            + _snmp_tlv(0x04, community.encode("ascii", "replace"))
            + pdu
        )
        packet = _snmp_tlv(0x30, msg)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (host, 161))
        data, _ = sock.recvfrom(65535)
        sock.close()
    except Exception:
        return {}
    return _snmp_walk_varbinds(data, [oid])


def snmp_walk(host: str, community: str, root_oid: str, timeout: float = 1.4, max_entries: int = 200) -> dict[str, str]:
    """SNMPv2c GETNEXT walk of a subtree. Returns {full_oid: value} for every
    entry under ``root_oid``. Stops when the response OID leaves the subtree
    or ``max_entries`` is reached."""
    results: dict[str, str] = {}
    current = root_oid
    for _ in range(max_entries):
        resp = _snmp_getnext(host, community, current, timeout)
        if not resp:
            break
        next_oid, value = next(iter(resp.items()))
        if not next_oid.startswith(root_oid):
            break
        results[next_oid] = value
        current = next_oid
    return results


# --------------------------------------------------------------------------- #
# LLDP / CDP neighbor discovery                                              #
# --------------------------------------------------------------------------- #

def lldp_neighbors(host: str, community: str = "public", timeout: float = 1.4) -> list[dict]:
    """Walk the LLDP-MIB lldpRemTable and return discovered neighbors.

    Each entry: {local_port, remote_sysname, remote_port}.
    Walks lldpRemSysName (column 9) and lldpRemPortId (column 7) and merges
    by the shared index (time_mark.local_port.index).
    """
    base = "1.0.8802.1.1.2.1.4.1.1"
    sysname = snmp_walk(host, community, f"{base}.9", timeout=timeout, max_entries=100)
    portid = snmp_walk(host, community, f"{base}.7", timeout=timeout, max_entries=100)

    # Parse the index suffix: <time_mark>.<local_port>.<index>
    entries: dict[str, dict] = {}
    for oid, val in sysname.items():
        suffix = oid[len(f"{base}.9."):]
        parts = suffix.split(".")
        if len(parts) >= 3:
            key = parts[1]  # local port number
            entries.setdefault(key, {"local_port": parts[1], "remote_sysname": val, "remote_port": ""})
    for oid, val in portid.items():
        suffix = oid[len(f"{base}.7."):]
        parts = suffix.split(".")
        if len(parts) >= 3:
            key = parts[1]
            if key in entries:
                entries[key]["remote_port"] = val
    return list(entries.values())


def cdp_neighbors(host: str, community: str = "public", timeout: float = 1.4) -> list[dict]:
    """Walk the Cisco CDP cache table and return discovered neighbors.

    Each entry: {local_port, remote_device_id, remote_port, remote_platform}.
    Index: <ifIndex>.<device_index>. Column OIDs relative to
    1.3.6.1.4.1.9.9.23.1.2.1.1:  6=deviceId, 7=devicePort, 8=platform.
    """
    base = "1.3.6.1.4.1.9.9.23.1.2.1.1"
    device_id = snmp_walk(host, community, f"{base}.6", timeout=timeout, max_entries=100)
    dev_port = snmp_walk(host, community, f"{base}.7", timeout=timeout, max_entries=100)
    platform = snmp_walk(host, community, f"{base}.8", timeout=timeout, max_entries=100)

    entries: dict[str, dict] = {}
    for oid, val in device_id.items():
        suffix = oid[len(f"{base}.6."):]
        parts = suffix.split(".")
        if len(parts) >= 2:
            key = ".".join(parts[:2])
            entries.setdefault(key, {"local_port": parts[0], "remote_device_id": val, "remote_port": "", "remote_platform": ""})
    for oid, val in dev_port.items():
        suffix = oid[len(f"{base}.7."):]
        parts = suffix.split(".")
        if len(parts) >= 2:
            key = ".".join(parts[:2])
            if key in entries:
                entries[key]["remote_port"] = val
    for oid, val in platform.items():
        suffix = oid[len(f"{base}.8."):]
        parts = suffix.split(".")
        if len(parts) >= 2:
            key = ".".join(parts[:2])
            if key in entries:
                entries[key]["remote_platform"] = val
    return list(entries.values())


def _snmp_probe(sysdescr: str) -> dict:
    """Extract useful facts from an SNMP sysDescr string."""
    d = sysdescr.lower()
    gear = {}
    for kw in ("cisco", "juniper", "huawei", "arista", "mikrotik", "fortinet",
               "palo alto", "zyxel", "d-link", "hp ", "hewlett", "brother",
               "canon", "epson", "ricoh", "xerox", "lexmark", "dell", "netgear",
               "hikvision", "dahua", "reolink", "axis", "uniview", "amcrest",
               "foscam", "wisenet", "hanwha", "vstarcam", "zkteco", "lorex"):
        if kw in d:
            gear["vendor"] = kw.strip().title()
            break
    if "hardware type" in d or "ios" in d or "vios" in d or "router" in d:
        gear["kind"] = "router/switch/os"
    elif "printer" in d or "laserjet" in d or "jetdirect" in d:
        gear["kind"] = "printer"
    elif "switch" in d:
        gear["kind"] = "switch"
    return gear


# --------------------------------------------------------------------------- #
# Type inference                                                            #
# --------------------------------------------------------------------------- #

def guess_type(ip: str, vendor: str, services: list[dict], mac: str, snmp: dict, target_ip: str, hostname: str = "") -> str:
    ports = {s["port"] for s in services}
    dv = vendor.lower()
    hn = (hostname or "").lower()
    if ip == target_ip:
        return "router"

    # ---- camera signatures (checked first so they beat the generic fallbacks) ----
    # RTSP streaming ports are the definitive camera fingerprint.
    if 554 in ports or 8554 in ports:
        return "camera"
    # Vendor SDK / ONVIF discovery ports are strong camera-only signals.
    if 8000 in ports or 37777 in ports or 34567 in ports:
        if not ({135, 139, 445, 3389} & ports):
            return "camera"
    cam_vendors = ("hikvision", "dahua", "axis", "reolink", "amcrest", "foscam",
                   "wyze", "arlo", "hanwha", "wisenet", "bosch", "uniview",
                   "zkteco", "annke", "lorex", "swann", "eufy", "vstarcam",
                   "tessafe", "cleverloop", "empiretec", "safire", "vipcam",
                   "dvrtime", "ipcamera", "znj")
    if any(k in dv or k in hn for k in cam_vendors):
        return "camera"
    # Typical camera hostnames: IPC-xxx, CAM-01, DVR/nvr, CCTV webcam
    if re.search(r"(^|[^a-z0-9_-])(ipc[-_ ]?[0-9a-z]*|cam[-_ ]?[0-9]*|dvr|cctv|webcam)([^a-z0-9_-]|$)", hn):
        return "camera"

    if not services and not snmp:
        return "host"
    if 9100 in ports or 515 in ports or 631 in ports:
        return "printer"
    if snmp.get("kind"):
        return {"printer": "printer", "switch": "switch"}.get(snmp["kind"], "router")
    if any(k in dv for k in ("brother", "canon", "epson", "ricoh", "xerox", "lexmark", "hp")):
        return "printer"
    # mobile/phone: Apple (iPhone/iPad), Samsung, OnePlus, Xiaomi, Oppo, Vivo, Realme
    if any(k in dv for k in ("apple", "samsung", "oneplus", "xiaomi", "oppo", "vivo", "realme", "motorola", "nokia")):
        # Apple MACs with no server ports are phones/tablets
        if not ({22, 80, 443, 445, 3389} & ports):
            return "mobile"
    if any(k in dv for k in ("cisco", "juniper", "huawei", "arista", "mikrotik",
                             "fortinet", "tp-link", "d-link", "netgear", "linksys")):
        return "switch" if ports <= {80, 443, 8080} else "router"
    if 135 in ports and 139 in ports and 445 in ports:
        return "server" if {80, 443} & ports else "host"
    if 3389 in ports or 5900 in ports:
        return "laptop"
    if 80 in ports or 443 in ports or 8080 in ports:
        return "server"
    return "host"


# --------------------------------------------------------------------------- #
# Main scan                                                                 #
# --------------------------------------------------------------------------- #

def scan(target: str, community: str = "public", do_ping: bool = True, max_devices: int = 120) -> dict:
    """Discover systems connected to the segment of `target`.

    Returns a JSON-able dict:
        {network, mask, target, devices: [...], notes: [...]}
    """
    start = threading.Event()
    result = {"network": None, "mask": None, "target": target.strip(), "devices": [], "notes": []}

    try:
        net, net_str = target_to_network(target)
    except ValueError as exc:
        result["notes"].append(f"bad target '{target}': {exc}")
        return result
    result["network"] = str(net)
    result["mask"] = str(net.netmask)
    target_ip = str(net.network_address) if "/" in target.strip() else target.strip()

    arp = arp_table()
    alive = set(arp.keys())

    if do_ping:
        swept = ping_sweep(net)
        alive |= swept
        if not swept:
            result["notes"].append("ping sweep returned nothing (ICMP may be blocked by the local firewall)")

    try:
        if ipaddress.ip_address(target_ip) not in net:
            result["notes"].append(f"{target_ip} is not inside {net}; scanning anyway as requested")
    except Exception:
        pass
    alive.add(target_ip)

    cands = [ip for ip in alive if not ipaddress.ip_address(ip).is_multicast]
    skipped_multicast = len(alive) - len(cands)
    if skipped_multicast:
        result["notes"].append(f"ignored {skipped_multicast} multicast address(es)")
    result["notes"].append(f"found {len(cands)} live address(es) (of {len(list(net.hosts()))} possible)")

    work = cands[:max_devices]
    snmp_candidates = mac_to_vendor(arp.get(target_ip, "")).lower() or "target"
    all_pairs = [(ip, pr) for ip in work for pr in SERVICE_PORTS]
    probes = probe_ports_many(all_pairs)

    rdns: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=40) as ex:
        futs = {ip: ex.submit(_rdns, ip) for ip in work}
        for ip, f in futs.items():
            try:
                rdns[ip] = f.result() or ""
            except Exception:
                rdns[ip] = ""

    names: dict[str, str] = {}

    def _name(ip: str) -> str:
        pai = {s["port"] for s in probes.get(ip, [])}
        if ip == target_ip or ({135, 139, 445, 3389, 5900} & pai) or not pai:
            # The target router and anything with a shell/PC-style port get the
            # full NetBIOS try; everything else (printers, cameras, IoT) only
            # reads the already-bounded reverse-DNS cache - a NetBIOS block per
            # host is exactly what used to blow the scan timeout.
            if ip == target_ip or ({135, 139, 445, 3389, 5900} & pai):
                return hostname_of(ip) or rdns.get(ip, "")
            return rdns.get(ip, "")
        return rdns.get(ip, "")

    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = {ip: ex.submit(_name, ip) for ip in work}
        for ip, f in futs.items():
            try:
                names[ip] = f.result() or ""
            except Exception:
                names[ip] = ""

    snmp_idx = [target_ip] + [ip for ip in work if mac_to_vendor(arp.get(ip, "")).lower() in
                              ("cisco", "d-link", "netgear", "linksys", "mikrotik", "huawei", "tplink", "tp-link")]
    snmp: dict[str, dict] = {}
    if community:
        which = [ip for ip in snmp_idx if ip in work or ip == target_ip]
        with ThreadPoolExecutor(max_workers=4) as ex:
            futs = {ip: ex.submit(snmp_get, ip, community, [".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.5.0", ".1.3.6.1.2.1.1.2.0", ".1.3.6.1.2.1.1.6.0"]) for ip in which}
            for ip, f in futs.items():
                try:
                    vals = f.result()
                except Exception:
                    vals = {}
                if vals.get(".1.3.6.1.2.1.1.1.0"):
                    snmp[ip] = vals
    if snmp and not community.strip():
        result["notes"].append("SNMP probe skipped (no community given)")

    # -- LLDP / CDP neighbor discovery on the target ---------------------------
    neighbors: list[dict] = []
    if community and snmp:
        target_snmp = snmp.get(target_ip, {})
        lldp = lldp_neighbors(target_ip, community)
        if lldp:
            neighbors.extend({"protocol": "lldp", **n} for n in lldp)
            result["notes"].append(f"LLDP: discovered {len(lldp)} neighbor(s) on {target_ip}")
        cdp = cdp_neighbors(target_ip, community)
        if cdp:
            neighbors.extend({"protocol": "cdp", **n} for n in cdp)
            result["notes"].append(f"CDP: discovered {len(cdp)} neighbor(s) on {target_ip}")

    for ip in sorted(work, key=lambda x: ipaddress.ip_address(x)):
        mac = arp.get(ip, "")
        services = probes.get(ip, [])
        vendor = mac_to_vendor(mac)
        snmp_basic = snmp.get(ip, {})
        if snmp_basic:
            gear = _snmp_probe(snmp_basic.get(".1.3.6.1.2.1.1.1.0", ""))
            if gear.get("vendor"):
                vendor = gear["vendor"]
            if not mac:
                mac = f"snmp:{ip}"
        dtype = guess_type(ip, vendor, services, mac, _snmp_probe(snmp_basic.get(".1.3.6.1.2.1.1.1.0", "")), target_ip, names.get(ip, ""))
        result["devices"].append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "hostname": names.get(ip, ""),
            "type_guess": dtype,
            "services": services,
            "is_target": ip == target_ip,
            "snmp": {
                "sysName": snmp_basic.get(".1.3.6.1.2.1.1.5.0", ""),
                "sysDescr": snmp_basic.get(".1.3.6.1.2.1.1.1.0", ""),
                "sysObjectID": snmp_basic.get(".1.3.6.1.2.1.1.2.0", ""),
                "sysLocation": snmp_basic.get(".1.3.6.1.2.1.1.6.0", ""),
            },
        })
    if neighbors:
        result["neighbors"] = neighbors
    return result