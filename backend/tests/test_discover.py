"""P3: discover.py must work on Linux/macOS too. The OS-facing probing helpers
can't run here, but the pure functions get pinned so the platform branch in the
subprocess helpers can't silently break them."""
from engine.discover import mac_to_vendor, target_to_network, guess_type


def test_target_to_network_cidr():
    net, text = target_to_network("10.0.0.5/24")
    assert str(net) == "10.0.0.0/24"


def test_target_to_network_ip_becomes_24():
    net, text = target_to_network("192.168.7.200")
    assert net.prefixlen == 24
    assert net.network_address.exploded == "192.168.7.0"


def test_mac_to_vendor():
    assert mac_to_vendor("B8:27:EB:AA:BB:CC") == "Raspberry Pi"
    assert mac_to_vendor("00:00:00:00:00:00") == "Unknown"
    assert mac_to_vendor("") == "Unknown"


def test_guess_type_router_target():
    assert guess_type("192.168.1.1", "Cisco", [], "005056a1", {}, "192.168.1.1") == "router"


def test_guess_type_camera_by_rtsp():
    assert guess_type("192.168.1.9", "Unknown", [{"port": 554, "service": "rtsp"}], "", {}, "192.168.1.1") == "camera"


def test_guess_type_server_http():
    assert guess_type("192.168.1.20", "Dell", [{"port": 80, "service": "http"}], "", {}, "192.168.1.1") == "server"


def _scan(neighbors=None):
    devices = [
        {"ip": "192.168.1.1", "mac": "005056111111", "vendor": "Cisco", "hostname": "gw",
         "type_guess": "router", "is_target": True, "services": [],
         "snmp": {"sysName": "gw"}},
        {"ip": "192.168.1.10", "mac": "b827eb222222", "vendor": "Raspberry Pi", "hostname": "web",
         "type_guess": "server", "is_target": False, "services": [{"port": 80, "service": "http"}],
         "snmp": {"sysName": "web"}},
    ]
    scan = {"network": "192.168.1.0/24", "target": "192.168.1.1", "devices": devices}
    if neighbors:
        scan["neighbors"] = neighbors
    return scan


def test_build_net_star_fallback_without_neighbors():
    from engine.buildnet import build_net
    net, meta = build_net(_scan())
    assert meta["topology"] == "inferred-star"
    assert meta["links_discovered"] == 0
    router = net.devices["gw"]
    assert any(i.name.startswith("Eth") for i in router.interfaces)
    assert router.iface("Eth1").connected_to == "web Eth0"


def test_build_net_accepts_cidr_target():
    """A CIDR target (the UI accepts "IP or CIDR") must not crash the model
    build: discover.scan reports the raw target in scan["target"], and build_net
    used to append the prefix again ("a.b.c.d/24/24"), blowing up Prefix.parse."""
    from engine.buildnet import build_net
    scan = _scan()
    scan["target"] = "192.168.1.5/24"            # operator typed a CIDR
    scan["devices"][0]["ip"] = "192.168.1.0"     # scanner flags the network address as target
    net, meta = build_net(scan)
    assert "gw" in net.devices
    lan = net.devices["gw"].iface("Eth1")
    assert lan.prefix is not None and lan.prefix.plen == 24


def test_build_net_lldp_real_ports():
    from engine.buildnet import build_net
    net, meta = build_net(_scan(neighbors=[
        {"protocol": "lldp", "local_port": "Gi1/0/1", "remote_sysname": "web", "remote_port": "Eth0"},
    ]))
    assert meta["topology"] == "lldp-discovered"
    assert meta["links_discovered"] == 1
    router = net.devices["gw"]
    iface = router.iface("Gi1/0/1")
    assert iface is not None, [i.name for i in router.interfaces]
    web = net.devices["web"]
    assert web.iface("Eth0") is not None
    assert iface.connected_to == "web Eth0"
    assert web.iface("Eth0").connected_to == "gw Gi1/0/1"
    assert any(nbr[0] == "web" for nbr in net.adjacency.get("gw", []))


def test_build_net_cdp_topology_label():
    from engine.buildnet import build_net
    net, meta = build_net(_scan(neighbors=[
        {"protocol": "cdp", "local_port": "1", "remote_device_id": "web", "remote_port": "E0"},
    ]))
    assert meta["topology"] == "cdp-discovered"
    assert net.devices["gw"].iface("1").connected_to == "web E0"


def test_build_net_unmatched_neighbor_falls_back_to_star():
    from engine.buildnet import build_net
    # the neighbor's sysName is unknown to the scan inventory -> star remains
    net, meta = build_net(_scan(neighbors=[
        {"protocol": "lldp", "local_port": "Gi1/0/1", "remote_sysname": "unknown-switch", "remote_port": "Eth0"},
    ]))
    assert meta["topology"] == "inferred-star"
    assert meta["links_discovered"] == 0
    assert any(i.name.startswith("Eth") for i in net.devices["gw"].interfaces)


def test_lldp_neighbors_parses_walk(monkeypatch):
    from engine.discover import lldp_neighbors
    fake = {
        "1.0.8802.1.1.2.1.4.1.1.9.0.1.1": "switch-01",
        "1.0.8802.1.1.2.1.4.1.1.9.0.2.1": "printer",
        "1.0.8802.1.1.2.1.4.1.1.7.0.1.1": "Gi0/3",
    }
    monkeypatch.setattr(
        "engine.discover.snmp_walk",
        lambda host, community, root, timeout=1.4, max_entries=100: {o: v for o, v in fake.items() if o.startswith(root)},
    )
    nbrs = lldp_neighbors("10.0.0.1")
    assert len(nbrs) == 2
    one = next(n for n in nbrs if n["remote_sysname"] == "switch-01")
    assert one["local_port"] == "1"
    assert one["remote_port"] == "Gi0/3"
    assert {n["remote_sysname"] for n in nbrs} == {"switch-01", "printer"}


def test_cdp_neighbors_parses_walk(monkeypatch):
    from engine.discover import cdp_neighbors
    fake = {
        "1.3.6.1.4.1.9.9.23.1.2.1.1.6.1.1": "gw-switch",
        "1.3.6.1.4.1.9.9.23.1.2.1.1.7.1.1": "GigabitEthernet0/1",
        "1.3.6.1.4.1.9.9.23.1.2.1.1.6.2.1": "ap-01",
        "1.3.6.1.4.1.9.9.23.1.2.1.1.8.2.1": "cisco AIR-CAP3702",
    }
    monkeypatch.setattr(
        "engine.discover.snmp_walk",
        lambda host, community, root, timeout=1.4, max_entries=100: {o: v for o, v in fake.items() if o.startswith(root)},
    )
    nbrs = cdp_neighbors("10.0.0.1")
    assert len(nbrs) == 2
    one = next(n for n in nbrs if n["remote_device_id"] == "gw-switch")
    assert one["local_port"] == "1"
    assert one["remote_port"] == "GigabitEthernet0/1"
    ap = next(n for n in nbrs if n["remote_device_id"] == "ap-01")
    assert ap["remote_platform"] == "cisco AIR-CAP3702"


def test_snmp_walk_stops_outside_subtree(monkeypatch):
    from engine.discover import snmp_walk
    seq = iter(["1.3.6.1.4.1.9.9.23.1.2.1.1.6.1.1", "1.3.6.1.4.1.9.9.23.1.2.1.1.6.2.1", "1.3.6.1.4.1.99.9"])  # leaves subtree
    monkeypatch.setattr("engine.discover._snmp_getnext", lambda host, community, oid, timeout=1.4: {next(seq): "x"})
    got = snmp_walk("10.0.0.1", "public", "1.3.6.1.4.1.9.9.23.1.2.1.1.6")
    assert len(got) == 2