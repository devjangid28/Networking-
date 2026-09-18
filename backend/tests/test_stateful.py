"""Stateful firewall return-traffic tests.

A stateless engine answers "is the server's reply to a permitted client
connection allowed?" with a flat no (default-deny firewall, no matching rule) —
a false warning for any real stateful firewall. These tests prove the engine
now honours the connection table: the reverse of a flow that was actually
permitted across a stateful filter edge is auto-allowed, while explicit denies
still win and stateless ACLs stay stateless.
"""
import json
from pathlib import Path

from engine.audit import canonical_snapshot
from engine.model import Device, Filter, Interface, Net, Prefix, Route, Rule, load_net, ip_int
from engine.reach import check_filters, resolve_flow

ACME = Path(__file__).resolve().parents[1] / "data" / "acme_office.yaml"


def _fw_filter(name, rules, stateful):
    f = Filter(name=name, default="deny", stateful=stateful)
    f.rules = [Rule.from_dict(r) for r in rules]
    return f


def _net(stateful=True, extra_out_rule=None):
    """client --- r1 --- fw --- r2 --- server

    fw-in (inside, toward server) permits tcp/443 client->server only.
    fw-out-in (outside, toward client) is empty, default deny. Without the
    connection table the server's reply dies on fw-out-in's implicit default.
    """
    net = Net(name="stateful-test")
    net.filters["fw-in"] = _fw_filter(
        "fw-in",
        [{"action": "permit", "src": "10.0.1.0/24", "dst": "10.0.2.0/24", "proto": "tcp", "dport": 443}],
        stateful,
    )
    out_rules = ([extra_out_rule] if extra_out_rule else [])
    net.filters["fw-out-in"] = _fw_filter("fw-out-in", out_rules, stateful)

    def add(name, dtype, ifaces, routes=None):
        dev = Device(name=name, dtype=dtype)
        for iname, cfg in ifaces.items():
            dev.interfaces.append(
                Interface(
                    name=iname,
                    ip=cfg["ip"],
                    prefix=Prefix.parse(cfg["ip"]),
                    filters=cfg.get("filters", []),
                    connected_to=cfg.get("connected_to"),
                )
            )
        for r in routes or []:
            dev.routes.append(Route.from_dict(r))
        net.devices[dev.name] = dev
        return dev

    add("pc1", "host", {"eth0": {"ip": "10.0.1.10/24", "connected_to": "r1 eth0"}},
        routes=[{"network": "0.0.0.0/0", "next_hop": "10.0.1.1"}])
    add("r1", "router", {
        "eth0": {"ip": "10.0.1.1/24", "connected_to": "pc1 eth0"},
        "eth1": {"ip": "192.0.2.1/30", "connected_to": "fw eth0"},
    }, routes=[{"network": "0.0.0.0/0", "next_hop": "192.0.2.2"}])
    add("fw", "firewall", {
        "eth0": {"ip": "192.0.2.2/30", "connected_to": "r1 eth1", "filters": ["fw-in"]},
        "eth1": {"ip": "192.0.2.5/30", "connected_to": "r2 eth0", "filters": ["fw-out-in"]},
    }, routes=[
        {"network": "10.0.1.0/24", "next_hop": "192.0.2.1"},
        {"network": "10.0.2.0/24", "next_hop": "192.0.2.6"},
    ])
    add("r2", "router", {
        "eth0": {"ip": "192.0.2.6/30", "connected_to": "fw eth1"},
        "eth1": {"ip": "10.0.2.1/24", "connected_to": "srv eth0"},
    }, routes=[{"network": "0.0.0.0/0", "next_hop": "192.0.2.5"}])
    add("srv", "host", {"eth0": {"ip": "10.0.2.10/24", "connected_to": "r2 eth1"}},
        routes=[{"network": "0.0.0.0/0", "next_hop": "10.0.2.1"}])
    net.build_adjacency()
    return net


def test_stateful_return_traffic_of_permitted_flow_allowed():
    net = _net()
    est: set = set()
    fwd = resolve_flow(net, ip_int("10.0.1.10"), "pc1", ip_int("10.0.2.10"), "tcp", 443, established=est)
    assert fwd["reachable"]
    assert ("tcp", "10.0.1.0/24", "10.0.2.0/24") in est

    ret = resolve_flow(net, ip_int("10.0.2.10"), "srv", ip_int("10.0.1.10"), "any", None, established=est)
    assert ret["reachable"]
    assert any(t.get("established") for t in ret["trace"])


def test_stateful_profile_state_allowed_flag():
    net = _net()
    est = {("tcp", "10.0.1.0/24", "10.0.2.0/24")}
    allowed, detail = check_filters(
        [net.filters["fw-out-in"]], ip_int("10.0.2.10"), ip_int("10.0.1.10"), "any", None,
        net=net, established=est,
    )
    assert allowed is True
    assert detail["state_allowed"] is True
    assert detail["trace"][0]["established"] is True


def test_no_state_table_means_return_still_blocked():
    net = _net()
    ret = resolve_flow(net, ip_int("10.0.2.10"), "srv", ip_int("10.0.1.10"), "any", None)
    assert not ret["reachable"]
    assert ret["drop"]["filter"] == "fw-out-in"


def test_stateless_firewall_does_not_auto_allow_return():
    net = _net(stateful=False)
    est = {("tcp", "10.0.1.0/24", "10.0.2.0/24")}
    ret = resolve_flow(net, ip_int("10.0.2.10"), "srv", ip_int("10.0.1.10"), "any", None, established=est)
    assert not ret["reachable"]
    assert ret["drop"]["filter"] == "fw-out-in"


def test_explicit_deny_still_blocks_return_traffic():
    net = _net(extra_out_rule={"action": "deny", "src": "any", "dst": "any", "proto": "any"})
    est = {("tcp", "10.0.1.0/24", "10.0.2.0/24")}
    ret = resolve_flow(net, ip_int("10.0.2.10"), "srv", ip_int("10.0.1.10"), "any", None, established=est)
    assert not ret["reachable"]
    assert ret["drop"]["filter"] == "fw-out-in"
    assert ret["drop"]["rule"] == "deny any -> any"


def test_demo_forward_through_firewall_recorded():
    # user-pc -> Internet tcp/443 is the one demo flow that actually crosses
    # fw-inside-in, proving a real stateful firewall edge records connections.
    net = load_net(ACME)
    est: set = set()
    fwd = resolve_flow(net, ip_int("10.0.10.50"), "user-pc", ip_int("8.8.8.8"), "tcp", 443, established=est)
    assert fwd["reachable"]
    assert any(t["filter"] == "fw-inside-in" for t in fwd["trace"])
    assert ("tcp", "10.0.10.0/24", None) in est


def test_intra_site_demo_traffic_stays_l2():
    # In the demo topology the server replies to the office LAN on the same L2
    # segment at the access switch (no firewall or ACL on that interface), so a
    # stateless engine is already honest there - the stateful gap only bites
    # cross-firewall host pairs (covered by the unit net tests above).
    net = load_net(ACME)
    ret = resolve_flow(net, ip_int("10.0.20.10"), "app-server", ip_int("10.0.10.50"), "any", None)
    assert ret["reachable"]


def test_demo_snapshot_roundtrip_preserves_stateful():
    net = load_net(ACME)
    assert net.filters["fw-inside-in"].stateful is True
    assert net.filters["fw-outside-in"].stateful is True
    assert net.filters["core-user-in"].stateful is False
    snap = canonical_snapshot(net)
    net2 = Net.from_dict(json.loads(snap))
    assert net2.filters["fw-inside-in"].stateful is True
    assert net2.filters["fw-outside-in"].stateful is True
    assert canonical_snapshot(net2) == snap


def test_validate_presets_still_run_with_stateful_fixpoint():
    from engine.validate import ALL_PRESETS, validate_change
    net = load_net(ACME)
    for p in ALL_PRESETS:
        r = validate_change(net, p["change"])
        assert r["summary"]["verdict"] is not None, f"preset {p['id']}"