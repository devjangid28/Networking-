"""Regression tests for chained (multiple) ACL/firewall filters on one interface.

History: check_filters used to return on the FIRST filter, so a flow that was
permitted by filter #1 was never evaluated against filter #2. These tests prove
every filter in the chain is enforced.
"""
import pytest

from engine.model import Device, Filter, Interface, Net, Prefix, Route, Rule, ip_int
from engine.reach import check_filters, resolve_flow


def _filt(name, rules, default="deny"):
    f = Filter(name=name, default=default)
    f.rules = [Rule.from_dict(r) for r in rules]
    return f


def _chain_filters():
    return [
        _filt("allow-https", [{"action": "permit", "src": "any", "dst": "any", "proto": "tcp", "dport": 443}]),
        _filt("deny-https-out", [{"action": "deny", "src": "any", "dst": "any", "proto": "tcp", "dport": 443}]),
    ]


def _net(filters, iface_filter_names):
    net = Net(name="chain-test")
    for f in filters:
        net.filters[f.name] = f

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

    add("pc1", "host", {"eth0": {"ip": "10.0.0.10/24", "connected_to": "r1 eth0"}}, routes=[{"network": "0.0.0.0/0", "next_hop": "10.0.0.1"}])
    add(
        "r1",
        "router",
        {
            "eth0": {"ip": "10.0.0.1/24", "connected_to": "pc1 eth0", "filters": iface_filter_names},
            "eth1": {"ip": "20.0.0.1/24", "connected_to": "srv eth0"},
        },
    )
    add("srv", "host", {"eth0": {"ip": "20.0.0.10/24", "connected_to": "r1 eth1"}})
    net.build_adjacency()
    return net


def test_check_filters_second_filter_blocks():
    filters = _chain_filters()
    allowed, detail = check_filters(filters, ip_int("10.0.0.10"), ip_int("20.0.0.10"), "tcp", 443)
    assert allowed is False
    assert detail["filter"] == "deny-https-out"
    assert detail["rule"] == "deny any -> any tcp/443"
    assert [t["filter"] for t in detail["trace"]] == ["allow-https", "deny-https-out"]


def test_check_filters_all_permitting():
    filters = [_filt("a", [{"action": "permit", "src": "any", "dst": "any", "proto": "tcp", "dport": 443}]),
               _filt("b", [{"action": "permit", "src": "any", "dst": "any", "proto": "tcp", "dport": 443}])]
    allowed, detail = check_filters(filters, ip_int("10.0.0.10"), ip_int("20.0.0.10"), "tcp", 443)
    assert allowed is True
    assert all(t["allowed"] for t in detail["trace"])


def test_check_filters_defaults_combine_across_filters():
    filters = [_filt("a", [], default="deny"), _filt("b", [], default="permit")]
    allowed, detail = check_filters(filters, ip_int("10.0.0.10"), ip_int("20.0.0.10"), "tcp", 22)
    assert allowed is False
    assert detail["filter"] == "a"
    assert detail["by_default"] is True
    assert detail["default"] == "deny"


def test_check_filters_no_filters():
    allowed, detail = check_filters([], ip_int("10.0.0.10"), ip_int("20.0.0.10"), "tcp", 443)
    assert allowed is True
    assert detail["no_filter"] is True


def test_resolve_flow_blocked_by_second_acl():
    net = _net(_chain_filters(), ["allow-https", "deny-https-out"])
    verdict = resolve_flow(net, ip_int("10.0.0.10"), "pc1", ip_int("20.0.0.10"), "tcp", 443)
    assert verdict["status"] == "blocked"
    assert verdict["drop"]["filter"] == "deny-https-out"


def test_resolve_flow_chain_records_all_traces():
    net = _net(_chain_filters(), ["allow-https", "deny-https-out"])
    verdict = resolve_flow(net, ip_int("10.0.0.10"), "pc1", ip_int("20.0.0.10"), "tcp", 443)
    trace = verdict["trace"]
    assert [t["filter"] for t in trace] == ["allow-https", "deny-https-out"]
    assert [t["device"] for t in trace] == ["r1", "r1"]


def test_resolve_flow_single_filter_still_enforced():
    net = _net([_filt("drop-443", [{"action": "deny", "src": "any", "dst": "any", "proto": "tcp", "dport": 443}])], ["drop-443"])
    verdict = resolve_flow(net, ip_int("10.0.0.10"), "pc1", ip_int("20.0.0.10"), "tcp", 443)
    assert verdict["status"] == "blocked"
    assert verdict["drop"]["filter"] == "drop-443"
    assert verdict["drop"]["rule"] == "deny any -> any tcp/443"