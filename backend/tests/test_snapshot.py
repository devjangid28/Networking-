"""P3: replay must survive a server restart. The baseline model is persisted
as a canonical snapshot in the verdicts table, and `Net.from_dict` reconstructs
it so the hash matches and the replay is deterministic."""
from engine.model import Net, Device, Interface, Route, Filter, Rule, Zone, Prefix, Requirement, ip_int
from engine.audit import canonical_snapshot, model_hash, save_verdict, get_snapshot, get_verdict
from engine import buildnet


def _tiny_net() -> Net:
    net = Net(name="tiny", description="round-trip fixture")
    f = Filter(name="lan-in", default="permit")
    f.rules = [Rule("permit", "any", "any", "tcp", 443),
               Rule("deny", "any", "any", "tcp", 22)]
    net.filters[f.name] = f
    r = Device("r1", "router")
    r.interfaces.append(Interface("eth0", ip="10.0.0.1/24", network="10.0.0.0/24"))
    r.routes.append(Route("10.0.1.0/24", Prefix.parse("10.0.1.0/24"), "10.0.0.254"))
    net.devices["r1"] = r
    net.zones["lan"] = Zone("lan", Prefix.parse("10.0.0.0/24"), "10.0.0.1", True, True, ip_int("10.0.0.5"))
    net.requirements.append(Requirement("web", "any", "10.0.0.5", "tcp", 443, "reachable"))
    net.build_adjacency()
    return net


def test_snapshot_roundtrip_hash_identical():
    net = _tiny_net()
    snap = canonical_snapshot(net)
    rebuilt = Net.from_dict(__import__("json").loads(snap))
    assert model_hash(rebuilt) == model_hash(net)
    # spot-check critical structure survived
    assert rebuilt.filters["lan-in"].rules[1].dport == 22
    assert "10.0.0.1/24" in [i.ip for i in rebuilt.devices["r1"].interfaces]


def test_buildnet_snapshot_roundtrip():
    scan = {
        "target": "192.168.50.1", "network": "192.168.50.0/24",
        "devices": [
            {"ip": "192.168.50.1", "hostname": "gw", "is_target": True, "type_guess": "router", "services": []},
            {"ip": "192.168.50.10", "hostname": "web", "type_guess": "server", "services": [{"port": 80, "service": "http"}]},
        ],
        "notes": [],
    }
    net, _ = buildnet.build_net(scan)
    rebuilt = Net.from_dict(__import__("json").loads(canonical_snapshot(net)))
    assert model_hash(rebuilt) == model_hash(net)


def test_saved_verdict_reconstructs_baseline(tmp_path):
    net = _tiny_net()
    db = str(tmp_path / "v.db")
    vid = save_verdict(net, {"summary": {"verdict": "pass", "trust_score": 95}, "change": {}},
                       {"type": "add_rule"}, db=db)
    got = get_snapshot(vid, db=db)
    assert got is not None and model_hash(got) == model_hash(net)
    assert get_verdict(vid, db=db).get("model_snapshot") is None  # lean API output