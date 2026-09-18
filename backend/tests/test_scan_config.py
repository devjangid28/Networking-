"""The web "Run" flow: /api/scan now accepts an imported config file (option A)
and an SSH login (option B). Imported rules land on the scanned model as
CONFIRMED, config-only policy points are materialized, and invalid files are
rejected with a 400 — while a missing paramiko degrades gracefully."""
import json

from fastapi.testclient import TestClient
from main import app

TEST_ADMIN_PASS = "admin-test-pass-2026"

SCAN = {
    "target": "192.168.50.1",
    "network": "192.168.50.0/24",
    "devices": [
        {"ip": "192.168.50.1", "hostname": "gw", "is_target": True,
         "type_guess": "router", "vendor": "Acme", "services": []},
        {"ip": "192.168.50.10", "hostname": "web", "type_guess": "server",
         "vendor": "Acme", "services": [{"port": 80, "service": "http"}]},
    ],
    "notes": [],
}

CONFIG = {
    "192.168.50.1": {
        "filters": [
            {"name": "router-lan-in", "rules": [
                {"action": "permit", "src": "10.0.10.0/24", "dst": "any",
                 "proto": "tcp", "dport": 443},
            ]},
            {"name": "wan-in", "rules": [
                {"action": "permit", "src": "any", "dst": "any",
                 "proto": "tcp", "dport": 80},
            ]},
        ],
        "routes": [{"network": "0.0.0.0/0", "next_hop": "203.0.113.1"}],
    }
}


def test_ingest_config_materializes_config_only_policy_points():
    from engine.buildnet import build_net
    from engine.confirm import counts, ingest_config

    net, _meta = build_net(SCAN)
    changes = ingest_config(net, CONFIG)

    gw = next(d for d in net.devices.values() if d.dtype == "router")
    assert "router-lan-in" in net.filters
    assert "wan-in" in net.filters
    assert net.filters["wan-in"].default == "permit"
    assert all(r.source == "confirmed" for r in net.filters["wan-in"].rules)
    iface_names = " ".join(" ".join(i.filters or []) for i in gw.interfaces)
    assert "wan-in" in iface_names
    assert changes["rules_added"] == 2
    assert counts(net)["rules"]["confirmed"] == 2


def test_merge_config_direct_from_engine():
    from engine.confirm import merge_configs

    merged = merge_configs({"10.0.0.1": {"filters": [{"name": "a", "rules": [{"action": "permit"}]}]}},
                           {"10.0.0.1": {"filters": [{"name": "a", "rules": [{"action": "deny"}]}]}})
    a = next(f for f in merged["10.0.0.1"]["filters"] if f["name"] == "a")
    assert [r["action"] for r in a["rules"]] == ["permit", "deny"]


def _session():
    c = TestClient(app)
    assert c.post("/api/login", json={"username": "admin", "password": TEST_ADMIN_PASS}).status_code == 200
    return c


def _scan_config(config_text):
    session = _session()
    r = session.post("/api/scan", json={
        "target": "127.0.0.1", "ping": False, "consent": True,
        "config_file": config_text,
    })
    return r


def test_scan_with_config_file_imports_confirmed_rules():
    cfg = {**CONFIG, "127.0.0.1": CONFIG["192.168.50.1"]}
    r = _scan_config(json.dumps(cfg))
    assert r.status_code == 200, r.text
    data = r.json()
    assert data.get("config_sources") == ["config-file"]

    m = _session().get("/api/model?mode=scan")
    info = m.json()
    assert info.get("config_sources") == ["config-file"]
    assert info["confirmations"]["rules"]["confirmed"] > 0
    names = [f["name"] for f in info["filters"]]
    assert "wan-in" in names
    wan = next(f for f in info["filters"] if f["name"] == "wan-in")
    assert all(rule["source"] == "confirmed" for rule in wan["rules"])


def test_scan_invalid_config_file_400():
    r = _scan_config("this is not json")
    assert r.status_code == 400
    assert "config file invalid" in r.json()["detail"]


def test_scan_ssh_degrades_when_paramiko_missing():
    try:
        import paramiko  # noqa: F401
        return  # library present -> nothing to assert here
    except ImportError:
        pass
    session = _session()
    r = session.post("/api/scan", json={
        "target": "127.0.0.1", "ping": False, "consent": True,
        "ssh": {"user": "admin", "password": "pw"},
    })
    assert r.status_code == 200, r.text
    assert r.json().get("config_sources", []) == []


def test_scan_without_consent_still_403_with_config():
    session = _session()
    r = session.post("/api/scan", json={
        "target": "192.0.2.9", "ping": False, "consent": False,
        "config_file": json.dumps(CONFIG),
    })
    assert r.status_code == 403