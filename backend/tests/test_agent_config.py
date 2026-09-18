"""Agent Option A + B wiring: config-file import AND SSH pull merge into one
confirmed model, and SSH degrades gracefully when paramiko is absent."""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agent.agent import _merge_config, gather  # noqa: E402

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

FILE_CONFIG = {
    "192.168.50.1": {
        "filters": [{"name": "lan-in", "rules": [
            {"action": "permit", "src": "10.0.10.0/24", "dst": "any",
             "proto": "tcp", "dport": 80},
        ]}],
        "routes": [{"network": "0.0.0.0/0", "next_hop": "203.0.113.1"}],
    }
}

SSH_CONFIG = {
    "filters": [
        {"name": "lan-in", "rules": [
            {"action": "deny", "src": "any", "dst": "any", "proto": "tcp",
             "dport": 22},
        ]},
        {"name": "wan-in", "rules": [
            {"action": "permit", "src": "any", "dst": "any", "proto": "tcp",
             "dport": 443},
        ]},
    ],
    "routes": [{"network": "10.5.5.0/24", "next_hop": "192.168.1.254"}],
}


def test_merge_config_combines_same_named_filters_and_routes():
    merged = _merge_config(FILE_CONFIG, {"192.168.50.1": SSH_CONFIG})
    dev = merged["192.168.50.1"]
    lan_in = next(f for f in dev["filters"] if f["name"] == "lan-in")
    assert [r["action"] for r in lan_in["rules"]] == ["permit", "deny"]
    assert any(f["name"] == "wan-in" for f in dev["filters"])
    assert len(dev["routes"]) == 2


def test_merge_config_handles_missing_and_multi_device():
    merged = _merge_config(FILE_CONFIG, {"192.168.50.99": SSH_CONFIG})
    assert "192.168.50.1" in merged
    assert "192.168.50.99" in merged
    assert merged["192.168.50.99"]["filters"][0]["name"] == "lan-in"
    assert _merge_config(None, {}) == {}


def test_gather_merges_file_and_ssh_and_reports_sources(monkeypatch):
    import agent.agent as ag
    from agent import pull

    monkeypatch.setattr(ag.discover, "scan",
                        lambda target, community="public", do_ping=True,
                               max_devices=120: dict(SCAN))

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
        json.dump(FILE_CONFIG, fh)
        path = fh.name
    try:
        monkeypatch.setattr(pull, "load_config_file", lambda p: FILE_CONFIG if p == path else None)
        monkeypatch.setattr(pull, "via_ssh",
                            lambda host, **kw: {"raw": "x", "config": SSH_CONFIG})

        payload = ag.gather("192.168.50.1", path, "public", True, 120,
                            ssh={"host": "192.168.50.1", "user": "admin",
                                 "password": "pw", "port": 22})

        assert payload["config_sources"] == ["config-file", "ssh"]
        assert payload["meta"]["config_sources"] == ["config-file", "ssh"]
        dev = payload["config"]["192.168.50.1"]
        lan_in = next(f for f in dev["filters"] if f["name"] == "lan-in")
        assert [r["action"] for r in lan_in["rules"]] == ["permit", "deny"]
        assert any(f["name"] == "wan-in" for f in dev["filters"])
        assert len(dev["routes"]) == 2
    finally:
        os.unlink(path)


def test_via_ssh_returns_none_without_paramiko():
    try:
        import paramiko  # noqa: F401
        return  # library present -> nothing to assert here
    except ImportError:
        pass
    from agent.pull import via_ssh
    assert via_ssh("192.168.50.1", username="x", password="y") is None


def test_report_roundtrips_config_sources():
    import time
    import uuid

    from starlette.testclient import TestClient
    from main import app
    from engine import tenant as _tenant

    with TestClient(app, raise_server_exceptions=False) as c:
        assert c.post("/api/login", json={
            "username": "admin", "password": "admin-test-pass-2026"}).status_code == 200
        stamp = f"{int(time.time() * 1000) % 1000000}-{uuid.uuid4().hex[:4]}"
        org = c.post("/api/orgs", json={"name": f"TestOrg-CS-{stamp}"}).json()["org"]
        cfg = {
            "192.168.50.1": {
                "filters": [{"name": "router-lan-in", "rules": [
                    {"action": "permit", "src": "10.0.10.0/24", "dst": "any",
                     "proto": "tcp", "dport": 443},
                ]}],
                "routes": [{"network": "0.0.0.0/0", "next_hop": "203.0.113.1"}],
            }
        }
        try:
            post = c.post("/api/agent/report",
                          json={"scan": SCAN, "config": cfg,
                                "config_sources": ["config-file", "ssh"],
                                "agent_version": "0.1.0", "consent": True},
                          headers={"X-NetProof-Key": org["api_key"]})
            assert post.status_code == 200
            data = c.get(f"/api/network?org={org['id']}").json()
            assert data.get("config_sources") == ["config-file", "ssh"]
            assert data["confirmations"]["rules"]["confirmed"] > 0
        finally:
            conn = _tenant._conn()
            conn.execute("DELETE FROM agent_reports WHERE org_id=?", (org["id"],))
            conn.execute("DELETE FROM orgs WHERE id=?", (org["id"],))
            conn.commit()