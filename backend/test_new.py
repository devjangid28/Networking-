"""Full backward-compatibility + new agent endpoint verification."""
import json, sys, os
os.environ.setdefault("NETPROOF_ADMIN_USER", "admin")
os.environ.setdefault("NETPROOF_ADMIN_PASS", "admin-test-pass-2026")
from starlette.testclient import TestClient
from main import app
from engine.validate import ALL_PRESETS

c = TestClient(app, raise_server_exceptions=False)
c_anon = TestClient(app, raise_server_exceptions=False)
ok = True

def check(label, cond):
    global ok
    status = "PASS" if cond else "FAIL"
    if not cond:
        ok = False
    print(f"  [{status}] {label}")

print("=== Phase 0: dashboard session auth ===")

r = c_anon.get("/api/orgs")
check("orgs 401 without session", r.status_code == 401)

r = c.post("/api/login", json={"username": "admin", "password": "admin-test-pass-2026"})
check("login ok", r.status_code == 200 and r.json().get("ok"))

r = c.post("/api/login", json={"username": "admin", "password": "wrong"})
check("login wrong password 401", r.status_code == 401)

r = c.get("/api/session")
check("session authenticated", r.json().get("authenticated") is True)

check("orgs 200 with session", c.get("/api/orgs").status_code == 200)
print()

print("=== Phase 1-5 backward compat ===")

# All 13 engine presets should validate without error
for p in ALL_PRESETS:
    r = c.post("/api/validate", json={"change": p["change"]})
    data = r.json()
    if r.status_code != 200:
        check(f"preset {p['id']} HTTP {r.status_code}", False)
        continue
    verdict = data.get("summary", {}).get("verdict")
    check(f"preset {p['id']} -> {verdict}", verdict is not None)

# Guardrail hard-block (VLAN 4095)
r = c.post("/api/guardrails", json={
    "change": {"type":"add_vlan_assignment","device":"switch","iface":"Gi0/3","vlan_id":4095,"name":"bad"},
    "mode": "demo"
})
check("guardrail vlan_4095 hard block", r.json().get("hard_block"))

# Intent BGP parse
r = c.post("/api/intent", json={"text":"bgp 203.0.113.1 as 65000"})
check("intent bgp parse", r.json().get("ok") and r.json().get("change", {}).get("type") == "add_bgp_peer")

# Replay determinism
r_val = c.post("/api/validate", json={"change": {"type":"add_filter_rule","filter":"fw-inside-in","rule":{"action":"permit","src":"10.0.20.0/24","dst":"any","proto":"any"},"at_index":0}})
vid = r_val.json()["audit"]["verdict_id"]
r_rep = c.post(f"/api/verdicts/{vid}/replay")
check("replay deterministic", r_rep.json().get("deterministic"))

# Export
r_exp = c.get(f"/api/verdicts/{vid}/export")
check("export 200", r_exp.status_code == 200)

# Provenance
r_prov = c.post("/api/validate", json={"change": {"type":"add_filter_rule","filter":"fw-inside-in","rule":{"action":"permit","src":"10.0.20.0/24","dst":"any","proto":"any"},"at_index":0}, "org": "test"})
check("provenance has audit id", "audit" in r_prov.json())

print()
print("=== NEW: Org + agent report endpoints ===")

# Clean stale test orgs
from engine import tenant as _tenant
conn = _tenant._conn()
for _r in conn.execute("SELECT id, name FROM orgs WHERE name LIKE 'TestOrg-%'").fetchall():
    conn.execute("DELETE FROM agent_reports WHERE org_id=?", (_r[0],))
    conn.execute("DELETE FROM orgs WHERE id=?", (_r[0],))
conn.commit()

import time as _time
_ts = int(_time.time() * 1000) % 1000000

# Create org
r = c.post("/api/orgs", json={"name": f"TestOrg-{_ts}"})
check("create org 200", r.status_code == 200)
org = r.json()["org"]
org_id, org_key = org["id"], org["api_key"]
check("org has api_key", len(org_key) > 10)
beta = c.post("/api/orgs", json={"name": f"TestOrg-Beta-{_ts}"}).json()["org"]

# Duplicate name
r = c.post("/api/orgs", json={"name": f"TestOrg-{_ts}"})
check("duplicate org 400", r.status_code == 400)

# List orgs
r = c.get("/api/orgs")
check("list orgs has >=2", len(r.json()["orgs"]) >= 2)

# Post report no auth
r = c.post("/api/agent/report", json={"scan": {"target":"1.2.3.4","network":"1.2.3.0/24","devices":[{"ip":"1.2.3.1","is_target":True,"type_guess":"router","hostname":"r","services":[]}],"notes":[]}, "consent": True})
check("no-auth 401", r.status_code == 401)

# Post report valid
scan_payload = {
    "target": "192.168.50.1", "network": "192.168.50.0/24",
    "devices": [
        {"ip": "192.168.50.1", "hostname": "gw", "is_target": True, "type_guess": "router", "vendor": "Acme", "services": []},
        {"ip": "192.168.50.10", "hostname": "web", "type_guess": "server", "vendor": "Acme", "services": [{"port": 80, "service": "http"}]},
    ],
    "notes": [],
}
config_payload = {
    "192.168.50.1": {
        "filters": [{"name": "router-lan-in", "rules": [
            {"action": "permit", "src": "any", "dst": "any", "proto": "tcp", "dport": 443},
            {"action": "permit", "src": "any", "dst": "any", "proto": "tcp", "dport": 80},
        ]}],
        "routes": [{"network": "0.0.0.0/0", "next_hop": "203.0.113.1"}],
    }
}
r = c.post("/api/agent/report", json={"scan": scan_payload, "config": config_payload, "agent_version": "0.1.0", "source_host": "laptop", "consent": True}, headers={"X-NetProof-Key": org_key})
check("report ok", r.status_code == 200 and r.json().get("ok"))
report_id = r.json()["report_id"]

# Agent status
r = c.get(f"/api/agent/status?org={org_id}")
check("agent status has_report", r.json()["has_report"] and r.json()["network"] == "192.168.50.0/24")

# /api/network?org= with report
r = c.get(f"/api/network?org={org_id}")
data = r.json()
check("network agent source", data.get("source") == "agent" and data.get("mode") == "agent")
check("network confirmed rules > 0", data["confirmations"]["rules"]["confirmed"] > 0)
check("network has devices", len(data["devices"]) >= 2)
check("network has presets", "presets" in data)
check("network has reported_at", "reported_at" in data)

# /api/network?org= no report
r = c.get(f"/api/network?org={beta['id']}")
check("no-report onboarding", r.json().get("onboarding") is True and r.json().get("source") == "none")

# /api/network no org (backward compat demo)
r = c.get("/api/network")
check("no-org demo source", r.json().get("source") == "demo" and "presets" in r.json())

# Validate in agent mode
r = c.post("/api/validate", json={
    "change": {"type":"add_filter_rule","filter":"router-lan-in","rule":{"action":"deny","proto":"tcp","dport":22}},
    "mode": "agent", "account": org_id
})
check("validate-agent verdict", r.json()["summary"]["verdict"] in ("pass", "warn", "block"))
check("validate-agent provenance", r.json()["provenance"]["model_source"]["mode"] == "agent")

# Re-post invalidates cache, confirmed count drops to 0
r = c.post("/api/agent/report", json={"scan": scan_payload, "config": {}, "agent_version": "0.1.0", "consent": True}, headers={"X-NetProof-Key": org_key})
r2 = c.get(f"/api/network?org={org_id}")
check("new report invalidates cache (confirmed rules drop to 0)", r2.json()["confirmations"]["rules"]["confirmed"] == 0)

# /api/model?mode=agent&org= works
r = c.get(f"/api/model?mode=agent&org={org_id}")
check("model agent 200", r.status_code == 200 and r.json().get("source") == "agent")

# /api/model?mode=agent no report = 400
r = c.get(f"/api/model?mode=agent&org={beta['id']}")
check("model agent no-report 400", r.status_code == 400)

# Dev scan endpoint still works
r = c.get("/api/scan")
check("dev scan status", r.status_code == 200)

# Intent in agent mode
r = c.post("/api/intent", json={"text":"block ssh from any to web", "mode": "agent", "account": org_id})
check("intent agent mode", r.json().get("ok") and r.json().get("change", {}).get("type") == "add_filter_rule")

print()
if ok:
    print("ALL OK")
else:
    print("SOME FAILURES")
    sys.exit(1)
