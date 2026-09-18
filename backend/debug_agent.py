import os
os.environ.setdefault("NETPROOF_ADMIN_USER", "admin")
os.environ.setdefault("NETPROOF_ADMIN_PASS", "admin-test-pass-2026")

from starlette.testclient import TestClient
from main import app, _AGENT_CACHE
import engine.tenant as tenant
from engine.buildnet import build_net
from engine.confirm import mark_confirmed, counts

c = TestClient(app)
c.post("/api/login", json={"username": "admin", "password": "admin-test-pass-2026"})

# Clean any prior Debug2 org so we get a fresh API key
from engine import tenant as _tenant
_conn = _tenant._conn()
for _r in _conn.execute("SELECT id FROM orgs WHERE name = 'Debug2'").fetchall():
    _conn.execute("DELETE FROM agent_reports WHERE org_id=?", (_r[0],))
    _conn.execute("DELETE FROM orgs WHERE id=?", (_r[0],))
_conn.commit()

org = c.post("/api/orgs", json={"name": "Debug2"}).json()["org"]
org_id, org_key = org["id"], org["api_key"]
scan = {"target":"10.0.1.1","network":"10.0.1.0/24","devices":[
    {"ip":"10.0.1.1","hostname":"gw","is_target":True,"type_guess":"router","vendor":"X","services":[]},
    {"ip":"10.0.1.10","hostname":"web","type_guess":"server","vendor":"X","services":[]}],"notes":[]}
cfg = {"10.0.1.1": {"filters":[{"name":"router-lan-in","rules":[{"action":"permit","src":"any","dst":"any","proto":"tcp","dport":443}]}], "routes":[{"network":"0.0.0.0/0","next_hop":"198.51.100.1"}]}}

# Report 1 with config
c.post("/api/agent/report", json={"scan":scan,"config":cfg,"consent":True}, headers={"X-NetProof-Key": org_key})
rep1 = tenant.latest_agent_report(org_id)
net1, _ = build_net(rep1["raw"]["scan"])
c1 = mark_confirmed(net1, rep1["raw"]["config"])
print("report1 changes:", c1)
print("report1 counts:", counts(net1))

# Report 2 without config
c.post("/api/agent/report", json={"scan":scan,"config":{},"consent":True}, headers={"X-NetProof-Key": org_key})
rep2 = tenant.latest_agent_report(org_id)
print("rep2 raw keys:", list(rep2["raw"].keys()))
print("rep2 config:", rep2["raw"].get("config"))
net2, _ = build_net(rep2["raw"]["scan"])
c2 = mark_confirmed(net2, rep2["raw"].get("config"))
print("report2 changes:", c2)
print("report2 counts:", counts(net2))
print("net2 filter rules:", [(r.action, r.src, r.proto, r.source) for f in net2.filters.values() for r in f.rules])