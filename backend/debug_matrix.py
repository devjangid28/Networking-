import json, sys
sys.path.insert(0, r"C:\Users\DK\Desktop\Networking\netproof\backend")
from engine.model import load_net
from engine.validate_pipeline import run_validation_pipeline

net = load_net(r"C:\Users\DK\Desktop\Networking\netproof\backend\data\acme_office.yaml")

for label, ch in [
  ("allow_server_internet", {"type":"add_filter_rule","filter":"fw-inside-in","at_index":0,"rule":{"action":"permit","src":"10.0.20.0/24","dst":"any","proto":"any"}}),
  ("block_user_internet", {"type":"add_filter_rule","filter":"fw-inside-in","at_index":0,"rule":{"action":"deny","src":"10.0.10.0/24","dst":"any","proto":"any"}}),
]:
    rep = run_validation_pipeline(ch, net)["report"]
    print("==", label, rep["summary"]["verdict"])
    for k, cell in rep["matrix"].items():
        b, a = cell.get("before"), cell.get("after")
        for which, d in (("B", b), ("A", a)):
            p = d.get("path"); s = d.get("status"); drop = d.get("drop") or {}
            dv = d.get("nat")
            print(f"  {k:<28} {which} {s:<9} path={p} drop={drop.get('device') or '-'} nat={bool(dv)}")
