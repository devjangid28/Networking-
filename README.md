NetProof 0.3.0
================
Neutral network-change validation: propose a change, get a verdict
(pass / warn / block), a 0-100 trust score, and machine-checkable proof.

"the referee test" - built for AI agents and humans alike.


What it does
------------
Loads a network model (topology, interfaces, routes, filters/ACLs, NAT,
zones, policy requirements). Given a proposed change it:

  1. applies the change to a copy of the model,
  2. resolves reachability for every zone-pair flow and every policy
     requirement (start -> end packet paths, per-device ingress filters,
     NAT, loops, missing routes),
  3. diffs before vs after: connectivity lost, new exposure, path changes,
     requirement violations,
  4. returns verdict + trust score + findings + full evidence per flow.

The engine is conservative: a protocol/port-specific rule does not match
"any"-protocol flows, the firewall defaults to deny, and cloud networks
accept all traffic. If it cannot prove safety, it does not bless the change.


Run it
------
PowerShell:

    .\run.ps1

then open http://127.0.0.1:8000

Manual:

    cd backend
    ..\lib\venv\Scripts\python.exe -m uvicorn main:app --port 8000


Bootstrap (one-time)
--------------------
    python -m venv lib\venv
    lib\venv\Scripts\python.exe -m pip install -r requirements.txt


API
---
    GET  /api/network    network model + zones + requirements + presets
    POST /api/validate   {"change": {...}}

Change object shapes:

    {"type":"add_filter_rule","filter":"fw-inside-in","at_index":0,
     "rule":{"action":"permit","src":"10.0.20.0/24","dst":"any","proto":"tcp","dport":443}}

    {"type":"remove_filter_rule","filter":"fw-inside-in","at_index":3}

    {"type":"replace_filter_rule","filter":"fw-inside-in","at_index":3,
     "rule":{"action":"deny","src":"any","dst":"10.0.20.0/24","proto":"tcp","dport":22}}

    {"type":"add_route","device":"firewall",
     "route":{"network":"0.0.0.0/0","next_hop":"203.0.113.1"}}

    {"type":"remove_route","device":"firewall","index":1}


Layout
------
    backend/
        engine/          model, routing/reachability, differential validation
        data/            acme_office.yaml (the example network)
        main.py          FastAPI app
    web/
        index.html       UI shell
        styles.css       the aesthetic
        app.js           frontend logic
    requirements.txt
    run.ps1


Tests
-----
    lib\venv\Scripts\python.exe -c "import sys; sys.path.insert(0,'backend'); \
      from engine.model import load_net; from engine.validate import validate_change, PRESETS; \
      net = load_net('backend/data/acme_office.yaml'); \
      [print(p['id'],'->',validate_change(net,p['change'])['summary']['verdict']) for p in PRESETS]"

Expected outcome today:

    allow_server_internet  -> block   (violates servers-no-internet)
    block_ssh_to_servers   -> block   (breaks admins-to-app-ssh)
    remove_web_rule        -> block   (breaks users-to-app)
    add_icmp_ping          -> pass    (safe; trust 100)
    redirect_default_route -> block   (silent internet outage)


Roadmap
-------
- More topologies and collectors (NetBox/Nautobot read-only, NAPALM/Nornir).
- Dynamic protocols (OSPF/BGP), stateful return paths.
- As-built / config diffs as the change input.
- Go core for hardened production use.