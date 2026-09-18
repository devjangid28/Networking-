# NetProof — Full Project Context (living document)

> **Read this first.** This file is the single source of truth for *what this
> project is, why it exists, how it is built, how it has evolved, and how its
> owner works*. It is written so that any AI (Claude, GPT, Gemini, DeepSeek,
> whichever) can pick it up cold and contribute usefully — architecture review,
> bug hunts, new features, security audits, whatever is asked.
>
> **It is updated after every change.** If a sentence below is stale, update it
> and add a changelog line at the bottom. The changelog is the running log of
> every meaningful change since this file was born.
>
> Built by the opencode assistant from the current codebase state. Version **0.3.0**.

---

## 1. What NetProof is (the elevator pitch)

**NetProof is a neutral network-change validator for AI agents and humans.**
You propose a change to a network ("allow https from the office LAN to the app
server", "remove the firewall's default route", "port-forward 8080 to the app
server", "peer BGP with the ISP"), and NetProof answers:

- a **verdict**: `pass` / `warn` / `block`
- a **trust score** 0–100
- **proof**: which flows still reach, which broke, which new access opened, and
  *why* (the exact filter/rule that blocks a flow, with a per-rule trace)
- an **audit id** that can be replayed to prove the verdict is deterministic

It never touches a real network: it deep-copies the baseline model, applies the
proposed change to the copy, resolves reachability before/after, and diffs. It
is deliberately **conservative** — if it cannot prove a flow is safe, it does
not bless the change.

The README tagline is *"the referee test"* — built for AI agents and humans
alike. Any agent or any human proposes a change; NetProof answers
"safe / unsafe, and here's proof."

---

## 2. Why it exists / the core philosophy

- AI agents will increasingly be handed *write* access to network gear. Before
  that happens there must be a **neutral referee layer** that validates a change
  *before* it is applied — the way a referee validates a play.
- Everything is a **dry run**: deep copy, test, diff, never mutate, never touch
  the box.
- **Honest uncertainty** beats confident guessing: protocol/port-specific rules
  never match `any`-protocol flows, firewalls default to deny, cloud networks
  accept all, and if the engine cannot prove safety it blocks.
- **Machine-checkable proof**: verdicts are persisted to a SQLite audit trail
  with a model snapshot hash + change fingerprint + full trace, and can be
  **replayed deterministically** after a restart.
- **Ground truth vs scanner guess**: config pulled from the box (SSH/config file)
  marks rules and routes `confirmed`; scanner-inferred facts stay `inferred`,
  and the UI shows which is which.
- **The server never walks into a customer network.** A tiny agent runs *inside*
  the LAN, discovers it, and phones the report **outbound** to the central
  server under an org API key. NAT-friendly, and multi-tenant isolation stays
  clean.

---

## 3. How the owner works (the workflow you should operate under)

- **Platform:** Windows 11, PowerShell 5.1, Python 3.12. Development happens
  with the opencode CLI in `C:\Users\DK\Desktop\Networking`. The project lives
  in the `netproof/` subfolder.
- **No git repo** is initialized (as of writing). Files live directly under
  `netproof/`.
- **Bootstrap (one-time):** `.\bootstrap.ps1` creates `lib\venv` and installs
  `requirements.txt`. The interpreter is `lib\venv\Scripts\python.exe`.
- **Run locally:** `.\run.ps1` → serves the web UI + API on
  `http://127.0.0.1:8000`. It loads `.env`; on first run it **generates a random
  admin password and writes it to `.env`** (gitignored) unless
  `NETPROOF_ADMIN_PASS` is already set. Current local `.env` has
  `admin` / `admin` (dev only — the container refuses to start with an empty
  password).
- **Manual run:** `cd backend; ..\lib\venv\Scripts\python.exe -m uvicorn main:app --port 8000`.
- **Tests:** `pytest` from `backend\` covers the engine units, REST API, RBAC,
  tenant/agent flows, rate limits, metrics, MCP tools, TLS/HSTS, discovery and
  config-pull parsing. Standalone smoke scripts also exist:
  `backend\test_new.py`, `backend\debug_agent.py`.
- **Conventions:** type hints everywhere (`from __future__ import annotations`),
  dataclasses for the model, std-lib only inside `engine/`, `pydantic` models
  for API bodies, YAML for the demo network and org guardrails, JSON-lines
  logging, Prometheus text metrics, and best-effort-but-never-crashing for the
  live scanner.
- **Versioning:** single source of truth in `backend/engine/metainfo.py` →
  `PROJECT_VERSION = "0.3.0"` (`PROJECT_NAME = "NetProof"`). Every consumer
  (FastAPI metadata, reports, frontend, agent) reads from there so it cannot
  drift again.
- **Rule for this file:** after every change to the repo, update the changelog
  at the bottom (with the date) and refresh any section the change makes stale.

---

## 4. The journey — how the project grew to this point (A to Z)

Reconstructed from the codebase (there is no git history in this folder, so
this is the story the code itself tells). Phases are approximate and overlap.

### Phase 0 — the seed: differential validation (v0.1.0-era core)
- `engine/model.py`: a declarative YAML network model (devices, interfaces,
  links, routes, filters/ACLs, NAT, zones, requirements) — the "control plane"
  the engine reasons over. Ships with the demo `backend/data/acme_office.yaml`
  ("Acme Corporation" — small office: user LAN 10.0.10.0/24, server VLAN
  10.0.20.0/24, a stateful firewall with NAT to the Internet, an ISP router, a
  cloud node, and policy requirements such as `users-to-app`,
  `admins-to-app-ssh`, `users-to-internet`, `servers-no-internet`).
- `engine/reach.py`: the verification engine that derives the "data plane" from
  the control-plane model. `resolve_flow()` walks hop-by-hop, applies ingress
  filters, does longest-prefix-match routing, applies source/dest NAT, detects
  loops, and returns a path + drop evidence + a per-rule trace.
- `engine/validate.py`: the differential validator — deep copy + apply change,
  resolve **every zone-pair flow and every policy requirement** before vs after,
  produce verdict + trust score + structured findings. Conservative matching
  rules. Ships the demo `PRESETS` (`allow_server_internet` → block,
  `block_ssh_to_servers` → block, `remove_web_rule` → block,
  `add_icmp_ping` → pass, `redirect_default_route` → block).
- `web/` dashboard: a clean single-page UI (index.html + styles.css + app.js)
  rendering the topology, a change builder, the verdict, findings, requirement
  results and the zone reachability matrix.

### Phase 1 — intent & guardrails (human-first layer)
- `engine/intent.py`: a plain-English → machine-change parser. One line in,
  structured `{type, filter, rule, ...}` out, with a **confirmation string** and
  a **confidence score**. Resolves entity names/IPs against the live model and
  never invents a value it cannot prove. Examples: *"block ssh from user-pc to
  app-server"*, *"port-forward 8080 to app-server:80"*, *"add route 10.99.0.0/16
  via 192.168.1.2 on firewall"*.
- `engine/guardrails.py` + `backend/data/orgs/default.yaml`: a per-org,
  **data-driven policy pre-flight** layer that runs *before* the referee. Rules
  live in YAML with a `when` matcher (change type + field conditions) and a
  severity; `critical` **hard-blocks** regardless of the engine score. Built-in
  rules cover allow-all/deny-all rules, broad SSH/RDP exposure, default-route
  removal/add, NAT exposure to desktops, and later the wider BGP/OSPF/DNS/VLAN
  rules. Org files merge over the built-ins (same `id` replaces). The dashboard
  org `default` adds an org rule ("any BGP peering requires a ticket").

### Phase 2 — live discovery (scan this LAN)
- `engine/discover.py`: real LAN discovery with **zero third-party deps**: ARP
  table (instant/authoritative), ICMP ping sweep (64 workers), concurrent TCP
  service probes (~40 services incl. printers and cameras), NetBIOS + bounded
  reverse-DNS hostnames, MAC-OUI → vendor (incl. big CCTV brands), and a
  **raw-UDP SNMPv2c client** (GET/GETNEXT/WALK in hand-rolled BER/TLV) for
  sysDescr/sysName/sysObjectID plus **LLDP and Cisco CDP neighbor-table walks**.
  `guess_type()` fingerprints routers/switches/hosts/servers/printers/cameras/
  mobiles/laptops from ports + vendor + hostname.
- `engine/buildnet.py`: turns a scan into a `Net`. Honest about what a sweep
  knows: **router-centric star** — every device hangs off the target router,
  each host interface is a /32, one `router-lan-in` default-permit policy, every
  device becomes its own zone (per-machine reachability matrix), an assumed WAN
  uplink 203.0.113.0/24. **When real LLDP/CDP neighbor tables exist on the
  target**, matched devices get their REAL port names and a discovered topology
  instead of the synthetic star.
- `/api/scan` with a strict **consent gate** ("I own this network"), a 30s
  daemon-thread timeout, `protect` opt-in (tick exactly which `ip:port`
  services become guarded requirements; the rest stay "discovered but open"),
  and 2-per-minute per-IP rate limiting. Scans require a login session
  (attributable action).

### Phase 3 — config ground truth (confirmed vs inferred)
- `engine/confirm.py`: config ingestion. A scanner can only *guess*; when the
  agent also pulls the **real config**, matching rules/routes flip to
  `source="confirmed"` and config-only entries the scanner never saw are added
  as confirmed. `merge_configs` combines config-file + SSH-pull snapshots into
  one dict. `counts()` feeds the dashboard's confirmed/inferred badges.
- `agent/pull.py`: two OPTIONAL best-effort pullers:
  - **Option A** `--config-file some.json` — a static `{ip: {filters, routes}}`
    snapshot (reliable, recommended).
  - **Option B** SSH via optional `paramiko` — pulls the config file remotely,
    **rejects unknown host keys** (RejectPolicy, never AutoAdd), shell-quotes
    the path, plus a `parse_router_text()` minimal parser for Cisco (`ip route`,
    numbered + named ACLs), VyOS (`ip route ... via ...`), Linux `route add` /
    iptables chains. Unrecognized lines are skipped, never fatal.

### Phase 4 — the agent model (never scan the customer LAN)
- `agent/agent.py`: a one-shot or interval script that runs **inside** the
  customer network, runs the engine discovery, optionally attaches config
  (file/SSH), and posts the report **outbound** to the central backend
  (`POST /api/agent/report`) over HTTPS with an org API key
  (`X-NetProof-Key`). Requires a **consent flag** (`--consent`; the server
  rejects reports without it), validates the backend URL (refuses to send the
  key over plain HTTP to non-loopback unless `NETPROOF_ALLOW_HTTP=1`), and never
  opens a listener (NAT-friendly).
- `engine/tenant.py`: orgs/accounts with **salted PBKDF2 API-key digests** (raw
  key returned exactly once, never stored), outbound `agent_reports` storage,
  and org-scoped dashboard **users** (`admin` / `operator` / `viewer` roles)
  with PBKDF2 password digests. Includes a legacy-migration path that digests
  any plaintext keys from an earlier schema in place.
- `backend/security.py`: httponly session cookies in SQLite, env-only global
  admin with **no default password** (the process refuses to start if
  `NETPROOF_ADMIN_PASS` is unset), role-rank dependency guards (`require_role` /
  `require_admin`), tenant isolation (org-scoped users only ever see their own
  account — 403 otherwise).
- `backend/ratelimit.py`: per-client-IP in-memory sliding-window limits (scan
  2/min, login 5/min, orgs 20/min, validate 60/min, agent reports 60/min,
  org-network 120/min). Proxy-aware — trusts `X-Forwarded-For` only when
  `NETPROOF_DOMAIN` / `NETPROOF_TRUST_PROXY` is set.

### Phase 5 — audit & provenance (proof, and proof it is proof)
- `engine/audit.py`: every verdict is persisted to SQLite with the **model
  snapshot JSON**, model hash (SHA-256 over a canonical sorted snapshot), change
  fingerprint, raw + IR change, guardrail results, trace and requester.
  **`replay_verdict` re-runs the stored change against the same snapshot and
  proves determinism** — the replayed verdict + score + findings must match
  byte-for-byte. `unified_diff` renders a flat config diff of before/after.
- `engine/events.py`: append-only audit **event log** (login/logout, org
  create/key rotate, agent reports, scans, validations) shown to admins.
- REST additions: `GET /api/verdicts`, `GET /api/verdicts/{id}`,
  `POST /api/verdicts/{id}/replay`, `GET /api/verdicts/{id}/export`
  (machine-readable JSON artifact), `GET /api/verdicts/{id}/diff`, and
  `GET /api/audit` (admin-only).

### Phase 6 — ops & production (v0.3.0 era)
- `backend/metrics.py`: dependency-free Prometheus text metrics (`/metrics`):
  per-route request counters + latency (route segments collapsed to `{id}` to
  bound cardinality), scan counter/duration/failures, verdict counters,
  active-agents gauge, uptime.
- `backend/logfmt.py`: JSON-lines structured logging for uvicorn and app logs.
- `backend/main.py` hardening: `/health` liveness probe, CORS same-origin by
  default (opt-in allow-list), **terminal TLS enforcement** — when
  `NETPROOF_DOMAIN` is set, plain-HTTP proxied requests 307 → HTTPS and HTTPS
  responses get HSTS; requests without the forwarded header (Docker healthcheck)
  are left alone. Session cookie becomes `Secure` behind TLS.
- **Docker**: `Dockerfile` (python:3.12-slim, unprivileged `netproof` user,
  refuses to start without `NETPROOF_ADMIN_PASS`), `docker-compose.yml` (app +
  persistent `netproof-data` volume + healthcheck; `production` profile adds a
  **Caddy** reverse proxy on 80/443 with auto Let's Encrypt certs), `Caddyfile`
  (`{$NETPROOF_DOMAIN}` → netproof:8000).
- `backend/mcp_server.py`: a Model Context Protocol server (official `mcp`
  Python SDK; stdio by default, or Streamable HTTP on 127.0.0.1:8100) so AI
  agents get the referee natively: `validate_change`, `get_verdict`,
  `list_network_inventory`, `parse_intent`, `get_guardrails`, `list_presets`.
  Model paths confined to `backend/data` (no arbitrary file reads).
- `DEPLOY.md`, `README.md`, `.env.example` written up: dev, Docker, the TLS
  profile, hardening checklist, RBAC and agent usage.

### Phase 7 — stateful semantics + the wider change language (latest work)
- **Stateful firewalls**: `model.Filter.stateful`, and `reach.py` now carries a
  **connection table** (`established` set of `(proto, src_net, dst_net)`).
  `validate._run` iterates to a fixpoint: a stateful edge records connections it
  actually permitted forward, then the next pass auto-allows the mirror-image
  return traffic (explicit denies still win; stateless ACLs stay stateless).
  The demo firewall's return traffic and the reverse-direction matrix flows now
  resolve honestly. Covered by `backend/tests/test_stateful.py`.
- **Wider DSL — control-plane changes** (`validate.py` `CONTROL_PLANE_PRESETS`
  + `reach.apply_change` + `validate._control_plane_findings`):
  - `add_bgp_peer` / `remove_bgp_peer` — ASN range checks, neighbor must be an
    IP owned by a modelled device (else critical: session cannot come up),
    export prefixes must be routable from the device (else blackhole
    warning/critical), default-route exports flagged, last-upstream-removed
    warning on removal.
  - `add_ospf_network` / `remove_ospf_network` — must be a directly attached
    subnet; same-subnet-multiple-areas and area-mismatch-on-shared-link caught;
    OSPF-on-WAN-link topology-leak warning; adjacency expectations.
  - `add_dns_record` / `remove_dns_record` — record-type whitelist, name must be
    inside an authoritative zone, address sanity (no 0.0.0.0/broadcast), records
    pointing outside managed inventory flagged, dangling CNAMEs, last-record
    removal warnings.
  - `add_vlan_assignment` / `remove_vlan_assignment` — 1–4094 range (else
    hard-block), VLAN-on-host category error, native-VLAN-1 warning, silent
    L2-segment-move warning (with the attached host names).
  - The demo YAML now models DNS records (`portal.internal` etc.), OSPF area 0,
    and VLAN assignments on the core switch so these presets validate on the
    demo.
- **Guardrails extended** to mirror the control-plane findings (BGP export
  default / neighbor unreachable, OSPF WAN advertise, DNS unmanaged target,
  VLAN range / native / host / segment-move).
- `acme_office.yaml` grown to ~250 lines; the engine ships **13 presets total
  (7 data-plane `PRESETS` + 6 control-plane `CONTROL_PLANE_PRESETS`)** covering
  the demo network, plus 4 requirements.
- `validate.py` exposes `ALL_PRESETS = PRESETS + CONTROL_PLANE_PRESETS`, used by
  the dashboard and the MCP `list_presets` tool.

---

## 5. Architecture map (current, v0.3.0)

```
netproof/
  backend/                  # FastAPI app ("the referee")
    main.py                 # app factory: REST endpoints, scan state, agent cache,
                            #   TLS/CORS/metrics middlewares, static web/
    security.py             # sessions, admin creds (env-only), RBAC dependencies
    ratelimit.py            # per-IP sliding-window rate limits (proxy-aware)
    metrics.py              # /metrics Prometheus text (in-memory)
    logfmt.py               # JSON-lines logging
    mcp_server.py           # MCP server for AI agents (stdio / HTTP 127.0.0.1:8100)
    debug_agent.py          # dev/diagnostic agent-report script
    conftest.py             # pytest fixtures
    test_new.py             # manual backward-compat + agent-endpoint smoke suite
    engine/                 # std-lib-only verification core
      __init__.py
      metainfo.py           # PROJECT_NAME / PROJECT_VERSION (single source of truth)
      model.py              # dataclasses: Prefix, Rule, Filter, Interface, Route,
                            #   Nat, DstNatRule, BgpPeer, OspfArea, DnsRecord,
                            #   VlanAssignment, Device, Zone, Requirement, Link, Net
                            #   + YAML loader + snapshot round-trip (Net.from_dict)
      reach.py              # apply_change (isolated deep copy), resolve_flow
                            #   (hop-by-hop data plane), check_filters, NAT, loops,
                            #   stateful connection-table return traffic
      validate.py           # differential validator: flows, findings, verdict,
                            #   trust score, matrix, requirements + control-plane
                            #   checks (BGP/OSPF/DNS/VLAN), PRESETS
      discover.py           # live LAN discovery: ARP / ping / TCP probes /
                            #   SNMPv2c (raw) / LLDP / CDP / hostname + vendor
      buildnet.py           # scan -> Net (router-centric star, or real
                            #   LLDP/CDP topology, per-device zones, protect opt-in)
      confirm.py            # confirmed vs inferred; merge_configs, ingest_config,
                            #   mark_confirmed, counts
      intent.py             # plain-English -> change IR (+ confirmation + confidence)
      guardrails.py         # per-org data-driven pre-flight policy (YAML rules)
      audit.py              # verdicts table + snapshot/hash/fingerprint + replay +
                            #   unified diff + canonical snapshot
      events.py             # append-only audit-event log
      tenant.py             # orgs, API-key digests, org users, agent reports
    data/
      acme_office.yaml      # demo network ("Acme Corporation")
      orgs/default.yaml     # dashboard org guardrails (org "default")
      netproof.db           # SQLite state (verdicts, sessions, orgs, events) - gitignored
  agent/
    agent.py                # outbound-only discovery agent (one-shot / interval)
    pull.py                 # config-file + SSH config pullers, router-text parser
  web/
    index.html (33 KB)      # single-page dashboard
    app.js (167 KB)         # UI logic, mode switch Demo/Live/Agent, builder, verdict view
    styles.css (52 KB)      # styling
  Dockerfile                # python:3.12-slim, unprivileged user, /health, requires
                            #   NETPROOF_ADMIN_PASS (refuses to start without it)
  docker-compose.yml        # app + netproof-data volume; "production" profile adds Caddy
  Caddyfile                 # {$NETPROOF_DOMAIN} -> netproof:8000 (auto HTTPS)
  run.ps1 / run.sh          # local launchers (load .env, generate admin pass on 1st run)
  bootstrap.ps1             # creates lib\venv, installs requirements
  .env.example              # documented env vars
  .env                      # local secrets (gitignored; currently admin/admin)
  README.md, DEPLOY.md, .gitignore, LICENSE (MIT)
```

---

## 6. HTTP API surface (from `backend/main.py`)

- `GET  /` + `/static/*` — the dashboard and assets.
- `GET  /health` — liveness probe (no auth).
- `GET  /metrics` — Prometheus text metrics (no auth).
- `GET  /api/gateway` — read-only helper: suggests the default gateway of the
  host serving the app (empty list if undeterminable, e.g. VPN/container).
- `POST /api/login`, `POST /api/logout`, `GET /api/session` — session auth.
- `GET  /api/network` — current network model (demo, scan or agent report).
- `POST /api/scan` — run LAN discovery (auth + consent + rate limit).
- `GET  /api/scan` — fetch the last scan result.
- `GET  /api/model?mode=scan` — build a `Net` from the active scan.
- `POST /api/validate` — validate a change (engine). The core referee endpoint.
- `POST /api/intent` — parse plain English → change IR.
- `GET  /api/guardrails`, `POST /api/guardrails` — guardrail policy + pre-flight
  run over a change.
- `GET  /api/orgs`, `POST /api/orgs` — list/create accounts; create returns the
  API key **once**. `POST /api/orgs/{org_id}/rotate-key` rotates it.
- `GET  /api/org/network` — account network using ONLY the API key (no session;
  this is what the Agent tab uses when you paste a key).
- `GET  /api/agent/status?org={org}` — latest report status for an account
  (session required).
- `POST /api/agent/report` — agent check-in (org key header + consent).
- `GET  /api/users`, `POST /api/users`, `DELETE /api/users/{org_id}/{username}`
  — org user management (admin role).
- `GET  /api/verdicts` (list), `GET /api/verdicts/{vid}`,
  `POST /api/verdicts/{vid}/replay` (determinism proof),
  `GET /api/verdicts/{vid}/export` (JSON artifact), `GET /api/verdicts/{vid}/diff`.
- `GET  /api/audit` — admin-only event log.

Environment variables (`NETPROOF_*`): `ADMIN_PASS` (required), `ADMIN_USER`,
`DB`, `ORG_DIR`, `ALLOWED_ORIGINS` (CORS), `DOMAIN` (TLS/HSTS), `ALLOW_HTTP`
(agent), `TRUST_PROXY` (rate-limit proxy awareness).

---

## 7. Data model & storage

- **Net (control plane)** — YAML in, dataclasses out: devices with interfaces,
  links, routes, named filters (ACLs) with ordered rules, NAT (source + dest,
  incl. port forwarding), zones, BGP peers, OSPF areas, DNS records, VLAN
  assignments, and requirements (declarative policy: `{src, dst, proto, dport,
  desc}`). Fully round-trippable to a canonical snapshot dict (`Net.from_dict`)
  so verdicts can be replayed.
- **Data plane** — computed per validation, never stored as the model: hop-by-hop
  path resolution with ingress-filter checks, LPM routing, NAT rewriting,
  loop detection, and a stateful connection table.
- **SQLite `netproof.db`** (single file, ~18 MB):
  - `verdicts` — snapshot, model_hash, change fingerprint, raw + IR change,
    guardrail results, trace, verdict, score, requester.
  - `sessions` — httponly session cookies (7-day lifetime), org-scoped users.
  - `orgs` — name + salted PBKDF2 API-key digest (raw key never stored).
  - `users` — org users, PBKDF2 password digests, role
    (`admin` / `operator` / `viewer`).
  - `agent_reports` — outbound agent check-ins (per org).
  - `events` — append-only audit-event log.
- Guardrails: YAML per org in `ORG_DIR` (built-ins shipped with the engine, org
  files merge over them).

---

## 8. Security model

- **No default credentials.** Process refuses to start without
  `NETPROOF_ADMIN_PASS`. Local `.env` currently uses `admin`/`admin` for dev.
- Global admin comes from env only; org users are created through the API and
  scoped to their org (cross-org access → 403).
- API keys: returned exactly once at create/rotate, stored only as salted PBKDF2
  digests; a legacy migration path digests any plaintext keys found in an older
  DB in place.
- Sessions in SQLite, httponly cookie; `Secure` when behind TLS.
- Rate limiting per client IP; proxy headers trusted only when explicitly
  configured (`NETPROOF_DOMAIN` / `NETPROOF_TRUST_PROXY`).
- Agent HTTPS enforcement; loopback HTTP allowed for dev/testing, everything
  else requires HTTPS unless `NETPROOF_ALLOW_HTTP=1`.
- Terminal TLS enforcement behind Caddy (307/HSTS) when `NETPROOF_DOMAIN` set.
- Verification artifacts (verdict exports, audit replay) are the "proof"
  surface; notable-by-design: replay must be byte-identical.

---

## 9. Guardrails & intent (the pre-flight layers)

- Guardrails run on the **IR change**, before the engine. Severity
  `warning`/`critical`; critical hard-blocks regardless of engine score. Rule
  shape: `{id, severity, when: {enabled, type, ...field matchers}, why}`.
- The dashboard org additionally ships a "ticket required for BGP" rule to
  demonstrate org-level policy.
- Intent: NLP-free, keyword + entity-resolution parser; every produced change is
  accompanied by a confirmation string the caller should echo back, and a
  confidence score that drops if something could not be proven.

---

## 10. Frontend (web/)

Single-page dashboard, vanilla JS, no framework/build step. Three modes via the
mode pills in the header:
- **Demo** — preloaded `acme_office.yaml` sample (banner warns it is demo data).
- **Live** — "scan this LAN": target IP/CIDR + "I own this network" consent
  checkbox, then discovery via `/api/scan`; protect-list lets you guard chosen
  services.
- **Agent** — pick an account (org) or paste an org API key to render that
  network from its latest agent report.

Sections: Overview (hero, verdict summary), Systems & Policy (topology,
confirmed/inferred badges), Change & Result (builder + verdict/findings/
requirements/matrix), Settings (options, audit, admin). Login/logout and
role-aware UI in the top bar.

---

## 11. Testing

16 test files under `backend/tests/` covering: agent config, agent HTTPS
policy, consent gate, discovery, end-to-end, filter semantics,
MCP tools, metrics, config pull, rate limits, RBAC/tenant isolation, scan
config, snapshots, stateful firewalls, TLS/HSTS, plus `test_new.py` (manual
backward-compat + agent endpoint checks, verifies "All 13 engine presets";
sets `NETPROOF_ADMIN_PASS=admin-test-pass-2026`) and `test_stateful.py`.
`conftest.py` provides shared fixtures. `debug_agent.py` is a scratch/diagnostic
script for exercising the agent-report path outside pytest.

---

## 12. Deployment

- **Dev:** `run.ps1` → `http://127.0.0.1:8000` (uvicorn, JSON-lines logs,
  metrics, SQLite in `backend/data`).
- **Docker:** `docker compose up --build` (profile default) → app on :8000,
  data volume persisted. `docker compose --profile production up` → Caddy on
  80/443 with automatic Let's Encrypt certs for `NETPROOF_DOMAIN`.
- Container entrypoint requires `NETPROOF_ADMIN_PASS`; runs as unprivileged
  user; healthcheck on `/health`. See `DEPLOY.md` for the hardening checklist.

---

## 13. Current state & what to look at next

Solid, internally consistent v0.3.0: 13 presets, differential + stateful
validation, intent + guardrails, multi-tenant agent model, audit/replay,
metrics, TLS deployment, MCP interface. Obvious next candidates (not yet built):
- Batfish-class features at depth (e.g. realistic firewall/NAT interaction
  beyond the current scoping).
- YAML/JSON export of a full validation "proof bundle" for external audit.
- More router dialects / vendors in `parse_router_text`.
- Automated CI (this folder is not a git repo yet) and packaging (PyPI / OCI).
- Distributed/on-host scan worker so huge networks don't die on one process.

**Ask any AI you give this file to:** critique the engine's conservative rules,
the tenancy/security model, the replay-determinism guarantee, and the
frontend/architecture split; then propose the single highest-value next feature.

---

## 14. Changelog (updated after every change)

- **2026-09-18** — Created this living context document from a full codebase
  review (version 0.3.0). No functional changes to the code.