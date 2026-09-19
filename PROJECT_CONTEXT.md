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
- **Git repo:** initialized 2026-09-18 inside `netproof/` (this living doc plus
  the current codebase were committed as a baseline checkpoint
  `c01ee31`). `.gitignore` keeps `.env`, `backend/data/*.db*`, `lib/venv/` and
  `__pycache__/` out. Commit at meaningful checkpoints (one clear message per
  fix / feature).
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

Reconstructed from the codebase (git history exists from 2026-09-18 but the
story below is older than the oldest commit, so it is the tale the code tells).
Phases are approximate and overlap.

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
  `list_network_inventory`, `parse_intent`, `get_guardrails`, `list_presets`,
  `describe_target` (the same per-device intelligence bundle as the REST
  endpoint).
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
      postchange.py         # evidence-aware post-change verification: statuses,
                            #   evidence redaction + source precedence, prediction
                            #   from the persisted report, expected-vs-observed
                            #   comparison, mismatch grouping, read-only health
                            #   checks, rollback recommendation, exportable bundle
      intel.py              # target-intelligence bundle: per-device identity,
                            #   discovery detail, confirmed-vs-inferred, applicable
                            #   org guardrails w/ evidence, validation history,
                            #   suggested actions
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
  The response now carries an **additive `prediction` block** (from
  `postchange.py`): what the change must produce post-deployment — `deltas`
  (expected present new state / expected absent old state, per section), a
  `summary` (counts + per-section groups + simulation verdict), and the change
  fingerprint — so the caller can compare predicted vs observed later.
- `POST /api/verifications` — open a post-change verification for a persisted
  verdict (`{verdict_id, requester, pre_change_evidence?,
  source_precedence?}`); rebuilds the prediction from the stored report (never
  from a fresh simulation).
- `GET  /api/verifications/{vid}` — verification state (status, evidence
  excerpts, prediction, result, rollback, bundle id).
- `POST /api/verifications/{vid}/evidence` — append evidence documents
  (config snapshot / agent report); stored redacted at rest; per-section source
  precedence resolved by freshness; → status `awaiting_observation`.
- `POST /api/verifications/{vid}/run` — compare predicted vs observed: health
  checks (pass/warn/fail per expected change), mismatches grouped by root
  cause, unexpected unrelated changes, rollback recommendation (with inverse
  change when derivable). Read-only — never executes vendor commands.
- `GET  /api/verifications/{vid}/bundle` — exportable artifact: prediction,
  evidence, result, health checks, rollback + source verdict summary (secrets
  always redacted).
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
  `GET /api/verdicts/{vid}/export` (JSON artifact), `GET /api/verdicts/{vid}/bundle`
  (full diagnostic bundle: trace + checklist + pipeline layers + drift + inventory),
  `GET /api/verdicts/{vid}/diff`.
- `GET  /api/drift` — current model vs. the last approved baseline (drift
  posture, risk level, per-section diffs) independent of any one change.
- `GET  /api/audit` — admin-only event log.
- `GET  /api/target/{ip}/intelligence` — per-device target dossier scoped to the
  active model window (demo / scan / agent): identity + discovery detail,
  confirmed-vs-inferred counts, the applicable org guardrails with their
  evidence, validation history (past verdicts touching this address), and
  evidence-based suggested actions. `GET /api/target/{ip}/intelligence/export`
  returns the same bundle as an attachment JSON artifact. Session scoping
  mirrors `/api/model` (scan → session, agent → org scope or session, demo →
  open).

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
  - `verifications` — post-change verification per verdict: status machine
    (`not_started` → `awaiting_observation` → terminal: `verified`,
    `verified_with_warnings`, `mismatch`, `failed`, `inconclusive`,
    `unsupported`), redacted evidence documents + source precedence, prediction
    snapshot, comparison result, health checks, rollback recommendation, bundle.
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
- CSRF: cookie-authenticated state changes must be same-origin (`backend/csrf.py`,
  A3) — cross-site `Origin`/`Referer` → 403; non-browser and cookie-less
  requests pass; `/api/login` exempt; `NETPROOF_ALLOWED_ORIGINS` allowlisted.
- Rate limiting per client IP; proxy headers trusted only when explicitly
  configured (`NETPROOF_DOMAIN` / `NETPROOF_TRUST_PROXY`).
- Global request-body bound (A5): `NETPROOF_MAX_BODY_BYTES` (default 8 MiB)
  caps state-changing bodies via a `Content-Length` pre-check plus an innermost
  stream guard, so declared *and* chunked/oversized bodies never commit memory
  past the cap (413 with the strict headers); engine's tighter per-artefact caps
  unchanged.
- Agent HTTPS enforcement; loopback HTTP allowed for dev/testing, everything
  else requires HTTPS unless `NETPROOF_ALLOW_HTTP=1`.
- Terminal TLS enforcement behind Caddy (307/HSTS) when `NETPROOF_DOMAIN` set.
- Default hardening response headers on every route (A4): strict CSP
  (`script-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`;
  operators may extend via `NETPROOF_CSP_SRC`), `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`
  (microphone/camera/geolocation/payment/usb all `()`), plus a correlation id
  `X-NetProof-Request-ID` on every response (sane caller-supplied tokens are
  honoured; junk/malicious values are replaced with a fresh id).
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

Single-page dashboard, vanilla JS, no framework/build step (`index.html` +
`styles.css` + `app.js`, cache-busted as `app.js?v=0.3.0` — the buster tracks
`metainfo.PROJECT_VERSION` so docs, frontend, image tag and the version
consistency gate in `tests/test_release_checks.py` stay aligned). Three modes via the
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

**Post-change verification view (v0.3.0):** any persisted verdict gains a
"Post-change verify" tab. It walks a 5-step lifecycle (capture pre-change
evidence → dry-run prediction → deploy on the live network → collect
post-change evidence → compare & health-check) and manages the verification via
`VERIF_BY_VID`, rendering an evidence JSON editor prefilled by
`sampleEvidence(report)` with the *predicted* state (which the engineer edits to
match what was actually deployed), per-section source precedence, and
`buildPreChangeEvidence()` supplying the baseline. The "Run verification" button
is held disabled until evidence documents are actually stored (a run with zero
evidence is meaningless — missing evidence is never success). The result
section renders: status badge (`verified` / `verified_with_warnings` /
`mismatch` / `failed` / `inconclusive` / `unsupported`), per-delta confirmation
stats, mismatch cards grouped by root cause (expected vs observed),
unexpected-change rows, the read-only health-check list, evidence
coverage/freshness, and the rollback card (with a replayable inverse change when
derivable) — plus a "Download diagnostic bundle" link that activates after a
successful run. The view is generated by `renderVerifyTab`/`vfRenderInto` and
the helper callables in the verification module inside `web/app.js` (inserted
between `renderTrace` and `exportReport`); styling lives in the `.vf-*` block at
the end of `styles.css`.

### UX affordances (all verified live on 2026-09-18)
- **Glossary tooltips** — every technical term rendered through `glossHtml()`
  gets a `data-gloss` tooltip (`GLOSSARY` map in `app.js`; hover/click/keyboard
  shows a floating card). Covers acl, bgp, ospf, vlan, nat, guardrail, zone,
  snmp, intent, verdict, confirmed, inferred, critical, warning.
- **Simple / expert view toggle** — header `#ux-switch`; simple hides the
  advanced builder fields and shows plain-English hints, expert exposes every
  control. Persisted in `sessionStorage` (`applyUxMode`/`resumeUxMode`).
- **First-run walkthrough** — a 4-step overlay (`showWalkthrough`) opens on
  first load unless dismissed; "Show guide" (`#tour-btn`) re-opens it; dismissal
  persisted in `localStorage`.
- **Footgun confirmation dialog** — before running validation, `riskSummary()`
  detects guardrail-critical findings, remove/replace changes, and default-route
  repoints and asks the user to confirm via an in-DOM `confirmRisk()` dialog
  (Cancel / Escape, or "Yes — run the dry run"). Validation always stays a dry
  run.
- **Device-inspect drawer** — clicking a device (`renderDetail`) opens the
  right-hand drawer (`#dev-detail`) with identity, interfaces, routes, filters
  and policy entries; confirmed vs inferred entries carry distinct badges
  (`srcBadge`), and source/destination fields reuse the glossary tooltips. A
  second **Intelligence** tab (`loadIntelligence`/`renderIntelligence`) fetches
  `/api/target/{ip}/intelligence` for the active model window and renders the
  dossier: identity, SNMP/services/neighbors, confirmed-vs-inferred counts,
  applicable guardrails with evidence, validation history (rows deep-link back
  into the verdict view), and suggested actions.

Verification: on 2026-09-18 the real `index.html` + `app.js` (fetched from a
running server) were executed in a jsdom harness against the live backend — 36
behavioral assertions passed (hover tooltip, mode toggle both ways, walkthrough
open/dismiss/re-open, risk dialog yes/cancel/escape, direct function calls, and
the device-inspect Intelligence tab rendering a real bundle from
`/api/target/{ip}/intelligence`). On 2026-09-19 the harness grew to **56
assertions**: verdict parsing against the enhanced pipeline response, the
after-view "restored" matrix cell, the Phase-7 UI renderers (pipeline bar
cells + early-stop note, checklist items, hop-by-hop trace cards, drift chip),
and the dotted-line "journey" fix (a blocked flow's red line now reaches its
drop device). Every preset in "Propose a change" and every builder change type
was also exercised over HTTP (verdict, findings, checklist, trace, matrix
path-node validity), and a live scan of the user's router (`192.168.31.1`)
produced an all-pairs source→destination matrix whose paths resolve through
valid topology devices. For the v0.3.0 verification view the harness ran again
against a fresh server (**34/34**): boot, glossary, mode toggle fallback, risk
dialog, the result renderers (pipeline bar, checklist, trace, matrix, drift
chip), the verification view end-to-end (open → sample evidence → save → run →
terminal status with health checks, rollback card and enabled bundle link), the
failed path (absent expected change → `failed` + rollback recommended) and
bundle export. It also caught one real UI bug (run button permanently disabled
because it was gated on a result only a run could produce) which was fixed in
`vfRenderInto`.

---

## 11. Testing

22 test files under `backend/tests/` covering: agent config, agent HTTPS
policy, consent gate, discovery, end-to-end, filter semantics, target
intelligence, MCP tools, metrics, config pull, rate limits, RBAC/tenant
isolation, scan config, snapshots, stateful firewalls, TLS/HSTS, the
multi-layer validation pipeline (incl. trace + checklist), the drift/bundle
diagnostics endpoints, the evidence-aware verification engine
(`test_postchange.py`, 36) and the verification REST API
(`test_verifications_api.py`, 12), plus
`test_new.py` (manual backward-compat + agent endpoint checks, verifies "All 13
engine presets"; sets `NETPROOF_ADMIN_PASS=admin-test-pass-2026`) and
`test_stateful.py`. `conftest.py` provides shared fixtures. `debug_agent.py` is
a scratch/diagnostic script for exercising the agent-report path outside pytest.

**Phase A gates (A1, 2026-09-19):**
- New: `backend/tests/test_release_checks.py` — single version source
  (`metainfo.PROJECT_VERSION` == FastAPI app + `app.js?v=` cache-buster +
  docker-compose image tag + pyproject + harness package.json), documented files
  and routes all exist / are registered, YAML parses, the 13-preset catalogue is
  well-formed, and PROJECT_CONTEXT.md references no stale cache-buster.
- New: `scripts/ci.py` (deterministic gate on any OS: compile → import → full
  pytest → boot a throwaway server on a scratch DB → execute all 13 presets over
  HTTP → run the jsdom harness) and `scripts/secret_scan.py` (private keys /
  API-key / secret-assignment scan; fails closed). `.github/workflows/ci.yml`
  runs both jobs (Linux+Windows backend gate, ubuntu static gate).
- **Static-check scope (:warning: legacy debt is tracked, not enforced):** ruff
  and mypy rule *new* code only (`scripts/`, `backend/security_headers.py`, the
  two Phase-A test files) so the gate is deterministic. The pre-0.3.0 modules
  carry legacy debt (ruff ~211 findings incl. `backend/main.py`; mypy 136 in
  `backend/engine/*`) — a Phase C backlog item, not a regression of any baseline
  (they were never linted before).
- New A4 security-header tests `backend/tests/test_security_headers.py` (8) —
  headers on every API + static route, strict CSP, request-id echo/rotation, CSP
  operator extension, TLS-bump headers.
- New A3 CSRF tests `backend/tests/test_csrf.py` (10) — cross-site
  Origin/Referer/`null` → 403, cookie-less and headerless non-browser requests
  pass, login exempt, allowlist honoured, GET/health untouched, 403 carries the
  strict headers.
- New A5 body-size tests `backend/tests/test_limits.py` (9) — under/at/over the
  boundary (computed against httpx's compact wire serialisation), chunked body
  without Content-Length streamed and capped, GET unaffected, env override and
  documented default, 413 keeps the security headers.
- Full gate green on 2026-09-19: pytest **242 passed**, harness **40/40**,
  presets **13/13**, `pip-audit -r requirements.txt` **0 vulnerabilities**.

---

## 12. Deployment

- **Dev:** `run.ps1` → `http://127.0.0.1:8000` (uvicorn, JSON-lines logs,
  metrics, SQLite in `backend/data`).
- **Docker:** `docker compose up --build` (profile default) → app on :8000,
  data volume persisted. `docker compose --profile production up` → Caddy on
  80/443 with automatic Let's Encrypt certs for `NETPROOF_DOMAIN`.
  `NETPROOF_DOMAIN` is also propagated into the app container (compose
  `netproof.environment`) so the terminal-TLS enforcement (HTTP→HTTPS 307, HSTS,
  Secure cookies) actually activates in the production profile — otherwise only
  Caddy's own redirect would fire.
- Container entrypoint requires `NETPROOF_ADMIN_PASS`; runs as unprivileged
  user; healthcheck on `/health`. See `DEPLOY.md` for the hardening checklist.

---

## 13. Current state & what to look at next

Solid, internally consistent v0.3.0: 13 presets, differential + stateful
validation, intent + guardrails, multi-tenant agent model, audit/replay,
**evidence-aware post-change verification**, metrics, TLS deployment, MCP interface.

**Production-readiness roadmap (Phases A–H) in progress — status:**
- Phase A (release/security gate): A0–A1–A3–A4–A5 COMPLETE; A2/A6 NOT STARTED.
- A1: CI + release-checks gate green (242 pytest / 13 presets / 40 harness / ruff+mypy new-code / pip-audit clean / secret scan).
- A4: strict default security headers + request-id COMPLETE; harness 6/6 new assertions green.
- A5: global request-body size bound COMPLETE (`backend/limits.py` + 9 tests) — body memory capped at `NETPROOF_MAX_BODY_BYTES` on state-changing requests.
- Local Docker verified run remains BLOCKED BY ENVIRONMENT (no Docker binary); ubuntu CI carries the Docker gate.
- Backlog: legacy ruff/mypy debt (Phase C), A2/A6, Phases B–H.

**Bug-status reconciliation (2026-09-18, verified against the current code):**
- *"`intent.py` has an `or True` bug"* — **not present.** `grep` for `or True` /
  `and True` in `backend/engine/intent.py` returns nothing.
- *"`validate.py` always marks findings critical"* — **not present.** The module
  emits mixed severity: 23 `critical`, 19 `warning`, 16 `info` findings across
  data-plane and control-plane checks (`_finding(sev, ...)` / `_cp_finding`).

Obvious next candidates (not yet built):
- Batfish-class features at depth (e.g. realistic firewall/NAT interaction
  beyond the current scoping).
- More router dialects / vendors in `parse_router_text`.
- Automated CI (git repo initialized 2026-09-18; no CI added yet) and
  packaging (PyPI / OCI).
- Distributed/on-host scan worker so huge networks don't die on one process.

**Ask any AI you give this file to:** critique the engine's conservative rules,
the tenancy/security model, the replay-determinism guarantee, and the
frontend/architecture split; then propose the single highest-value next feature.

---

## 14. Changelog (updated after every change)

- **2026-09-19 — Phase A: global request-body size bound (A5).** New
  `backend/limits.py`: `NETPROOF_MAX_BODY_BYTES` (default 8 MiB) enforced two
  ways — a `Content-Length` pre-check inside the security-header layer
  (413 carries CSP/nosniff/request-id) and an innermost ASGI guard that counts
  real bytes on state-changing requests (chunked/unannounced bodies are never
  buffered past the cap; FastAPI's swallowed body-read 400 is rewritten to 413
  via the guard's `send` wrapper). `backend/tests/test_limits.py` (9):
  under/at/over boundary, chunked overflow, env override + default documented,
  GETs unaffected, 413 carries headers. Engine per-artefact caps (2 MiB/64 docs)
  unchanged.
- **2026-09-19 — Phase A: CSRF origin enforcement (A3).** New `backend/csrf.py`
  + an HTTP middleware (runs under the security-header middleware so its 403s
  still carry CSP/nosniff/request-id): cookie-authenticated POST/PUT/PATCH/DELETE
  requests are rejected 403 when their `Origin` is cross-site, `null`, or — when
  `Origin` is absent — when their `Referer` is cross-site. Non-browser clients
  (no Origin, no Referer) and cookie-less requests pass; `/api/login` is exempt
  (login CSRF only ever signs the victim into attacker-chosen creds).
  `NETPROOF_ALLOWED_ORIGINS` (the CORS allowlist) is honoured for deliberately
  integrated foreign dashboards. `backend/tests/test_csrf.py` (10) covers all
  branches.
- **2026-09-19 — Phase A: release gate + default security response headers (A1, A4).**
  - Added `.github/workflows/ci.yml` (backend gate on Linux+Windows: compile,
    import, full pytest, server boot, 13 presets over HTTP, jsdom harness;
    static gate on ubuntu: ruff/mypy on new code, pip-audit, secret scan, Docker
    build, `docker compose config -q` + container health smoke), `scripts/ci.py`,
    `scripts/secret_scan.py`, `web/harness/` (repo-internalized jsdom harness,
    now 40 assertions incl. the six security-header/request-id checks),
    `requirements-dev.txt`, `pyproject.toml`, and single-source version
    enforcement (`app.js?v=0.3.0` cache-buster + image tag + package.json all
    tracked to `metainfo.PROJECT_VERSION` in `test_release_checks.py`). Legacy
    ruff/mypy debt (~211 / ~136) recorded as Phase C backlog.
  - Added `backend/security_headers.py` + an outermost HTTP middleware in
    `main.py`: strict CSP + nosniff + frame-deny + referrer + permissions policy,
    and `X-NetProof-Request-ID` correlation on every response. CSP extensions
    via `NETPROOF_CSP_SRC`; caller-supplied request ids are honoured only when
    they match a strict `^[A-Za-z0-9._:/-]{1,128}$` token (header-injection
    safe). Note: FastAPI's /docs + /redoc load CDN JS and are intentionally
    blocked by the strict CSP — the OpenAPI JSON stays at `/openapi.json`.
- **2026-09-19** — **Evidence-aware post-change verification (v0.3.0).** Verdicts
  can now be verified *after* the change is actually deployed on the live
  network, against real observed evidence — never by trusting the dry-run pass:
  - **Engine** (`backend/engine/postchange.py`): verification status machine
    (`not_started` → `awaiting_observation` → `verified` /
    `verified_with_warnings` / `mismatch` / `failed` / `inconclusive` /
    `unsupported`), evidence documents redacted at rest + per-section source
    precedence resolved by freshness, and a prediction rebuilt from the
    *persisted report* (never a fresh simulation) with expected-present/
    expected-absent deltas per section. The comparison emits health checks
    (pass/warn/fail per predicted delta), mismatches grouped by root cause,
    unexpected unrelated changes, and a rollback recommendation (inverse change
    emitted as a replayable JSON backout when derivable from the retained
    pre-change baseline; vendor commands are **never** generated). An observed
    layer that is missing or unverifiable from evidence is treated as a failure
    (`unsupported` + explanatory edge cases), and a dry-run pass never overrides
    a post-change mismatch.
  - **REST** (`backend/main.py`): `POST /api/validate` now returns an additive
    `prediction` block so callers can compare predicted vs observed; new
    `POST /api/verifications`, `GET /api/verifications/{vid}`,
    `POST /api/verifications/{vid}/evidence`, `POST /api/verifications/{vid}/run`
    (read-only health checks) and `GET /api/verifications/{vid}/bundle`
    (exportable redacted artifact). All rate-limited and RBAC-scoped like the
    rest of the API.
  - **Dashboard** (`web/app.js` + `index.html` + `styles.css`): "Post-change
    verify" tab on any persisted verdict — 5-step lifecycle, evidence JSON
    editor prefilled with the predicted state (engineer edits it to match
    reality), run button held disabled until evidence is stored (a run with no
    evidence is meaningless), status badge, mismatch cards, health-check list,
    coverage/freshness, rollback card, and a diagnostic-bundle download.
    Cache-buster now tracks `metainfo.PROJECT_VERSION` (`app.js?v=0.3.0`); the old
ad-hoc `0.9.1` buster is gone and `test_release_checks.py` enforces it. A real UI
bug (run button gated on
    a result that only a run could create — permanently disabled) was found and
    fixed by the harness.
  - **Verification:** backend suite **207 passed** (159 baseline + 36
    `test_postchange.py` + 12 `test_verifications_api.py`); jsdom harness vs a
    live server **34/34** covering boot, glossary, mode toggle, walkthrough,
    risk dialog, the full result renderers, the verification view end-to-end
    (open → sample evidence → save → run → terminal status + health checks +
    rollback card + enabled bundle link → failed-path where the absent expected
    change fails and recommends rollback) and bundle export. Sections 5/6/7/10/11/13
    refreshed.

- **2026-09-19** — **Per-change correctness sweep + live-home-network check.**
  Exercised every preset (7 data-plane + 6 control-plane) and every builder
  change type (`add/remove/replace_filter_rule`, `add/remove_route`,
  `add/remove_dst_nat`, `add_bgp_peer`, `add_ospf_network`, `add_dns_record`,
  `add_vlan_assignment`) over `/api/validate` and confirmed verdicts, pipeline
  layers, checklist, trace, and path-node validity — all cleanup/planning
  changes pass, policy-breaking presets block, route removal warns, and a
  dst-nat on a port the policy still denies warns correctly. **Bugs found and
  fixed:**
  - `reach.py` anti-blackhole guard (private dst must never egress to the
    uplink) had two defects: `ip in ip_network` raised `AttributeError` on
    Python 3.12 (now `ipaddress.ip_address(ip) in net`), and it followed
    *default* routes only, so LAN traffic that is genuinely delivered on a
    connected segment was mis-flagged as a blackhole (every change warned with
    "Requirement 'users-to-app' violated"). Rewritten as `_egresses_to_cloud`:
    a longest-prefix-match walk toward the actual destination that reports a
    blackhole only when the packet would really land at the internet cloud.
    Now `remove_route` of the interior `/16` warns ("Route removal cuts the
    path to …") via `_check_route_removal` in `validate.py`.
  - Dotted lines (`app.js`): the engine's `path` records only devices that
    forwarded/delivered, so a flow killed at an ingress filter (e.g.
    `office-lan → internet` drop at the firewall) had a 1-node path and the red
    line could not reach the blocking device. `_buildTopoFlows` now computes a
    `journey` = path + drop device, used by `_drawPathLines` and
    `_animateFlowPacket`; harness asserts the red dashed line reaches the
    firewall.
  - Live scan: `GET /api/model?mode=scan` on the user's home network
    (router `192.168.31.1`, 6 hosts) validated a clean change in scan mode and
    produced the full **source→destination matrix**: all 30 ordered device-IP
    pairs resolve reachable through the router with valid path nodes, so every
    pair gets a dotted line in the topology view.
  - Verification: backend suite **159 passed**; jsdom harness **56/56**
    (51 + 5 dotline/journey assertions).

- **2026-09-19** — **Validation usefulness package (Phases 1–7).** The verdict
  response became a machine-usable diagnostic payload instead of just
  pass/block:
  - **Phase 6 multi-layer pipeline** (`backend/engine/validate_pipeline.py` +
    `drift.py`): SYNTAX → SEMANTIC → STATE → REACHABILITY, short-circuiting on
    the first failing layer, each layer reporting `{layer, passed, duration_ms,
    finding_count}` → `report["pipeline"]`; wired into `/api/validate`.
  - **Phase 2 hop-by-hop trace** (`validate._trace_hops`): for every flow whose
    status or reachability moved, the per-hop chain (device/iface/note + drop
    filter/rule) → `report["trace"]`.
  - **Phase 3 pre-change checklist** (`_build_checklist` + `KNOWN_CHANGE_TYPES`):
    touched devices/filters and an honest blast-radius count of zone + policy
    flows affected → `report["checklist"]`.
  - **Phase 4 drift surfacing**: `drift.baseline_meta()` + pipeline
    `_state_summary` → `report["drift"]`, plus a new `GET /api/drift` endpoint
    (current model vs last approved baseline, risk level, per-section diffs).
  - **Phase 5 diagnostic bundle**: `GET /api/verdicts/{vid}/bundle` assembles
    provenance, environment, change, proposed diff, verdict, checklist, trace,
    pipeline layers, drift, findings, matrix, requirements, flow summary,
    control-plane checks, guardrails and inventory into one attachment.
  - **Phase 7 dashboard UX** (`web/app.js` + `styles.css`): layer-progress bar
    in the verdict card (pass/fail/skip cells with durations + early-stop note),
    category-styled finding chips (critical/warning/info), a **Pre-change
    checklist** tab and a **Hop-by-hop trace** tab (blocked hops pinned with the
    exact filter/rule), a drift chip in the topology view, and a "Download
    diagnostic bundle" link per verdict.
  - Verification: backend suite **159 passed** (139 baseline + pipeline/trace/
    checklist/diagnostics); jsdom harness **51/51** against the live server.
  Sections 4/6/10/11/13 refreshed.

- **2026-09-18** — **S4 static deployment review.** Statically verified the
  `Caddyfile` (site block, `reverse_proxy netproof:8000`), `Dockerfile`
  (non-root `netproof` user, admin-pass guard, healthcheck) and
  `docker-compose.yml` (profiles, volumes, `:?` required-env guards). **Fixed a
  real gap found during review:** `NETPROOF_DOMAIN` was only wired to the Caddy
  service, so the app-side terminal-TLS enforcement (`main.py` HTTP→HTTPS 307 +
  HSTS + Secure cookies) never activated in the production profile — added
  `NETPROOF_DOMAIN=${NETPROOF_DOMAIN:-}` to the `netproof` service env. Compose
  YAML re-parsed OK (PyYAML). Clean-build / docker-compose-up proof and a real
  Let's Encrypt certificate remain **unverifiable in this environment** (no
  Docker binary; a real cert needs a real domain with DNS A/AAAA on 80/443).
- **2026-09-18** — **Target Intelligence Bundle (S3).** New
  `backend/engine/intel.py` (`target_intelligence`) + `audit.list_verdicts_for_target`
  assemble a per-device dossier: identity (with its source), discovery detail
  (SNMP/services/neighbors/interfaces/links), confirmed-vs-inferred counts, the
  org guardrails that fire on THIS device with their evidence, validation
  history (org-scoped in agent mode for tenant isolation), and evidence-based
  suggested actions. New REST: `GET /api/target/{ip}/intelligence` +
  `/export` (auth mirrors `/api/model`). New MCP tool `describe_target(ip)`.
  Frontend: the device-inspect drawer gained an **Intelligence** tab
  (`renderIntelligence` in `web/app.js` + new `web/styles.css` block) that
  renders the bundle and deep-links history rows into the verdict view. Tests:
  `backend/tests/test_intel.py` (10) + `test_mcp.describe_target`, live-verified
  in the jsdom harness (36/36 assertions, incl. 9 intel-tab checks). Full suite:
  130 pass. Sections 5/6/11/13 refreshed.
- **2026-09-18** — Context-doc reconciliation session: initialized the git repo
  in `netproof/` and committed `PROJECT_CONTEXT.md` (baseline `c01ee31`);
  verified all frontend UX affordances (glossary tooltips, simple/expert view,
  first-run walkthrough, footgun confirmation dialog) by executing the real
  `index.html` + `app.js` against a live server in a jsdom harness (27/27
  assertions); confirmed the `intent.py or True` and
  `validate.py always-critical` bugs are **not** present in the current code
  (grep + severity counts). Sections 3/4/10/13 refreshed. No functional code
  changes.
- **2026-09-18** — Created this living context document from a full codebase
  review (version 0.3.0). No functional changes to the code.