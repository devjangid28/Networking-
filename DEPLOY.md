# Deploying NetProof

NetProof 0.3.0 is a single FastAPI process that serves the web dashboard and
the JSON API from one port (8000). The SQLite database (`netproof.db`), the
audit trail, sessions and the org guardrail files all live under
`backend/data/` — that is the only state you must persist.

## Quick start (Docker)

```bash
cp .env.example .env            # then set NETPROOF_ADMIN_PASS to a long secret
docker compose up -d
open http://127.0.0.1:8000
```

## Production: TLS with the bundled Caddy reverse proxy

`docker compose up` runs plain HTTP on port 8000 — fine for local/trusted
networks. For the Internet, start the `production` profile: Caddy terminates
TLS and auto-provisions a Let's Encrypt certificate for your domain (no cert
management, no manual renewal).

```bash
# set NETPROOF_ADMIN_PASS (required) and NETPROOF_DOMAIN (required in this mode)
grep -q NETPROOF_DOMAIN .env || echo "NETPROOF_DOMAIN=netproof.example.org" >> .env
docker compose --profile production up -d
open https://netproof.example.org
```

Requirements & behaviour:

- Point a DNS A/AAAA record at this host before starting; Caddy validates
  ownership through the ACME HTTP-01 challenge on port 80.
- Port mapping changes to `80` + `443` (HTTP on 8000 is no longer exposed).
- Caddy state lives in the `caddy-data` and `caddy-config` volumes — the
  issued certificate persists across restarts/redeploys, so you won't hit
  Let's Encrypt rate limits.
- `NETPROOF_DOMAIN` is `{domain}` in the Caddyfile; the stored config is
  `./Caddyfile` (`{$NETPROOF_DOMAIN}` → reverse_proxy `netproof:8000`).
- The app itself still binds its internal port 8000 and never sees the public
  TLS connection; Caddy forwards `X-Forwarded-Proto: https`.

The container:
- refuses to start unless `NETPROOF_ADMIN_PASS` is non-empty (no default
  credentials);
- runs a `/health` liveness probe (used by the compose healthcheck);
- writes all logs as JSON lines to stdout — parse `level`, `logger`, `ts`.

Persistence: `netproof-data` volume → `/app/backend/data`. Delete the volume
only to reset the whole world (tenants, verdicts, sessions, guardrails).

## Build once, run anywhere

```bash
docker build -t netproof .
docker run -d -p 8000:8000 \
  -e NETPROOF_ADMIN_USER=admin \
  -e NETPROOF_ADMIN_PASS='<strong-secret>' \
  -v netproof-data:/app/backend/data \
  netproof
```

## Native (no Docker)

```bash
python -m venv venv
# Windows: venv\Scripts\python.exe -m pip install -r requirements.txt
venv/bin/pip install -r requirements.txt
NETPROOF_ADMIN_PASS='<strong-secret>' ./run.sh
# or: (cd backend && ../venv/bin/python -m uvicorn main:app --host 127.0.0.1 --port 8000)
```

Windows users: `.\run.ps1` (uses `lib\venv`, created by `.\bootstrap.ps1`).

## Configuration (all environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `NETPROOF_ADMIN_PASS` | *(required in prod)* | Dashboard admin password. The container hard-fails if empty. |
| `NETPROOF_ADMIN_USER` | `admin` | Dashboard admin username. |
| `NETPROOF_DB` | `backend/data/netproof.db` | Path to the SQLite database (verdicts, sessions, tenants, audit events). |
| `NETPROOF_ORG_DIR` | `backend/data/orgs` | Per-org guardrail YAML directory. |
| `NETPROOF_ALLOWED_ORIGINS` | (empty) | Comma-separated CORS allow-list; empty = same-origin only. Also envelopes the CSRF origin allow-list (A3). |
| `NETPROOF_MAX_BODY_BYTES` | `8388608` (8 MiB) | Global request-body cap (content-length pre-check + streaming guard); 413 on oversized bodies (A5). |
| `NETPROOF_CSP_SRC` | (empty) | Extra CSP directives appended to the shipped policy, e.g. `connect-src https://grafana.internal` (A4). |
| `NETPROOF_HOST` / `NETPROOF_PORT` | `127.0.0.1` / `8000` | Bind address / port (`run.sh`). In Docker the app binds `0.0.0.0` (internal only). |
| `NETPROOF_DOMAIN` | *(empty)* | Public hostname. Set it + `docker compose --profile production up -d` to enable the Caddy TLS reverse proxy (Let's Encrypt).

Agent-side variables (`agent/agent.py`): `NETPROOF_BACKEND` (default
`http://127.0.0.1:8000`), `NETPROOF_API_KEY`, `NETPROOF_ALLOW_HTTP=1` (permit
plain-HTTP to a non-loopback backend; not recommended).

## Hardening checklist (production)

1. **Always set `NETPROOF_ADMIN_PASS`.** Sessions, org/key management and the
   audit trail are admin-only; leaving the default `admin`/`admin` is an open
   door.
2. **Terminate TLS in front of the server** (reverse proxy / load balancer) and
   point the agent at `https://…`. The agent refuses to send its API key over
   plain HTTP to a non-loopback host unless `NETPROOF_ALLOW_HTTP=1`. The
   simplest option is the bundled Caddy reverse proxy — see the *Production:
   TLS with the bundled Caddy reverse proxy* section above.
3. **Rate limits** apply per client IP for scan (2/min), login (5/min), orgs
   (20/min), validate (60/min) and agent reports (60/min). Put the server
   behind a real proxy with its own limits for heavy abuse.
4. **CORS stays same-origin** unless you explicitly set
   `NETPROOF_ALLOWED_ORIGINS`.
5. **Back up `backend/data/`** (or the compose volume) — it is the full
   provenance trail.
6. Rotate an org's agent key via `POST /api/orgs/{id}/rotate-key` the moment an
   agent is retired or compromised.

## Operations

- **Liveness:** `GET /health` → `{"status":"ok","version":"0.3.0","db":"reachable",…}`.
- **Metrics:** `GET /metrics` (Prometheus text format) — request counters per
  route with dynamic segments collapsed to `{id}`, latency count/sum per route,
  scan counter + duration, uptime. Like `/health` it is unauthenticated: keep
  the container's port 8000 internal and scrape it from the collector network.
  Alert ideas: `netproof_scans_total` flatlining for > 24 h, 5xx rate per route,
  `netproof_scan_duration_seconds_sum` spikes.
- **Logs:** JSON lines on stdout; every uvicorn request record is
  `{"ts":…,"level":"INFO","logger":"uvicorn.access","msg":"…"}`.
- **Viewing the audit trail:** `GET /api/audit` (admin session) returns the
  append-only event log (logins, scans, reports, validations, key rotations).

## Users & roles (RBAC)

The global admin (env credentials, role `admin`) sees every account. Create
org-scoped dashboard users so operators and viewers never touch accounts or
admin functions:

```bash
curl -b netproof.jar -c netproof.jar -H 'Content-Type: application/json' \
  -d '{"org_id":"<account-id>","username":"engineer.jane","password":"<secret>","role":"operator"}' \
  https://netproof.example/api/users
```

Roles:
- **admin** — full control of the org, plus user/create/delete and key
  rotation.
- **operator** — runs scans/validations and reads everything *within their own
  account*. Cannot create accounts, rotate keys, manage users, or read the
  cross-account audit trail.
- **viewer** — read-only, still tenant-isolated to their own account.

Rules applied uniformly: org-scoped users only ever see their own account
(response `403` for any other account id), the audit trail is admin-only, and
deleting a user revokes their live sessions immediately. Usernames are globally
unique. Passwords are stored as salted PBKDF2 digests only; the audit trail
records `user.create` / `user.delete` events. Manage users from the dashboard
*(Users & roles* panel, admin only) or via `GET/POST/DELETE /api/users`.

## Agent

```bash
NETPROOF_API_KEY=<org-key> python agent/agent.py \
  --target 192.168.50.1 \
  --backend https://netproof.example \
  --consent
```

Details (SSH/SNMP config pull, consent flag, HTTPS enforcement) are documented
in `agent/agent.py`'s module docstring and `agent/pull.py`.