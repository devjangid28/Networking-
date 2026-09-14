"""NetProof provenance & audit trail.

Every validation verdict is persisted to SQLite (a `verdicts` table) with:
model version + snapshot hash, timestamp, the raw + IR change, the full
validation trace, the final verdict / trust score and the requester identity.

`replay_verdict` re-runs the stored change against the same snapshot and proves
the engine is deterministic: the replayed verdict must equal the stored one.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Optional

from .model import Net

DEFAULT_DB = os.environ.get("NETPROOF_DB", str(Path(__file__).resolve().parent.parent / "data" / "netproof.db"))

_conns: dict[str, sqlite3.Connection] = {}
_lock = threading.RLock()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS verdicts (
    id                  TEXT PRIMARY KEY,
    created_at          TEXT NOT NULL,
    model_name          TEXT NOT NULL,
    model_source        TEXT NOT NULL,
    model_hash          TEXT NOT NULL,
    engine_version      TEXT NOT NULL,
    requester           TEXT,
    raw_change          TEXT NOT NULL,
    ir_change           TEXT NOT NULL,
    change_fingerprint  TEXT,
    verdict_final       TEXT NOT NULL,
    trust_score         INTEGER,
    guardrails          TEXT,
    trace               TEXT,
    report              TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verdicts_created ON verdicts (created_at);
"""


# --------------------------------------------------------------------------- #
# canonical snapshot + hash                                                  #
# --------------------------------------------------------------------------- #

def canonical_snapshot(net: Net) -> str:
    """A stable, deterministic JSON representation of the whole model."""
    devices = []
    for name in sorted(net.devices.keys()):
        d = net.devices[name]
        devices.append({
            "name": d.name,
            "type": d.dtype,
            "interfaces": sorted(
                [{
                    "name": i.name, "ip": i.ip, "network": i.network,
                    "filters": sorted(i.filters or []), "connected_to": i.connected_to,
                } for i in d.interfaces],
                key=lambda x: x["name"],
            ),
            "routes": sorted([{"network": r.network, "next_hop": r.next_hop, "source": r.source} for r in d.routes],
                             key=lambda r: (r["network"], r["next_hop"])),
            "nat": {"outside_interface": d.nat.outside_interface,
                    "inside_prefixes": sorted(p.text for p in d.nat.inside_prefixes)} if d.nat else None,
            "dst_nat": sorted(
                [{"public_ip": r.public_ip, "public_port": r.public_port, "private_ip": r.private_ip,
                  "private_port": r.private_port, "proto": r.proto} for r in (d.dst_nat or [])],
                key=lambda r: (r["public_port"], r["private_ip"]),
            ),
            "bgp": sorted(
                [{"neighbor": p.neighbor, "local_as": p.local_as, "remote_as": p.remote_as,
                  "export_prefixes": sorted(p.export_prefixes or []), "active": p.active} for p in (d.bgp or [])],
                key=lambda p: p["neighbor"],
            ),
            "ospf": sorted(
                [{"area_id": a.area_id, "networks": sorted(a.networks or []), "auth_type": a.auth_type} for a in (d.ospf or [])],
                key=lambda a: a["area_id"],
            ),
            "dns": sorted(
                [{"zone": r.zone, "fqdn": r.fqdn, "rtype": r.rtype, "value": r.value, "ttl": r.ttl} for r in (d.dns or [])],
                key=lambda r: (r["fqdn"], r["rtype"], r["value"]),
            ),
            "vlans": sorted(
                [{"iface": v.iface, "vlan_id": v.vlan_id, "name": v.name, "tagged": v.tagged} for v in (d.vlans or [])],
                key=lambda v: v["iface"],
            ),
        })
    payload = {
        "name": net.name,
        "description": net.description,
        "devices": devices,
        "filters": sorted(
            [{"name": f.name, "default": f.default,
              "rules": [{"action": r.action, "src": r.src, "dst": r.dst, "proto": r.proto, "dport": r.dport, "source": r.source} for r in f.rules]} for f in net.filters.values()],
            key=lambda f: f["name"],
        ),
        "zones": sorted(
            [{"name": z, "prefix": zz.prefix.text if zz.prefix else None, "gateway": zz.gateway,
              "source": zz.is_source, "dest": zz.is_dest, "sample_dst": zz.sample_dst} for z, zz in net.zones.items()],
            key=lambda z: z["name"],
        ),
        "requirements": sorted(
            [{"name": r.name, "src": r.src, "dst": r.dst, "proto": r.proto, "dport": r.dport, "expect": r.expect} for r in net.requirements],
            key=lambda r: r["name"],
        ),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def model_hash(net: Net) -> str:
    return hashlib.sha256(canonical_snapshot(net).encode("utf-8")).hexdigest()


def change_fingerprint(change: dict) -> str:
    return hashlib.sha256(json.dumps(change, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# storage                                                                     #
# --------------------------------------------------------------------------- #

def _conn(db: str = DEFAULT_DB) -> sqlite3.Connection:
    with _lock:
        conn = _conns.get(db)
        if conn is None:
            Path(db).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(db, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.executescript(_SCHEMA)
            conn.commit()
            _conns[db] = conn
        return conn


def save_verdict(
    net: Net,
    report: dict,
    raw_change: dict,
    model_source: dict | None = None,
    requester: str | None = None,
    guardrails: list[dict] | None = None,
    db: str = DEFAULT_DB,
) -> str:
    vid = uuid.uuid4().hex[:16]
    summary = report.get("summary") or {}
    with _lock:
        conn = _conn(db)
        import datetime
        conn.execute(
            """INSERT INTO verdicts
               (id, created_at, model_name, model_source, model_hash, engine_version, requester,
                raw_change, ir_change, change_fingerprint, verdict_final, trust_score,
                guardrails, trace, report)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                vid,
                datetime.datetime.now().isoformat(timespec="seconds"),
                net.name,
                json.dumps(model_source or {}),
                model_hash(net),
                report.get("engine_version", ""),
                requester,
                json.dumps(raw_change, default=str),
                json.dumps(report.get("change") or raw_change, default=str),
                change_fingerprint(raw_change),
                summary.get("verdict", ""),
                summary.get("trust_score"),
                json.dumps(guardrails or []),
                json.dumps(report.get("findings", []), default=str),
                json.dumps(report, default=str),
            ),
        )
        conn.commit()
    return vid


def get_verdict(vid: str, db: str = DEFAULT_DB) -> Optional[dict]:
    with _lock:
        row = _conn(db).execute("SELECT * FROM verdicts WHERE id = ?", (vid,)).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


def list_verdicts(limit: int = 20, db: str = DEFAULT_DB) -> list[dict]:
    with _lock:
        rows = _conn(db).execute(
            "SELECT id, created_at, model_name, engine_version, requester, change_fingerprint, "
            "verdict_final, trust_score FROM verdicts ORDER BY created_at DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def _row_to_dict(row) -> dict:
    d = dict(row)
    for k in ("model_source", "raw_change", "ir_change", "guardrails", "trace", "report"):
        if d.get(k):
            try:
                d[k] = json.loads(d[k])
            except (TypeError, ValueError):
                pass
    return d


# --------------------------------------------------------------------------- #
# unified-diff export                                                         #
# --------------------------------------------------------------------------- #

def _config_lines(net: Net) -> list[str]:
    """Render the model as a flat, ordered config file (for unified diffs)."""
    lines: list[str] = [f"! {net.name} — {net.description}"]
    for name in sorted(net.devices.keys()):
        d = net.devices[name]
        lines.append(f"hostname {name}  (type {d.dtype})")
        for i in d.interfaces:
            lines.append(f"  interface {i.name} ip {i.ip or '-'} network {i.network or '-'}"
                         + (f" filters={','.join(i.filters)}" if i.filters else ""))
        for r in sorted(d.routes, key=lambda x: x.network):
            lines.append(f"  ip route {r.network} {r.next_hop}")
        for p in sorted(d.bgp or [], key=lambda x: x.neighbor):
            lines.append(f"  router bgp {p.local_as} neighbor {p.neighbor} remote-as {p.remote_as}"
                         + (f" export {' '.join(p.export_prefixes)}" if p.export_prefixes else ""))
        for a in sorted(d.ospf or [], key=lambda x: x.area_id):
            lines.append(f"  router ospf area {a.area_id} network {' '.join(a.networks)} auth {a.auth_type}")
        for r in sorted(d.dns or [], key=lambda x: (x.fqdn, x.rtype)):
            lines.append(f"  dns {r.fqdn}. {r.rtype} {r.value} ttl {r.ttl} (zone {r.zone})")
        for v in sorted(d.vlans or [], key=lambda x: x.iface):
            lines.append(f"  switchport {v.iface} access vlan {v.vlan_id}" + (f" name {v.name}" if v.name else ""))
        if d.nat:
            lines.append(f"  ip nat outside {d.nat.outside_interface} inside {', '.join(p.text for p in d.nat.inside_prefixes)}")
        for r in d.dst_nat:
            lines.append(f"  ip nat dnat {r.public_ip or 'wan'}:{r.public_port} -> {r.private_ip}:{r.private_port} {r.proto}")
    for fname in sorted(net.filters.keys()):
        f = net.filters[fname]
        lines.append(f"ip access-list {fname} default {f.default}")
        for k, r in enumerate(f.rules):
            lines.append(f"  {k} {r.describe()}")
    for zname in sorted(net.zones.keys()):
        z = net.zones[zname]
        lines.append(f"zone {zname} prefix {z.prefix.text if z.prefix else '-'} gateway {z.gateway}"
                     + f" src={int(z.is_source)} dst={int(z.is_dest)}")
    for r in net.requirements:
        lines.append(f"requirement {r.name} {r.src}->{r.dst} {r.proto}/{r.dport or '-'} expect {r.expect}")
    return lines


def unified_diff(before: Net, after: Net) -> str:
    """Unified diff between two model snapshots (the proposed change)."""
    import difflib
    b = _config_lines(before)
    a = _config_lines(after)
    diff = difflib.unified_diff(b, a, fromfile=f"baseline/{before.name}.conf", tofile=f"proposed/{after.name}.conf", lineterm="")
    return "\n".join(diff) or "no configuration lines changed"


# --------------------------------------------------------------------------- #
# determinism replay                                                          #
# --------------------------------------------------------------------------- #

def replay_verdict(vid: str, net: Net, db: str = DEFAULT_DB) -> dict:
    """Re-run the stored raw change against the SAME baseline model snapshot.

    `deterministic` is True only when the replayed verdict, trust score and
    findings match the stored report byte-for-byte.
    """
    stored = get_verdict(vid, db=db)
    if stored is None:
        raise LookupError(f"no verdict '{vid}' in the audit trail")

    if stored["model_hash"] != model_hash(net):
        return {
            "verdict_id": vid,
            "deterministic": False,
            "reason": "model snapshot differs from the stored verdict — replay needs the same baseline",
            "stored_model_hash": stored["model_hash"],
            "current_model_hash": model_hash(net),
        }

    from .validate import validate_change

    replayed: dict = validate_change(net, stored["raw_change"])
    rsummary = replayed.get("summary") or {}
    ssummary = stored["report"].get("summary") or {}
    s_verdict = ssummary.get("engine_verdict") or ssummary.get("verdict")
    s_score = ssummary.get("engine_score") if "engine_score" in ssummary else ssummary.get("trust_score")

    same_verdict = rsummary.get("verdict") == s_verdict
    same_score = rsummary.get("trust_score") == s_score
    same_findings = (replayed.get("findings") == stored["report"].get("findings"))
    return {
        "verdict_id": vid,
        "deterministic": bool(same_verdict and same_score and same_findings),
        "factors": {"verdict": same_verdict, "trust_score": same_score, "findings": same_findings},
        "replayed": {
            "verdict": rsummary.get("verdict"),
            "trust_score": rsummary.get("trust_score"),
            "findings": len(replayed.get("findings") or []),
            "flows_checked": rsummary.get("flows_checked"),
            "engine_version": replayed.get("engine_version"),
        },
        "stored": {
            "verdict": s_verdict,
            "trust_score": s_score,
            "findings": len(stored["report"].get("findings") or []),
            "created_at": stored["created_at"],
            "engine_version": stored["engine_version"],
        },
        "change": stored["raw_change"],
    }