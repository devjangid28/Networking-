"""Evidence-aware post-change verification for NetProof v0.3.0.

A validation verdict predicts HOW the network should look after a change
(`build_prediction`). When the operator has actually applied the change they
collect evidence about the real network afterwards — a config snapshot the
agent exported, a structured agent report, or a manual observation. This module
turns that evidence into observations, compares them against the prediction and
reports one of a fixed set of lifecycle statuses; a *pass* from the dry-run
simulation NEVER overrides a post-change mismatch. Health checks are read-only
observations (never executed on devices) and rollback recommendations are never
auto-executed — they require human approval and re-verification.

The module is std-lib only, uses deterministic JSON serialization everywhere,
and redacts secrets (passwords, private keys, API keys, SNMP community strings,
session tokens) before anything is persisted or exported.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import sqlite3
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .metainfo import PROJECT_VERSION

ENGINE_VERSION = PROJECT_VERSION
SCHEMA_VERSION = "1"

DEFAULT_DB = os.environ.get("NETPROOF_DB", str(Path(__file__).resolve().parent.parent / "data" / "netproof.db"))

MAX_EVIDENCE_DOCS = 64
MAX_EVIDENCE_SIZE_BYTES = 2_000_000
MAX_OBSERVATIONS = 2000
DEFAULT_STALE_AFTER_SECONDS = 900

STATUS_NOT_STARTED = "not_started"
STATUS_AWAITING_OBSERVATION = "awaiting_observation"
STATUS_VERIFIED = "verified"
STATUS_VERIFIED_WITH_WARNINGS = "verified_with_warnings"
STATUS_MISMATCH = "mismatch"
STATUS_FAILED = "failed"
STATUS_INCONCLUSIVE = "inconclusive"
STATUS_UNSUPPORTED = "unsupported"

MISMATCH_EXPECTED_MISSING = "expected_missing"
MISMATCH_UNEXPECTED_PRESENT = "unexpected_present"
MISMATCH_CONTENT_DIFFERS = "content_differs"
MISMATCH_UNEXPECTED_CHANGE = "unexpected_change"

_SECRET_KEYS = {
    "password", "passwd", "pwd", "secret", "secret_key",
    "api_key", "apikey", "access_key", "private_key", "privatekey",
    "session_token", "token", "community", "snmp_community",
    "root_password", "enable", "enable_password", "auth_key", "authpass",
    "priv", "priv_key", "snmpv3_priv", "passphrase", "psk", "pre_shared_key",
    "client_secret", "shared_secret", "refresh_token", "id_token",
    "auth_token", "access_token", "secret_token", "bearer", "credential",
    "credentials",
    "admin_pass", "db_pass", "user_pass", "root_pass", "app_pass",
    "master_pass", "login_pass", "pass", "passcode",
}
# Bare secret tokens matched against the *squished* key name (lowercased with
# every separator removed, e.g. "preSharedKey" -> "presharedkey"), so
# prefixed / camelCase / hyphen / dotted spellings of a credential key are all
# caught. Deliberately generous: over-redaction at rest is safe (the engine has
# already run), under-redaction leaks credentials into evidence exports.
_KEY_SECRET_TOKENS = (
    "password", "passwd", "passphrase", "secret", "psk", "credential",
    "authpass", "community", "snmpcomm", "apikey", "accesskey", "authkey",
    "sessiontoken", "privatekey", "rootpassword", "enablepassword",
    "presharedkey", "sharedsecret", "clientsecret",
    "adminpass", "apppass", "dbpass", "userpass", "masterpass", "loginpass",
)
_SECRET_PATTERN = re.compile(
    r"(?i)(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"session[_-]?token|token|community|snmp[_-]?community|passphrase|psk|"
    r"auth[_-]?key|shared[_-]?secret|client[_-]?secret|pre[_-]?shared[_-]?key|"
    r"bearer|credential)\s*[\"']?\s*[=:]\s*[\"']?\S+"
)
_SECRET_URL_QUERY = re.compile(
    r"(?i)[?&](?:api[_-]?key|auth[_-]?key|access[_-]?key|private[_-]?key|token|secret|passwd?)=[^&\s]+"
)
_SECRET_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=\-]+")
_SECRET_PEM = re.compile(
    r"-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]+PRIVATE KEY-----"
)
# Value-class patterns shared with scripts/secret_scan.py: any of these in an
# evidence string must be scrubbed so the proof surface never ships a
# credential the repository's own scanner would refuse to commit.
_SECRET_VALUE_PATTERNS = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "API key (sk-...)"),
    (re.compile(r"\bghp_[A-Za-z0-9]{36,}\b"), "GitHub token"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"), "Slack token"),
    (_SECRET_PEM, "private key block"),
]
_TIMEZONE = _dt.UTC

_MAX_UNEXPECTED = 20


# --------------------------------------------------------------------------- #
# dataclasses                                                                 #
# --------------------------------------------------------------------------- #

@dataclass
class EvidenceItem:
    id: str
    source: str
    device: str
    section: str
    collected_at: str
    parser_version: str
    model_version: str
    content_hash: str
    content: dict
    confirmed: bool
    errors: list[str]
    size_bytes: int
    unsupported: list[str] = field(default_factory=list)


@dataclass
class StateObservation:
    id: str
    source: str
    device: str
    section: str
    collected_at: str
    parser_version: str
    model_version: str
    content_hash: str
    content: dict
    confirmed: bool
    errors: list[str]
    stale: bool
    coverage: float
    unsupported: list[str] = field(default_factory=list)


@dataclass
class PredictedDelta:
    key: str
    section: str
    device: str
    label: str
    kind: str
    change_type: str
    expected_present: bool
    expected: dict | None
    before: dict | None
    index: int | None = None
    impact: str = "info"
    advisory: bool = False
    needs_before: bool = False


@dataclass
class VerificationMismatch:
    key: str
    section: str
    device: str
    label: str
    kind: str
    status: str
    expected: dict | None
    observed: dict | None
    evidence_ids: list[str]
    severity: str
    detail: str


# --------------------------------------------------------------------------- #
# deterministic serialization / hashing                                       #
# --------------------------------------------------------------------------- #

def deterministic_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def content_hash(value: Any) -> str:
    return hashlib.sha256(deterministic_json(value).encode("utf-8")).hexdigest()


def iso_now() -> str:
    return _dt.datetime.now(_TIMEZONE).isoformat(timespec="seconds")


def iso_parse(text: str) -> _dt.datetime | None:
    try:
        return _dt.datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------------- #
# secret redaction                                                            #
# --------------------------------------------------------------------------- #

def _squish_key(key: str) -> str:
    return "".join(ch for ch in str(key).lower() if ch.isalnum())


def _is_sensitive_key(key: str) -> bool:
    raw = str(key or "").strip()
    camel_split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", raw).lower()
    lowered = camel_split.replace("-", "_").replace(".", "_").replace(" ", "_").replace("/", "_")
    if lowered in _SECRET_KEYS or lowered.endswith(("_key", "_token")):
        return True
    squished = _squish_key(raw)
    return any(token in squished for token in _KEY_SECRET_TOKENS)


def _redact_value(value: Any, key: str | None = None) -> Any:
    if isinstance(value, dict):
        return {k: _redact_value(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(v, key) for v in value]
    if isinstance(value, str):
        if _is_sensitive_key(key):
            return "[REDACTED]"
        for regex, _label in _SECRET_VALUE_PATTERNS:
            value = regex.sub("[REDACTED]", value)
        value = _SECRET_PATTERN.sub("[REDACTED]", value)
        return _SECRET_BEARER.sub("[REDACTED]", _SECRET_URL_QUERY.sub("[REDACTED]", value))
    return value


def redact_secrets(value: Any) -> Any:
    """Recursively scrub credentials from any JSON-ish structure.

    Sensitive key names (passwords, API keys, private keys, SNMP community
    strings, session tokens — including prefixed / camelCase / hyphen / dotted
    spellings) are replaced with ``[REDACTED]``; inline ``name=value`` text,
    URL query credentials, ``Bearer`` tokens, PEM private-key blocks and the
    value classes cleared by ``scripts/secret_scan.py`` (AWS keys, ``sk-``
    keys, GitHub/Slack tokens) are masked inside strings too.
    """
    return _redact_value(value)


def sensitives_present(value: Any) -> bool:
    """True when a structure still contains an un-redacted secret.

    Used as the 'is this clean?' oracle: already-redacted sentinels
    (``[REDACTED]``) are treated as clean, so the key *name* alone never
    triggers once the value has been scrubbed.
    """
    if isinstance(value, dict):
        for k, v in value.items():
            if _is_sensitive_key(k) and isinstance(v, str) and v != "[REDACTED]":
                return True
            if sensitives_present(v):
                return True
    elif isinstance(value, list):
        return any(sensitives_present(v) for v in value)
    elif isinstance(value, str):
        if value == "[REDACTED]":
            return False
        if any(regex.search(value) for regex, _label in _SECRET_VALUE_PATTERNS):
            return True
        if _SECRET_PATTERN.search(value) or _SECRET_URL_QUERY.search(value) or _SECRET_BEARER.search(value):
            return True
    return False


# --------------------------------------------------------------------------- #
# evidence schema validation                                                  #
# --------------------------------------------------------------------------- #

def normalize_evidence_doc(doc: dict, parser_version: str, model_version: str) -> list[dict]:
    """Validate one evidence document and split it into observation records.

    Returns a list of observation records. Raises ``ValueError`` on schema
    violations or oversized payloads, and rejects documents whose ``content``
    is not an object.
    """
    if not isinstance(doc, dict):
        raise ValueError("evidence must be a JSON object")
    source = str(doc.get("source") or "manual").strip().lower()
    if source not in ("snapshot", "agent_report", "probe", "manual", "discovery"):
        raise ValueError(f"unknown evidence source '{source}'")
    confirmed = bool(doc.get("confirmed", False))
    errors = [str(e) for e in (doc.get("errors") or []) if str(e)]
    raw_unsupported = doc.get("unsupported") or []
    if isinstance(raw_unsupported, bool):
        raw_unsupported = ["unsupported parser construct"] if raw_unsupported else []
    unsupported = [str(u) for u in raw_unsupported if str(u)]
    collected_at = str(doc.get("collected_at") or iso_now())
    if iso_parse(collected_at) is None:
        raise ValueError(f"collected_at is not a valid ISO timestamp: {collected_at!r}")

    size = 0
    for token in ("content", "raw", "snapshot"):
        raw = doc.get(token)
        if isinstance(raw, (dict, list)):
            size += len(json.dumps(raw, default=str).encode("utf-8"))
    if size > MAX_EVIDENCE_SIZE_BYTES:
        raise ValueError(f"evidence too large: {size} bytes exceeds {MAX_EVIDENCE_SIZE_BYTES}")

    source_doc = doc.get("content")
    if isinstance(source_doc, list):
        records: list[dict] = []
        for item in source_doc:
            if isinstance(item, dict) and item.get("source"):
                records.extend(extract_observations([item]))
        if not records and source_doc:
            records.append(_observation_record(
                source, str(doc.get("device") or ""), str(doc.get("section") or "manual"),
                redact_secrets({"items": source_doc}), collected_at,
                confirmed, errors, unsupported, parser_version, model_version))
        return records
    if not isinstance(source_doc, dict):
        raise ValueError("evidence content must be a JSON object")

    device = str(doc.get("device") or "").strip()
    section = str(doc.get("section") or "").strip().lower()

    records = _records_from_content(source, device, section, source_doc, collected_at,
                                    confirmed, errors, unsupported, parser_version, model_version)
    if records:
        return records

    for token in ("raw", "snapshot"):
        raw = doc.get(token)
        if isinstance(raw, dict):
            records = _records_from_content(source, device, section, raw, collected_at,
                                            confirmed, errors, unsupported, parser_version, model_version)
            if records:
                return records
    return []


def _records_from_content(source, device, section, content, collected_at, confirmed,
                          errors, unsupported, parser_version, model_version) -> list[dict]:
    if not isinstance(content, dict):
        return []
    if section:
        return [_observation_from_section(source, device, section, content, collected_at,
                                          confirmed, errors, unsupported, parser_version, model_version)]

    records: list[dict] = []
    if "config" in content:
        config = content.get("config")
        for ip, conf in (config or {}).items():
            if not isinstance(conf, dict):
                continue
            for section_name, section_content in conf.items():
                sect = str(section_name).lower()
                if sect in ("filters", "routes", "bgp", "ospf", "dns", "vlan_assignment", "interfaces", "dst_nat"):
                    records.append(_observation_from_section(
                        source, str(ip), sect, {sect: section_content}, collected_at,
                        confirmed, errors, unsupported, parser_version, model_version))
    scan = content.get("scan") or {}
    for dev in scan.get("devices") or []:
        if not isinstance(dev, dict) or not dev.get("ip"):
            continue
        records.append(_observation_record(
            source, str(dev["ip"]), "device", {"device": redact_secrets(dev)}, collected_at,
            confirmed, errors, unsupported, parser_version, model_version))
        services = dev.get("services")
        if isinstance(services, list):
            records.append(_observation_record(
                source, str(dev["ip"]), "services", {"services": services}, collected_at,
                confirmed, errors, unsupported, parser_version, model_version))
    if records:
        return records

    for section_name in ("filters", "routes", "bgp", "ospf", "dns", "vlan_assignment",
                         "interfaces", "dst_nat", "reachability", "device", "services", "control_plane"):
        if section_name in content:
            records.append(_observation_from_section(
                source, device, section_name, {section_name: content[section_name]}, collected_at,
                confirmed, errors, unsupported, parser_version, model_version))
    return records


def _observation_from_section(source, device, section, content, collected_at, confirmed,
                              errors, unsupported, parser_version, model_version) -> dict:
    return _observation_record(source, device, section, redact_secrets(content), collected_at,
                               confirmed, errors, unsupported, parser_version, model_version)


def _observation_record(source, device, section, content, collected_at, confirmed,
                        errors, unsupported, parser_version, model_version) -> dict:
    return {
        "id": uuid.uuid4().hex[:16],
        "source": source,
        "device": device,
        "section": section,
        "collected_at": collected_at,
        "parser_version": parser_version,
        "model_version": model_version,
        "content_hash": content_hash(content),
        "content": content,
        "confirmed": confirmed,
        "errors": list(errors),
        "stale": False,
        "coverage": _section_coverage(section, content),
        "unsupported": list(unsupported),
    }


def _section_coverage(section: str, content: dict) -> float:
    body = content.get(section)
    if section == "reachability":
        return 1.0 if isinstance(body, dict) and body else 0.0
    if body is None:
        return 0.0
    if isinstance(body, (list, dict)):
        return 1.0
    return 0.5


# --------------------------------------------------------------------------- #
# prediction from a stored verdict report                                     #
# --------------------------------------------------------------------------- #

def _canonical_net(text: str) -> str:
    return str(text or "").strip().lower()


def _rule_key(rule: dict) -> dict:
    return {
        "action": str(rule.get("action", "")),
        "src": str(rule.get("src", "")),
        "dst": str(rule.get("dst", "")),
        "proto": str(rule.get("proto", "")).lower(),
        "dport": rule.get("dport"),
    }


def _impact_of(report: dict) -> str:
    summary = report.get("summary") or {}
    if summary.get("blocked"):
        return "critical"
    if summary.get("warnings"):
        return "warning"
    return "info"


def _primary_resource_deltas(change: dict, report: dict) -> list[PredictedDelta]:
    ctype = change.get("type", "")
    deltas: list[PredictedDelta] = []
    impact = _impact_of(report)

    def route_key(device, network):
        return f"route:{device}:{_canonical_net(network)}"

    if ctype == "add_filter_rule":
        idx = int(change.get("at_index", 0) or 0)
        fname = str(change.get("filter", ""))
        rule = _rule_key(change.get("rule") or {})
        deltas.append(PredictedDelta(
            key=f"filter_rule:{fname}:{idx}", section="filters", device="",
            label=f"{rule['action']} {rule['proto']} {rule['src']} -> {rule['dst']} on {fname}",
            kind="filter_rule", change_type=ctype, expected_present=True, expected=rule, before=None,
            index=idx, impact=impact))
    elif ctype == "remove_filter_rule":
        idx = int(change.get("at_index", change.get("index", 0)) or 0)
        fname = str(change.get("filter", ""))
        deltas.append(PredictedDelta(
            key=f"filter_rule:{fname}:{idx}", section="filters", device="",
            label=f"rule #{idx} removed from {fname}",
            kind="filter_rule", change_type=ctype, expected_present=False, expected=None, before=None,
            index=idx, impact="critical", needs_before=True))
    elif ctype == "replace_filter_rule":
        idx = int(change.get("at_index", change.get("index", 0)) or 0)
        fname = str(change.get("filter", ""))
        rule = _rule_key(change.get("rule") or {})
        deltas.append(PredictedDelta(
            key=f"filter_rule:{fname}:{idx}", section="filters", device="",
            label=f"rule #{idx} replaced on {fname}",
            kind="filter_rule", change_type=ctype, expected_present=True, expected=rule, before=None,
            index=idx, impact=impact))
    elif ctype == "add_route":
        device = str(change.get("device", ""))
        route = change.get("route") or {}
        network = str(route.get("network", ""))
        deltas.append(PredictedDelta(
            key=route_key(device, network), section="routes", device=device,
            label=f"route {network} via {route.get('next_hop')} on {device}",
            kind="route", change_type=ctype, expected_present=True,
            expected={"network": network, "next_hop": str(route.get("next_hop", ""))},
            before=None, impact=impact))
    elif ctype == "remove_route":
        device = str(change.get("device", ""))
        idx = int(change.get("index", -1))
        deltas.append(PredictedDelta(
            key=f"route:{device}:index:{idx}", section="routes", device=device,
            label=f"route #{idx} removed on {device}",
            kind="route", change_type=ctype, expected_present=False, expected=None, before=None,
            index=idx, impact="critical", needs_before=True))
    elif ctype == "add_dst_nat":
        device = str(change.get("device", ""))
        rule = change.get("dst_nat") or {}
        pub = str(rule.get("public_ip") or "*")
        dport = str(rule.get("public_port", ""))
        proto = str(rule.get("proto", "")).lower()
        deltas.append(PredictedDelta(
            key=f"dst_nat:{device}:{pub}:{dport}:{proto}", section="dst_nat", device=device,
            label=f"port-forward :{dport} to {rule.get('private_ip')}:{rule.get('private_port')} on {device}",
            kind="dst_nat", change_type=ctype, expected_present=True,
            expected={"public_ip": None if pub == "*" else pub, "public_port": rule.get("public_port"),
                      "private_ip": rule.get("private_ip"), "private_port": rule.get("private_port"),
                      "proto": proto},
            before=None, impact=impact))
    elif ctype == "remove_dst_nat":
        device = str(change.get("device", ""))
        idx = int(change.get("index", change.get("at_index", -1)))
        deltas.append(PredictedDelta(
            key=f"dst_nat:{device}:index:{idx}", section="dst_nat", device=device,
            label=f"port-forward #{idx} removed on {device}",
            kind="dst_nat", change_type=ctype, expected_present=False, expected=None, before=None,
            index=idx, impact="critical", needs_before=True))
    elif ctype in ("add_bgp_peer", "remove_bgp_peer"):
        device = str(change.get("device", ""))
        peer = change.get("peer") or change.get("bgp_peer") or change
        neighbor = str(peer.get("neighbor") or "")
        wants_add = ctype == "add_bgp_peer"
        deltas.append(PredictedDelta(
            key=f"bgp:{device}:{neighbor}", section="bgp", device=device,
            label=f"BGP peer {neighbor} {'added' if wants_add else 'removed'} on {device}",
            kind="bgp", change_type=ctype, expected_present=wants_add,
            expected={"neighbor": neighbor, "local_as": peer.get("local_as"),
                      "remote_as": peer.get("remote_as"), "export_prefixes": peer.get("export_prefixes") or []},
            before=None, impact=impact))
    elif ctype in ("add_ospf_network", "remove_ospf_network"):
        device = str(change.get("device", ""))
        area = int(change.get("area_id", change.get("area", 0)))
        network = _canonical_net(change.get("network"))
        wants_add = ctype == "add_ospf_network"
        deltas.append(PredictedDelta(
            key=f"ospf:{device}:area:{area}:{network}", section="ospf", device=device,
            label=f"OSPF area {area} {'advertises' if wants_add else 'stops advertising'} {network} on {device}",
            kind="ospf", change_type=ctype, expected_present=wants_add,
            expected={"area_id": area, "network": str(change.get("network", ""))},
            before=None, impact=impact))
    elif ctype in ("add_dns_record", "remove_dns_record"):
        device = str(change.get("device", ""))
        rec = change.get("record") or {}
        zone = str(rec.get("zone", ""))
        fqdn = _canonical_net(rec.get("fqdn"))
        rtype = str(rec.get("type", rec.get("rtype", ""))).upper()
        value = str(rec.get("value", ""))
        wants_add = ctype == "add_dns_record"
        deltas.append(PredictedDelta(
            key=f"dns:{device}:{zone}:{fqdn}:{rtype}:{value}", section="dns", device=device,
            label=f"DNS {rtype} {rec.get('fqdn')} -> {value} {'added' if wants_add else 'removed'} on {device}",
            kind="dns", change_type=ctype, expected_present=wants_add,
            expected={"zone": zone, "fqdn": rec.get("fqdn"), "rtype": rtype, "value": value, "ttl": rec.get("ttl")},
            before=None, impact=impact))
    elif ctype in ("add_vlan_assignment", "remove_vlan_assignment"):
        device = str(change.get("device", ""))
        vlan = change.get("vlan") or change
        iface = str(vlan.get("iface", ""))
        wants_add = ctype == "add_vlan_assignment"
        deltas.append(PredictedDelta(
            key=f"vlan:{device}:{iface}", section="vlan_assignment", device=device,
            label=f"VLAN {vlan.get('vlan_id')} on {device}/{iface} "
                  + ("assigned" if wants_add else "removed"),
            kind="vlan", change_type=ctype, expected_present=wants_add,
            expected={"iface": iface, "vlan_id": vlan.get("vlan_id"), "name": vlan.get("name")},
            before=None, impact=impact))
    return deltas


def _flow_deltas(report: dict) -> list[PredictedDelta]:
    deltas: list[PredictedDelta] = []
    for key, cell in (report.get("matrix") or {}).items():
        before = cell.get("before") or {}
        after = cell.get("after") or {}
        if before.get("reachable") == after.get("reachable"):
            impact = "info"
        elif before.get("reachable") and not after.get("reachable"):
            impact = "critical"
        else:
            impact = "warning"
        deltas.append(PredictedDelta(
            key=f"flow:{_canonical_net(key)}", section="reachability", device="",
            label=str(cell.get("label") or key),
            kind="flow", change_type="", expected_present=bool(after.get("reachable")),
            expected={"reachable": after.get("reachable"), "status": after.get("status")},
            before={"reachable": before.get("reachable"), "status": before.get("status")},
            impact=impact, advisory=True))
    for req in (report.get("requirements") or []):
        name = str(req.get("name", ""))
        deltas.append(PredictedDelta(
            key=f"requirement:{_canonical_net(name)}", section="requirements", device="",
            label=str(req.get("label") or name),
            kind="requirement", change_type="", expected_present=bool(req.get("ok")),
            expected={"expect": req.get("expect"), "after": req.get("after"), "ok": bool(req.get("ok"))},
            before={"before": req.get("before")},
            impact="critical" if not req.get("ok") else "info", advisory=True))
    return deltas


def _control_plane_deltas(report: dict) -> list[PredictedDelta]:
    cp = report.get("control_plane") or {}
    before = cp.get("before") or {}
    after = cp.get("after") or {}
    deltas: list[PredictedDelta] = []
    for family in ("bgp_peers", "ospf_areas", "dns_records", "vlan_assignments"):
        b = int(before.get(family, 0) or 0)
        a = int(after.get(family, 0) or 0)
        if a == b:
            continue
        added = a > b
        deltas.append(PredictedDelta(
            key=f"control_plane:{family}", section="control_plane", device="",
            label=f"{family}: {b} -> {a}",
            kind="control_plane", change_type="", expected_present=added,
            expected={"before": b, "after": a},
            before={"before": b, "after": a},
            impact="info" if added else "critical", advisory=True))
    return deltas


def _baseline_from_evidence(pre_change_evidence: dict) -> dict:
    baseline: dict[str, dict] = {}
    if isinstance(pre_change_evidence.get("config"), dict):
        for ip, conf in pre_change_evidence["config"].items():
            if not isinstance(conf, dict):
                continue
            for section_name, payload in conf.items():
                sect = str(section_name).lower()
                if sect not in ("filters", "routes", "dst_nat", "bgp", "ospf", "dns", "vlan_assignment"):
                    continue
                bucket = baseline.setdefault(sect, {"device": {}, "global": []})
                canonical = _canonical_section_items(sect, payload)
                if ip:
                    bucket["device"].setdefault(str(ip), []).extend(canonical)
                else:
                    bucket["global"].extend(canonical)
    return baseline


def _device_entries(pre_change_evidence: dict) -> list[tuple[str, str]]:
    """``(device name, config key)`` pairs from an optional device map or a
    name-keyed config (falling back to the config keys themselves)."""
    mapping = pre_change_evidence.get("devices") or {}
    out: list[tuple[str, str]] = []
    if isinstance(mapping, dict):
        for name, keys in mapping.items():
            if isinstance(keys, str):
                out.append((str(name), keys))
            elif isinstance(keys, list):
                for k in keys:
                    out.append((str(name), str(k)))
    config = pre_change_evidence.get("config") or {}
    if not out and isinstance(config, dict):
        for key in config:
            out.append((str(key), str(key)))
    return out


def _config_section(pre_change_evidence: dict, config_key: str, section: str) -> Any:
    config = pre_change_evidence.get("config") or {}
    conf = config.get(config_key) if isinstance(config, dict) else None
    if not isinstance(conf, dict):
        return None
    return conf.get(section)


def _attach_before_values(change: dict, deltas: list[PredictedDelta], pre_change_evidence: dict) -> None:
    ctype = change.get("type", "")
    if ctype in ("remove_filter_rule", "replace_filter_rule"):
        fname = str(change.get("filter", ""))
        idx = int(change.get("at_index", change.get("index", 0)) or 0)
        found = _before_filter_rule(pre_change_evidence, fname, idx)
        if found is not None:
            for d in deltas:
                if d.kind == "filter_rule":
                    d.before = found
                    d.needs_before = False
        return

    if ctype in ("remove_route", "remove_dst_nat", "add_route", "add_dst_nat"):
        device_to_ips = _device_entries(pre_change_evidence)
        idx = change.get("index", change.get("at_index"))
        for name, config_key in device_to_ips:
            if name != str(change.get("device", "")):
                continue
            if ctype == "remove_route":
                section = "routes"
                payload = _config_section(pre_change_evidence, config_key, section)
                rules = payload if isinstance(payload, list) else []
                if isinstance(idx, int) and 0 <= idx < len(rules):
                    before = rules[idx]
                    for d in deltas:
                        if d.kind == "route" and not d.expected_present:
                            d.before = {"network": before.get("network"), "next_hop": before.get("next_hop")}
                            d.needs_before = False
            elif ctype == "remove_dst_nat":
                payload = _config_section(pre_change_evidence, config_key, "dst_nat")
                rules = payload if isinstance(payload, list) else []
                if isinstance(idx, int) and 0 <= idx < len(rules):
                    before = rules[idx]
                    for d in deltas:
                        if d.kind == "dst_nat" and not d.expected_present:
                            d.before = dict(before)
                            d.needs_before = False
        return

    if ctype in ("remove_bgp_peer", "remove_dns_record", "remove_vlan_assignment"):
        device_to_ips = _device_entries(pre_change_evidence)
        section_map = {
            "remove_bgp_peer": ("bgp", "bgp"),
            "remove_dns_record": ("dns", "dns"),
            "remove_vlan_assignment": ("vlan", "vlan_assignment"),
        }
        delta_kind, config_section = section_map[ctype]
        for name, config_key in device_to_ips:
            if name != str(change.get("device", "")):
                continue
            payload = _config_section(pre_change_evidence, config_key, config_section)
            rules = payload if isinstance(payload, list) else []
            before = _before_value_in_list(change, config_section, rules)
            if before is not None:
                for d in deltas:
                    if d.kind == delta_kind and not d.expected_present:
                        d.before = before
                        d.needs_before = False
        return


def _before_filter_rule(pre_change_evidence: dict, fname: str, idx: int) -> dict | None:
    config = pre_change_evidence.get("config") or {}
    if not isinstance(config, dict):
        return None
    for key, conf in config.items():
        if not isinstance(conf, dict):
            continue
        filters = conf.get("filters")
        if not isinstance(filters, dict):
            continue
        filt = filters.get(fname)
        if not isinstance(filt, dict):
            continue
        rules = filt.get("rules") if isinstance(filt.get("rules"), list) else []
        if 0 <= idx < len(rules):
            return dict(rules[idx])
    return None


def _before_value_in_list(change: dict, section: str, rules: list) -> dict | None:
    if section == "bgp":
        peer = change.get("peer") or change.get("bgp_peer") or change
        neighbor = str(peer.get("neighbor") or "")
        for r in rules:
            if isinstance(r, dict) and str(r.get("neighbor")) == neighbor:
                return dict(r)
        return None
    if section == "dns":
        rec = change.get("record") or {}
        for r in rules:
            if isinstance(r, dict) and str(r.get("fqdn")) == str(rec.get("fqdn")) and \
               str(r.get("type", r.get("rtype", ""))).upper() == str(rec.get("type", "")).upper():
                return dict(r)
        return None
    if section == "vlan_assignment":
        vlan = change.get("vlan") or change
        iface = str(vlan.get("iface") or "")
        for r in rules:
            if isinstance(r, dict) and str(r.get("iface")) == iface:
                return dict(r)
        return None
    return None


def _canonical_section_items(section: str, payload: Any) -> list[str]:
    items: list[str] = []
    if section == "filters":
        if isinstance(payload, dict):
            for fname, filt in payload.items():
                rules = (filt or {}).get("rules") or []
                for r in rules:
                    items.append(deterministic_json(
                        {"section": "filters", "filter": fname, "rule": _rule_key(r)}))
        elif isinstance(payload, list):
            for r in payload:
                items.append(deterministic_json({"section": "filters", "rule": _rule_key(r)}))
    elif section == "routes":
        for r in (payload or []) if isinstance(payload, list) else []:
            if isinstance(r, dict):
                items.append(deterministic_json(
                    {"section": "routes", "route": {"network": r.get("network"), "next_hop": r.get("next_hop")}}))
    else:
        body = payload if isinstance(payload, list) else []
        for item in body:
            if isinstance(item, dict):
                items.append(deterministic_json({"section": section, "item": item}))
    return items


def build_prediction(report: dict, pre_change_evidence: dict | None = None) -> dict:
    """Derive the predicted post-change state from a stored verdict report.

    The prediction is built ONLY from the persisted report (matrix,
    requirements, control-plane inventory, and the change itself) — never from
    a freshly simulated model, so it always describes the exact state the
    validation was scored against. ``pre_change_evidence`` (optional) supplies
    before-values for removed/replaced resources and a baseline for detecting
    unrelated changes afterwards.
    """
    change = report.get("change") or {}
    deltas = _primary_resource_deltas(change, report)
    deltas.extend(_flow_deltas(report))
    deltas.extend(_control_plane_deltas(report))

    baseline = _baseline_from_evidence(pre_change_evidence) if pre_change_evidence else {}
    if pre_change_evidence:
        _attach_before_values(change, deltas, pre_change_evidence)

    primary = [d for d in deltas if not d.advisory]
    prev_devices = {}
    if pre_change_evidence and isinstance(pre_change_evidence.get("devices"), dict):
        prev_devices = pre_change_evidence["devices"]
    return {
        "schema": SCHEMA_VERSION,
        "engine_version": ENGINE_VERSION,
        "verdict_id": report.get("audit", {}).get("verdict_id"),
        "change": change,
        "built_at": iso_now(),
        "baseline": baseline,
        "device_map": prev_devices,
        "deltas": [as_delta(d) for d in deltas],
        "summary": {
            "deltas": len(deltas),
            "primary_deltas": len(primary),
            "advisory_deltas": len(deltas) - len(primary),
            "expected_present": sum(1 for d in deltas if d.expected_present),
            "expected_absent": sum(1 for d in deltas if not d.expected_present),
            "critical_impact": sum(1 for d in deltas if d.impact == "critical"),
            "simulation_verdict": (report.get("summary") or {}).get("verdict"),
            "simulation_trust_score": (report.get("summary") or {}).get("trust_score"),
        },
    }


def as_delta(delta: PredictedDelta) -> dict:
    return {
        "key": delta.key, "section": delta.section, "device": delta.device,
        "label": delta.label, "kind": delta.kind, "change_type": delta.change_type,
        "expected_present": delta.expected_present,
        "expected": delta.expected, "before": delta.before,
        "index": delta.index, "impact": delta.impact,
        "advisory": delta.advisory, "needs_before": delta.needs_before,
    }


def _delta_from_dict(d: dict) -> PredictedDelta:
    return PredictedDelta(
        key=str(d.get("key", "")), section=str(d.get("section", "")), device=str(d.get("device", "")),
        label=str(d.get("label", "")), kind=str(d.get("kind", "")), change_type=str(d.get("change_type", "")),
        expected_present=bool(d.get("expected_present", True)),
        expected=d.get("expected"), before=d.get("before"),
        index=d.get("index"), impact=str(d.get("impact", "info")),
        advisory=bool(d.get("advisory", False)), needs_before=bool(d.get("needs_before", False)),
    )


# --------------------------------------------------------------------------- #
# observations from evidence                                                  #
# --------------------------------------------------------------------------- #

def extract_observations(evidence_docs: list[dict]) -> list[dict]:
    """Normalize a list of evidence documents into StateObservation records."""
    if len(evidence_docs) > MAX_EVIDENCE_DOCS:
        raise ValueError(f"too many evidence documents: {len(evidence_docs)} exceeds {MAX_EVIDENCE_DOCS}")
    records: list[dict] = []
    for doc in evidence_docs:
        records.extend(normalize_evidence_doc(doc, ENGINE_VERSION, ENGINE_VERSION))
    if len(records) > MAX_OBSERVATIONS:
        raise ValueError(f"too many observations: {len(records)} exceeds {MAX_OBSERVATIONS}")

    now = _dt.datetime.now(_TIMEZONE)
    merged: dict[tuple[str, str], dict] = {}
    order: list[tuple[str, str]] = []
    for rec in records:
        rec["stale"] = _is_stale(rec.get("collected_at"), now)
        key = (rec["device"], rec["section"])
        previous = merged.get(key)
        if previous is None:
            merged[key] = rec
            order.append(key)
        elif rec["stale"] and not previous.get("stale"):
            continue
        else:
            merged[key] = rec
    return [merged[k] for k in order if not merged[k].get("stale")]


def _is_stale(collected_at: str, now: _dt.datetime | None = None) -> bool:
    ts = iso_parse(collected_at)
    if ts is None:
        return True
    age = (now or _dt.datetime.now(_TIMEZONE)) - ts
    return age.total_seconds() > DEFAULT_STALE_AFTER_SECONDS


# --------------------------------------------------------------------------- #
# comparison                                                                  #
# --------------------------------------------------------------------------- #

def _section_content(obs: dict, section: str) -> Any:
    content = obs.get("content") or {}
    if section in content:
        return content[section]
    return content


def _rules_matching(rules: list, expected: dict) -> list[dict]:
    want_dport = expected.get("dport")
    out = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if str(rule.get("action", "")) != str(expected.get("action", "")):
            continue
        if str(rule.get("proto", "")).lower() != str(expected.get("proto", "")).lower():
            continue
        if str(rule.get("src", "")) != str(expected.get("src", "")):
            continue
        if str(rule.get("dst", "")) != str(expected.get("dst", "")):
            continue
        if want_dport is not None and str(rule.get("dport")) != str(want_dport):
            continue
        out.append(rule)
    return out


def _section_has(section: str, obs: dict, delta: PredictedDelta) -> bool:
    body = _section_content(obs, section)
    expected = delta.expected or {}
    before = delta.before
    if section == "filters":
        filters = body if isinstance(body, dict) else {}
        for fname, filt in filters.items():
            rules = (filt or {}).get("rules") if isinstance(filt, dict) else None
            if not isinstance(rules, list):
                continue
            if delta.expected_present:
                if expected.get("action") is not None:
                    if _rules_matching(rules, expected):
                        return True
                continue
            if before:
                return bool(_rules_matching(rules, _rule_key(before)))
            if delta.index is not None and 0 <= delta.index < len(rules):
                return True
        return False
    if section == "routes":
        routes = body if isinstance(body, list) else (body or {}).get("routes") or []
        if before is not None:
            return any(isinstance(r, dict) and str(r.get("network", "")) == str(before.get("network"))
                       for r in routes)
        if delta.index is not None and f":index:{delta.index}" in delta.key:
            return 0 <= delta.index < len(routes)
        for r in routes:
            if str(r.get("network", "")) == expected.get("network") and \
               str(r.get("next_hop", "")) == expected.get("next_hop", ""):
                return True
        return False
    if section == "dst_nat":
        rules = body if isinstance(body, list) else (body or {}).get("dst_nat") or []
        if before is not None:
            return any(isinstance(r, dict) and str(r.get("public_port")) == str(before.get("public_port"))
                       and str(r.get("proto", "")).lower() == str(before.get("proto", "")).lower()
                       for r in rules)
        if expected.get("public_port") is None:
            return False
        for r in rules:
            if not isinstance(r, dict):
                continue
            if str(r.get("public_port")) == str(expected.get("public_port")) and \
               str(r.get("proto", "")).lower() == str(expected.get("proto", "")).lower():
                return True
        return False
    if section == "bgp":
        peers = body if isinstance(body, list) else (body or {}).get("bgp") or []
        nbr = str(before.get("neighbor")) if before is not None else expected.get("neighbor")
        return any(isinstance(p, dict) and str(p.get("neighbor")) == nbr for p in peers)
    if section == "ospf":
        areas = body if isinstance(body, list) else (body or {}).get("ospf") or []
        if before is not None:
            net, area_id = str(before.get("network")), int(before.get("area_id", 0) or 0)
        else:
            net, area_id = str(expected.get("network", "")), int(expected.get("area_id", 0) or 0)
        for a in areas:
            if not isinstance(a, dict):
                continue
            if int(a.get("area_id", 0) or 0) == area_id and \
               net in (a.get("networks") or []):
                return True
        return False
    if section == "dns":
        records = body if isinstance(body, list) else (body or {}).get("dns") or []
        if before is not None:
            fqdn = str(before.get("fqdn"))
            rtype = str(before.get("type", before.get("rtype", ""))).upper()
            value = str(before.get("value"))
        else:
            fqdn = str(expected.get("fqdn", ""))
            rtype = str(expected.get("rtype", "")).upper()
            value = str(expected.get("value", ""))
        for r in records:
            if not isinstance(r, dict):
                continue
            if str(r.get("fqdn")) == fqdn and \
               str(r.get("type", r.get("rtype", ""))).upper() == rtype and \
               str(r.get("value")) == value:
                return True
        return False
    if section == "vlan_assignment":
        vlans = body if isinstance(body, list) else (body or {}).get("vlan_assignment") or []
        if before is not None:
            iface, vid = str(before.get("iface")), str(before.get("vlan_id"))
        else:
            iface, vid = str(expected.get("iface")), str(expected.get("vlan_id"))
        for v in vlans:
            if not isinstance(v, dict):
                continue
            if str(v.get("iface")) == iface and \
               str(v.get("vlan_id")) == vid:
                return True
        return False
    if section == "reachability":
        flows = body if isinstance(body, dict) else (body or {}).get("flows") or {}
        if isinstance(flows, dict):
            if any(isinstance(v, dict) and "reachable" in v for v in flows.values()):
                hit = next((v for v in flows.values() if isinstance(v, dict) and "reachable" in v), None)
                return bool(hit["reachable"]) if hit else False
            return bool(flows.get("reachable"))
        if isinstance(flows, list):
            return bool(flows and flows[0].get("reachable"))
        return False
    if section == "requirements":
        return bool(expected.get("ok", True))
    return False


def _match_expectation(delta: PredictedDelta, found: bool) -> dict | None:
    if delta.expected_present:
        if found:
            return {"match": True, "message": "expected resource present", "mismatch": None}
        if delta.advisory:
            severity = delta.impact if delta.impact == "critical" else "warning"
        else:
            severity = "critical"
        return {
            "match": False,
            "message": "expected resource missing",
            "mismatch": {
                "kind": MISMATCH_EXPECTED_MISSING,
                "status": "expected_missing",
                "severity": severity,
                "detail": f"Expected {delta.label} to be present after the change, "
                          "but the evidence does not show it.",
                "expected": delta.expected,
                "observed": None,
            },
        }
    if not found:
        return {"match": True, "message": "expected resource absent", "mismatch": None}
    return {
        "match": False,
        "message": "expected resource still present",
        "mismatch": {
            "kind": MISMATCH_UNEXPECTED_PRESENT,
            "status": "unexpected_present",
            "severity": "critical",
            "detail": f"Expected {delta.label} to be gone after the change, "
                      "but the evidence still shows it.",
            "expected": None,
            "observed": delta.before if delta.before is not None else (delta.expected or {}),
        },
    }


def _candidate_observations(delta: PredictedDelta, observations: list[dict],
                            device_map: dict | None = None) -> list[dict]:
    section = delta.section
    device = delta.device
    aliases: set[str] = set()
    if device and device_map:
        raw = device_map.get(device)
        if isinstance(raw, str):
            aliases = {raw}
        elif isinstance(raw, list):
            aliases = {str(k) for k in raw}
    out = []
    for obs in observations:
        if obs.get("section") != section:
            continue
        if not device:
            out.append(obs)
        elif obs.get("device") == device:
            out.append(obs)
        elif str(obs.get("device")) in aliases:
            out.append(obs)
        elif not obs.get("device"):
            out.append(obs)
    return out


def _check_delta(delta: PredictedDelta, observations: list[dict],
                 precedence: list[str] | None, device_map: dict | None = None) -> dict:
    candidates = _candidate_observations(delta, observations, device_map)
    if not candidates:
        return {
            "key": delta.key, "status": "inconclusive", "found": None,
            "mismatch": None, "message": "no evidence sampled this section",
            "evidence_ids": [],
        }

    if any(o.get("unsupported") for o in candidates):
        return {
            "key": delta.key, "status": "unsupported", "found": None,
            "mismatch": None, "message": "evidence contains unsupported parser constructs for this section",
            "evidence_ids": [o["id"] for o in candidates],
        }

    found_by_obs = {o["id"]: _section_has(delta.section, o, delta) for o in candidates}
    distinct = {True, False}
    opinions = set(found_by_obs.values())
    if len(opinions) > 1 and not precedence:
        return {
            "key": delta.key, "status": "inconclusive", "found": None,
            "mismatch": None, "message": "conflicting evidence sources report different results",
            "evidence_ids": list(found_by_obs.keys()),
        }

    if precedence:
        ordered = sorted(candidates, key=lambda o: _precedence_index(o.get("source"), precedence))
        chosen = ordered[0]
    else:
        chosen = max(candidates, key=lambda o: iso_parse(o.get("collected_at")) or _dt.datetime.min)
    found = found_by_obs[chosen["id"]]
    evidence_ids = [chosen["id"]]

    if chosen.get("coverage", 0) < 1.0 and not found:
        return {
            "key": delta.key, "status": "inconclusive", "found": found,
            "mismatch": None, "message": "section sampled but coverage incomplete",
            "evidence_ids": evidence_ids,
        }
    if delta.needs_before and not delta.before:
        return {
            "key": delta.key, "status": "inconclusive", "found": found,
            "mismatch": None, "message": "removal has no pre-change value to confirm against",
            "evidence_ids": evidence_ids,
        }

    match_result = _match_expectation(delta, found)
    if match_result is None:
        return {
            "key": delta.key, "status": "inconclusive", "found": found,
            "mismatch": None, "message": "required state unavailable in evidence",
            "evidence_ids": evidence_ids,
        }
    if match_result["match"]:
        return {
            "key": delta.key, "status": "confirmed", "found": found,
            "mismatch": None, "message": match_result["message"], "evidence_ids": evidence_ids,
        }
    mm = match_result["mismatch"]
    mm["key"] = delta.key
    mm["section"] = delta.section
    mm["device"] = delta.device
    mm["label"] = delta.label
    return {
        "key": delta.key, "status": "mismatch", "found": found,
        "mismatch": mm, "message": match_result["message"], "evidence_ids": evidence_ids,
    }


def _precedence_index(source: str, precedence: list[str]) -> int:
    try:
        return precedence.index(source)
    except ValueError:
        return len(precedence)


def compare_observed_state(prediction: dict, observations: list[dict],
                           source_precedence: list[str] | None = None) -> dict:
    """Compare observed post-change evidence against the predicted state.

    Returns the verification result with a lifecycle status. Missing, stale or
    conflicting evidence is never converted into a pass.
    """
    deltas = [_delta_from_dict(d) for d in (prediction.get("deltas") or [])]
    device_map = prediction.get("device_map") or {}
    results = [_check_delta(d, observations, source_precedence, device_map) for d in deltas]

    mismatches: list[dict] = []
    confirmed = consist = unsupported_k = 0
    for r in results:
        if r["status"] == "confirmed":
            confirmed += 1
        elif r["status"] == "inconclusive":
            consist += 1
        elif r["status"] == "unsupported":
            unsupported_k += 1
        elif r["mismatch"]:
            mismatches.append(r["mismatch"])

    unexpected = _unexpected_changes(prediction, observations)
    status, edge_cases = _status_for(prediction, deltas, results, mismatches, unexpected)
    total = max(len(results), 1)

    return {
        "status": status,
        "edge_cases": edge_cases,
        "summary": {
            "deltas_checked": len(results),
            "deltas_confirmed": confirmed,
            "deltas_inconclusive": consist,
            "deltas_unsupported": unsupported_k,
            "mismatches": len(mismatches),
            "critical_mismatches": sum(1 for m in mismatches if m.get("severity") == "critical"),
            "unexpected_changes": len(unexpected),
            "coverage": _coverage_map(observations),
            "confidence": round(confirmed / total, 3),
            "messages": [r["message"] for r in results if r["status"] != "confirmed"],
            "checked_at": iso_now(),
        },
        "mismatches": mismatches,
        "unexpected_changes": unexpected,
    }


def _status_for(prediction: dict, deltas: list[PredictedDelta], results: list[dict],
                mismatches: list[dict], unexpected: list[dict] | None = None) -> tuple[str, list[str]]:
    edge_cases: list[str] = []
    change = prediction.get("change") or {}

    if any(r["status"] == "unsupported" for r in results):
        edge_cases.append("unsupported parser constructs in sampled evidence")
        return STATUS_UNSUPPORTED, edge_cases

    if not deltas:
        edge_cases.append("no resource deltas derivable from the change")
        return STATUS_INCONCLUSIVE, edge_cases

    critical = [m for m in mismatches if m.get("severity") == "critical"]
    if any(m.get("kind") == MISMATCH_EXPECTED_MISSING for m in critical):
        edge_cases.append("an expected addition is absent from the post-change evidence")
        return STATUS_FAILED, edge_cases

    if any(m["kind"] == MISMATCH_UNEXPECTED_PRESENT for m in critical):
        edge_cases.append("a change that should have removed state is still present")
        return STATUS_MISMATCH, edge_cases

    if critical:
        edge_cases.append("critical content mismatch between prediction and evidence")
        return STATUS_MISMATCH, edge_cases

    critical_unconfirmed = any(
        r["status"] == "inconclusive" and d.impact == "critical" and not d.advisory
        for d, r in zip(deltas, results)
    )
    if critical_unconfirmed:
        edge_cases.append("critical-impact delta not independently confirmed")
        return STATUS_INCONCLUSIVE, edge_cases

    primary_inconclusive = any(
        r["status"] == "inconclusive" and not d.advisory for d, r in zip(deltas, results))
    if primary_inconclusive:
        edge_cases.append("primary deltas lack confirmable evidence")
        return STATUS_INCONCLUSIVE, edge_cases

    warnings = [m for m in mismatches if m.get("severity") == "warning"]
    if warnings or any(m["kind"] == MISMATCH_UNEXPECTED_CHANGE for m in mismatches) \
            or unexpected:
        edge_cases.append("unexpected or low-severity divergence from the prediction")
        return STATUS_VERIFIED_WITH_WARNINGS, edge_cases

    return STATUS_VERIFIED, edge_cases


def _unexpected_changes(prediction: dict, observations: list[dict]) -> list[dict]:
    baseline = prediction.get("baseline") or {}
    changed_sections = {d.get("section") for d in (prediction.get("deltas") or [])}
    filter_name = (prediction.get("change") or {}).get("filter", "")
    expected_resource_ids = set()
    for d in (prediction.get("deltas") or []):
        rule = d.get("expected") or {}
        if d.get("section") == "filters" and rule:
            expected_resource_ids.add(deterministic_json(
                {"section": "filters", "filter": filter_name, "rule": rule}))
        elif d.get("section") == "routes" and rule:
            expected_resource_ids.add(deterministic_json({"section": "routes", "route": rule}))

    out: list[dict] = []
    for obs in observations:
        section = obs.get("section")
        if section not in changed_sections:
            continue
        if obs.get("source") in ("probe", "discovery"):
            continue
        baseline_sect = baseline.get(section) or {}
        if not (baseline_sect.get("device") or baseline_sect.get("global")):
            continue
        canonical_items = _canonical_section_items(section, _section_content(obs, section))
        baseline_dev = baseline_sect.get("device", {}).get(obs.get("device")) or []
        baseline_global = baseline_sect.get("global") or []
        for item in canonical_items:
            if item in expected_resource_ids:
                continue
            if item in baseline_dev or item in baseline_global:
                continue
            parsed = json.loads(item)
            out.append({
                "kind": MISMATCH_UNEXPECTED_CHANGE,
                "status": "unexpected_change",
                "severity": "warning",
                "detail": f"Observed {section} state on {obs.get('device') or 'global'} that "
                          "was neither part of the predicted change nor present before it.",
                "expected": None, "observed": parsed.get("item", parsed.get("rule", parsed)),
                "evidence_ids": [obs["id"]],
            })
            if len(out) >= _MAX_UNEXPECTED:
                return out
    return out


def _coverage_map(observations: list[dict]) -> dict:
    groups: dict[str, dict] = {}
    for obs in observations:
        section = obs.get("section", "")
        g = groups.get(section)
        if g is None:
            g = {"sampled": True, "sources": [], "freshest": obs.get("collected_at"), "stale": bool(obs.get("stale"))}
            groups[section] = g
        if obs.get("source") not in g["sources"]:
            g["sources"].append(obs["source"])
        if (iso_parse(obs.get("collected_at")) or _dt.datetime.min) > (iso_parse(g["freshest"]) or _dt.datetime.min):
            g["freshest"] = obs.get("collected_at")
        if obs.get("stale"):
            g["stale"] = True
    return groups


# --------------------------------------------------------------------------- #
# read-only health checks                                                      #
# --------------------------------------------------------------------------- #

def _hck(ident, status, expected, observed, evidence_ids, confidence, explanation) -> dict:
    return {
        "id": ident, "status": status, "expected": expected, "observed": observed,
        "evidence_ids": evidence_ids, "confidence": round(float(confidence), 3),
        "explanation": explanation,
    }


def run_health_checks(model, observations: list[dict], requirements: list[dict] | None = None) -> list[dict]:
    """Run read-only health checks from observations against a model.

    ``model`` may be a reconstructed ``Net`` (from the stored snapshot) or
    ``None`` for model-free checks. Health checks never touch live devices —
    they only reason over the supplied evidence.
    """
    checks: list[dict] = []
    requirements = requirements or []

    def section_obs(section: str) -> list[dict]:
        return [o for o in observations if o.get("section") == section]

    def count_items(section: str, kind: str = "") -> int:
        total = 0
        for o in observations:
            if o.get("section") != section:
                continue
            body = _section_content(o, section)
            if isinstance(body, list):
                total += len(body)
            elif isinstance(body, dict):
                total += 1
        return total

    has_fresh = not any(o.get("stale") for o in observations)

    device_obs = section_obs("device")
    alive = sum(1 for o in device_obs if o.get("content", {}).get("device"))
    checks.append(_hck(
        "device_reachability",
        "pass" if device_obs and alive == len(device_obs) else ("unknown" if not device_obs else "warn"),
        f"every discovered device ({len(device_obs)}) reachable at collection time",
        f"{alive}/{len(device_obs)} devices responded to the probe" if device_obs else "no device probes",
        [o["id"] for o in device_obs],
        1.0 if device_obs and alive == len(device_obs) else 0.0,
        "Reachability is inferred from live discovery at evidence collection time only.",
    ))

    iface_obs = section_obs("interfaces")
    if iface_obs:
        checks.append(_hck("interface_state", "pass" if not any(o.get("errors") for o in iface_obs) else "warn",
                           "interface operational state present", "interfaces captured in snapshot evidence",
                           [o["id"] for o in iface_obs], 1.0, "Interface state read from config snapshot."))
    else:
        checks.append(_hck("interface_state", "unknown", "operational interface state", [], [], 0.0,
                           "No interface evidence supplied."))

    route_obs = section_obs("routes")
    if route_obs:
        total_routes = count_items("routes")
        checks.append(_hck("route_presence", "pass" if total_routes else "unknown",
                           "expected static routes present", f"{total_routes} route(s) observed",
                           [o["id"] for o in route_obs], 1.0 if total_routes else 0.0,
                           "Route tables read from snapshot/config evidence."))
    else:
        checks.append(_hck("route_presence", "unknown", "static route tables", [], [], 0.0,
                           "No route evidence supplied; route presence unconfirmed."))

    bgp_obs = section_obs("bgp")
    peers = count_items("bgp")
    checks.append(_hck("bgp_session",
                       "pass" if peers > 0 else ("unknown" if not bgp_obs else "warn"),
                       "BGP sessions present", f"{peers} peer(s) observed" if bgp_obs else "no BGP evidence",
                       [o["id"] for o in bgp_obs], 1.0 if peers else 0.0,
                       "BGP state read from evidence."))

    ospf_obs = section_obs("ospf")
    areas = count_items("ospf")
    checks.append(_hck("ospf_adjacency",
                       "pass" if areas > 0 else ("unknown" if not ospf_obs else "warn"),
                       "OSPF adjacency present", f"{areas} area(s) observed" if ospf_obs else "no OSPF evidence",
                       [o["id"] for o in ospf_obs], 1.0 if areas else 0.0,
                       "OSPF state read from evidence."))

    vlan_obs = section_obs("vlan_assignment")
    vlans = count_items("vlan_assignment")
    checks.append(_hck("vlan_assignment",
                       "pass" if vlans > 0 else ("unknown" if not vlan_obs else "warn"),
                       "VLAN assignments present", f"{vlans} assignment(s) observed" if vlan_obs else "no VLAN evidence",
                       [o["id"] for o in vlan_obs], 1.0 if vlans else 0.0,
                       "VLAN state read from evidence."))

    filt_obs = section_obs("filters")
    total_filters = count_items("filters")
    if filt_obs:
        checks.append(_hck("acl_presence", "pass" if total_filters else "warn",
                           "ACL / firewall filters present", f"{total_filters} filter(s) observed",
                           [o["id"] for o in filt_obs], 1.0, "ACL presence read from evidence."))
        checks.append(_hck("acl_ordering", "pass" if not any(o.get("errors") for o in filt_obs) else "warn",
                           "rule order matches snapshot", "rule indexes preserved in snapshot evidence",
                           [o["id"] for o in filt_obs], 1.0,
                           "Rule ordering is read from the confirmed snapshot; exact device state unverified."))
    else:
        checks.append(_hck("acl_presence", "unknown", "ACL / firewall filters present", [], [], 0.0,
                           "No ACL evidence supplied."))
        checks.append(_hck("acl_ordering", "unknown", "rule order preserved", [], [], 0.0,
                           "No ACL evidence supplied."))

    nat_obs = section_obs("dst_nat")
    nats = count_items("dst_nat")
    checks.append(_hck("nat_presence",
                       "pass" if nats > 0 else ("unknown" if not nat_obs else "warn"),
                       "port-forward / NAT rules present", f"{nats} forward(s) observed" if nat_obs else "no NAT evidence",
                       [o["id"] for o in nat_obs], 1.0 if nats else 0.0,
                       "NAT state read from evidence."))

    req_flows = [r for r in requirements if str(r.get("expect", "")).lower() == "reachable"]
    reach_obs = section_obs("reachability")
    if req_flows and reach_obs:
        reach_ok = []
        for o in reach_obs:
            flows = _section_content(o, "reachability")
            if isinstance(flows, dict):
                reach_ok.append(bool(flows.get("reachable")))
        pass_ = bool(reach_ok) and all(reach_ok)
        checks.append(_hck("required_flow", "pass" if pass_ else "fail",
                           "all required flows reachable", f"{sum(reach_ok)}/{len(reach_ok)} flows reachable",
                           [o["id"] for o in reach_obs], 1.0 if reach_ok else 0.0,
                           "Reachability judged on explicit observation evidence only."))
    else:
        checks.append(_hck("required_flow", "pass" if not req_flows else "unknown",
                           "required flows reachable" if req_flows else "no required flows to verify",
                           [r.get("name") for r in req_flows], [],
                           1.0 if not req_flows else 0.0,
                           ("No reachability observations supplied for required flows.") if req_flows
                           else "No required flows defined."))

    protected_services = [r for r in requirements
                          if str(r.get("expect", "")).lower() == "reachable" and r.get("dport")]
    svc_obs = section_obs("services")
    seen_ports = set()
    for o in svc_obs:
        body = _section_content(o, "services")
        items = body if isinstance(body, list) else []
        seen_ports.update(int(s.get("port")) for s in items if isinstance(s, dict) and s.get("port") is not None)
    missing = sorted({int(r.get("dport")) for r in protected_services} - seen_ports)
    if protected_services and svc_obs:
        checks.append(_hck("protected_service", "pass" if not missing else "warn",
                           f"protected services on ports {sorted({int(r.get('dport')) for r in protected_services})} reachable",
                           f"missing: {missing or 'none'}",
                           [o["id"] for o in svc_obs], 1.0 if not missing else 0.6,
                           "Service reachability inferred from discovery probes at collection time."))
    else:
        checks.append(_hck("protected_service", "pass" if not protected_services else "unknown",
                           "protected services reachable" if protected_services else "no protected services",
                           [r.get("name") for r in protected_services], [],
                           1.0 if not protected_services else 0.0,
                           ("No service probes for protected services.") if protected_services
                           else "No protected services defined."))

    deny_reqs = [r for r in requirements if str(r.get("expect", "")).lower() in ("denied", "blocked")]
    checks.append(_hck("required_non_reachability",
                       "unknown" if deny_reqs and not reach_obs else ("pass" if not deny_reqs else "unknown"),
                       "blocked flows stay blocked" if deny_reqs else "no denied flow requirements",
                       [r.get("name") for r in deny_reqs], [],
                       0.5 if deny_reqs and reach_obs else (1.0 if not deny_reqs else 0.0),
                       "Non-reachability of denied flows is not provable from config snapshot evidence."))

    dns_obs = section_obs("dns")
    dns_count = count_items("dns")
    checks.append(_hck("dns_resolution",
                       "pass" if dns_count else ("unknown" if not dns_obs else "warn"),
                       "DNS records present", f"{dns_count} record(s) observed" if dns_obs else "no DNS evidence",
                       [o["id"] for o in dns_obs], 1.0 if dns_count else 0.0,
                       "DNS state read from evidence."))

    checks.append(_hck("evidence_freshness", "pass" if has_fresh else "fail",
                       "evidence fresher than stale window",
                       "all observations in-window" if has_fresh else "stale observations present",
                       [], 1.0 if has_fresh else 0.0,
                       "Stale evidence is never treated as a pass."))
    return checks


# --------------------------------------------------------------------------- #
# rollback                                                                    #
# --------------------------------------------------------------------------- #

_TRIGGER_TITLES = {
    "critical_flow_broken": "Critical flow broken",
    "route_absent": "Route absent",
    "security_boundary_violated": "Security boundary violated",
    "incomplete_deployment": "Deployment incomplete",
    "control_plane_down": "Control-plane down",
}


def inverse_change(change: dict, prediction: dict | None = None) -> tuple[dict | None, list[str]]:
    """Derive a deterministic inverse change (never vendor commands).

    Returns ``(inverse, warnings)``. ``inverse`` is ``None`` when a safe inverse
    cannot be derived from the information available (e.g. the pre-change value
    of a removed resource was not captured).
    """
    ctype = change.get("type", "")
    warnings: list[str] = []
    before_for: dict | None = None

    if ctype == "add_filter_rule":
        filt = str(change.get("filter", ""))
        idx = int(change.get("at_index", 0) or 0)
        warnings.append("Confirm the exact rule identity before removing; indexes can shift.")
        return {"type": "remove_filter_rule", "filter": filt, "at_index": idx}, warnings

    if ctype == "remove_filter_rule":
        filt = str(change.get("filter", ""))
        idx = int(change.get("at_index", change.get("index", 0)) or 0)
        before_for = _before_for_change(change, prediction)
        if not before_for:
            warnings.append("Pre-change rule content was not captured; cannot restore the removed rule.")
            return None, warnings
        warnings.append("Restores the removed rule at its original position; re-verify after applying.")
        return {"type": "add_filter_rule", "filter": filt, "at_index": idx, "rule": before_for}, warnings

    if ctype == "replace_filter_rule":
        filt = str(change.get("filter", ""))
        idx = int(change.get("at_index", change.get("index", 0)) or 0)
        before_for = _before_for_change(change, prediction)
        if not before_for:
            warnings.append("Pre-change rule content was not captured; cannot restore the replaced rule.")
            return None, warnings
        return {"type": "replace_filter_rule", "filter": filt, "at_index": idx, "rule": before_for}, warnings

    if ctype == "add_route":
        device = str(change.get("device", ""))
        route = change.get("route") or {}
        warnings.append("Rollback removes the added route; confirm route identity first.")
        return {"type": "remove_route_by_value", "device": device, "route": dict(route)}, warnings

    if ctype == "remove_route":
        device = str(change.get("device", ""))
        before_for = _before_for_change(change, prediction)
        if not before_for:
            warnings.append("Pre-change route was not captured; can only re-add after inspection.")
            return None, warnings
        warnings.append("Restores the removed route; re-spot the position after applying.")
        return {"type": "add_route", "device": device, "route": before_for}, warnings

    if ctype == "add_dst_nat":
        device = str(change.get("device", ""))
        warnings.append("Removes the port-forward; confirm the public IP/port before applying.")
        return {"type": "remove_dst_nat_by_value", "device": device, "dst_nat": dict(change.get("dst_nat") or {})}, warnings

    if ctype == "remove_dst_nat":
        device = str(change.get("device", ""))
        before_for = _before_for_change(change, prediction)
        if not before_for:
            warnings.append("Pre-change forward rule was not captured; restore by inspection.")
            return None, warnings
        return {"type": "add_dst_nat", "device": device, "dst_nat": before_for}, warnings

    if ctype in ("add_bgp_peer", "remove_bgp_peer"):
        device = str(change.get("device", ""))
        peer = change.get("peer") or change.get("bgp_peer") or change
        if ctype == "add_bgp_peer":
            return {"type": "remove_bgp_peer", "device": device, "peer": peer}, warnings
        before_for = _before_for_change(change, prediction)
        if not before_for:
            warnings.append("Pre-change BGP peer was not captured; peer details unknown.")
            return None, warnings
        return {"type": "add_bgp_peer", "device": device, "peer": before_for}, warnings

    if ctype in ("add_ospf_network", "remove_ospf_network"):
        device = str(change.get("device", ""))
        area_id = int(change.get("area_id", change.get("area", 0)))
        network = str(change.get("network", ""))
        if ctype == "add_ospf_network":
            return {"type": "remove_ospf_network", "device": device, "area_id": area_id, "network": network}, warnings
        return {"type": "add_ospf_network", "device": device, "area_id": area_id, "network": network}, warnings

    if ctype in ("add_dns_record", "remove_dns_record"):
        device = str(change.get("device", ""))
        rec = change.get("record") or {}
        if ctype == "add_dns_record":
            return {"type": "remove_dns_record", "device": device, "record": rec}, warnings
        before_for = _before_for_change(change, prediction)
        if not before_for:
            warnings.append("Pre-change DNS record was not captured; restore by inspection.")
            return None, warnings
        return {"type": "add_dns_record", "device": device, "record": before_for}, warnings

    if ctype in ("add_vlan_assignment", "remove_vlan_assignment"):
        device = str(change.get("device", ""))
        vlan = change.get("vlan") or change
        if ctype == "add_vlan_assignment":
            return {"type": "remove_vlan_assignment", "device": device, "vlan": vlan}, warnings
        before_for = _before_for_change(change, prediction)
        if not before_for:
            warnings.append("Pre-change VLAN assignment was not captured; restore by inspection.")
            return None, warnings
        return {"type": "add_vlan_assignment", "device": device, "vlan": before_for}, warnings

    warnings.append(f"no inverse derivation for change type '{ctype}'")
    return None, warnings


def _before_for_change(change: dict, prediction: dict | None) -> dict | None:
    ctype = change.get("type", "")
    for d in (prediction or {}).get("deltas") or []:
        if d.get("change_type") != ctype:
            continue
        before = d.get("before")
        if before is not None:
            return before
    return None


def _trigger_for(mismatch: dict) -> str | None:
    section = str(mismatch.get("section", ""))
    label = str(mismatch.get("label", ""))
    if "flow" in label or section == "reachability" or section == "requirements":
        return "critical_flow_broken"
    if section == "routes":
        return "route_absent"
    if section in ("filters", "dst_nat") and mismatch.get("severity") == "critical":
        return "security_boundary_violated"
    if section in ("bgp", "ospf", "control_plane"):
        return "control_plane_down"
    if mismatch.get("kind") == MISMATCH_EXPECTED_MISSING:
        return "incomplete_deployment"
    return None


def build_rollback_recommendation(verification: dict, original_change: dict | None = None) -> dict:
    """Build a read-only rollback recommendation from a completed verification.

    Never executes anything. The inverse change is a NetProof change object
    (replayable through the same validation engine), never invented vendor
    commands, and is omitted when it cannot be derived safely.
    """
    status = verification.get("status")
    result = verification.get("result") or {}
    mismatches = result.get("mismatches") or []
    change = original_change or (verification.get("change") or {})
    prediction = verification.get("prediction") or {}

    if status not in (STATUS_MISMATCH, STATUS_FAILED, STATUS_VERIFIED_WITH_WARNINGS):
        return {
            "recommended": False,
            "reason": "no rollback is recommended while verification has not failed",
            "triggers": [], "affected_systems": [], "original_change": change,
            "inverse_change": None, "warnings": [],
            "requires_human_approval": True,
            "requires_post_rollback_verification": True,
            "vendor_commands": None,
        }

    critical = [m for m in mismatches if m.get("severity") == "critical"]
    considered = critical or mismatches
    triggers: list[dict] = []
    affected: list[str] = []
    seen: set[str] = set()
    for m in considered:
        trig = _trigger_for(m)
        if trig is None or trig in seen:
            continue
        seen.add(trig)
        device = m.get("device")
        if device and device not in affected:
            affected.append(device)
        triggers.append({
            "id": trig,
            "title": _TRIGGER_TITLES.get(trig, trig.replace("_", " ")),
            "severity": m.get("severity", "critical"),
            "evidence_ids": m.get("evidence_ids") or [],
            "detail": m.get("detail", ""),
        })

    inverse, warnings = inverse_change(change, prediction)
    recommended = bool(triggers)
    return {
        "recommended": recommended,
        "reason": "post-change evidence conflicts with the predicted state" if recommended
                  else "evidence does not justify a rollback",
        "triggers": triggers,
        "affected_systems": affected,
        "original_change": change,
        "inverse_change": inverse,
        "warnings": warnings,
        "requires_human_approval": True,
        "requires_post_rollback_verification": True,
        "vendor_commands": None,
    }


# --------------------------------------------------------------------------- #
# persistence                                                                 #
# --------------------------------------------------------------------------- #

_VERIFICATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS verifications (
    id                  TEXT PRIMARY KEY,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    org_id              TEXT,
    requester           TEXT,
    verdict_id          TEXT NOT NULL,
    change_fingerprint  TEXT,
    status              TEXT NOT NULL,
    payload             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verifications_org_created ON verifications (org_id, created_at);
"""

_conns: dict[str, sqlite3.Connection] = {}
_verif_lock = threading.RLock()


def _conn(db: str = DEFAULT_DB) -> sqlite3.Connection:
    with _verif_lock:
        conn = _conns.get(db)
        if conn is None:
            Path(db).parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(db, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.executescript(_VERIFICATION_SCHEMA)
            _conns[db] = conn
        return conn


def init_verifications(db: str = DEFAULT_DB) -> None:
    _conn(db)


def create_verification(verdict_id: str, org_id: str = "default", requester: str | None = None,
                        change: dict | None = None, prediction: dict | None = None,
                        source_precedence: list[str] | None = None,
                        db: str = DEFAULT_DB) -> dict:
    """Persist a new verification in the ``not_started`` lifecycle state."""
    from .audit import change_fingerprint
    now = iso_now()
    vid = uuid.uuid4().hex[:16]
    fingerprint = change_fingerprint(change or {}) if change else ""
    payload = {
        "id": vid,
        "created_at": now,
        "updated_at": now,
        "org_id": org_id,
        "requester": requester,
        "verdict_id": verdict_id,
        "change_fingerprint": fingerprint,
        "status": STATUS_NOT_STARTED,
        "change": change or {},
        "prediction": prediction or {},
        "source_precedence": source_precedence or [],
        "evidence": [],
        "observations": [],
        "result": None,
        "rollback": None,
        "health_checks": [],
        "bundle": None,
    }
    with _verif_lock:
        conn = _conn(db)
        conn.execute(
            "INSERT INTO verifications (id, created_at, updated_at, org_id, requester, verdict_id, "
            "change_fingerprint, status, payload) VALUES (?,?,?,?,?,?,?,?,?)",
            (vid, now, now, org_id, requester, verdict_id, fingerprint, STATUS_NOT_STARTED,
             deterministic_json(payload)),
        )
        conn.commit()
    return payload


def get_verification(vid: str, db: str = DEFAULT_DB) -> dict | None:
    with _verif_lock:
        row = _conn(db).execute("SELECT * FROM verifications WHERE id = ?", (vid,)).fetchone()
    if row is None:
        return None
    payload = json.loads(row["payload"])
    payload["id"] = row["id"]
    payload["status"] = row["status"]
    payload["created_at"] = row["created_at"]
    payload["updated_at"] = row["updated_at"]
    payload["org_id"] = row["org_id"] or "default"
    payload["verdict_id"] = row["verdict_id"]
    payload["change_fingerprint"] = row["change_fingerprint"]
    return payload


def list_verifications(org_id: str | None = None, limit: int = 20, db: str = DEFAULT_DB) -> list[dict]:
    with _verif_lock:
        if org_id:
            rows = _conn(db).execute(
                "SELECT id, created_at, updated_at, org_id, requester, verdict_id, change_fingerprint, "
                "status, payload FROM verifications WHERE org_id = ? ORDER BY created_at DESC LIMIT ?",
                (org_id, int(limit)),
            ).fetchall()
        else:
            rows = _conn(db).execute(
                "SELECT id, created_at, updated_at, org_id, requester, verdict_id, change_fingerprint, "
                "status, payload FROM verifications ORDER BY created_at DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
    out = []
    for row in rows:
        item = json.loads(row["payload"])
        item["id"] = row["id"]
        item["status"] = row["status"]
        item["created_at"] = row["created_at"]
        item["updated_at"] = row["updated_at"]
        out.append(item)
    return out


def _save(vid: str, payload: dict, db: str) -> None:
    with _verif_lock:
        conn = _conn(db)
        conn.execute(
            "UPDATE verifications SET updated_at = ?, status = ?, payload = ? WHERE id = ?",
            (payload["updated_at"], payload["status"], deterministic_json(payload), vid),
        )
        conn.commit()


def add_evidence(vid: str, documents: list[dict], db: str = DEFAULT_DB) -> dict:
    """Append evidence documents (redacted at rest) to a verification."""
    verification = get_verification(vid, db)
    if verification is None:
        raise KeyError(f"verification '{vid}' not found")
    if len(documents) > MAX_EVIDENCE_DOCS:
        raise ValueError(f"too many evidence documents: {len(documents)} exceeds {MAX_EVIDENCE_DOCS}")
    for doc in documents:
        normalize_evidence_doc(doc, ENGINE_VERSION, ENGINE_VERSION)
    persistence_ready = [_persisted_evidence(d) for d in documents]
    current = list(verification.get("evidence") or [])
    current.extend(persistence_ready)
    verification["evidence"] = current
    verification["updated_at"] = iso_now()
    if verification["status"] == STATUS_NOT_STARTED:
        verification["status"] = STATUS_AWAITING_OBSERVATION
    _save(vid, verification, db)
    return verification


def _persisted_evidence(doc: dict) -> dict:
    return redact_secrets(dict(doc))


def run_verification(vid: str, source_precedence: list[str] | None = None, db: str = DEFAULT_DB) -> dict:
    """Run comparison + health checks + rollback for a verification."""
    from .audit import get_snapshot, get_verdict
    verification = get_verification(vid, db)
    if verification is None:
        raise KeyError(f"verification '{vid}' not found")

    verdict = get_verdict(verification["verdict_id"], db=db)
    if verdict is None or not (verdict.get("report") or {}):
        raise ValueError(f"verdict '{verification['verdict_id']}' has no stored report to verify against")

    stored_prediction = verification.get("prediction") or {}
    prediction = stored_prediction if stored_prediction else build_prediction(verdict["report"], None)
    verification["prediction"] = prediction

    evidence_docs = verification.get("evidence") or []
    observations = extract_observations([_as_doc(d) for d in evidence_docs])
    verification["observations"] = observations

    result = compare_observed_state(prediction, observations, source_precedence)
    verification["result"] = result
    verification["status"] = result["status"]

    model = get_snapshot(verification["verdict_id"], db=db)
    requirements = [
        {"name": r.get("name"), "src": r.get("src"), "dst": r.get("dst"),
         "proto": r.get("proto"), "dport": r.get("dport"), "expect": r.get("expect")}
        for r in (verdict["report"].get("requirements") or [])
    ]
    verification["health_checks"] = run_health_checks(model, observations, requirements)
    verification["rollback"] = build_rollback_recommendation(verification)
    verification["updated_at"] = iso_now()
    verification["bundle"] = _bundle(verification, verdict)
    _save(vid, verification, db)
    return verification


def _as_doc(doc: dict) -> dict:
    if doc.get("content") is not None:
        return doc
    return {"content": doc}


def _bundle(verification: dict, verdict: dict | None) -> dict:
    report = (verdict or {}).get("report") or {}
    summary = report.get("summary") or {}
    return {
        "verification": {
            "id": verification["id"],
            "created_at": verification["created_at"],
            "updated_at": verification["updated_at"],
            "status": verification["status"],
            "requester": verification.get("requester"),
            "change": verification.get("change") or {},
            "prediction_summary": (verification.get("prediction") or {}).get("summary"),
            "result": verification.get("result"),
            "rollback": verification.get("rollback"),
            "health_checks": verification.get("health_checks") or [],
            "evidence_ids": [e.get("id") for e in verification.get("evidence") or []],
        },
        "verdict": {
            "id": verification["verdict_id"],
            "verdict_final": summary.get("verdict"),
            "trust_score": summary.get("trust_score"),
            "change_fingerprint": verification.get("change_fingerprint"),
        },
        "schema": SCHEMA_VERSION,
        "engine_version": ENGINE_VERSION,
        "exported_at": iso_now(),
        "redacted": True,
    }
