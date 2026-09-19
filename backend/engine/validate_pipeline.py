"""Multi-layer validation pipeline (Phase 6).

Runs validation in the order an engineer actually debugs a network problem:

  1. SYNTAX       - values are well-formed (actions, protocols, ports, addresses)
  2. SEMANTIC     - references resolve (filters/devices/interfaces/next hops exist)
  3. STATE        - configuration drift vs. the last approved baseline
  4. REACHABILITY - the differential engine proves before/after paths

Each layer short-circuits the next when it has a critical finding, so a value
that can never work does not waste time on reachability math. The reachability
layer doubles as the existing /api/validate report, so verdict schema stays
backward compatible.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .drift import baseline_for_org, detect_drift
from .model import Finding, Net, Prefix
from .validate import ENGINE_VERSION, _device_owning_ip, _section_for, validate_change


class ValidationLayer(Enum):
    SYNTAX = "syntax"
    SEMANTIC = "semantic"
    STATE = "state"
    REACHABILITY = "reachability"


@dataclass
class LayerResult:
    layer: ValidationLayer
    passed: bool
    findings: list = field(default_factory=list)
    duration_ms: float = 0.0
    report: Optional[dict] = None  # only the reachability layer carries the full report


def _pf(sev: str, category: str, title: str, detail: str, change: dict,
        device: Optional[str] = None, iface: Optional[str] = None,
        remediation: Optional[list] = None) -> dict:
    rem = remediation or ["Correct the reported value in the proposed change",
                          "Re-run validation to confirm the fix"]
    loc = {"change_type": change.get("type"),
           "config_section": _section_for(str(change.get("type") or ""))}
    if device:
        loc["device"] = device
    if iface:
        loc["interface"] = iface
    return Finding(
        severity=sev, type="pipeline", title=title, detail=detail,
        category=category, why=detail, location=loc,
        affected_flows=[], impact_score={"critical": 80, "warning": 50, "info": 10}[sev],
        plain_english=f"{sev.upper()}: {title}. {detail}" + (f" Fix: {rem[0]}" if rem else ""),
        remediation=rem, confidence="high", evidence={},
    ).to_dict()


def _is_port(v) -> bool:
    try:
        return 0 <= int(v) <= 65535
    except (TypeError, ValueError):
        return False


def _validate_syntax(change: dict, net: Net) -> list[dict]:
    """Values must be well-formed: actions, protocols, ports, addresses."""
    findings: list[dict] = []
    ctype = str(change.get("type") or "")
    dev = change.get("device")

    if ctype in ("add_filter_rule", "replace_filter_rule"):
        rule = change.get("rule") or {}
        action = str(rule.get("action") or "permit").lower()
        if action not in ("permit", "deny"):
            findings.append(_pf("critical", "syntax_error", "Invalid firewall action",
                                f"Action '{rule.get('action')}' must be permit or deny.", change))
        proto = str(rule.get("proto") or "any").lower()
        if proto not in ("any", "tcp", "udp", "icmp"):
            findings.append(_pf("critical", "syntax_error", "Unsupported protocol",
                                f"Protocol '{proto}' is not supported on a firewall rule.", change))
        dport = rule.get("dport")
        if dport not in (None, "", "any") and not _is_port(dport):
            findings.append(_pf("critical", "syntax_error", "Port out of range",
                                f"dport {dport!r} must be an integer between 0 and 65535.", change))
        for key in ("src", "dst"):
            val = rule.get(key)
            if val and val != "any":
                try:
                    Prefix.parse(str(val))
                except (ValueError, TypeError):
                    findings.append(_pf("critical", "syntax_error", f"Unparseable {key}",
                                        f"'{val}' is not a valid IP or CIDR.", change))

    if ctype in ("add_route", "replace_route"):
        route = change.get("route") or change
        net_txt = route.get("network")
        if net_txt:
            try:
                Prefix.parse(str(net_txt))
            except (ValueError, TypeError):
                findings.append(_pf("critical", "syntax_error", "Invalid network prefix",
                                    f"'{net_txt}' is not a valid network prefix.", change, device=dev))
        nh = route.get("next_hop")
        if nh:
            try:
                Prefix.parse(str(nh))
            except (ValueError, TypeError):
                findings.append(_pf("critical", "syntax_error", "Invalid next-hop address",
                                    f"'{nh}' is not a valid IP address.", change, device=dev))

    if ctype in ("add_dst_nat", "remove_dst_nat"):
        dn = change.get("dst_nat") or {}
        for k in ("public_port", "private_port"):
            v = dn.get(k)
            if v is not None and not _is_port(v):
                findings.append(_pf("critical", "syntax_error", "Port out of range",
                                    f"{k} {v!r} must be an integer between 0 and 65535.", change))
        proto = str(dn.get("proto") or "tcp").lower()
        if proto not in ("tcp", "udp"):
            findings.append(_pf("critical", "syntax_error", "Unsupported NAT protocol",
                                f"DST NAT protocol '{proto}' must be tcp or udp.", change))

    return findings


def _validate_semantic(change: dict, net: Net) -> list[dict]:
    """References must resolve: filters, devices, interfaces, next hops."""
    findings: list[dict] = []
    ctype = str(change.get("type") or "")
    dev_name = change.get("device")
    filt_name = change.get("filter")

    if filt_name and ctype in ("add_filter_rule", "remove_filter_rule", "replace_filter_rule"):
        filt = net.filters.get(filt_name)
        if filt is None:
            findings.append(_pf("critical", "semantic_error", "Unknown filter",
                                f"Filter '{filt_name}' does not exist in the model.", change))
        else:
            idx = int(change.get("at_index", change.get("index", 0)))
            if ctype in ("remove_filter_rule", "replace_filter_rule") and not (0 <= idx < len(filt.rules)):
                findings.append(_pf("critical", "semantic_error", "Rule index out of range",
                                    f"Rule {idx} does not exist in filter '{filt.name}' ({len(filt.rules)} rules).", change))

    if dev_name and dev_name not in net.devices:
        findings.append(_pf("critical", "semantic_error", "Unknown device",
                            f"Device '{dev_name}' does not exist in the model.", change))
        return findings

    if ctype in ("add_route", "replace_route", "remove_route"):
        if net.devices.get(dev_name) is not None:
            route = change.get("route") or change
            nh = route.get("next_hop")
            if nh and str(nh) != "any":
                if _device_owning_ip(net, str(nh)) is None:
                    try:
                        gw = net.gateway_for(int(Prefix.parse(str(nh)).lo))
                    except (ValueError, TypeError):
                        gw = None
                    if gw is None:
                        findings.append(_pf("critical", "semantic_error", "Next hop not routed",
                                            f"Next hop {nh} is neither owned by a modelled device nor on a connected subnet.",
                                            change, device=dev_name))

    if ctype in ("add_dst_nat", "remove_dst_nat"):
        dn = change.get("dst_nat") or {}
        pri = dn.get("private_ip")
        if pri and _device_owning_ip(net, str(pri)) is None:
            findings.append(_pf("warning", "semantic_error", "Port-forward target not in inventory",
                                f"Private target {pri} is not owned by any modelled device.", change,
                                device=dev_name, remediation=["Point the forward at a host the model actually owns"]))

    if ctype in ("add_vlan_assignment", "remove_vlan_assignment"):
        v = change.get("vlan") or change
        iface_val = change.get("iface") or (v.get("iface") if isinstance(v, dict) else None)
        dev = net.devices.get(dev_name)
        if dev is not None and iface_val and dev.iface(str(iface_val)) is None:
            findings.append(_pf("critical", "semantic_error", "Unknown interface",
                                f"Interface '{iface_val}' does not exist on '{dev_name}'.", change))

    return findings


def _validate_state(change: dict, net: Net, org_id: Optional[str]) -> list[dict]:
    """Silent config drift vs. the last approved baseline for this network."""
    findings: list[dict] = []
    baseline = baseline_for_org(net, org_id)
    for dr in detect_drift(net, baseline, org_id):
        detail_diffs = dr.details.get("diffs") or []
        risk = dr.details.get("risk_level") or "low"
        if not detail_diffs:
            continue  # only surface the summary DriftResult
        sev = "critical" if risk in ("high", "critical") else "warning"
        summary = f"{len(detail_diffs)} config section(s) moved off the last approved baseline"
        findings.append(_pf(
            sev, "compliance_drift", f"Configuration drift: {summary}",
            dr.suggested_action + f" ({summary}: " + "; ".join(
                f"{d.get('device')}/{d.get('section')}" for d in detail_diffs[:6]) + ").",
            change,
            remediation=[dr.suggested_action.capitalize(), "Re-run validation against a fresh baseline"],
        ))
    return findings


def _state_summary(net: Net, org_id: Optional[str]) -> dict | None:
    """Compact drift verdict for the dashboard chip (None when nothing drifted)."""
    baseline = baseline_for_org(net, org_id)
    results = detect_drift(net, baseline, org_id)
    if not results:
        return None
    lead = results[0]
    return {
        "has_drift": True,
        "risk_level": lead.details.get("risk_level") or "low",
        "diff_count": lead.details.get("drifted_sections") or 0,
        "drift_type": lead.drift_type,
        "baseline_exists": baseline is not None,
        "suggested_action": lead.suggested_action,
    }


def _layer_syntax(change, net) -> LayerResult:
    t0 = time.perf_counter()
    f = _validate_syntax(change, net)
    return LayerResult(ValidationLayer.SYNTAX, not any(x["severity"] == "critical" for x in f), f,
                       (time.perf_counter() - t0) * 1000)


def _layer_semantic(change, net) -> LayerResult:
    t0 = time.perf_counter()
    f = _validate_semantic(change, net)
    return LayerResult(ValidationLayer.SEMANTIC, not any(x["severity"] == "critical" for x in f), f,
                       (time.perf_counter() - t0) * 1000)


def _layer_state(change, net, org_id) -> LayerResult:
    t0 = time.perf_counter()
    f = _validate_state(change, net, org_id)
    return LayerResult(ValidationLayer.STATE, not any(x["severity"] == "critical" for x in f), f,
                       (time.perf_counter() - t0) * 1000)


def _layer_reachability(change, net) -> LayerResult:
    t0 = time.perf_counter()
    report = validate_change(net, change)  # ValueError propagates to /api/validate (400)
    f = report["findings"]
    return LayerResult(ValidationLayer.REACHABILITY, not any(x["severity"] == "critical" for x in f), f,
                       (time.perf_counter() - t0) * 1000, report=report)


def _layer_meta(layer_results: list[LayerResult]) -> list[dict]:
    return [{
        "layer": l.layer.value,
        "passed": l.passed,
        "duration_ms": round(l.duration_ms, 1),
        "finding_count": len(l.findings),
    } for l in layer_results]


def _blocked_report(change: dict, net: Net, blockers: list[LayerResult], drift: dict | None = None) -> dict:
    findings = [f for l in blockers for f in l.findings]
    crits = [f for f in findings if f["severity"] == "critical"]
    warns = [f for f in findings if f["severity"] == "warning"]
    infos = [f for f in findings if f["severity"] == "info"]
    score = max(0, min(100, 100 - len(crits) * 65 - len(warns) * 20 - len(infos) * 3))
    report = {
        "network": net.name,
        "engine_version": ENGINE_VERSION,
        "change": change,
        "summary": {
            "verdict": "block",
            "pass": False,
            "trust_score": score,
            "blocked": len(crits),
            "warnings": len(warns),
            "info": len(infos),
            "flows_checked": 0,
            "stopped_before_reachability": True,
        },
        "findings": sorted(findings, key=lambda x: {"critical": 0, "warning": 1, "info": 2}[x["severity"]]),
        "matrix": {},
        "requirements": [],
        "trace": [],
        "checklist": [{
            "id": "traffic_impact", "status": "fail",
            "label": "Validation stopped before reachability",
            "detail": "Fix the layer findings above to unlock the traffic-impact checklist.",
        }],
        "before": {"reachable": 0, "total": 0},
        "after": {"reachable": 0, "total": 0},
        "control_plane": {"before": {}, "after": {}},
    }
    report["pipeline"] = {"layers": _layer_meta(blockers), "verdict": "block",
                          "reason": f"stopped in {blockers[0].layer.value} validation"}
    if drift:
        report["drift"] = drift
    return report


def run_validation_pipeline(change: dict, net: Net, org_id: Optional[str] = None) -> dict:
    """Run the four layers; return ``{"layers": [...], "report": {...}}``.

    The reachability layer reuses the existing differential validator, so every
    field the API used to return is still present, plus a new ``report.pipeline``
    block describing each layer for the dashboard progress bar.
    """
    layers: list[LayerResult] = []
    blockers: list[LayerResult] = []

    syntax = _layer_syntax(change, net)
    layers.append(syntax)
    if not syntax.passed:
        blockers.append(syntax)

    if not blockers:
        semantic = _layer_semantic(change, net)
        layers.append(semantic)
        if not semantic.passed:
            blockers.append(semantic)

    if not blockers:
        state = _layer_state(change, net, org_id)
        layers.append(state)
        if not state.passed:
            blockers.append(state)

    if blockers:
        drift = None
        if any(l.layer == ValidationLayer.STATE for l in layers):
            drift = _state_summary(net, org_id)
        report = _blocked_report(change, net, blockers, drift)
        return {"layers": layers, "report": report}

    reach = _layer_reachability(change, net)
    layers.append(reach)
    report = reach.report
    drift = _state_summary(net, org_id)
    if drift:
        report["drift"] = drift
    report["pipeline"] = {"layers": _layer_meta(layers),
                          "verdict": report["summary"]["verdict"],
                          "reason": "reachability validation completed"}
    report["summary"]["stopped_before_reachability"] = False
    return {"layers": layers, "report": report}