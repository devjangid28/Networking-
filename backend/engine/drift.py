"""Configuration drift detection (Phase 4).

Catch silent changes before they cause outages: compare the current model
against the last *approved* baseline snapshot (a previous non-blocked verdict
for the same network). Anything that moved off the baseline is surfaced as a
structured, risk-classified drift so an engineer can decide to document the
change or roll it back.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from .audit import DEFAULT_DB, _conn, canonical_snapshot
from .model import Net

SECTION_RISK = {
    "routes": "high",
    "filters": "high",
    "dst_nat": "high",
    "interfaces": "medium",
    "nat": "medium",
    "vlans": "medium",
    "bgp": "high",
    "ospf": "high",
    "dns": "low",
}


@dataclass
class DriftResult:
    """One discrete drift event found between the current model and a baseline."""
    has_drift: bool
    drift_type: str  # expected_change | undocumented_change | policy_violation | golden_baseline_mismatch
    details: dict = field(default_factory=dict)
    affected_flows: list = field(default_factory=list)
    suggested_action: str = ""


def classify_drift_risk(details: dict) -> str:
    """Risk of a drift detail: low / medium / high / critical.

    Device removal and routing/firewall section changes are the ones that
    silently kill traffic, so they weight higher than a comment or a TTL.
    """
    if details.get("section") == "device" and details.get("after") is None:
        return "critical"
    base = SECTION_RISK.get(details.get("section"), "medium")
    if details.get("device") and details["device"] in ("firewall", "router"):
        if base == "high":
            return "critical"
        if base == "medium":
            return "high"
    return base


def _snap_dict(net: Net) -> dict:
    return json.loads(canonical_snapshot(net))


def _diff_device_sections(before: dict, after: dict) -> list[dict]:
    """Per-device config-section diffs between two canonical snapshot dicts."""
    diffs: list[dict] = []
    bdevs = {d["name"]: d for d in before.get("devices") or []}
    adevs = {d["name"]: d for d in after.get("devices") or []}
    for name in sorted(set(bdevs) | set(adevs)):
        b = bdevs.get(name)
        a = adevs.get(name)
        if b is None and a is not None:
            diffs.append({"device": name, "section": "device", "kind": "added",
                          "before": None, "after": a.get("type"), "risk_level": "medium"})
            continue
        if b is not None and a is None:
            diffs.append({"device": name, "section": "device", "kind": "removed",
                          "before": b.get("type"), "after": None, "risk_level": "critical"})
            continue
        for section in ("routes", "bgp", "ospf", "dns", "vlans", "dst_nat", "nat"):
            if b.get(section) != a.get(section):
                diffs.append({"device": name, "section": section, "kind": "changed",
                              "before": b.get(section), "after": a.get(section),
                              "risk_level": classify_drift_risk({"section": section, "device": name})})
        b_if = {(i["name"], i["ip"], tuple(i.get("filters") or ())) for i in b.get("interfaces") or []}
        a_if = {(i["name"], i["ip"], tuple(i.get("filters") or ())) for i in a.get("interfaces") or []}
        if b_if != a_if:
            diffs.append({"device": name, "section": "interfaces", "kind": "changed",
                          "before": sorted(tuple(x) for x in b_if), "after": sorted(tuple(x) for x in a_if),
                          "risk_level": classify_drift_risk({"section": "interfaces", "device": name})})
    b_filt = {(f["name"], f["default"], f["stateful"], tuple((r["action"], r["src"], r["dst"], r["proto"], r["dport"]) for r in f.get("rules") or ()))
              for f in before.get("filters") or []}
    a_filt = {(f["name"], f["default"], f["stateful"], tuple((r["action"], r["src"], r["dst"], r["proto"], r["dport"]) for r in f.get("rules") or ()))
              for f in after.get("filters") or []}
    if b_filt != a_filt:
        names = sorted({elem[0] for s in (b_filt, a_filt) for elem in s})
        diffs.append({"device": "global", "section": "filters", "kind": "changed",
                      "before": names, "after": names,
                      "risk_level": classify_drift_risk({"section": "filters", "device": "firewall"})})
    return diffs


def baseline_meta(net: Net, org_id: str | None = None, db: str = DEFAULT_DB) -> tuple[Net | None, str | None]:
    """The most recent approved (non-blocked) snapshot for the same network,
    along with its creation time. Returns ``(None, None)`` when no baseline has
    been recorded yet - then drift is skipped instead of invented.
    """
    try:
        conn = _conn(db)
        row = conn.execute(
            "SELECT model_snapshot, created_at FROM verdicts "
            "WHERE model_name=? AND org_id IS ? AND verdict_final IN ('pass','warn') "
            "AND model_snapshot IS NOT NULL "
            "ORDER BY created_at DESC LIMIT 1",
            (net.name, org_id),
        ).fetchone()
    except Exception:
        return None, None
    if row is None or not row["model_snapshot"]:
        return None, None
    try:
        return Net.from_dict(json.loads(row["model_snapshot"])), row["created_at"]
    except Exception:
        return None, None


def baseline_for_org(net: Net, org_id: str | None = None, db: str = DEFAULT_DB) -> Net | None:
    baseline, _ = baseline_meta(net, org_id, db)
    return baseline


def detect_drift(current_net: Net, baseline_net: Net | None, org_id: str | None = None) -> list[DriftResult]:
    """Compare the current model against ``baseline_net``.

    No baseline -> no drift (first validation on a fresh DB). Otherwise every
    moved config section becomes one ``DriftResult`` with a risk classification
    and an actionable suggestion.
    """
    if baseline_net is None:
        return []
    cur = _snap_dict(current_net)
    base = _snap_dict(baseline_net)
    if cur == base:
        return []
    diffs = _diff_device_sections(base, cur)
    if not diffs:
        return []
    risk = max((d.get("risk_level") or "low") for d in diffs)
    results = []
    for d in diffs:
        results.append(DriftResult(
            has_drift=True,
            drift_type="golden_baseline_mismatch" if org_id else "undocumented_change",
            details=d,
            affected_flows=[],
            suggested_action=(
                "Rollback to baseline" if d.get("risk_level") in ("critical", "high")
                else "Document this change, or rollback if unexpected"
            ),
        ))
    summary = {
        "drifted_sections": len(diffs),
        "risk_level": risk,
        "diffs": diffs,
    }
    results.insert(0, DriftResult(
        has_drift=True,
        drift_type="golden_baseline_mismatch" if org_id else "undocumented_change",
        details=summary,
        affected_flows=_analyze_flow_impact(diffs),
        suggested_action=(
            "Review and document or rollback the drifted configuration"
            if risk in ("high", "critical") else "Review if this deviation is intentional"
        ),
    ))
    return results


def _analyze_flow_impact(diffs: list[dict]) -> list[str]:
    """The zone pairs a drifted section could plausibly affect (best-effort)."""
    flows: list[str] = []
    for d in diffs:
        if d.get("section") == "filters":
            flows.append("all zone pairs through the changed filter")
            break
        if d.get("section") in ("routes", "interfaces", "dst_nat"):
            flows.append(f"flows routed through {d.get('device')}")
    return flows