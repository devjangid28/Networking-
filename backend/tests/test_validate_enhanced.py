"""Phase 1: enhanced diagnostic findings.

Every finding produced by ``validate_change`` must now carry the full
diagnostic envelope (category, why, location, affected_flows, impact_score,
plain_english, remediation, confidence, evidence) so an engineer can act on it
without cross-referencing anything else.
"""
from pathlib import Path

from engine.model import load_net
from engine.validate import (ALL_PRESETS, _enrich_finding, validate_change)

ACME = Path(__file__).resolve().parents[1] / "data" / "acme_office.yaml"

ENHANCED_KEYS = {
    "severity", "type", "title", "detail",
    "category", "why", "location", "affected_flows", "impact_score",
    "plain_english", "remediation", "confidence", "evidence",
}


def _find(report, ftype, needle=None):
    for f in report["findings"]:
        if f["type"] != ftype:
            continue
        if needle is not None:
            blob = f"{f['title']} {f['detail']}".lower()
            if needle.lower() not in blob:
                continue
        return f
    return None


def test_all_preset_findings_carry_the_full_diagnostic_envelope():
    net = load_net(ACME)
    for p in ALL_PRESETS:
        report = validate_change(net, p["change"])
        if not report["findings"]:
            assert report["summary"]["verdict"] == "pass", f"preset {p['id']}"
            continue
        for f in report["findings"]:
            missing = ENHANCED_KEYS - set(f)
            assert not missing, f"preset {p['id']} finding missing {sorted(missing)}"
            assert isinstance(f["location"], dict) and "change_type" in f["location"]
            assert 0 <= f["impact_score"] <= 100
            assert f["confidence"] in ("high", "medium", "low")
            assert isinstance(f["remediation"], list) and f["remediation"]
            assert isinstance(f["affected_flows"], list)
            assert f["plain_english"].startswith(f["severity"].upper() + ":")


def test_vlan_out_of_range_is_syntax_error_with_exact_remediation():
    net = load_net(ACME)
    preset = next(p for p in ALL_PRESETS if p["id"] == "invalid_vlan")
    report = validate_change(net, preset["change"])
    f = _find(report, "vlan", "range")
    assert f is not None
    assert f["severity"] == "critical"
    assert f["category"] == "syntax_error"
    assert f["location"]["device"] == "core-switch"
    assert f["location"]["interface"] == "Gi0/4"
    assert f["location"]["config_section"] == "vlan_assignment"
    assert f["location"]["change_type"] == "add_vlan_assignment"
    assert f["impact_score"] >= 70
    assert f["confidence"] == "high"
    assert any("4094" in r for r in f["remediation"])
    assert "4095" in f["plain_english"]


def test_bgp_invalid_asn_is_syntax_error():
    net = load_net(ACME)
    change = {"type": "add_bgp_peer", "device": "firewall",
              "peer": {"neighbor": "203.0.113.1", "local_as": 99999, "remote_as": 65000}}
    report = validate_change(net, change)
    f = _find(report, "bgp", "asn")
    assert f is not None
    assert f["category"] == "syntax_error"
    assert f["location"]["device"] == "firewall"
    assert any("1-65535" in r for r in f["remediation"])


def test_requirement_violation_is_policy_violation_scoped_to_its_flow():
    net = load_net(ACME)
    preset = next(p for p in ALL_PRESETS if p["id"] == "block_user_internet")
    report = validate_change(net, preset["change"])
    f = _find(report, "requirement")
    assert f is not None
    assert f["category"] == "policy_violation"
    assert f["affected_flows"] == ["users-to-internet"]
    assert any("after state" in r.lower() for r in f["remediation"])


def test_broken_port_forward_is_operational_risk():
    net = load_net(ACME)
    preset = next(p for p in ALL_PRESETS if p["id"] == "add_web_port_forward")
    report = validate_change(net, preset["change"])
    f = _find(report, "port_forward")
    assert f is not None
    assert f["severity"] == "warning"
    assert f["category"] == "operational_risk"
    assert f["affected_flows"], "port-forward finding must name the forward"


def test_unparsable_dns_record_is_syntax_error():
    net = load_net(ACME)
    change = {"type": "add_dns_record", "device": "dns-server",
              "record": {"zone": "internal", "fqdn": "junk.internal", "type": "A", "value": "not-an-ip", "ttl": 300}}
    report = validate_change(net, change)
    f = _find(report, "dns", "unparsable")
    assert f is not None
    assert f["category"] == "syntax_error"
    assert any("supported" in r or "valid" in r.lower() or "IPv" in r for r in f["remediation"])


def test_connectivity_loss_is_reachability_impact_scoped_to_flows():
    f = _enrich_finding(
        {"type": "add_filter_rule", "filter": "fw-inside-in", "at_index": 0},
        {
            "severity": "critical", "type": "connectivity_loss",
            "title": "Connectivity lost: users -> internet",
            "detail": "Blocked by fw-inside-in on firewall (rule: deny any -> any).",
            "before": {"reachable": True, "path": ["users", "fw", "internet"],
                       "steps": [], "drop": None, "nat": None, "trace": []},
            "after": {"reachable": False, "path": ["users", "fw"],
                      "steps": [], "nat": None,
                      "drop": {"device": "firewall", "filter": "fw-inside-in", "rule": "deny any -> any"},
                      "trace": []},
        },
    )
    assert f["category"] == "reachability_impact"
    assert f["affected_flows"] == ["users -> internet"]
    assert any("permit" in r or "restore" in r for r in f["remediation"])
    assert f["evidence"]["before"]["reachable"] is True
    assert f["evidence"]["after"]["reachable"] is False
    assert f["evidence"]["rule_blocking"]["filter"] == "fw-inside-in"
    assert f["confidence"] == "high"
    assert f["plain_english"].startswith("CRITICAL:")
    assert f["plain_english"].startswith("CRITICAL:") and "Fix:" in f["plain_english"]


def test_new_exposure_is_policy_violation():
    f = _enrich_finding(
        {"type": "add_filter_rule", "filter": "fw-inside-in", "at_index": 0},
        {
            "severity": "warning", "type": "new_exposure",
            "title": "New access opened: server-net -> internet",
            "detail": "Previously blocked traffic can now get through. Verify this is intended.",
            "before": {"reachable": False, "path": [], "steps": [], "drop": {}, "nat": None, "trace": []},
            "after": {"reachable": True, "path": ["server-net", "fw", "internet"],
                      "steps": [], "drop": None, "nat": None, "trace": []},
        },
    )
    assert f["category"] == "policy_violation"
    assert f["affected_flows"] == ["server-net -> internet"]
    assert f["confidence"] == "medium"  # zone-level inference, not an explicit confirmed rule
    assert any("narrow" in r.lower() for r in f["remediation"])


def test_findings_are_deterministic_for_replay():
    net = load_net(ACME)
    change = next(p for p in ALL_PRESETS if p["id"] == "block_ssh_to_servers")["change"]
    a = validate_change(net, change)["findings"]
    b = validate_change(net, change)["findings"]
    assert a == b