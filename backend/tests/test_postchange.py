"""Evidence-aware post-change verification engine.

Predicts the post-change state from a stored verdict report, compares it against
collected evidence (config snapshots, agent reports, probes, manual input) and
classifies the change into a lifecycle status. Missing / stale / conflicting
evidence is never converted into a pass.
"""
import os
import tempfile
from pathlib import Path

import pytest

from engine import postchange as pc
from engine.model import load_net
from engine.validate_pipeline import run_validation_pipeline

ACME = Path(__file__).resolve().parents[1] / "data" / "acme_office.yaml"

RULES = [
    ("permit", "10.0.10.0/24", "10.0.20.0/24", "tcp", 443),
    ("permit", "10.0.10.0/24", "10.0.20.0/24", "tcp", 22),
    ("permit", "10.0.10.0/24", "any", "tcp", 80),
    ("permit", "10.0.10.0/24", "any", "tcp", 443),
]
R = [dict(zip(("action", "src", "dst", "proto", "dport"), r)) for r in RULES]
ICMP = {"action": "permit", "src": "10.0.10.0/24", "dst": "10.0.20.0/24", "proto": "icmp"}
EXTRA = {"action": "deny", "src": "0.0.0.0/0", "dst": "10.0.20.0/24", "proto": "tcp", "dport": 3389}
FW_FILTER = {"filters": {"fw-inside-in": {"rules": R}}}
PRE_EVIDENCE = {"devices": {"firewall": "192.168.1.1"}, "config": {"192.168.1.1": FW_FILTER}}


def _net():
    return load_net(ACME)


def _report(change):
    return run_validation_pipeline(change, _net())["report"]


def _doc(section, content, device="192.168.1.1", source="snapshot", stale=False,
         confirmed=True, unsupported=False):
    doc = {
        "source": source,
        "device": device,
        "section": section,
        "content": content,
        "collected_at": ("2020-01-01T00:00:00Z" if stale else "2099-01-01T00:00:00Z"),
        "confirmed": confirmed,
    }
    if unsupported:
        doc["unsupported"] = True
    return doc


def _obs(section, content, **kw):
    return pc.extract_observations([_doc(section, content, **kw)])


def _synthetic(change, cp_before=None, cp_after=None):
    return {
        "change": change,
        "matrix": {},
        "requirements": [],
        "control_plane": {"before": cp_before or {}, "after": cp_after or {}},
        "summary": {"verdict": "pass"},
    }


ADD_ICMP = {"type": "add_filter_rule", "filter": "fw-inside-in", "rule": ICMP}
ADD_ICMP_CHANGE = {"type": "add_filter_rule", "filter": "fw-inside-in", "rule": ICMP}


# --------------------------------------------------------------------------- #
# filter-rule lifecycle                                                        #
# --------------------------------------------------------------------------- #

def test_add_verified():
    pred = pc.build_prediction(_report(ADD_ICMP_CHANGE), None)
    outcome = pc.compare_observed_state(
        pred, _obs("filters", {"filters": {"fw-inside-in": {"rules": R + [ICMP]}}}))
    assert outcome["status"] == "verified"
    assert outcome["summary"]["deltas_confirmed"] >= 1
    assert not outcome["mismatches"]
    assert outcome["summary"]["confidence"] > 0


def test_add_missing_is_failed():
    pred = pc.build_prediction(_report(ADD_ICMP_CHANGE), None)
    outcome = pc.compare_observed_state(pred, _obs("filters", {"filters": {"fw-inside-in": {"rules": R}}}))
    assert outcome["status"] == "failed"
    kinds = [m["status"] for m in outcome["mismatches"]]
    assert "expected_missing" in kinds
    assert all(m["severity"] == "critical" for m in outcome["mismatches"])


def test_remove_without_before_is_inconclusive():
    report = _report({"type": "remove_filter_rule", "filter": "fw-inside-in", "at_index": 0})
    pred = pc.build_prediction(report, None)
    assert any(d["kind"] == "filter_rule" and d["needs_before"] for d in pred["deltas"])
    outcome = pc.compare_observed_state(
        pred, _obs("filters", {"filters": {"fw-inside-in": {"rules": R[1:]}}}))
    assert outcome["status"] == "inconclusive"


def test_remove_with_before_verified():
    report = _report({"type": "remove_filter_rule", "filter": "fw-inside-in", "at_index": 0})
    pred = pc.build_prediction(report, PRE_EVIDENCE)
    removed = [d for d in pred["deltas"] if d["kind"] == "filter_rule"][0]
    assert removed["before"] == R[0]
    assert removed["needs_before"] is False
    outcome = pc.compare_observed_state(
        pred, _obs("filters", {"filters": {"fw-inside-in": {"rules": R[1:]}}}))
    assert outcome["status"] == "verified"


def test_remove_still_present_is_mismatch():
    report = _report({"type": "remove_filter_rule", "filter": "fw-inside-in", "at_index": 0})
    pred = pc.build_prediction(report, PRE_EVIDENCE)
    outcome = pc.compare_observed_state(pred, _obs("filters", FW_FILTER))
    assert outcome["status"] == "mismatch"
    mm = outcome["mismatches"][0]
    assert mm["status"] == "unexpected_present"
    assert mm["observed"] == R[0]


def test_no_evidence_is_inconclusive_not_pass():
    pred = pc.build_prediction(_report(ADD_ICMP_CHANGE), None)
    outcome = pc.compare_observed_state(pred, [])
    assert outcome["status"] == "inconclusive"


def test_stale_evidence_is_inconclusive_not_pass():
    pred = pc.build_prediction(_report(ADD_ICMP_CHANGE), None)
    outcome = pc.compare_observed_state(
        pred, _obs("filters", {"filters": {"fw-inside-in": {"rules": R + [ICMP]}}}, stale=True))
    assert outcome["status"] == "inconclusive"
    assert "evidence_freshness" in {h["id"] for h in pc.run_health_checks(_net(), [], [])}


def test_conflicting_evidence_inconclusive():
    pred = pc.build_prediction(_report(ADD_ICMP_CHANGE), None)
    conf = pc.extract_observations([
        _doc("filters", {"filters": {"fw-inside-in": {"rules": R + [ICMP]}}}, device="192.168.1.1", source="snapshot"),
        _doc("filters", {"filters": {"fw-inside-in": {"rules": R}}}, device="203.0.113.2", source="agent_report"),
    ])
    assert pc.compare_observed_state(pred, conf)["status"] == "inconclusive"


def test_source_precedence_resolves_conflict():
    pred = pc.build_prediction(_report(ADD_ICMP_CHANGE), None)
    conf = pc.extract_observations([
        _doc("filters", {"filters": {"fw-inside-in": {"rules": R + [ICMP]}}}, device="192.168.1.1", source="snapshot"),
        _doc("filters", {"filters": {"fw-inside-in": {"rules": R}}}, device="203.0.113.2", source="agent_report"),
    ])
    assert pc.compare_observed_state(pred, conf, source_precedence=["snapshot", "agent_report"])["status"] == "verified"
    assert pc.compare_observed_state(pred, conf, source_precedence=["agent_report", "snapshot"])["status"] == "failed"


def test_unsupported_constructs_are_unsupported():
    pred = pc.build_prediction(_report(ADD_ICMP_CHANGE), None)
    outcome = pc.compare_observed_state(
        pred, _obs("filters", {"filters": {"fw-inside-in": {"rules": R + [ICMP]}}}, unsupported=True))
    assert outcome["status"] == "unsupported"


def test_unexpected_change_lowered_to_warnings():
    report = _report(ADD_ICMP_CHANGE)
    pred = pc.build_prediction(report, PRE_EVIDENCE)
    outcome = pc.compare_observed_state(
        pred, _obs("filters", {"filters": {"fw-inside-in": {"rules": R + [ICMP] + [EXTRA]}}}))
    assert outcome["status"] == "verified_with_warnings"
    assert any(u["observed"] == EXTRA for u in outcome["unexpected_changes"])
    # without the extra rule nothing is flagged
    clean = pc.compare_observed_state(
        pred, _obs("filters", {"filters": {"fw-inside-in": {"rules": R + [ICMP]}}}))
    assert clean["status"] == "verified"
    assert not clean["unexpected_changes"]


# --------------------------------------------------------------------------- #
# other change families                                                        #
# --------------------------------------------------------------------------- #

def test_route_remove_with_before():
    pre = {"devices": {"firewall": "192.168.1.1"},
           "config": {"192.168.1.1": {"routes": [
               {"network": "10.0.0.0/16", "next_hop": "192.168.1.2"},
               {"network": "0.0.0.0/0", "next_hop": "203.0.113.1"}]}}}
    pred = pc.build_prediction(_synthetic({
        "type": "remove_route", "device": "firewall", "index": 0}), pre)
    removed = [d for d in pred["deltas"] if d["kind"] == "route"][0]
    assert removed["before"]["network"] == "10.0.0.0/16"
    gone = _obs("routes", {"routes": [{"network": "0.0.0.0/0", "next_hop": "203.0.113.1"}]})
    assert pc.compare_observed_state(pred, gone)["status"] == "verified"
    still = _obs("routes", {"routes": pre["config"]["192.168.1.1"]["routes"]})
    assert pc.compare_observed_state(pred, still)["status"] == "mismatch"


def test_route_remove_without_before_is_inconclusive():
    pred = pc.build_prediction(_synthetic({
        "type": "remove_route", "device": "192.168.1.1", "index": 0}), None)
    assert any(d["kind"] == "route" and d["needs_before"] and not d["before"] for d in pred["deltas"])
    gone = _obs("routes", {"routes": [{"network": "0.0.0.0/0", "next_hop": "203.0.113.1"}]}, device="192.168.1.1")
    assert pc.compare_observed_state(pred, gone)["status"] == "inconclusive"


def test_dst_nat_verified_and_missing():
    nat = {"public_ip": "203.0.113.5", "public_port": 443, "proto": "tcp",
           "private_ip": "10.0.20.5", "private_port": 8443}
    pred = pc.build_prediction(_synthetic({
        "type": "add_dst_nat", "device": "192.168.1.1", "dst_nat": nat}), None)
    present = _obs("dst_nat", {"dst_nat": [dict(nat)]}, device="192.168.1.1")
    assert pc.compare_observed_state(pred, present)["status"] == "verified"
    absent = _obs("dst_nat", {"dst_nat": []}, device="192.168.1.1")
    assert pc.compare_observed_state(pred, absent)["status"] == "failed"


def test_dst_nat_remove_with_before():
    nat = {"public_ip": "203.0.113.5", "public_port": 443, "proto": "tcp",
           "private_ip": "10.0.20.5", "private_port": 8443}
    pre = {"config": {"192.168.1.1": {"dst_nat": [dict(nat)]}}}
    pred = pc.build_prediction(_synthetic({
        "type": "remove_dst_nat", "device": "192.168.1.1", "index": 0}), pre)
    removed = [d for d in pred["deltas"] if d["kind"] == "dst_nat"][0]
    assert removed["before"]["public_port"] == 443
    assert pc.compare_observed_state(pred, _obs("dst_nat", {"dst_nat": []}, device="192.168.1.1"))["status"] == "verified"


def test_bgp_remove_with_before():
    peers = [{"neighbor": "192.0.2.1", "local_as": 65000, "remote_as": 65002,
              "export_prefixes": ["10.0.0.0/16"]}]
    pre = {"devices": {"firewall": ["192.168.1.1"]}, "config": {"192.168.1.1": {"bgp": peers}}}
    pred = pc.build_prediction(_synthetic({
        "type": "remove_bgp_peer", "device": "firewall",
        "peer": {"neighbor": "192.0.2.1"}}), pre)
    removed = [d for d in pred["deltas"] if d["kind"] == "bgp"][0]
    assert removed["before"]["neighbor"] == "192.0.2.1"
    assert pc.compare_observed_state(pred, _obs("bgp", {"bgp": []}))["status"] == "verified"
    assert pc.compare_observed_state(pred, _obs("bgp", {"bgp": peers}))["status"] == "mismatch"


def test_bgp_add_verified():
    peer = {"neighbor": "192.0.2.1", "local_as": 65000, "remote_as": 65002}
    pred = pc.build_prediction(_synthetic({
        "type": "add_bgp_peer", "device": "192.168.1.1", "peer": peer}), None)
    ok = _obs("bgp", {"bgp": [dict(peer)]}, device="192.168.1.1")
    assert pc.compare_observed_state(pred, ok)["status"] == "verified"


def test_ospf_add_verified_and_missing():
    pred = pc.build_prediction(_synthetic({
        "type": "add_ospf_network", "device": "192.168.1.1", "area_id": 0, "network": "10.0.0.0/16"}), None)
    ok = _obs("ospf", {"ospf": [{"area_id": 0, "networks": ["10.0.0.0/16"]}]}, device="192.168.1.1")
    assert pc.compare_observed_state(pred, ok)["status"] == "verified"
    missing = _obs("ospf", {"ospf": [{"area_id": 0, "networks": []}]}, device="192.168.1.1")
    assert pc.compare_observed_state(pred, missing)["status"] == "failed"


def test_dns_add_verified():
    rec = {"zone": "acme.test", "fqdn": "app.acme.test", "type": "A",
           "value": "10.0.20.10", "ttl": 300}
    pred = pc.build_prediction(_synthetic({
        "type": "add_dns_record", "device": "192.168.1.1", "record": rec}), None)
    ok = _obs("dns", {"dns": [dict(rec)]}, device="192.168.1.1")
    assert pc.compare_observed_state(pred, ok)["status"] == "verified"


def test_dns_remove_with_before():
    rec = {"zone": "acme.test", "fqdn": "app.acme.test", "type": "A",
           "value": "10.0.20.10", "ttl": 300}
    pre = {"config": {"192.168.1.1": {"dns": [dict(rec)]}}}
    pred = pc.build_prediction(_synthetic({
        "type": "remove_dns_record", "device": "192.168.1.1",
        "record": {"fqdn": "app.acme.test", "type": "A"}}), pre)
    removed = [d for d in pred["deltas"] if d["kind"] == "dns"][0]
    assert removed["before"]["fqdn"] == "app.acme.test"
    assert pc.compare_observed_state(pred, _obs("dns", {"dns": []}, device="192.168.1.1"))["status"] == "verified"


def test_vlan_add_and_remove():
    vlan = {"iface": "eth0.10", "vlan_id": 10, "name": "users"}
    pred = pc.build_prediction(_synthetic({
        "type": "add_vlan_assignment", "device": "192.168.1.1", "vlan": vlan}), None)
    ok = _obs("vlan_assignment", {"vlan_assignment": [dict(vlan)]}, device="192.168.1.1")
    assert pc.compare_observed_state(pred, ok)["status"] == "verified"

    pre = {"devices": {"core-switch": "192.168.1.1"},
           "config": {"192.168.1.1": {"vlan_assignment": [dict(vlan)]}}}
    pred = pc.build_prediction(_synthetic({
        "type": "remove_vlan_assignment", "device": "core-switch", "vlan": {"iface": "eth0.10"}}), pre)
    removed = [d for d in pred["deltas"] if d["kind"] == "vlan"][0]
    assert removed["before"]["vlan_id"] == 10
    assert pc.compare_observed_state(pred, _obs("vlan_assignment", {"vlan_assignment": []}))["status"] == "verified"


# --------------------------------------------------------------------------- #
# prediction structure                                                         #
# --------------------------------------------------------------------------- #

def test_prediction_summary_counts():
    report = _report(ADD_ICMP_CHANGE)
    pred = pc.build_prediction(report, None)
    assert pred["schema"] == "1"
    assert pred["engine_version"] == pc.ENGINE_VERSION
    assert pred["summary"]["simulation_verdict"] == "pass"
    primary = [d for d in pred["deltas"] if not d["advisory"]]
    assert any(d["kind"] == "filter_rule" for d in primary)


def test_redacts_secrets():
    doc = {
        "source": "snapshot", "device": "192.168.1.1", "section": "bgp",
        "content": {"bgp": [{"neighbor": "192.0.2.1", "password": "hunter2"}]},
        "service": {"password": "s3cret", "private_key": "abc", "api_key": "k",
                    "community": "public", "token": "t", "snmpv3_priv": "p"},
    }
    red = pc.redact_secrets(doc)
    joined = str(red).lower()
    for leaked in ("hunter2", "s3cret", "abc", "public"):
        assert leaked not in joined
    assert red["content"]["bgp"][0]["password"] == "[REDACTED]"
    assert red["service"]["password"] == "[REDACTED]"
    assert red["service"]["private_key"] == "[REDACTED]"
    assert red["service"]["api_key"] == "[REDACTED]"
    assert red["service"]["community"] == "[REDACTED]"
    assert red["service"]["token"] == "[REDACTED]"
    assert red["service"]["snmpv3_priv"] == "[REDACTED]"


def test_deterministic_hash():
    a = {"b": "z", "a": [{"x": 1, "y": 2}]}
    b = {"a": [{"y": 2, "x": 1}], "b": "z"}
    assert pc.content_hash(a) == pc.content_hash(b)
    assert len(pc.content_hash(a)) == 64


def test_extract_observations_limits():
    docs = [_doc("filters", FW_FILTER) for _ in range(pc.MAX_EVIDENCE_DOCS + 1)]
    with pytest.raises(ValueError):
        pc.extract_observations(docs)


# --------------------------------------------------------------------------- #
# health checks + rollback                                                     #
# --------------------------------------------------------------------------- #

def test_health_checks_cover_sections():
    obs = _obs("filters", {"filters": {"fw-inside-in": {"rules": R + [ICMP]}}})
    checks = pc.run_health_checks(_net(), obs, [{"name": "users-to-app"}, {"name": "servers-no-internet"}])
    ids = {h["id"] for h in checks}
    assert ids == {
        "device_reachability", "interface_state", "route_presence", "bgp_session",
        "ospf_adjacency", "vlan_assignment", "acl_presence", "acl_ordering",
        "nat_presence", "required_flow", "protected_service",
        "required_non_reachability", "dns_resolution", "evidence_freshness",
    }
    assert {"acl_presence", "acl_ordering"} <= {h["id"] for h in checks if h["status"] == "pass"}
    for h in checks:
        assert {"id", "status", "expected", "observed", "evidence_ids", "confidence", "explanation"} <= set(h)


def test_rollback_recommended_on_failed_change():
    changed = _report(ADD_ICMP_CHANGE)
    pred = pc.build_prediction(changed, None)
    outcome = pc.compare_observed_state(pred, _obs("filters", FW_FILTER))
    rb = pc.build_rollback_recommendation(
        {"status": outcome["status"], "result": outcome, "change": ADD_ICMP_CHANGE})
    assert rb["recommended"] is True
    assert rb["triggers"]
    assert rb["inverse_change"]["type"] == "remove_filter_rule"
    assert rb["requires_human_approval"] is True
    assert rb["requires_post_rollback_verification"] is True
    assert rb["vendor_commands"] is None


def test_rollback_not_recommended_when_verified():
    changed = _report(ADD_ICMP_CHANGE)
    pred = pc.build_prediction(changed, None)
    outcome = pc.compare_observed_state(
        pred, _obs("filters", {"filters": {"fw-inside-in": {"rules": R + [ICMP]}}}))
    assert outcome["status"] == "verified"
    rb = pc.build_rollback_recommendation(
        {"status": outcome["status"], "result": outcome, "change": ADD_ICMP_CHANGE})
    assert rb["recommended"] is False


def test_rollback_removal_requires_before():
    change = {"type": "remove_filter_rule", "filter": "fw-inside-in", "at_index": 0}
    inv, warnings = pc.inverse_change(change, {"deltas": []})
    assert inv is None
    assert warnings

    report = _report(change)
    pred = pc.build_prediction(report, PRE_EVIDENCE)
    inv, warnings = pc.inverse_change(change, {"deltas": pred["deltas"]})
    assert inv == {"type": "add_filter_rule", "filter": "fw-inside-in", "at_index": 0, "rule": R[0]}


def test_rollback_non_failing_status_noop():
    rb = pc.build_rollback_recommendation(
        {"status": "verified", "result": {"mismatches": []}, "change": ADD_ICMP_CHANGE})
    assert rb["recommended"] is False


# --------------------------------------------------------------------------- #
# persistence                                                                  #
# --------------------------------------------------------------------------- #

@pytest.fixture()
def vf_db(tmp_path):
    return str(tmp_path / "verifications.db")


def _seed_verdict(db):
    report = _report(ADD_ICMP_CHANGE)
    from engine.audit import save_verdict
    return save_verdict(_net(), report, ADD_ICMP_CHANGE, db=db)


def test_verification_lifecycle_roundtrip(vf_db):
    vid = _seed_verdict(vf_db)
    v = pc.create_verification(vid, org_id="acme", requester="tester", change=ADD_ICMP_CHANGE, db=vf_db)
    assert v["status"] == "not_started"
    assert v["change"]["type"] == "add_filter_rule"

    evidence = _doc("filters", {"filters": {"fw-inside-in": {"rules": R + [ICMP]}}})
    evidence["service"] = {"password": "hunter2"}
    v = pc.add_evidence(v["id"], [evidence], db=vf_db)
    assert v["status"] == "awaiting_observation"
    assert "hunter2" not in str(pc.get_verification(v["id"], db=vf_db))

    out = pc.run_verification(v["id"], db=vf_db)
    assert out["status"] == "verified"
    assert out["result"]["summary"]["deltas_confirmed"] >= 1
    assert isinstance(out["health_checks"], list)
    assert out["rollback"]["recommended"] is False

    bundle = out["bundle"]
    assert bundle["verification"]["id"] == v["id"]
    assert bundle["verdict"]["id"] == vid
    assert bundle["redacted"] is True
    assert bundle["engine_version"] == pc.ENGINE_VERSION


def test_run_verification_missing_verdict_raises(vf_db):
    v = pc.create_verification("nonexistent-verdict", db=vf_db)
    with pytest.raises(ValueError):
        pc.run_verification(v["id"], db=vf_db)


def test_add_evidence_missing_verification_raises(vf_db):
    with pytest.raises(KeyError):
        pc.add_evidence("missing", [_doc("filters", FW_FILTER)], db=vf_db)


def test_list_verifications_scoped_to_org(vf_db):
    vid = _seed_verdict(vf_db)
    pc.create_verification(vid, org_id="acme", db=vf_db)
    pc.create_verification(vid, org_id="acme", db=vf_db)
    pc.create_verification(vid, org_id="other", db=vf_db)
    assert len(pc.list_verifications(org_id="acme", db=vf_db)) == 2
    assert len(pc.list_verifications(db=vf_db)) == 3
    assert len(pc.list_verifications(org_id="missing", db=vf_db)) == 0


def test_deterministic_persistence_serialization(vf_db):
    vid = _seed_verdict(vf_db)
    v1 = pc.create_verification(vid, org_id="acme", prediction={"x": 1, "a": [{"k": "v"}]}, db=vf_db)
    v2 = pc.get_verification(v1["id"], db=vf_db)
    assert v2["prediction"] == {"x": 1, "a": [{"k": "v"}]}


def test_engine_constants():
    assert pc.ENGINE_VERSION == "0.3.0"
    assert pc.STATUS_NOT_STARTED == "not_started"
    assert pc.STATUS_AWAITING_OBSERVATION == "awaiting_observation"
    assert pc.STATUS_VERIFIED == "verified"
    assert {pc.STATUS_VERIFIED_WITH_WARNINGS, pc.STATUS_MISMATCH, pc.STATUS_FAILED,
            pc.STATUS_INCONCLUSIVE, pc.STATUS_UNSUPPORTED} is not None