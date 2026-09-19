"""Phase A6: adversarial evidence-redaction coverage.

Every credential that ships in a verification bundle must be scrubbed *at rest*
so the proof surface never leaks config secrets. These tests hold ``redact_secrets``
to the vulnerabilities that matter: prefixed/camelCase/hyphen/dotted secret keys,
inline ``name=value`` text, URL-query credentials, Bearer tokens, PEM blocks and
the value classes the repo's own ``scripts/secret_scan.py`` would refuse to commit.
"""
import json
import re
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from engine import postchange as pc
from main import app

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import secret_scan  # noqa: E402

TEST_ADMIN_PASS = "admin-test-pass-2026"

CHANGE = {"type": "add_filter_rule", "filter": "fw-inside-in",
          "rule": {"action": "permit", "src": "10.0.10.0/24", "dst": "10.0.20.0/24", "proto": "icmp"}}

# scanner-families reconcile with scripts/secret_scan.py (label -> sample string)
SCANNER_SAMPLES = [
    ("private key block", "-----BEGIN RSA PRIVATE KEY-----\nMIIEVQIBADANBgkqhkiG9w0BA\n-----END RSA PRIVATE KEY-----\n"),
    ("AWS access key", "heard about AKIAIOSFODNN7EXAMPLE today"),
    ("API key (sk-...)", "rotate sk-12345678901234567890abcdefgh to a vault"),
    ("GitHub token", "clone with ghp_123456789012345678901234567890123456"),
    ("Slack token", "bot uses xoxb-12345678901234567890"),
]


# --------------------------------------------------------------------------- #
# key-name redaction                                                           #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("secret_key", sorted(pc._SECRET_KEYS))
def test_every_secret_keys_member_redacts(secret_key):
    red = pc.redact_secrets({"outer": {secret_key: "hunter2"}})
    assert red["outer"][secret_key] == "[REDACTED]"


@pytest.mark.parametrize("key", [
    "monitoring_api_key", "slack_webhook_token", "router_api_token",
    "vpn_client_secret", "auth_token", "refresh_token", "id_token",
])
def test_key_or_token_suffix_redacts(key):
    assert pc.redact_secrets({key: "s3cret"})[key] == "[REDACTED]"


@pytest.mark.parametrize("secret_key", [
    "wpa_passphrase", "ldap_password", "neighbor_password",
    "bootstrap_password", "root-password", "snmp-community",
    "snmp.community", "snmp community", "preSharedKey", "apiKey",
    "accessKey", "idToken", "authToken", "clientSecret", "x-api-key",
    "login-passphrase", "snmpCommunity", "peerPassword", "community",
])
def test_prefixed_and_separator_variant_secret_keys_redact(secret_key):
    red = pc.redact_secrets({"config": {secret_key: "v3ry-s3cret-value"}})
    assert red["config"][secret_key] == "[REDACTED]"


def test_nested_traversal_with_variant_keys():
    doc = {
        "source": "snapshot",
        "content": {
            "wifi": {"networks": [{"ssid": "corp-iot", "wpa_passphrase": "k0mpl3x"}]},
            "vpn": {"peer-auth": {"preSharedKey": "psk-v1th", "passphrase": "p1"}, "psk2": "x"},
        },
    }
    red = pc.redact_secrets(doc)
    assert red["content"]["wifi"]["networks"][0]["ssid"] == "corp-iot"
    assert red["content"]["wifi"]["networks"][0]["wpa_passphrase"] == "[REDACTED]"
    assert red["content"]["vpn"]["peer-auth"]["preSharedKey"] == "[REDACTED]"
    assert red["content"]["vpn"]["peer-auth"]["passphrase"] == "[REDACTED]"
    assert red["content"]["vpn"]["psk2"] == "[REDACTED]"
    assert "k0mpl3x" not in str(red)
    assert "psk-v1th" not in str(red)


def test_benign_keys_and_values_untouched():
    doc = {"hostname": "core-switch", "iface": {"name": "eth0.10", "mtu": 1500},
           "description": "uplink to backbone", "prefix": "10.0.0.0/16",
           "rule": {"action": "permit", "dport": 443, "notes": "some long benign value here"}}
    red = pc.redact_secrets(doc)
    assert red == doc


# --------------------------------------------------------------------------- #
# inline / value redaction                                                     #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("text, leak", [
    ("snmp community: public", "public"),
    ("password=hunter2", "hunter2"),
    ("auth_key = 1234567890", "1234567890"),
    ('json-ish "password":"hunter2"', "hunter2"),
    ("secret: hunter2, neighbour: 10.0.0.1", "hunter2"),
    ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc", "eyJhbGciOiJIUzI1NiJ9"),
    ("feed : https://example.com/api?token=abc123&page=2", "abc123"),
    ("feed https://example.com/api?api_key=abcd&x=1", "abcd"),
    ("rotate ?auth_key=zz9plz at once", "zz9plz"),
])
def test_inline_secret_text_masked(text, leak):
    out = pc.redact_secrets({"notes": text})["notes"]
    assert leak not in out
    assert pc.sensitives_present({"notes": text}) is True
    assert pc.sensitives_present({"notes": out}) is False


@pytest.mark.parametrize("label, sample", SCANNER_SAMPLES)
def test_scanner_value_classes_redacted_even_under_benign_key(label, sample):
    red = pc.redact_secrets({"notes": sample})
    assert "[REDACTED]" in str(red)
    assert pc.sensitives_present({"notes": sample}) is True
    assert pc.sensitives_present(red) is False


_FAMILY_PROBE = {
    "private key block": r"-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----",
    "AWS access key": r"\bAKIA[0-9A-Z]{16}\b",
    "API key (sk-...)": r"\bsk-[A-Za-z0-9_-]{20,}\b",
    "GitHub token": r"\bghp_[A-Za-z0-9]{36,}\b",
    "Slack token": r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b",
}


@pytest.mark.parametrize("label, sample", SCANNER_SAMPLES)
def test_redacted_output_contains_no_matching_secret(label, sample):
    red = pc.redact_secrets({"notes": sample})
    assert re.search(_FAMILY_PROBE[label], str(red)) is None


def test_benign_inline_text_untouched():
    text = "description : uplink to the dmz, filter permit ip any any"
    assert pc.redact_secrets({"notes": text})["notes"] == text


# --------------------------------------------------------------------------- #
# idempotency + detection                                                      #
# --------------------------------------------------------------------------- #

def test_redaction_is_idempotent():
    doc = {"a": {"password": "h1", "wpa_passphrase": "h2"},
           "b": ["api_key=abcdefghij", "Bearer tok123456789"],
           "c": {"notes": "sk-12345678901234567890abcdefghij"},
           "d": {"plain": "keep me"}}
    once = pc.redact_secrets(doc)
    assert pc.redact_secrets(once) == once


def test_sensitives_present_flips_false_after_redaction():
    messy = {
        "wifi": {"psk": "p"},
        "notes": "community: public AKIAIOSFODNN7EXAMPLE password=hunter2",
        "nested": [{"idToken": "t"}],
        "benign": ["iface", "probe", "firewall"],
    }
    assert pc.sensitives_present(messy) is True
    assert pc.sensitives_present(pc.redact_secrets(messy)) is False


def test_detects_camel_case_compound():
    assert pc.sensitives_present({"preSharedKey": "k"}) is True


def test_redaction_preserves_tree_shape():
    doc = {"x": [{"password": "a", "vlan": 10}, "free"],
           "y": {"b": 5, "notes": "ok"}, "z": {"enable_password": "e"}}
    red = pc.redact_secrets(doc)
    assert list(red["x"][0].keys()) == ["password", "vlan"]
    assert red["x"][0]["vlan"] == 10
    assert red["x"][1] == "free"
    assert red["y"]["b"] == 5
    assert red["y"]["notes"] == "ok"
    assert red["z"]["enable_password"] == "[REDACTED]"


# --------------------------------------------------------------------------- #
# reconciliation lock with scripts/secret_scan.py                              #
# --------------------------------------------------------------------------- #

def test_secret_scan_families_are_a_subset_of_redaction_vocabulary():
    scan_labels = {label for _, label in secret_scan._PATTERNS}
    redaction_labels = {label for _, label in pc._SECRET_VALUE_PATTERNS}
    assert scan_labels <= redaction_labels, scan_labels - redaction_labels


def test_scan_regex_still_flags_the_representative_samples():
    for label, sample in SCANNER_SAMPLES:
        assert any(regex.search(sample) for regex, lbl in secret_scan._PATTERNS if lbl == label), label


def test_name_value_assignment_class_redacts():
    scan = secret_scan._NAME_VALUE
    sample = 'PASSWORD = "supersecretsitecrepie12"'
    assert scan.match(sample.lstrip()), "scanner must flag the sample"
    out = pc.redact_secrets({"env": sample})["env"]
    assert "supersecretsitecrepie12" not in out


# --------------------------------------------------------------------------- #
# at-rest: stored rows and bundles never contain secrets                      #
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def admin():
    with TestClient(app, raise_server_exceptions=False) as cli:
        r = cli.post("/api/login", json={"username": "admin", "password": TEST_ADMIN_PASS})
        assert r.status_code == 200
        yield cli


@pytest.fixture(scope="module")
def verdict(admin):
    r = admin.post("/api/validate", json={"change": CHANGE})
    assert r.status_code == 200
    yield r.json()["audit"]["verdict_id"]


def test_secretty_evidence_is_redacted_at_rest_in_db(admin, verdict):
    r = admin.post("/api/verifications", json={"verdict_id": verdict})
    vid = r.json()["id"]
    docs = [{
        "source": "snapshot", "device": "192.168.1.1", "section": "wifi",
        "collected_at": "2099-01-01T00:00:00Z", "confirmed": True,
        "content": {"wifi": {"wpa_passphrase": "attack-after-redact-check"}},
        "notes": "rotate AKIAIOSFODNN7EXAMPLE and dbpassword = pinnacle-origin-secret",
    }]
    assert admin.post(f"/api/verifications/{vid}/evidence", json={"evidence": docs}).status_code == 200
    stored = pc.get_verification(vid)
    assert stored is not None
    dumped = json.dumps(stored)
    assert "attack-after-redact-check" not in dumped
    assert "AKIAIOSFODNN7EXAMPLE" not in dumped
    assert "pinnacle-origin-secret" not in dumped


def test_bundle_export_is_redacted_even_for_new_secret_classes(admin, verdict):
    r = admin.post("/api/verifications", json={"verdict_id": verdict})
    vid = r.json()["id"]
    docs = [{
        "source": "manual", "device": "192.168.1.1", "section": "vpn",
        "collected_at": "2099-01-01T00:00:00Z", "confirmed": True,
        "content": {"vpn": {"client": {"preSharedKey": "preshared-a6x"}}},
        "run": {"notes": "Bearer replacement-eyJhbGciOiJIUzI1NiJ9."},
    }]
    admin.post(f"/api/verifications/{vid}/evidence", json={"evidence": docs})
    admin.post(f"/api/verifications/{vid}/run", json={})
    bundle_text = json.dumps(admin.get(f"/api/verifications/{vid}/bundle").json())
    assert "preshared-a6x" not in bundle_text
    assert "replacement-eyJhbGciOiJIUzI1NiJ9." not in bundle_text


def test_sensitives_present_false_for_full_bundle(admin, verdict):
    r = admin.post("/api/verifications", json={"verdict_id": verdict})
    vid = r.json()["id"]
    admin.post(f"/api/verifications/{vid}/run", json={})
    r = admin.get(f"/api/verifications/{vid}/bundle")
    assert r.status_code == 200
    assert pc.sensitives_present(r.json()) is False
