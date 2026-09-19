"""Release & consistency checks (Phase A1).

Lightweight deterministic invariants the CI pipeline enforces on top of the
behavioural suite: a single version source, YAML parses, every documented REST
route is registered, and every file the docs reference still exists.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # backend/
ROOT = Path(__file__).resolve().parent.parent.parent

import yaml  # noqa: E402

import main as main_mod  # noqa: E402
from engine.metainfo import PROJECT_VERSION  # noqa: E402
from engine.validate import ALL_PRESETS  # noqa: E402


def _read_text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_version_is_single_source_of_truth():
    assert PROJECT_VERSION, "metainfo version must not be empty"
    assert re.match(r"^\d+\.\d+\.\d+$", PROJECT_VERSION), PROJECT_VERSION
    assert main_mod.app.version == PROJECT_VERSION
    assert f"app.js?v={PROJECT_VERSION}" in _read_text("web/index.html")
    assert f"image: netproof:{PROJECT_VERSION}" in _read_text("docker-compose.yml")
    pyproject = _read_text("pyproject.toml")
    assert re.search(rf'^version = "{re.escape(PROJECT_VERSION)}"', pyproject, re.M), pyproject
    assert re.search(rf'"version": "{re.escape(PROJECT_VERSION)}"', _read_text("web/harness/package.json"))
    stale = re.findall(r"app\.js\?v=([0-9.]+)", _read_text("PROJECT_CONTEXT.md"))
    for version in stale:
        assert version == PROJECT_VERSION, f"PROJECT_CONTEXT.md cache-buster {version} != {PROJECT_VERSION}"


DOCUMENTED_FILES = [
    "PROJECT_CONTEXT.md", "README.md", "DEPLOY.md", ".env.example", ".gitignore",
    "Dockerfile", "docker-compose.yml", "Caddyfile", "run.ps1", "run.sh",
    "bootstrap.ps1", "requirements.txt", "requirements-dev.txt", "pyproject.toml",
    "web/index.html", "web/app.js", "web/styles.css", "web/harness/harness.js",
    "web/harness/package.json", "web/harness/package-lock.json",
    "agent/agent.py", "agent/pull.py",
    "backend/main.py", "backend/security.py", "backend/ratelimit.py",
    "backend/metrics.py", "backend/logfmt.py", "backend/mcp_server.py",
    "backend/engine/model.py", "backend/engine/reach.py", "backend/engine/validate.py",
    "backend/engine/validate_pipeline.py", "backend/engine/audit.py",
    "backend/engine/postchange.py", "backend/engine/drift.py", "backend/engine/tenant.py",
    "backend/engine/discover.py", "backend/engine/buildnet.py", "backend/engine/confirm.py",
    "backend/engine/intent.py", "backend/engine/guardrails.py", "backend/engine/intel.py",
    "backend/engine/events.py", "backend/engine/metainfo.py",
    "backend/data/acme_office.yaml", "backend/data/orgs/default.yaml",
    ".github/workflows/ci.yml", "scripts/ci.py",
]


def test_all_documented_files_exist():
    missing = [p for p in DOCUMENTED_FILES if not (ROOT / p).exists()]
    assert not missing, f"documented files missing: {missing}"


def test_project_context_file_refs_exist():
    ctx = _read_text("PROJECT_CONTEXT.md")
    refs = set(re.findall(r"`([A-Za-z0-9_./-]+\.(?:py|js|css|html|yaml|yml|toml|sh|ps1|md|txt))`", ctx))

    def resolve(ref: str) -> bool:
        candidates = [ROOT / ref]
        if "/" in ref:
            candidates += [ROOT / "backend" / ref, ROOT / "web" / ref, ROOT / "agent" / ref, ROOT / "scripts" / ref]
        else:
            candidates += [ROOT / "backend" / ref, ROOT / "web" / ref, ROOT / "agent" / ref,
                           ROOT / "backend" / "engine" / ref, ROOT / "backend" / "data" / ref,
                           ROOT / "backend" / "tests" / ref]
        return any(p.exists() for p in candidates)

    missing = sorted(r for r in refs if not resolve(r))
    assert not missing, f"PROJECT_CONTEXT.md references missing files: {missing}"


def test_demo_network_yaml_parses():
    doc = yaml.safe_load(_read_text("backend/data/acme_office.yaml"))
    assert isinstance(doc, dict) and doc.get("name")


def test_org_guardrail_yaml_parses():
    org_dir = ROOT / "backend" / "data" / "orgs"
    docs = list(org_dir.glob("*.yaml"))
    assert docs
    for path in sorted(docs):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(doc, dict)


DOCUMENTED_ROUTES = [
    "/metrics", "/health", "/", "/api/gateway", "/api/login", "/api/logout",
    "/api/session", "/api/network", "/api/scan", "/api/model",
    "/api/validate", "/api/intent", "/api/guardrails", "/api/orgs",
    "/api/orgs/{org_id}/rotate-key", "/api/users", "/api/users/{org_id}/{username}",
    "/api/agent/report", "/api/agent/status", "/api/org/network", "/api/drift",
    "/api/audit", "/api/verdicts", "/api/verdicts/{vid}", "/api/verdicts/{vid}/replay",
    "/api/verdicts/{vid}/export", "/api/verdicts/{vid}/bundle", "/api/verdicts/{vid}/diff",
    "/api/target/{ip}/intelligence", "/api/target/{ip}/intelligence/export",
    "/api/verifications", "/api/verifications/{vid}", "/api/verifications/{vid}/evidence",
    "/api/verifications/{vid}/run", "/api/verifications/{vid}/bundle",
]


def test_documented_routes_are_registered():
    registered = {r.path for r in main_mod.app.routes}
    missing = [r for r in DOCUMENTED_ROUTES if r not in registered]
    assert not missing, f"documented routes not registered: {missing}"


def test_documented_routes_are_described_in_context_doc():
    ctx = _read_text("PROJECT_CONTEXT.md")
    missing = [r for r in DOCUMENTED_ROUTES if r not in ctx]
    assert not missing, f"routes missing from PROJECT_CONTEXT.md: {missing}"


def test_preset_catalogue_is_complete_and_wellformed():
    assert isinstance(ALL_PRESETS, list)
    assert len(ALL_PRESETS) == 13, ALL_PRESETS
    for preset in ALL_PRESETS:
        assert isinstance(preset, dict), preset
        assert "id" in preset and isinstance(preset["id"], str), preset
        assert "label" in preset and isinstance(preset["label"], str), preset
