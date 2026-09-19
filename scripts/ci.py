#!/usr/bin/env python3
"""Local CI orchestrator for NetProof.

Runs the same deterministic gates on any OS with a Python 3.12 + Node 18/20
environment — used both by GitHub Actions (.github/workflows/ci.yml) and for
local verification:

    python scripts/ci.py                # full gate: pytest + boot server + presets + jsdom harness
    python scripts/ci.py --skip-node    # skip the jsdom harness (no Node available)
    python scripts/ci.py --skip-pytest  # boot server + harness only (fast loop)

Steps:
  - compileall (syntax gate) for backend/ and agent/
  - import gate (main app, agent module, MCP server)
  - full backend pytest run
  - boot a throwaway uvicorn server on a scratch database (never the dev DB)
  - execute every one of the 13 engine presets over POST /api/validate
  - run the web/jsdom harness (web/harness/harness.js) against that server
Exit code 0 only when every step passes.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
PY = sys.executable
HARNESS_DIR = ROOT / "web" / "harness"

ADMIN_USER = "admin"
ADMIN_PASS = "admin-test-pass-2026"
PRESET_NAMES = 13


def run(cmd: list[str], cwd: Path, env: dict | None = None) -> None:
    print(">>> " + " ".join(str(c) for c in cmd))
    merged = dict(os.environ)
    if env:
        merged.update(env)
    subprocess.run(cmd, cwd=str(cwd), env=merged, check=True)


def gate_compile() -> None:
    run([PY, "-m", "compileall", "-q", "backend", "agent"], ROOT)


def gate_imports() -> None:
    sys.path.insert(0, str(BACKEND))
    sys.path.insert(0, str(ROOT))
    for mod, path in (("main", BACKEND / "main.py"),
                      ("agent", ROOT / "agent" / "agent.py"),
                      ("mcp_server", BACKEND / "mcp_server.py")):
        spec = importlib.util.spec_from_file_location(f"netproof_import_{mod}", path)
        assert spec and spec.loader, f"cannot build import spec for {path}"
        mod_obj = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod_obj)
        print(f"[import] {path.name} ok")


def gate_pytest() -> None:
    env = {"NETPROOF_ADMIN_USER": ADMIN_USER, "NETPROOF_ADMIN_PASS": ADMIN_PASS}
    run([PY, "-m", "pytest", "-q", "-p", "no:cacheprovider"], BACKEND, env=env)


def wait_health(base: str, timeout_s: int = 90) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base + "/health", timeout=2) as resp:
                if resp.status == 200:
                    return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError(f"server under {base} never became healthy")


def gate_presets(base: str) -> None:
    sys.path.insert(0, str(BACKEND))
    sys.path.insert(0, str(ROOT))
    import engine.validate as mod
    presets = mod.ALL_PRESETS
    assert len(presets) == PRESET_NAMES, f"expected {PRESET_NAMES} presets, got {len(presets)}"
    for i, preset in enumerate(presets, 1):
        change = preset["change"]
        req = urllib.request.Request(
            base + "/api/validate",
            data=json.dumps({"change": change}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        assert body.get("summary") and body["summary"].get("verdict"), f"preset {i} {preset.get('id')} missing verdict"
        print(f"[preset {i}/{len(presets)}] {preset.get('id')} -> {body['summary']['verdict']}")


def gate_harness(base: str) -> None:
    node = shutil.which("node")
    if node is None:
        raise RuntimeError("node not found on PATH — run JS tests or --skip-node")
    env = {
        "NP_BASE_URL": base,
        "NP_ADMIN_USER": ADMIN_USER,
        "NP_ADMIN_PASS": ADMIN_PASS,
    }
    run([node, "harness/harness.js"], ROOT / "web", env=env)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--skip-node", action="store_true", help="skip the jsdom harness")
    ap.add_argument("--skip-pytest", action="store_true", help="skip the full pytest run")
    ap.add_argument("--port", type=int, default=8787, help="port for the throwaway server")
    args = ap.parse_args(argv)

    os.environ.setdefault("NETPROOF_ADMIN_USER", ADMIN_USER)
    os.environ.setdefault("NETPROOF_ADMIN_PASS", ADMIN_PASS)

    gate_compile()
    gate_imports()
    if not args.skip_pytest:
        gate_pytest()

    scratch = Path(tempfile.mkdtemp(prefix="np-ci-"))
    db = scratch / "ci.db"
    orgs = scratch / "orgs"
    orgs.mkdir()
    server_env = {
        "NETPROOF_DB": str(db),
        "NETPROOF_ORG_DIR": str(orgs),
        "NETPROOF_ADMIN_USER": ADMIN_USER,
        "NETPROOF_ADMIN_PASS": ADMIN_PASS,
        "NETPROOF_ALLOW_HTTP": "1",
    }
    proc = subprocess.Popen(
        [PY, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", str(args.port),
         "--log-level", "warning"],
        cwd=str(BACKEND),
        env={**os.environ, **server_env},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{args.port}"
    try:
        wait_health(base)
        gate_presets(base)
        if not args.skip_node:
            gate_harness(base)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(scratch, ignore_errors=True)

    print("CI gate: ALL STEPS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())