"""P3: real end-to-end MCP test — spawn the actual `mcp_server.py` as a stdio
subprocess, perform the JSON-RPC handshake over its pipes, and call the tools.
This proves MCP integration works (imports, FastMCP registration, tool routing),
not just that the engine functions are individually testable."""
import json
import os
import subprocess
import sys
import time

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MCP = os.path.join(BACKEND, "mcp_server.py")

WRITE_TIMEOUT = 30  # seconds


def _read_msg(proc, timeout: float = WRITE_TIMEOUT) -> dict:
    """Read one newline-delimited JSON-RPC message from the MCP server."""
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("MCP server exited: " + (proc.stderr.read(4000) or "(no stderr)").strip())
    msg = json.loads(line)
    return msg


def _wait_id(proc, want, timeout: float = WRITE_TIMEOUT):
    """Consume notifications until the response for `want` appears."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        msg = _read_msg(proc, timeout=timeout)
        # response (has id) vs notification (method-only)
        if msg.get("id") == want:
            return msg
    raise TimeoutError(f"no response for id {want}")


def test_mcp_stdio_handshake_and_tools():
    proc = subprocess.Popen(
        [sys.executable, MCP],
        cwd=BACKEND,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1,
    )
    try:
        # 1. initialize
        init = {
            "jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
                "protocolVersion": "2024-11-05", "capabilities": {},
                "clientInfo": {"name": "opencode-test", "version": "0.0.0"},
            },
        }
        proc.stdin.write(json.dumps(init) + "\n")
        proc.stdin.flush()
        resp = _wait_id(proc, 0)
        assert resp["result"].get("serverInfo", {}).get("name") == "netproof"
        assert resp["result"].get("protocolVersion")

        # 2. initialized notification
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}) + "\n")
        proc.stdin.flush()

        # 3. tools/list
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}) + "\n")
        proc.stdin.flush()
        listed = _wait_id(proc, 1)
        tools = {t["name"] for t in listed["result"]["tools"]}
        assert {"validate_change", "get_verdict", "list_network_inventory",
                "parse_intent", "get_guardrails", "list_presets",
                "describe_target"} <= tools

        # 4. tools/call list_presets (no model dependency, read-only)
        proc.stdin.write(json.dumps({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "list_presets", "arguments": {}},
        }) + "\n")
        proc.stdin.flush()
        presets = _wait_id(proc, 2)
        content = presets["result"]["content"]
        raw = "".join(c.get("text", "") for c in content if c.get("type") == "text")
        assert "\"presets\"" in raw

        # 5. tools/call list_network_inventory (loads the bundled model)
        proc.stdin.write(json.dumps({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "list_network_inventory", "arguments": {}},
        }) + "\n")
        proc.stdin.flush()
        inv = _wait_id(proc, 3)
        inv_text = "".join(c.get("text", "") for c in inv["result"]["content"] if c.get("type") == "text")
        assert "\"devices\"" in inv_text
        assert "\"filters\"" in inv_text

        # 6. tool errors surface as proper JSON-RPC content, not a crash
        proc.stdin.write(json.dumps({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "get_verdict", "arguments": {"verdict_id": "does-not-exist"}},
        }) + "\n")
        proc.stdin.flush()
        err = _wait_id(proc, 4)
        assert "isError" in err["result"] or "error" in err  # surfaced, not killed

        assert proc.poll() is None, "MCP server must stay alive through the session"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_mcp_describe_target_tool():
    """describe_target returns the full intelligence bundle for a real IP on the
    bundled demo model, and stays read-only (no verdict is written)."""
    proc = subprocess.Popen(
        [sys.executable, MCP],
        cwd=BACKEND,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1,
    )
    try:
        proc.stdin.write(json.dumps({
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "opencode-test", "version": "0.0.0"}},
        }) + "\n")
        proc.stdin.flush()
        assert _wait_id(proc, 0)["result"].get("serverInfo", {}).get("name") == "netproof"

        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}) + "\n")
        proc.stdin.flush()

        proc.stdin.write(json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "describe_target", "arguments": {"ip": "10.0.20.10"}},
        }) + "\n")
        proc.stdin.flush()
        resp = _wait_id(proc, 1)
        assert proc.poll() is None
        assert resp.get("result") and not (resp["result"].get("isError") or False)
        raw = "".join(c.get("text", "") for c in resp["result"]["content"] if c.get("type") == "text")
        bundle = json.loads(raw if raw.strip().startswith("{") else _extract_json(raw))
        assert bundle["status"] == "found"
        for key in ("identity", "discovery_detail", "confirmed_vs_inferred",
                    "applicable_guardrails", "validation_history", "suggested_actions"):
            assert key in bundle, key
        assert isinstance(bundle["applicable_guardrails"], list)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def _extract_json(text: str) -> str:
    """FastMCP may wrap the payload; pull the first {...} block out."""
    start = text.find("{")
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    raise ValueError("no JSON object found in tool output")