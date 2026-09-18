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
                "parse_intent", "get_guardrails", "list_presets"} <= tools

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