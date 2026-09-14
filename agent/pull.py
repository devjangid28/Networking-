"""Optional device-config retrieval for the NetProof agent.

Two data sources, both OPTIONAL and both best-effort:

1. `--config-file some.json` — a static JSON snapshot of the network's device
   config, e.g. exported from a firewall/router management console. This is the
   reliable, recommended path. Shape:

   {
     "192.168.50.1": {
       "filters": [
         {"name": "lan-in", "rules": [
            {"action": "permit", "src": "10.0.10.0/24", "dst": "any", "proto": "tcp", "dport": 80},
            {"action": "deny",   "src": "any", "dst": "any", "proto": "tcp", "dport": 22}
         ]}
       ],
       "routes": [{"network": "0.0.0.0/0", "next_hop": "203.0.113.1"}]
     }
   }

2. `--ssh-script` / SNMP live reads — only if the operator gives credentials and
   the optional libraries (paramiko / pysnmp) are installed. If they aren't,
   these paths are no-ops with a clear message (never a crash).
"""
import json


def load_config_file(path: str) -> dict | None:
    """Read and sanity-check a device-config JSON snapshot."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        print(f"agent/pull: config file not found: {path}", file=__import__("sys").stderr)
        return None
    except json.JSONDecodeError as e:
        print(f"agent/pull: config file is not valid JSON: {e}", file=__import__("sys").stderr)
        return None

    if not isinstance(data, dict):
        print("agent/pull: config file must be a { ip-str: {filters, routes} } object",
              file=__import__("sys").stderr)
        return None

    cleaned = {}
    for ip, dev in data.items():
        if not isinstance(dev, dict):
            continue
        cleaned[ip] = {
            "filters": dev.get("filters") or [],
            "routes": dev.get("routes") or [],
        }
    return cleaned


def via_ssh(host: str, username: str, password: str | None = None,
            key_file: str | None = None, port: int = 22,
            config_path: str = "/config/run.cfg") -> dict | None:
    """Best-effort config read over SSH using paramiko (optional dep)."""
    try:
        import paramiko
    except ImportError:
        print("agent/pull: SSH pull requires 'pip install paramiko' — skipping",
              file=__import__("sys").stderr)
        return None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if key_file:
            client.connect(host, port=port, username=username, key_filename=key_file, timeout=10)
        else:
            client.connect(host, port=port, username=username, password=password, timeout=10)
        _, stdout, stderr = client.exec_command(f"cat {config_path}")
        text = stdout.read().decode("utf-8", "replace")
        client.close()
        return {"raw": text[:200_000]}
    except Exception as e:
        print(f"agent/pull: SSH read failed: {e}", file=__import__("sys").stderr)
        return None


def via_snmp(host: str, community: str = "public") -> dict | None:
    """Best-effort read of the system's SNMP sysDescr / routing table."""
    try:
        from engine.discover import snmp_get, guess_type
    except ImportError:
        return None
    try:
        rows = snmp_get(host, community, [".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.4.21.1.7"])
        return {"snmp": rows} if rows else None
    except Exception as e:
        print(f"agent/pull: SNMP read failed: {e}", file=__import__("sys").stderr)
        return None