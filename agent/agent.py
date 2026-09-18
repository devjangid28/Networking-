"""Local discovery agent for NetProof.

Runs on a machine inside the customer network, performs a local-machinery-only
scan (no central server involvement) and phones that report home OUTBOUND to
the NetProof backend over HTTPS. Optionally attaches device configs to mark
rules/routes as "confirmed".

Everything is one-shot or a simple interval loop:
    agent.py --target 192.168.50.1 --backend https://netproof.example --api-key K ...
    agent.py --target 192.168.50.1 --config-file network.json --api-key K ...

The agent never exposes a listener — it only talks out. Which makes it usable
from behind NAT/firewalls, as long as outbound HTTPS to the backend is open.
"""
import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(ROOT, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
# `from agent.pull import ...` needs the repo root itself importable, so the
# config-file / SSH pullers resolve no matter how the agent was launched.
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

try:
    from engine.metainfo import PROJECT_VERSION
    VERSION = PROJECT_VERSION
except Exception:  # pragma: no cover
    VERSION = "0.0.0"


def validate_backend(url: str | None) -> str:
    """Reject backends that would carry the API key in cleartext.

    Plain HTTP is only allowed for loopback addresses (local dev). Everything
    else must be HTTPS unless the operator explicitly opts out with
    $NETPROOF_ALLOW_HTTP=1 (trusted staging only).
    """
    import urllib.parse
    url = (url or "").strip().rstrip("/")
    if not url:
        raise ValueError("backend URL is required (--backend or $NETPROOF_BACKEND)")
    parts = urllib.parse.urlparse(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError(f"backend URL must start with http(s)://, got '{url}'")
    host = (parts.hostname or "").lower()
    is_loopback = host in ("127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1")
    if parts.scheme != "https" and not is_loopback and os.environ.get("NETPROOF_ALLOW_HTTP") != "1":
        raise ValueError(
            f"refusing to send the API key over plain HTTP to '{host}'. Point --backend "
            "at an https:// endpoint (loopback/local dev is allowed). To override for a "
            "trusted staging box, set NETPROOF_ALLOW_HTTP=1."
        )
    return url

try:
    from engine import discover, buildnet, confirm  # noqa: E402
    from engine.model import load_net  # noqa: E402
except Exception as e:  # pragma: no cover - import-time failure
    print(f"agent: cannot load engine modules: {e}", file=sys.stderr)
    sys.exit(2)


def _post(backend: str, api_key: str, payload: dict, timeout: float = 20.0) -> dict:
    """Outbound push of a discovery/config report to the central backend."""
    url = backend.rstrip("/") + "/api/agent/report"
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "X-NetProof-Key": api_key,
                 "User-Agent": f"netproof-agent/{VERSION}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read().decode("utf-8")
            return {"ok": True, "status": resp.status, "body": json.loads(data) or {}}
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        return {"ok": False, "status": e.code, "body": detail}
    except Exception as e:
        return {"ok": False, "status": 0, "body": str(e)}


def _merge_config(base: dict | None, extra: dict) -> dict:
    """Combine config snapshots; see engine.confirm.merge_configs."""
    from engine.confirm import merge_configs
    return merge_configs(base, extra)


def _load_pull():
    """Import the sibling ``pull.py`` without depending on ``agent`` resolving to
    a package — the script itself is named ``agent.py``, which shadows the
    ``agent`` package when launched as ``python agent/agent.py``."""
    try:
        from agent import pull
        return pull
    except ImportError:
        pass
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pull.py")
    spec = importlib.util.spec_from_file_location("netproof_pull", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def gather(target: str, config_file: str | None, community: str,
           do_ping: bool, max_devices: int,
           ssh: dict | None = None) -> dict:
    """Run the engine discovery + any config pull, returning the report payload."""
    print(f"agent: scanning {target} ...")
    scan = discover.scan(target, community=community, do_ping=do_ping,
                         max_devices=max_devices)
    print(f"agent: found {len(scan.get('devices', []))} systems")

    config = None
    config_sources: list = []

    if config_file:
        pull = _load_pull()
        config = pull.load_config_file(config_file)
        if config is not None:
            config_sources.append("config-file")
            print(f"agent: attached config from {config_file} "
                  f"({len(config or {})} devices)")

    if ssh:
        pull = _load_pull()
        host = ssh.get("host") or target
        print(f"agent: pulling config from {host} over SSH ...")
        got = pull.via_ssh(
            host,
            username=ssh.get("user") or "",
            password=ssh.get("password"),
            key_file=ssh.get("key"),
            port=int(ssh.get("port") or 22),
            config_path=ssh.get("config_path") or "/config/run.cfg",
            known_hosts=ssh.get("known_hosts"),
        )
        if got and got.get("config"):
            config = _merge_config(config, {host: got["config"]})
            config_sources.append("ssh")
            print(f"agent: SSH config attached from {host} "
                  f"({len(got['config'].get('filters') or [])} filters, "
                  f"{len(got['config'].get('routes') or [])} routes)")
        else:
            print("agent: SSH config pull returned nothing (best-effort, continuing)")

    from engine.buildnet import build_net
    net, by_ip = build_net(scan)
    confirmed = confirm.counts(net)["rules"]["confirmed"] if config else 0

    payload = {
        "agent_version": VERSION,
        "scan": scan,
        "config": config,
        "config_sources": config_sources,
        "meta": {
            "target": target,
            "hostname": os.uname().nodename if hasattr(os, "uname") else os.environ.get("COMPUTERNAME", "?"),
            "config_sources": config_sources,
        },
    }
    print(f"agent: report ready ({len(scan.get('devices', []))} devices, "
          f"{confirmed} confirmed rules)")
    return payload


def run_once(args, ssh: dict | None = None) -> dict:
    payload = gather(args.target, args.config_file, args.community,
                     not args.no_ping, args.max_devices, ssh=ssh)
    payload["consent"] = bool(args.consent)
    print(f"agent: posting report to {args.backend}/api/agent/report ...")
    result = _post(args.backend, args.api_key, payload)
    if result["ok"]:
        body = result["body"]
        print(f"agent: server accepted report id={body.get('report_id')} "
              f"org={body.get('org')}")
    else:
        tail = result["body"]
        if isinstance(tail, str):
            tail = tail[:300]
        print(f"agent: report FAILED (http {result['status']})"
              + (f" — {tail}" if tail else ""), file=sys.stderr)
    return result


def _default_backend() -> str:
    return os.environ.get("NETPROOF_BACKEND", "http://127.0.0.1:8000")


def _ssh_args(args) -> dict | None:
    """Build the option-B SSH pull settings when any SSH flag is supplied."""
    if not (args.ssh or args.ssh_user or args.ssh_host or args.ssh_key):
        return None
    return {
        "host": args.ssh_host or args.target,
        "user": args.ssh_user or "",
        "password": args.ssh_password,
        "key": args.ssh_key,
        "port": args.ssh_port,
        "config_path": args.ssh_config_path,
        "known_hosts": args.ssh_known_hosts,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="netproof-agent",
                                 description="Local discovery agent for NetProof")
    ap.add_argument("--target", required=True, help="router/gateway IP in the segment to scan")
    ap.add_argument("--backend", default=None, help="central backend base URL (default: $NETPROOF_BACKEND or http://127.0.0.1:8000)")
    ap.add_argument("--api-key", default=None, help="organization API key (or $NETPROOF_API_KEY)")
    ap.add_argument("--config-file", default=None, help="JSON file with confirmed device configs (filters + routes) — option A")
    ap.add_argument("--ssh", action="store_true", help="also pull device config over SSH (best effort) — option B")
    ap.add_argument("--ssh-host", default=None, help="host to pull config from (default: the --target router)")
    ap.add_argument("--ssh-user", default=None, help="SSH username (required for option B)")
    ap.add_argument("--ssh-password", default=None, help="SSH password (or pass --ssh-key below)")
    ap.add_argument("--ssh-key", default=None, help="path to an SSH private key file instead of a password")
    ap.add_argument("--ssh-port", type=int, default=22, help="SSH port (default: 22)")
    ap.add_argument("--ssh-config-path", default="/config/run.cfg", help="device config file path to read over SSH (e.g. /config/run.cfg)")
    ap.add_argument("--ssh-known-hosts", default=None, help="path to a known_hosts file (default: ~/.ssh/known_hosts; unknown hosts are rejected)")
    ap.add_argument("--community", default="public", help="SNMP community for reads")
    ap.add_argument("--no-ping", action="store_true", help="skip ICMP ping sweep")
    ap.add_argument("--consent", action="store_true",
                    help="record the network owner's explicit consent in the report (server will reject reports without this flag)")
    ap.add_argument("--max-devices", type=int, default=120)
    ap.add_argument("--interval", type=int, default=0,
                    help="seconds between reports; 0 = run once and exit")
    args = ap.parse_args(argv)

    args.backend = args.backend or _default_backend()
    args.api_key = args.api_key or os.environ.get("NETPROOF_API_KEY")
    if not args.api_key:
        print("agent: missing API key (--api-key or $NETPROOF_API_KEY)", file=sys.stderr)
        return 2
    try:
        args.backend = validate_backend(args.backend)
    except ValueError as exc:
        print(f"agent: {exc}", file=sys.stderr)
        return 2

    if args.interval <= 0:
        try:
            run_once(args, ssh=_ssh_args(args))
        except KeyboardInterrupt:
            return 130
        return 0

    print(f"agent: interval loop every {args.interval}s (Ctrl+C to stop)")
    try:
        while True:
            try:
                run_once(args, ssh=_ssh_args(args))
            except KeyboardInterrupt:
                raise
            except Exception as e:
                print(f"agent: run failed: {e}", file=sys.stderr)
            time.sleep(max(5, args.interval))
    except KeyboardInterrupt:
        print("\nagent: stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())