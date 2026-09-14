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
import re
import sys
import time
import urllib.request
import urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(ROOT, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

VERSION = "0.1.0"
CONFIG_URL_RE = re.compile(r"^https://")

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


def gather(target: str, config_file: str | None, community: str,
           do_ping: bool, max_devices: int) -> dict:
    """Run the engine discovery + any config pull, returning the report payload."""
    print(f"agent: scanning {target} ...")
    scan = discover.scan(target, community=community, do_ping=do_ping,
                         max_devices=max_devices)
    print(f"agent: found {len(scan.get('devices', []))} systems")

    config = None
    if config_file:
        from agent.pull import load_config_file
        config = load_config_file(config_file)
        if config is not None:
            print(f"agent: attached config from {config_file} "
                  f"({len(config or {})} devices)")

    from engine.buildnet import build_net
    net, by_ip = build_net(scan)
    confirmed = confirm.counts(net)["rules"]["confirmed"] if config else 0

    payload = {
        "agent_version": VERSION,
        "scan": scan,
        "config": config,
        "meta": {
            "target": target,
            "hostname": os.uname().nodename if hasattr(os, "uname") else os.environ.get("COMPUTERNAME", "?"),
        },
    }
    print(f"agent: report ready ({len(scan.get('devices', []))} devices, "
          f"{confirmed} confirmed rules)")
    return payload


def run_once(args) -> dict:
    payload = gather(args.target, args.config_file, args.community,
                     not args.no_ping, args.max_devices)
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


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="netproof-agent",
                                 description="Local discovery agent for NetProof")
    ap.add_argument("--target", required=True, help="router/gateway IP in the segment to scan")
    ap.add_argument("--backend", default=None, help="central backend base URL (default: $NETPROOF_BACKEND or http://127.0.0.1:8000)")
    ap.add_argument("--api-key", default=None, help="organization API key (or $NETPROOF_API_KEY)")
    ap.add_argument("--config-file", default=None, help="JSON file with confirmed device configs (filters + routes)")
    ap.add_argument("--community", default="public", help="SNMP community for reads")
    ap.add_argument("--no-ping", action="store_true", help="skip ICMP ping sweep")
    ap.add_argument("--max-devices", type=int, default=120)
    ap.add_argument("--interval", type=int, default=0,
                    help="seconds between reports; 0 = run once and exit")
    args = ap.parse_args(argv)

    args.backend = args.backend or _default_backend()
    args.api_key = args.api_key or os.environ.get("NETPROOF_API_KEY")
    if not args.api_key:
        print("agent: missing API key (--api-key or $NETPROOF_API_KEY)", file=sys.stderr)
        return 2

    if args.interval <= 0:
        try:
            run_once(args)
        except KeyboardInterrupt:
            return 130
        return 0

    print(f"agent: interval loop every {args.interval}s (Ctrl+C to stop)")
    try:
        while True:
            try:
                run_once(args)
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