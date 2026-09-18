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
            config_path: str = "/config/run.cfg",
            known_hosts: str | None = None) -> dict | None:
    """Best-effort config read over SSH using paramiko (optional dep).

    Host-key security: unknown host keys are REJECTED by default — a MITM
    presenting its own key fails the connection instead of being silently
    accepted. Pass ``known_hosts`` to point at a known_hosts file (defaults to
    the user's ``~/.ssh/known_hosts`` when it exists). If the host is not
    there yet, the read fails with a non-fatal message telling the operator to
    add it, rather than auto-trusting a stranger's key.
    """
    try:
        import paramiko
    except ImportError:
        print("agent/pull: SSH pull requires 'pip install paramiko' — skipping",
              file=__import__("sys").stderr)
        return None
    try:
        client = paramiko.SSHClient()
        known_hosts = known_hosts or __import__("os").path.expanduser("~/.ssh/known_hosts")
        if __import__("os").path.isfile(known_hosts):
            client.load_host_keys(known_hosts)
        # Never AutoAddPolicy: reject any host whose key we don't already trust.
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        if key_file:
            client.connect(host, port=port, username=username, key_filename=key_file, timeout=10)
        else:
            client.connect(host, port=port, username=username, password=password, timeout=10)
        # Remote command goes through the peer's shell, so the config path is
        # shell-quoted — a path can never inject extra commands or options.
        safe_path = __import__("shlex").quote(str(config_path))
        _, stdout, stderr = client.exec_command(f"cat {safe_path}")
        text = stdout.read().decode("utf-8", "replace")
        client.close()
        return {"raw": text[:200_000], "config": parse_router_text(text)}
    except Exception as e:
        print(f"agent/pull: SSH read failed: {e}", file=__import__("sys").stderr)
        return None


def parse_router_text(text: str, host: str = "device") -> dict:
    """Minimal, best-effort parser from raw device config text to the engine's
    ``{filters: [{name, rules}], routes: []}`` shape.

    Understands enough of the common dialects to be genuinely useful without
    pretending to be a full parser:
      - routes:  ``ip route <net> <mask> <nh>`` (Cisco), ``ip route <net>/<len> via <nh>``
                 (VyOS), ``route add [-net] <net>/<mask> gw <nh>`` (Linux)
      - ACLs:    numbered ``access-list N permit/deny <proto> <src> <mask> [eq <port>]``
                 and named ``ip access-list extended <name>`` … ``<seq> permit/deny ...``
      - iptables ``-A <chain> ... -p <proto> --dport <port> -j ACCEPT/DROP`` chains
                 are exported as one filter per chain
    Everything unrecognized is skipped (never a crash).
    """
    out: dict = {"routes": [], "filters": []}
    acl: dict | None = None            # named ACL currently being gathered
    iptables: dict = {}                # chain -> list of rules

    line: str
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith(("!", "#", "//", "--")):
            continue
        lw = line.split()
        if not lw:
            continue
        head = (lw[0] or "").lower()

        # --- static routes ------------------------------------------------
        low = [w.lower() for w in lw]
        if head in ("ip", "route", "set") and ("via" in low or "gw" in low or "next-hop" in low):
            if "via" in low and head == "ip":
                net = lw[low.index("via") - 1]
                nh = lw[low.index("via") + 1]
                out["routes"].append({"network": _canon(net), "next_hop": nh})
            elif "gw" in low:
                nh = lw[low.index("gw") + 1]
                net = lw[low.index("gw") - 1]
                out["routes"].append({"network": _canon(net), "next_hop": nh})
            elif "next-hop" in low:
                net = lw[low.index("next-hop") - 1]
                nh = lw[low.index("next-hop") + 1]
                out["routes"].append({"network": _canon(net), "next_hop": nh})
        elif head == "ip" and len(lw) >= 5 and lw[1].lower() == "route":
            # plain Cisco: ip route <net> <mask> <next-hop>
            out["routes"].append({"network": _canon(lw[2] + "/" + _mask_to_len(lw[3])), "next_hop": lw[4]})

        # --- numbered ACL:  access-list 101 permit tcp any any eq 443 -----
        elif head == "access-list" and len(lw) >= 3 and lw[1].isdigit():
            seq = lw[1]
            action = lw[2].lower()
            if action in ("permit", "deny"):
                acl_name = f"acl-{seq}"
                if not out["filters"] or out["filters"][-1]["name"] != acl_name:
                    out["filters"].append({"name": acl_name, "rules": []})
                rule = _acl_rule(lw[3:], action)
                if rule:
                    out["filters"][-1]["rules"].append(rule)

        # --- named ACL:  ip access-list extended lan-in  …  seq 5 permit --
        elif head == "ip" and lw[1:3] == ["access-list", "extended"] and len(lw) >= 4:
            acl = {"name": lw[3], "rules": []}
            out["filters"].append(acl)
        elif acl is not None and len(lw) >= 2:
            # named ACL rule:  [<seq>] permit|deny ...
            act = lw[0].lower()
            body = lw[1:]
            if not act.isdigit():
                act, body = lw[0].lower(), lw[1:]
            elif lw[0].isdigit() and len(lw) >= 3 and lw[1].lower() in ("permit", "deny"):
                act, body = lw[1].lower(), lw[2:]
            else:
                acl = None
                continue
            if act in ("permit", "deny"):
                rule = _acl_rule(body, act)
                if rule:
                    acl["rules"].append(rule)
            else:
                acl = None
        elif acl is not None and head not in ("ip", "access-list", "!"):
            # anything that isn't a rule line ends the named ACL block
            acl = None

        # --- iptables: -A CHAIN ... -p tcp --dport 80 -j ACCEPT -------------
        elif head.startswith("-a") and len(lw) >= 2:
            iptables.setdefault(lw[1], []).append(lw)

    for chain, entries in iptables.items():
        rules = [r for r in (_ipt_rule(e) for e in entries) if r]
        if rules:
            out["filters"].append({"name": f"iptables-{chain}", "rules": rules})

    if not out["routes"] and not out["filters"]:
        # mark raw-only so callers know nothing was structured
        out["_unparsed"] = True
    return out


def _canon(net: str) -> str:
    return net


def _mask_to_len(mask: str) -> str:
    """255.255.255.0 -> 24. Non-dotted -> as-is."""
    if not mask or "." not in mask:
        return mask
    try:
        bits = sum(bin(int(o)).count("1") for o in mask.split("."))
        return str(bits)
    except ValueError:
        return mask


_PORT_PROTO = {"tcp": "tcp", "udp": "udp"}


def _wild_to_len(mask: str) -> str:
    """Cisco wildcard mask -> prefix length, or None when not a clean wildcard.
    0.0.0.255 -> 24, 0.0.255.255 -> 16, 255.255.255.255 -> 0, 0.0.0.0 -> 32."""
    try:
        octets = [int(o) for o in mask.split(".")]
    except ValueError:
        return None
    wild_bits = sum(bin(o).count("1") for o in octets)
    if wild_bits in (0, 32) and octets not in ([0, 0, 0, 0], [255, 255, 255, 255]):
        return None
    if wild_bits == 32:
        return "0"
    return str(32 - wild_bits)


def _collapsed(tokens: list) -> list:
    """Collapse '<ip> <wildcard-mask>' pairs (Cisco) into '{ip}/{len}' tokens."""
    out: list = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if "." in tok and i + 1 < len(tokens):
            plen = _wild_to_len(tokens[i + 1])
            if plen is not None:
                out.append(f"{tok}/{plen}")
                i += 2
                continue
        out.append(tok)
        i += 1
    return out


def _acl_rule(tokens: list, action: str) -> dict | None:
    """Cisco-style tokens -> engine rule {action, src, dst, proto, dport}.
    Returns None when the rule is structurally unusable (e.g. a comment)."""
    tokens = _collapsed(tokens)
    if not tokens:
        return None
    src = dst = None
    proto = "any"
    dport: int | None = None
    slot = "src"
    i = 0
    while i < len(tokens):
        t = tokens[i]
        tl = t.lower().rstrip(",;")
        if i == 0 and tl in ("ip", "tcp", "udp", "icmp", "any"):
            proto = tl if tl in ("tcp", "udp") else "any"
        elif "." in t:
            if slot == "src":
                src, slot = t, "dst"
            elif dst is None:
                dst = t
        elif tl in ("any",):
            if slot == "src":
                src, slot = "any", "dst"
            else:
                dst = "any"
        elif tl == "host" and i + 1 < len(tokens):
            addr = tokens[i + 1]
            if slot == "src":
                src, slot = addr, "dst"
            elif dst is None:
                dst = addr
            i += 1
        elif tl in ("eq", "range", "lt", "gt"):
            if i + 1 < len(tokens) and tokens[i + 1].isdigit():
                dport = int(tokens[i + 1])
            i += 1
        i += 1
    if src is None:
        src = "any"
    if dst is None:
        dst = "any"
    return {"action": action, "src": src, "dst": dst,
            "proto": proto, "dport": dport}


def _ipt_rule(tokens: list) -> dict | None:
    """iptables token list -> engine rule (best effort)."""
    proto, dport, action = "any", None, None
    for i, t in enumerate(tokens):
        tl = t.lower()
        if tl == "-p" and i + 1 < len(tokens):
            proto = tokens[i + 1].lower() if tokens[i + 1].lower() in ("tcp", "udp") else "any"
        elif tl == "--dport" and i + 1 < len(tokens) and tokens[i + 1].isdigit():
            dport = int(tokens[i + 1])
        elif tl == "-j":
            action = tokens[i + 1].lower() if i + 1 < len(tokens) else None
    if action not in ("accept", "drop", "reject"):
        return None
    return {"action": action.replace("accept", "permit").replace("reject", "deny"),
            "src": "any", "dst": "any", "proto": proto, "dport": dport}


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