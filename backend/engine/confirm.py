"""Config ingestion: which model facts are CONFIRMED vs INFERRED.

An active scanner can only guess: a system profile (ARP + service ports) is
handed to build_net as an inferred model. When the agent also pulls the real
config (SSH `show running-config` or SNMP tables), matching rules/routes get
flipped to `source="confirmed"` and config-only entries are added as confirmed.
The dashboard surfaces both kinds so an engineer can tell "ground truth" from
"scanner guess" at a glance.
"""
from __future__ import annotations

from .model import Net, Prefix, Route, Rule


def _resolve_device(net: Net, key: str):
    dev = net.devices.get(key)
    if dev is not None:
        return dev
    try:
        want = int(ip_of(key))
    except Exception:
        return None
    for d in net.devices.values():
        if want in d.own_ips():
            return d
    return None


def ip_of(addr: str) -> int:
    """Parse a v4 dotted quad to int (lazy import to keep model import chain thin)."""
    from .model import ip_int
    return ip_int(addr)


def _rule_eq(rule: Rule, rc: dict) -> bool:
    return (
        rule.action == str(rc.get("action", "permit")).lower()
        and rule.src == str(rc.get("src") or "any")
        and rule.dst == str(rc.get("dst") or "any")
        and rule.proto == str(rc.get("proto") or "any").lower()
        and rule.dport == (int(rc["dport"]) if rc.get("dport") not in (None, "", "any") else None)
    )


def _route_eq(route: Route, rc: dict) -> bool:
    return (
        route.network == str(rc.get("network"))
        and route.next_hop == str(rc.get("next_hop"))
    )


def mark_confirmed(net: Net, config: dict | None) -> dict:
    """Mark rules/routes found in pulled config as `confirmed`.

    `config` shape (what the agent assembles from SSH/SNMP or a config file):
        { "<device name or ip>": {
             "filters": [ {"name": "router-lan-in", "rules": [
                              {"action","src","dst","proto","dport"}, ... ]} ],
             "routes":  [ {"network", "next_hop"}, ... ],
          } }

    Entries that match an existing model fact are confirmed; entries the scanner
    couldn't see are added as confirmed (config is ground truth). Returns a
    change summary for the UI.
    """
    changes = {"config_devices": 0, "rules_confirmed": 0, "rules_added": 0,
               "routes_confirmed": 0, "routes_added": 0}
    for dev_key, dev_conf in (config or {}).items():
        dev = _resolve_device(net, str(dev_key))
        if dev is None:
            continue
        changes["config_devices"] += 1

        for f_conf in dev_conf.get("filters") or []:
            filt = net.filters.get(str(f_conf.get("name")))
            if filt is None:
                continue
            for r_conf in f_conf.get("rules") or []:
                match = next((r for r in filt.rules if _rule_eq(r, r_conf)), None)
                if match is not None:
                    if match.source != "confirmed":
                        match.source = "confirmed"
                        changes["rules_confirmed"] += 1
                else:
                    filt.rules.append(Rule.from_dict({**r_conf, "source": "confirmed"}))
                    changes["rules_added"] += 1

        for r_conf in dev_conf.get("routes") or []:
            match = next((r for r in dev.routes if _route_eq(r, r_conf)), None)
            if match is not None:
                if match.source != "confirmed":
                    match.source = "confirmed"
                    changes["routes_confirmed"] += 1
            else:
                network = str(r_conf.get("network"))
                dev.routes.append(Route(network, Prefix.parse(network), str(r_conf.get("next_hop")), source="confirmed"))
                changes["routes_added"] += 1
    return changes


def counts(net: Net) -> dict:
    """Overall confirmed/inferred counts for the network (for the dashboard)."""
    rules = {"confirmed": 0, "inferred": 0}
    routes = {"confirmed": 0, "inferred": 0}
    for f in net.filters.values():
        for r in f.rules:
            k = "confirmed" if r.source == "confirmed" else "inferred"
            rules[k] += 1
    for dev in net.devices.values():
        for r in dev.routes:
            k = "confirmed" if r.source == "confirmed" else "inferred"
            routes[k] += 1
    return {"rules": rules, "routes": routes}