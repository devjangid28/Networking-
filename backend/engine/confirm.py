"""Config ingestion: which model facts are CONFIRMED vs INFERRED.

An active scanner can only guess: a system profile (ARP + service ports) is
handed to build_net as an inferred model. When the agent also pulls the real
config (SSH `show running-config` or SNMP tables), matching rules/routes get
flipped to `source="confirmed"` and config-only entries are added as confirmed.
The dashboard surfaces both kinds so an engineer can tell "ground truth" from
"scanner guess" at a glance.
"""
from __future__ import annotations

from .model import Net, Prefix, Route, Rule, Filter


def merge_configs(base: dict | None, extra: dict) -> dict:
    """Combine two ``{ip: {filters, routes}}`` config snapshots into ONE dict so
    config-file (option A) and SSH-pull (option B) feed a single confirmed model.
    Same-named filters get their rule lists concatenated (base first, then
    extra); routes are appended in order."""
    base = base or {}
    extra = extra or {}
    out: dict = {}
    for ip in list(base.keys()) + [k for k in extra.keys() if k not in base]:
        devs = [d for d in (base.get(ip), extra.get(ip)) if d]
        by_name: dict = {}
        order: list = []
        for dev in devs:
            for f in dev.get("filters") or []:
                name = f.get("name")
                if not name:
                    continue
                if name not in by_name:
                    by_name[name] = {"name": name, "rules": list(f.get("rules") or [])}
                    order.append(name)
                else:
                    by_name[name]["rules"].extend(f.get("rules") or [])
        routes: list = []
        for dev in devs:
            routes.extend(dev.get("routes") or [])
        out[ip] = {"filters": [by_name[n] for n in order], "routes": routes}
    return out


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


def ensure_interfaces_filters(dev, name: str) -> None:
    """Attach a policy point name to every interface of a device that got none."""
    if not getattr(dev, "interfaces", None):
        return
    for iface in dev.interfaces:
        if name not in (iface.filters or []):
            iface.filters.append(name)


def ingest_config(net: Net, config: dict | None) -> dict:
    """Mark rules/routes confirmed AND materialize config-only policy points.

    ``mark_confirmed`` only fills policy points the scanner already guessed
    (the single ``router-lan-in``). A real device usually has many ACLs the
    scanner never heard of — this adds those as NEW confirmed policy points and
    attaches them to the router's faces so every rule the device actually has
    is visible in the dashboard and usable in the Change Builder."""
    changes = mark_confirmed(net, config)
    for dev_key, dev_conf in (config or {}).items():
        dev = _resolve_device(net, str(dev_key))
        if dev is None:
            continue
        for f_conf in dev_conf.get("filters") or []:
            name = str(f_conf.get("name") or "").strip()
            if not name or name in net.filters:
                continue
            rules = [Rule.from_dict({**r, "source": "confirmed"})
                     for r in (f_conf.get("rules") or [])]
            net.filters[name] = Filter(name=name, default="permit", rules=rules)
            ensure_interfaces_filters(dev, name)
            changes["rules_added"] += len(rules)
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