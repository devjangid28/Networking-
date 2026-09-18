"""P3: the agent's config pull must turn raw device text into the engine's
{ filters: [{name, rules}], routes: [] } shape so rules/routes can be marked
confirmed — verified without requiring any optional SSH/native libs."""
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from agent.pull import parse_router_text  # noqa: E402

ROUTER_TEXT = """!
ip route 10.0.10.0 255.255.255.0 192.168.50.1
ip route 0.0.0.0 0.0.0.0 203.0.113.1
set protocols static route 172.16.0.0/16 next-hop 10.20.30.1
ip route add 10.5.5.0/24 via 192.168.1.254
!
access-list 101 permit tcp any any eq 443
access-list 101 deny tcp any any eq 22
ip access-list extended lan-in
 10 permit ip 10.0.10.0 0.0.0.255 any
 20 deny tcp any host 10.0.0.5 eq 3389
 30 permit ip any any
!"""


def test_routes_parsed():
    r = parse_router_text(ROUTER_TEXT)
    nets = {x["network"] for x in r["routes"]}
    assert nets == {"10.0.10.0/24", "0.0.0.0/0", "172.16.0.0/16", "10.5.5.0/24"}


def test_numbered_acl_parsed():
    r = parse_router_text(ROUTER_TEXT)
    acl = next(f for f in r["filters"] if f["name"] == "acl-101")
    assert acl["rules"][0]["dport"] == 443
    assert acl["rules"][1]["action"] == "deny"


def test_named_acl_wildcard_and_host():
    r = parse_router_text(ROUTER_TEXT)
    acl = next(f for f in r["filters"] if f["name"] == "lan-in")
    assert acl["rules"][0] == {"action": "permit", "src": "10.0.10.0/24",
                               "dst": "any", "proto": "any", "dport": None}
    deny = acl["rules"][1]
    assert deny["dst"] == "10.0.0.5" and deny["dport"] == 3389


def test_iptables_chain():
    r = parse_router_text("-A INPUT -p tcp --dport 80 -j ACCEPT\n-A INPUT -p tcp --dport 22 -j DROP")
    chain = next(f for f in r["filters"] if f["name"] == "iptables-INPUT")
    assert [x["dport"] for x in chain["rules"]] == [80, 22]
    assert chain["rules"][0]["action"] == "permit"
    assert chain["rules"][1]["action"] == "drop"


def test_gibberish_is_ignored_not_crashing():
    r = parse_router_text("this is not a router config\n!!%%\n  \nrandom 42!")
    assert isinstance(r["routes"], list)
    assert isinstance(r["filters"], list)