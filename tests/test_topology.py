import time
from pathlib import Path

import pytest

from landiscovery.models import Edge, Host, Topology
from landiscovery.nmapxml import ScanParseError
from landiscovery.topology import MAX_HOPS, build_topology, parse_traceroute

FIX = Path(__file__).parent / "fixtures"


def load(name):
    return (FIX / name).read_text(encoding="utf-8")


def edges(t):
    return {(e.a, e.b) for e in t.edges}


def nodes(t):
    return {n.id: n for n in t.nodes}


def test_parse_traceroute_hops():
    hops = parse_traceroute(load("nmap_traceroute.xml"))
    assert hops["192.168.1.20"] == ["192.168.1.1", "10.0.0.1", "10.0.1.1"]
    assert hops["192.168.1.30"] == ["192.168.1.1"]
    assert "192.168.1.40" not in hops


def test_parse_non_numeric_ttl_keeps_document_order():
    xml = ('<nmaprun><host><address addr="10.1.1.9" addrtype="ipv4"/><trace>'
           '<hop ttl="x" ipaddr="10.1.1.1"/><hop ttl="" ipaddr="10.1.1.2"/>'
           '</trace></host></nmaprun>')
    assert parse_traceroute(xml)["10.1.1.9"] == ["10.1.1.1", "10.1.1.2"]


def test_hostile_invalid_hops_skipped():
    xml = ('<nmaprun><host><address addr="10.1.1.9" addrtype="ipv4"/><trace>'
           '<hop ttl="1" ipaddr="999.1.1.1"/><hop ttl="2" ipaddr="; rm -rf /"/>'
           '<hop ttl="3" ipaddr="fe80::1%eth0"/><hop ttl="4" ipaddr="10.1.1.1"/>'
           '</trace></host></nmaprun>')
    assert parse_traceroute(xml)["10.1.1.9"] == ["fe80::1", "10.1.1.1"]


def test_truncated_xml_raises():
    with pytest.raises(ScanParseError):
        parse_traceroute(load("nmap_truncated.xml"))
    with pytest.raises(ScanParseError):
        parse_traceroute("")


def test_entity_xml_rejected():
    xml = ('<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x "y">]>'
           '<nmaprun></nmaprun>')
    with pytest.raises(ScanParseError):
        parse_traceroute(xml)


def test_star_when_no_hops():
    hosts = [Host(ip="192.168.1.20"), Host(ip="192.168.1.30")]
    t = build_topology(hosts, {}, "192.168.1.1")
    assert edges(t) == {("192.168.1.1", "192.168.1.20"),
                        ("192.168.1.1", "192.168.1.30")}
    assert nodes(t)["192.168.1.1"].kind == "gateway"


def test_host_with_empty_hops_falls_back_to_star():
    t = build_topology([Host(ip="192.168.1.20")], {"192.168.1.20": []},
                       "192.168.1.1")
    assert edges(t) == {("192.168.1.1", "192.168.1.20")}


def test_router_between_gateway_and_remote_host():
    hosts = [Host(ip="172.16.0.5", hostname="srv")]
    hops = {"172.16.0.5": ["192.168.1.1", "10.0.0.1"]}
    t = build_topology(hosts, hops, "192.168.1.1")
    n = nodes(t)
    assert n["10.0.0.1"].kind == "router"
    assert n["172.16.0.5"].label == "srv"
    assert edges(t) == {("10.0.0.1", "192.168.1.1"), ("10.0.0.1", "172.16.0.5")}


def test_gateway_equal_to_first_hop_not_duplicated():
    hosts = [Host(ip="192.168.1.20")]
    t = build_topology(hosts, {"192.168.1.20": ["192.168.1.1"]}, "192.168.1.1")
    assert [n.id for n in t.nodes].count("192.168.1.1") == 1
    assert len(t.nodes) == 2
    assert edges(t) == {("192.168.1.1", "192.168.1.20")}


def test_hosts_grouped_by_subnet():
    hosts = [Host(ip="192.168.1.20"), Host(ip="192.168.2.7")]
    n = nodes(build_topology(hosts, {}, "192.168.1.1"))
    assert n["192.168.1.20"].subnet == "192.168.1.0/24"
    assert n["192.168.2.7"].subnet == "192.168.2.0/24"
    assert n["192.168.1.1"].subnet == "192.168.1.0/24"


def test_duplicate_hop_creates_single_node():
    hosts = [Host(ip="172.16.0.5"), Host(ip="172.16.0.6")]
    hops = {"172.16.0.5": ["192.168.1.1", "10.0.0.1"],
            "172.16.0.6": ["192.168.1.1", "10.0.0.1"]}
    t = build_topology(hosts, hops, "192.168.1.1")
    assert [n.id for n in t.nodes].count("10.0.0.1") == 1
    assert len(t.edges) == 3


def test_hop_that_is_scanned_host_becomes_router():
    hosts = [Host(ip="192.168.1.50"), Host(ip="172.16.0.5")]
    hops = {"172.16.0.5": ["192.168.1.1", "192.168.1.50"]}
    t = build_topology(hosts, hops, "192.168.1.1")
    n = nodes(t)
    assert n["192.168.1.50"].kind == "router"
    assert len([x for x in t.nodes if x.id == "192.168.1.50"]) == 1


def test_scanned_host_uses_key_as_id():
    h = Host(ip="192.168.1.20", mac="AA:BB:CC:DD:EE:FF")
    t = build_topology([h], {}, "192.168.1.1")
    assert "AA:BB:CC:DD:EE:FF" in nodes(t)
    assert nodes(t)["AA:BB:CC:DD:EE:FF"].subnet == "192.168.1.0/24"


def test_gateway_wins_over_host():
    hosts = [Host(ip="192.168.1.1", hostname="gw"), Host(ip="192.168.1.20")]
    t = build_topology(hosts, {}, "192.168.1.1")
    n = nodes(t)
    assert n["192.168.1.1"].kind == "gateway"
    assert n["192.168.1.1"].label == "gw"
    assert edges(t) == {("192.168.1.1", "192.168.1.20")}


def test_ipv6_hops_and_subnet():
    hosts = [Host(ip="2001:db8:1:2::10")]
    hops = {"2001:db8:1:2::10": ["2001:db8:1:2::1", "2001:db8:ffff::1"]}
    t = build_topology(hosts, hops, "2001:db8:1:2::1")
    n = nodes(t)
    assert n["2001:db8:1:2::10"].subnet == "2001:db8:1:2::/64"
    assert n["2001:db8:ffff::1"].kind == "router"
    assert n["2001:db8:ffff::1"].subnet == "2001:db8:ffff::/64"


def test_gateway_inferred_from_common_first_hop():
    hosts = [Host(ip="172.16.0.5"), Host(ip="172.16.0.6"), Host(ip="172.16.0.7")]
    hops = {"172.16.0.5": ["192.168.1.1", "10.0.0.1"],
            "172.16.0.6": ["192.168.1.1"],
            "172.16.0.7": ["192.168.9.9"]}
    t = build_topology(hosts, hops, None)
    n = nodes(t)
    assert n["192.168.1.1"].kind == "gateway"
    assert n["192.168.9.9"].kind == "router"


def test_virtual_gateway_when_unknown():
    t = build_topology([Host(ip="192.168.1.20")], {}, None)
    g = nodes(t)["gateway"]
    assert g.kind == "gateway" and g.label == "Gateway" and g.subnet == ""
    assert edges(t) == {("192.168.1.20", "gateway")}


def test_edge_dedup_symmetrical_and_ordered():
    hosts = [Host(ip="172.16.0.5")]
    hops = {"172.16.0.5": ["192.168.1.1", "10.0.0.1", "192.168.1.1"]}
    t = build_topology(hosts, hops, "192.168.1.1")
    assert len(t.edges) == len({frozenset((e.a, e.b)) for e in t.edges})
    assert all(e.a < e.b for e in t.edges)


def test_deterministic_ordering():
    hosts = [Host(ip="192.168.1.30"), Host(ip="192.168.1.20"),
             Host(ip="172.16.0.5")]
    hops = {"172.16.0.5": ["192.168.1.1", "10.0.0.9", "10.0.0.2"]}
    t1 = build_topology(hosts, hops, "192.168.1.1")
    t2 = build_topology(list(reversed(hosts)), hops, "192.168.1.1")
    assert t1 == t2
    order = {"gateway": 0, "router": 1, "host": 2}
    keys = [(order[n.kind], n.id) for n in t1.nodes]
    assert keys == sorted(keys)


def test_empty_host_list_gateway_only():
    t = build_topology([], {}, "192.168.1.1")
    assert [n.id for n in t.nodes] == ["192.168.1.1"]
    assert t.edges == []


def test_topology_always_marked_inferred():
    assert build_topology([], {}, None).inferred is True
    assert build_topology([Host(ip="10.0.0.2")], {}, "10.0.0.1").inferred is True


def _big_xml(n):
    hops = "".join(
        f'<hop ttl="{i}" ipaddr="10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"/>'
        for i in range(1, n + 1))
    return ('<nmaprun><host><address addr="192.168.1.9" addrtype="ipv4"/>'
            f'<trace>{hops}</trace></host></nmaprun>')


def test_huge_trace_is_fast_and_capped():
    t0 = time.monotonic()
    hops = parse_traceroute(_big_xml(100_000))
    assert time.monotonic() - t0 < 2
    chain = hops["192.168.1.9"]
    assert len(chain) == MAX_HOPS == 64
    assert chain[0] == "10.0.0.1"
    t0 = time.monotonic()
    raw = [f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"
           for i in range(1, 100_001)]
    t = build_topology([Host(ip="192.168.1.9")], {"192.168.1.9": raw}, None)
    assert time.monotonic() - t0 < 2
    assert len(t.nodes) == 64 + 1


def test_uppercase_ipv6_host_matches_hops():
    h = Host(ip="2001:DB8:0:0:0:0:0:10")
    t = build_topology([h], {"2001:db8::10": ["2001:db8::1", "2001:db8::2"]},
                       "2001:DB8::1")
    n = nodes(t)
    assert [x.kind for x in t.nodes] == ["gateway", "router", "host"]
    assert n["2001:db8::2"].kind == "router"
    assert edges(t) == {("2001:db8::1", "2001:db8::2"),
                        ("2001:DB8:0:0:0:0:0:10", "2001:db8::2")}


def test_host_with_mac_that_is_hop_merges_without_dangling_edges():
    router = Host(ip="192.168.1.50", mac="AA:BB:CC:00:00:01")
    far = Host(ip="172.16.0.5")
    t = build_topology([router, far],
                       {"172.16.0.5": ["192.168.1.1", "192.168.1.50"]},
                       "192.168.1.1")
    n = nodes(t)
    assert n["AA:BB:CC:00:00:01"].kind == "router"
    assert "192.168.1.50" not in n
    assert len(t.nodes) == 3
    for e in t.edges:
        assert e.a in n and e.b in n
    assert edges(t) == {("192.168.1.1", "AA:BB:CC:00:00:01"),
                        ("172.16.0.5", "AA:BB:CC:00:00:01")}


def test_gateway_vote_tie_uses_numeric_order():
    hosts = [Host(ip="172.16.0.5"), Host(ip="172.16.0.6")]
    hops = {"172.16.0.5": ["10.0.0.9"], "172.16.0.6": ["10.0.0.10"]}
    n = nodes(build_topology(hosts, hops, None))
    assert n["10.0.0.9"].kind == "gateway"
    assert n["10.0.0.10"].kind == "router"


def test_hosts_sharing_a_mac_keep_separate_nodes():
    from landiscovery.models import Host
    from landiscovery.topology import build_topology
    mac = "AA:BB:CC:00:00:01"
    topo = build_topology([Host("10.0.0.2", mac), Host("10.0.0.3", mac), Host("10.0.0.1")],
                          {}, "10.0.0.1")
    ids = {n.id for n in topo.nodes}
    assert {"10.0.0.2", "10.0.0.3", "10.0.0.1"} <= ids
