"""Topologia di rete dedotta dai dati di traceroute di nmap."""
from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET
from collections import Counter

from .models import Edge, Host, Node, Topology, host_key, shared_macs
from .nmapxml import ScanParseError, reject_entities

_KIND_ORDER = {"gateway": 0, "router": 1, "host": 2}
VIRTUAL_GATEWAY = "gateway"
# Massimo di router intermedi per host: oltre, i salti sono ignorati.
MAX_HOPS = 64


def _norm(addr: str | None) -> str | None:
    """Indirizzo IPv4/IPv6 normalizzato, senza zona; None se non valido."""
    if not addr:
        return None
    addr = addr.strip().split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(addr))
    except ValueError:
        return None


def _subnet(addr: str) -> str:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return ""
    prefix = 24 if ip.version == 4 else 64
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def parse_traceroute(xml_text: str) -> dict[str, list[str]]:
    """Per ogni host, gli indirizzi intermedi del traceroute in ordine."""
    if not xml_text or not xml_text.strip():
        raise ScanParseError("XML di nmap vuoto")
    reject_entities(xml_text)
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ScanParseError(f"XML di nmap non valido: {exc}") from exc
    result: dict[str, list[str]] = {}
    for host in root.iter("host"):
        target = None
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                target = _norm(addr.get("addr"))
                if target:
                    break
        trace = host.find("trace")
        if target is None or trace is None:
            continue
        chain: list[str] = []
        seen: set[str] = set()
        for hop in trace.findall("hop"):
            if len(chain) >= MAX_HOPS:
                break
            ip = _norm(hop.get("ipaddr"))
            if ip is None or ip == target or ip in seen:
                continue
            seen.add(ip)
            chain.append(ip)
        result[target] = chain
    return result


def _infer_gateway(hops: dict[str, list[str]]) -> str | None:
    firsts = Counter(a for a in (_norm(h[0]) for h in hops.values() if h) if a)
    if not firsts:
        return None
    best = max(firsts.values())
    return min((a for a, n in firsts.items() if n == best),
               key=lambda a: (ipaddress.ip_address(a).version,
                              int(ipaddress.ip_address(a))))


def build_topology(hosts: list[Host], hops: dict[str, list[str]],
                   gateway: str | None) -> Topology:
    """Costruisce il grafo gateway -> router -> host; stella senza traceroute."""
    gw_ip = _norm(gateway) if gateway else None
    if gw_ip is None:
        gw_ip = _infer_gateway(hops)
    gw_id = gw_ip if gw_ip else VIRTUAL_GATEWAY

    shared = shared_macs(hosts)
    by_ip = {(_norm(h.ip) or h.ip): h for h in hosts}
    hops_by_ip = {(_norm(k) or k): v for k, v in hops.items()}
    nodes: dict[str, Node] = {}
    edges: set[tuple[str, str]] = set()

    gw_host = by_ip.get(gw_ip) if gw_ip else None
    nodes[gw_id] = Node(
        id=gw_id,
        label=(gw_host.hostname or gw_ip) if gw_host and gw_ip else
        ("Gateway" if gw_ip is None else gw_ip),
        kind="gateway",
        subnet=_subnet(gw_ip) if gw_ip else "",
    )

    def node_id(ip: str) -> str:
        if ip == gw_ip:
            return gw_id
        h = by_ip.get(ip)
        return host_key(h, shared) if h else ip

    def link(a: str, b: str) -> None:
        if a != b:
            edges.add((a, b) if a < b else (b, a))

    for host in sorted(hosts, key=lambda h: host_key(h, shared)):
        hip = _norm(host.ip) or host.ip
        hid = node_id(hip)
        chain: list[str] = []
        seen: set[str] = set()
        for raw in hops_by_ip.get(hip, []):
            if len(chain) >= MAX_HOPS:
                break
            ip = _norm(raw)
            if ip is None or ip == hip or ip in seen:
                continue
            seen.add(ip)
            chain.append(ip)
        prev = gw_id
        for ip in chain:
            nid = node_id(ip)
            if nid != gw_id:
                if nid not in nodes:
                    h = by_ip.get(ip)
                    nodes[nid] = Node(id=nid,
                                      label=(h.hostname if h and h.hostname
                                             else ip),
                                      kind="router", subnet=_subnet(ip))
            link(prev, nid)
            prev = nid
        if hid != gw_id:
            link(prev, hid)

    for host in hosts:
        hip = _norm(host.ip) or host.ip
        hid = node_id(hip)
        if hid in nodes:
            continue
        nodes[hid] = Node(id=hid, label=host.hostname or hip,
                          kind="host", subnet=_subnet(hip))

    ordered = sorted(nodes.values(),
                     key=lambda n: (_KIND_ORDER[n.kind], n.id))
    return Topology(nodes=ordered,
                    edges=[Edge(a, b) for a, b in sorted(edges)],
                    inferred=True)
